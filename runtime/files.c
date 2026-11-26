// kernel32 file system: Windows paths mapped onto the host, file handles over POSIX fds,
// directory search, volume queries, FILETIME conversions and the console bits of std I/O.
//
// Path mapping (guest Windows path -> host path):
//   <win_dir>\...    -> the game directory (the host cwd at boot); win_dir is rt_game.win_dir, e.g. C:\Games\X
//   X:\...           -> $<PREFIX>_DATA_DIR/x/... (default ~/Library/Application Support/<data_name>/x/...)
//   relative paths   -> resolved against the guest cwd, win_dir
// Lookups fall back to case-insensitive matching, component by component, so the guest's
// spelling of a path does not need to match the case on disk.
// Overlapped I/O completes synchronously: ReadFile/WriteFile return TRUE, fill the OVERLAPPED and set its event.
#include "rt.h"
#include "handles.h"
#include "game.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <copyfile.h>

#define INVALID_HANDLE 0xFFFFFFFFFFFFFFFFull
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define FILE_READ_DATA 1u
#define FILE_WRITE_DATA 2u
#define FILE_APPEND_DATA 4u
#define FLAG_OVERLAPPED 0x40000000u
#define FLAG_DELETE_ON_CLOSE 0x04000000u
#define FLAG_BACKUP_SEMANTICS 0x02000000u
#define ATTR_READONLY 0x01u
#define ATTR_HIDDEN 0x02u
#define ATTR_DIRECTORY 0x10u
#define ATTR_ARCHIVE 0x20u

enum {
    ERR_FILE_NOT_FOUND = 2, ERR_PATH_NOT_FOUND = 3, ERR_TOO_MANY_OPEN = 4, ERR_ACCESS_DENIED = 5, ERR_INVALID_HANDLE = 6,
    ERR_NO_MORE_FILES = 18, ERR_GEN_FAILURE = 31, ERR_SHARING = 32, ERR_HANDLE_EOF = 38, ERR_NOT_SUPPORTED = 50,
    ERR_BAD_NETPATH = 53, ERR_FILE_EXISTS = 80, ERR_INVALID_PARAMETER = 87, ERR_DISK_FULL = 112, ERR_INVALID_NAME = 123,
    ERR_NEGATIVE_SEEK = 131, ERR_DIR_NOT_EMPTY = 145, ERR_ALREADY_EXISTS = 183, ERR_FILENAME_TOO_LONG = 206,
};

extern void I_kernel32_dll_CloseHandle(CPU *c);

// ---------------- path mapping ----------------
static char g_root[PATH_MAX];        // host directory behind rt_game.win_dir
static char g_data[PATH_MAX];        // host directory holding the other drives
#define g_wcwd (rt_game.win_dir)   // the guest cwd: where the game believes it is installed
static pthread_once_t paths_once = PTHREAD_ONCE_INIT;
static uint32_t drive_made;          // bit per drive letter: host directory exists

static void mkdir_p(const char *path) {
    char t[PATH_MAX]; snprintf(t, sizeof t, "%s", path);
    for (char *p = t + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(t, 0755); *p = '/'; }
    mkdir(t, 0755);
}
static void paths_init(void) {
    if (!getcwd(g_root, sizeof g_root)) snprintf(g_root, sizeof g_root, ".");
    const char *d = rt_game_env("DATA_DIR");
    if (d && *d) snprintf(g_data, sizeof g_data, "%s", d);
    else snprintf(g_data, sizeof g_data, "%s/Library/Application Support/%s", getenv("HOME") ? getenv("HOME") : "/tmp", rt_game.data_name);
    mkdir_p(g_data);
    rt_log("[files] %s -> %s; other drives -> %s/<drive>\n", g_wcwd, g_root, g_data);
}

// Normalize a guest path to an absolute "X:\a\b" form (or pass a UNC/device path through).
// Returns 0 if the result does not fit.
static int win_full(const char *in, char *out, size_t n) {
    char s[2048];
    size_t L = strlen(in);
    if (L >= sizeof s) return 0;
    for (size_t i = 0; i <= L; i++) s[i] = in[i] == '/' ? '\\' : in[i];
    const char *p = s;
    if (!strncmp(p, "\\\\?\\", 4)) p += 4;
    if (p[0] == '\\' && p[1] == '\\') return snprintf(out, n, "%s", p) < (int)n;
    char t[4096];
    if (isalpha((unsigned char)p[0]) && p[1] == ':') {
        char drive = (char)toupper((unsigned char)p[0]);
        if (p[2] == '\\') snprintf(t, sizeof t, "%c:%s", drive, p + 2);
        else if (drive == g_wcwd[0]) snprintf(t, sizeof t, "%s\\%s", g_wcwd, p + 2);   // drive-relative
        else snprintf(t, sizeof t, "%c:\\%s", drive, p + 2);
    } else if (p[0] == '\\') snprintf(t, sizeof t, "%c:%s", g_wcwd[0], p);
    else snprintf(t, sizeof t, "%s\\%s", g_wcwd, p);
    int trailing = L && s[L - 1] == '\\';

    char *comp[512]; int nc = 0;
    char *rest = t + 3, *tok;
    while ((tok = strsep(&rest, "\\")) != NULL) {
        if (!*tok || !strcmp(tok, ".")) continue;
        if (!strcmp(tok, "..")) { if (nc) nc--; continue; }
        size_t k = strlen(tok);
        while (k > 1 && (tok[k - 1] == '.' || tok[k - 1] == ' ')) tok[--k] = 0;   // Windows trims these
        if (nc < 512) comp[nc++] = tok;
    }
    size_t o = (size_t)snprintf(out, n, "%c:", t[0]);
    for (int i = 0; i < nc && o < n; i++) o += (size_t)snprintf(out + o, n - o, "\\%s", comp[i]);
    if ((!nc || trailing) && o < n) o += (size_t)snprintf(out + o, n - o, "\\");
    return o < n;
}

// Fix the case of each missing component of a host path (below `bl`, the mapped root) to match the disk.
static void ci_resolve(char *p, size_t bl) {
    struct stat st;
    if (!lstat(p, &st)) return;
    size_t i = bl;
    while (p[i]) {   // p[i] == '/'
        size_t s = i + 1, j = s;
        while (p[j] && p[j] != '/') j++;
        char save = p[j]; p[j] = 0;
        if (lstat(p, &st)) {
            int found = 0;
            p[i] = 0;
            DIR *d = opendir(*p ? p : "/");
            p[i] = '/';
            if (d) {
                struct dirent *e;
                while ((e = readdir(d)))
                    if (strlen(e->d_name) == j - s && !strncasecmp(e->d_name, p + s, j - s)) { memcpy(p + s, e->d_name, j - s); found = 1; break; }
                closedir(d);
            }
            if (!found) { p[j] = save; return; }
        }
        p[j] = save;
        i = j;
    }
}

// Guest path -> malloc'd host path, or NULL with the last error set.
static char *host_path(const char *win) {
    pthread_once(&paths_once, paths_init);
    if (!win || !*win) { set_last_error(ERR_PATH_NOT_FOUND); return NULL; }
    if (!strcasecmp(win, "NUL") || !strcasecmp(win, "\\\\.\\NUL")) return strdup("/dev/null");
    if (!strcasecmp(win, "CONOUT$")) return strdup("/dev/stdout");
    if (!strcasecmp(win, "CONIN$")) return strdup("/dev/stdin");
    char full[4096];
    if (!win_full(win, full, sizeof full)) { set_last_error(ERR_FILENAME_TOO_LONG); return NULL; }
    if (full[0] == '\\') { set_last_error(ERR_BAD_NETPATH); return NULL; }   // UNC and \\.\ devices
    const char *rest = full + 2;
    char base[PATH_MAX];
    size_t wl = strlen(g_wcwd) - 2;   // win_dir without its drive ("\\Games\\X")
    if (toupper((unsigned char)full[0]) == toupper((unsigned char)g_wcwd[0]) && !strncasecmp(rest, g_wcwd + 2, wl) && (rest[wl] == '\\' || !rest[wl])) {
        snprintf(base, sizeof base, "%s", g_root);
        rest += wl;
    } else {
        int d = full[0] - 'A';
        snprintf(base, sizeof base, "%s/%c", g_data, 'a' + d);
        if (!(__atomic_load_n(&drive_made, __ATOMIC_RELAXED) & (1u << d))) { mkdir(base, 0755); __atomic_fetch_or(&drive_made, 1u << d, __ATOMIC_RELAXED); }
    }
    size_t bl = strlen(base), rl = strlen(rest);
    char *o = malloc(bl + rl + 1);
    memcpy(o, base, bl);
    for (size_t i = 0; i <= rl; i++) o[bl + i] = rest[i] == '\\' ? '/' : rest[i];
    size_t L = bl + rl;
    while (L > bl && o[L - 1] == '/') o[--L] = 0;
    ci_resolve(o, bl);
    return o;
}

char *rt_host_path(const char *win) { return host_path(win); }

static uint32_t errno_err(int e, const char *host) {
    switch (e) {
    case ENOENT:
        if (host) {   // FILE_NOT_FOUND only when the containing directory exists
            char t[PATH_MAX]; snprintf(t, sizeof t, "%s", host);
            char *sl = strrchr(t, '/'); struct stat st;
            if (sl && sl != t) { *sl = 0; if (stat(t, &st) || !S_ISDIR(st.st_mode)) return ERR_PATH_NOT_FOUND; }
        }
        return ERR_FILE_NOT_FOUND;
    case ENOTDIR: return ERR_PATH_NOT_FOUND;
    case EACCES: case EPERM: case EISDIR: case EROFS: return ERR_ACCESS_DENIED;
    case EEXIST: return ERR_FILE_EXISTS;
    case ENOTEMPTY: return ERR_DIR_NOT_EMPTY;
    case ENOSPC: case EDQUOT: return ERR_DISK_FULL;
    case EMFILE: case ENFILE: return ERR_TOO_MANY_OPEN;
    case ENAMETOOLONG: return ERR_FILENAME_TOO_LONG;
    case EBUSY: return ERR_SHARING;
    case EBADF: return ERR_INVALID_HANDLE;
    case EINVAL: return ERR_INVALID_PARAMETER;
    default: return ERR_GEN_FAILURE;
    }
}

// ---------------- small helpers ----------------
static char *arg_str(uint64_t p, int wide) { return p ? (wide ? w16_to_utf8(PTR(p)) : strdup(PTR(p))) : NULL; }
// Copy a string result: returns its length if it fit in n chars (with NUL), else the size needed including NUL.
static uint32_t put_str(uint64_t buf, uint32_t n, const char *s, int wide) {
    if (wide) {
        uint16_t *w = utf8_to_w16(s); uint32_t L = (uint32_t)w16len(w);
        if (buf && n > L) memcpy(PTR(buf), w, (L + 1) * 2u);
        free(w); return n > L ? L : L + 1;
    }
    uint32_t L = (uint32_t)strlen(s);
    if (buf && n > L) memcpy(PTR(buf), s, L + 1);
    return n > L ? L : L + 1;
}
static void put_fixed(uint64_t buf, uint32_t n, const char *s) { if (buf && n) { strlcpy(PTR(buf), s, n); } }
static uint64_t ts_ft(struct timespec t) { return (uint64_t)((int64_t)t.tv_sec + 11644473600ll) * 10000000ull + (uint64_t)t.tv_nsec / 100; }
static uint32_t attrs_of(const struct stat *st, const char *name) {
    uint32_t a = S_ISDIR(st->st_mode) ? ATTR_DIRECTORY : ATTR_ARCHIVE;
    if (!(st->st_mode & S_IWUSR)) a |= ATTR_READONLY;
    if (name && name[0] == '.' && strcmp(name, ".") && strcmp(name, "..")) a |= ATTR_HIDDEN;
    return a;
}
static const char *base_name(const char *p) { const char *b = strrchr(p, '/'); return b ? b + 1 : p; }
// stat a guest path; NULL host path on failure (last error set)
static char *stat_path(const char *win, struct stat *st) {
    char *h = host_path(win);
    if (h && stat(h, st)) { set_last_error(errno_err(errno, h)); free(h); return NULL; }
    return h;
}

// ---------------- file handles ----------------
static void file_close(HObj *o) {
    if (o->fd > 2) close(o->fd);
    if ((o->fflags & FLAG_DELETE_ON_CLOSE) && o->name) unlink(o->name);
}
// fd behind a guest handle (std handles map to 0/1/2); -1 with ERROR_INVALID_HANDLE
static int fd_of(uint64_t h, HObj **po) {
    if (po) *po = NULL;
    switch (h >> 32) { case 0x53544430: return 0; case 0x53544431: return 1; case 0x53544432: return 2; }
    HObj *o = h_get(h);
    if (!o || o->type != HT_FILE) { set_last_error(ERR_INVALID_HANDLE); return -1; }
    if (po) *po = o;
    return o->fd;
}

// CreateFile(name, access, share, sec, disposition, flags, template)
static void create_file(CPU *c, int wide) {
    char *win = arg_str(A0, wide);
    uint32_t access = (uint32_t)A1, disp = (uint32_t)AN(4), flags = (uint32_t)AN(5);
    char *h = NULL;
    if (win && !strncmp(win, "\\\\.\\", 4) && strcasecmp(win, "\\\\.\\NUL")) set_last_error(ERR_FILE_NOT_FOUND);   // devices
    else h = host_path(win);
    if (!h) { free(win); RET(INVALID_HANDLE); return; }

    int rd = (access & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA)) != 0;
    int wr = (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    int of = O_CLOEXEC | (wr ? (rd ? O_RDWR : O_WRONLY) : O_RDONLY);
    if (wr && !(access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA))) of |= O_APPEND;
    struct stat st; int existed = !stat(h, &st);
    if (existed && S_ISDIR(st.st_mode)) {
        if (!(flags & FLAG_BACKUP_SEMANTICS) || disp == 1 || disp == 2) { set_last_error(ERR_ACCESS_DENIED); goto fail; }
        of = O_CLOEXEC | O_RDONLY;
    } else {
        switch (disp) {
        case 1: of |= O_CREAT | O_EXCL; break;                     // CREATE_NEW
        case 2: of |= O_CREAT | O_TRUNC; if (!wr) of = (of & ~O_ACCMODE) | O_RDWR; break;   // CREATE_ALWAYS
        case 3: break;                                             // OPEN_EXISTING
        case 4: of |= O_CREAT; break;                              // OPEN_ALWAYS
        case 5: of |= O_TRUNC; if (!wr) of = (of & ~O_ACCMODE) | O_RDWR; break;             // TRUNCATE_EXISTING
        default: set_last_error(ERR_INVALID_PARAMETER); goto fail;
        }
    }
    int fd = open(h, of, 0644);
    if (fd < 0) { set_last_error(errno_err(errno, h)); goto fail; }
    HObj *o = h_alloc(HT_FILE);
    o->fd = fd; o->fflags = flags; o->name = h; o->close = file_close;
    set_last_error(existed && (disp == 2 || disp == 4) ? ERR_ALREADY_EXISTS : 0);
    free(win);
    RET(h_new(o));
    return;
fail:
    free(h); free(win);
    RET(INVALID_HANDLE);
}
void I_kernel32_dll_CreateFileA(CPU *c) { create_file(c, 0); }
void I_kernel32_dll_CreateFileW(CPU *c) { create_file(c, 1); }

// full transfer (regular files); one call for terminals/pipes. off < 0: use the file position.
static int64_t io_all(int fd, uint8_t *buf, size_t n, int64_t off, int wr) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = off >= 0 ? (wr ? pwrite(fd, buf + done, n - done, off + (int64_t)done) : pread(fd, buf + done, n - done, off + (int64_t)done))
                             : (wr ? write(fd, buf + done, n - done) : read(fd, buf + done, n - done));
        if (r < 0) { if (errno == EINTR) continue; return done ? (int64_t)done : -1; }
        if (r == 0) break;
        done += (size_t)r;
        if (!wr && fd <= 2) break;
    }
    return (int64_t)done;
}
// OVERLAPPED: Internal(status) +0, InternalHigh(bytes) +8, Offset +16, OffsetHigh +20, hEvent +24
static void ovl_done(uint64_t ovl, uint32_t status, uint64_t n) {
    wr64(ovl, status); wr64(ovl + 8, n);
    uint64_t ev = rd64(ovl + 24) & ~3ull;   // low bit: "don't post to a completion port"
    if (ev) {
        h_lock();
        HObj *e = h_get(ev);
        if (e && e->type == HT_EVENT) { e->state = 1; h_wake(e); }
        h_unlock();
    }
}
// ReadFile/WriteFile(h, buf, n, *done, ovl)
static void rw_file(CPU *c, int wr) {
    uint64_t buf = A1, pdone = A3, ovl = AN(4); uint32_t n = (uint32_t)A2;
    HObj *o; int fd = fd_of(A0, &o);
    if (pdone) wr32(pdone, 0);
    if (fd < 0) { RET(0); return; }
    int64_t off = -1;
    if (ovl) {
        off = (int64_t)((uint64_t)rd32(ovl + 16) | (uint64_t)rd32(ovl + 20) << 32);
        if (!(o && (o->fflags & FLAG_OVERLAPPED))) { lseek(fd, off, SEEK_SET); off = -1; }   // sync handle: also moves the file pointer
    }
    int64_t r = io_all(fd, PTR(buf), n, off, wr);
    if (r < 0) {
        uint32_t e = errno_err(errno, NULL);
        if (ovl) ovl_done(ovl, 0xC0000001u, 0);
        set_last_error(e); RET(0); return;
    }
    if (pdone) wr32(pdone, (uint32_t)r);
    if (ovl) {
        if (!wr && r == 0 && n) { ovl_done(ovl, 0xC0000011u, 0); set_last_error(ERR_HANDLE_EOF); RET(0); return; }   // STATUS_END_OF_FILE
        ovl_done(ovl, 0, (uint64_t)r);
    }
    RET(1);
}
void I_kernel32_dll_ReadFile(CPU *c) { rw_file(c, 0); }
void I_kernel32_dll_WriteFile(CPU *c) { rw_file(c, 1); }

// ReadFileScatter(h, FILE_SEGMENT_ELEMENT segs[], n, reserved, ovl): reads n bytes at the OVERLAPPED's offset into
// one system page (0x1000, as GetSystemInfo reports) per segment, each segment a 64-bit buffer pointer. Windows
// requires an overlapped, unbuffered handle, and such a read always goes pending: callers (id Tech's
// virtual-texture page streamer) only handle FALSE + ERROR_IO_PENDING followed by GetOverlappedResult. The function
// has no bytes-read output, so on a TRUE return the streamer sees 0 bytes and zero-fills the pages (black textures).
// So the read is done here at once, but reported as pending; the OVERLAPPED already holds the result.
#include <sys/uio.h>
void I_kernel32_dll_ReadFileScatter(CPU *c) {
    uint64_t segs = A1, ovl = AN(4); uint32_t n = (uint32_t)A2;
    const size_t page = 0x1000;
    HObj *o; int fd = fd_of(A0, &o);
    if (fd < 0 || !ovl || !segs) { set_last_error(87); RET(0); return; }   // ERROR_INVALID_PARAMETER
    int64_t off = (int64_t)((uint64_t)rd32(ovl + 16) | (uint64_t)rd32(ovl + 20) << 32);
    size_t total = 0, npages = (n + page - 1) / page;
    struct iovec iov[256];
    while (total < n) {
        int k = 0; size_t want = 0;
        for (size_t p = total / page; p < npages && k < 256; p++, k++) {
            iov[k].iov_base = PTR(rd64(segs + 8 * p));
            iov[k].iov_len = (p + 1) * page <= n ? page : n - p * page;
            want += iov[k].iov_len;
        }
        ssize_t r = preadv(fd, iov, k, off + (int64_t)total);
        if (r < 0) {
            if (errno == EINTR) continue;
            ovl_done(ovl, 0xC0000001u, total); set_last_error(errno_err(errno, NULL)); RET(0); return;
        }
        total += (size_t)r;
        if ((size_t)r < want) break;   // end of file
    }
    if (!total && n) ovl_done(ovl, 0xC0000011u, 0);   // STATUS_END_OF_FILE, reported by GetOverlappedResult
    else ovl_done(ovl, 0, total);
    set_last_error(997);   // ERROR_IO_PENDING
    RET(0);
}

// GetOverlappedResult(h, ovl, *bytes, wait): everything completed synchronously
void I_kernel32_dll_GetOverlappedResult(CPU *c) {
    uint64_t ovl = A1; uint32_t st = (uint32_t)rd64(ovl);
    if (A2) wr32(A2, (uint32_t)rd64(ovl + 8));
    if (st == 0) { RET(1); return; }
    set_last_error(st == 0xC0000011u ? ERR_HANDLE_EOF : ERR_GEN_FAILURE);
    RET(0);
}

static int whence_of(uint32_t m) { return m == 1 ? SEEK_CUR : m == 2 ? SEEK_END : SEEK_SET; }
// SetFilePointer(h, lo, *hi, method) -> new low dword
void I_kernel32_dll_SetFilePointer(CPU *c) {
    int fd = fd_of(A0, NULL);
    if (fd < 0) { RET(0xFFFFFFFFu); return; }
    int64_t dist = A2 ? (int64_t)((uint64_t)rd32(A2) << 32 | (uint32_t)A1) : (int64_t)(int32_t)A1;
    off_t p = lseek(fd, dist, whence_of((uint32_t)A3));
    if (p < 0) { set_last_error(ERR_NEGATIVE_SEEK); RET(0xFFFFFFFFu); return; }
    if (A2) wr32(A2, (uint32_t)((uint64_t)p >> 32));
    set_last_error(0);
    RET((uint32_t)p);
}
// SetFilePointerEx(h, LARGE_INTEGER dist, *newpos, method)
void I_kernel32_dll_SetFilePointerEx(CPU *c) {
    int fd = fd_of(A0, NULL);
    if (fd < 0) { RET(0); return; }
    off_t p = lseek(fd, (int64_t)A1, whence_of((uint32_t)A3));
    if (p < 0) { set_last_error(ERR_NEGATIVE_SEEK); RET(0); return; }
    if (A2) wr64(A2, (uint64_t)p);
    RET(1);
}
void I_kernel32_dll_GetFileSize(CPU *c) {
    int fd = fd_of(A0, NULL); struct stat st;
    if (fd < 0 || fstat(fd, &st)) { set_last_error(ERR_INVALID_HANDLE); RET(0xFFFFFFFFu); return; }
    if (A1) wr32(A1, (uint32_t)((uint64_t)st.st_size >> 32));
    set_last_error(0);
    RET((uint32_t)st.st_size);
}
void I_kernel32_dll_GetFileSizeEx(CPU *c) {
    int fd = fd_of(A0, NULL); struct stat st;
    if (fd < 0 || fstat(fd, &st)) { set_last_error(ERR_INVALID_HANDLE); RET(0); return; }
    wr64(A1, (uint64_t)st.st_size);
    RET(1);
}
void I_kernel32_dll_GetFileTime(CPU *c) {
    int fd = fd_of(A0, NULL); struct stat st;
    if (fd < 0 || fstat(fd, &st)) { set_last_error(ERR_INVALID_HANDLE); RET(0); return; }
    if (A1) wr64(A1, ts_ft(st.st_birthtimespec));
    if (A2) wr64(A2, ts_ft(st.st_atimespec));
    if (A3) wr64(A3, ts_ft(st.st_mtimespec));
    RET(1);
}
// GetFileInformationByHandle(h, BY_HANDLE_FILE_INFORMATION*): attributes +0, creation +4, access +12, write +20,
// volume serial +28, size high +32 / low +36, links +40, file index high +44 / low +48. The UCRT's fstat uses it.
void I_kernel32_dll_GetFileInformationByHandle(CPU *c) {
    HObj *o; int fd = fd_of(A0, &o); struct stat st;
    if (fd < 0 || fstat(fd, &st)) { set_last_error(ERR_INVALID_HANDLE); RET(0); return; }
    uint64_t b = A1;
    wr32(b, attrs_of(&st, o && o->name ? o->name : ""));
    wr64(b + 4, ts_ft(st.st_birthtimespec)); wr64(b + 12, ts_ft(st.st_atimespec)); wr64(b + 20, ts_ft(st.st_mtimespec));
    wr32(b + 28, (uint32_t)st.st_dev);
    wr32(b + 32, (uint32_t)((uint64_t)st.st_size >> 32)); wr32(b + 36, (uint32_t)st.st_size);
    wr32(b + 40, (uint32_t)st.st_nlink);
    wr32(b + 44, (uint32_t)((uint64_t)st.st_ino >> 32)); wr32(b + 48, (uint32_t)st.st_ino);
    RET(1);
}
// CancelIo(h): overlapped I/O here completes inside the call that starts it, so nothing is ever outstanding
void I_kernel32_dll_CancelIo(CPU *c) { RET(1); }
void I_kernel32_dll_SetEndOfFile(CPU *c) {
    int fd = fd_of(A0, NULL);
    if (fd < 0) { RET(0); return; }
    off_t p = lseek(fd, 0, SEEK_CUR);
    if (p < 0 || ftruncate(fd, p)) { set_last_error(errno_err(errno, NULL)); RET(0); return; }
    RET(1);
}
void I_kernel32_dll_FlushFileBuffers(CPU *c) {
    int fd = fd_of(A0, NULL);
    if (fd < 0) { RET(0); return; }
    if (fd > 2) fsync(fd);
    RET(1);
}
// GetFileInformationByHandleEx(h, class, buf, size): FileBasicInfo (0) and FileStandardInfo (1)
void I_kernel32_dll_GetFileInformationByHandleEx(CPU *c) {
    HObj *o; int fd = fd_of(A0, &o); struct stat st; uint64_t b = A2;
    if (fd < 0 || fstat(fd, &st)) { set_last_error(ERR_INVALID_HANDLE); RET(0); return; }
    switch ((uint32_t)A1) {
    case 0:
        if ((uint32_t)A3 < 40) break;
        memset(PTR(b), 0, 40);
        wr64(b, ts_ft(st.st_birthtimespec)); wr64(b + 8, ts_ft(st.st_atimespec));
        wr64(b + 16, ts_ft(st.st_mtimespec)); wr64(b + 24, ts_ft(st.st_ctimespec));
        wr32(b + 32, attrs_of(&st, o && o->name ? base_name(o->name) : NULL));
        RET(1); return;
    case 1:
        if ((uint32_t)A3 < 24) break;
        memset(PTR(b), 0, 24);
        wr64(b, (uint64_t)st.st_blocks * 512); wr64(b + 8, (uint64_t)st.st_size);
        wr32(b + 16, (uint32_t)st.st_nlink);
        wr8(b + 20, o && (o->fflags & FLAG_DELETE_ON_CLOSE)); wr8(b + 21, S_ISDIR(st.st_mode));
        RET(1); return;
    default:
        rt_log("[files] GetFileInformationByHandleEx class %u not supported\n", (unsigned)A1);
        set_last_error(ERR_NOT_SUPPORTED); RET(0); return;
    }
    set_last_error(ERR_INVALID_PARAMETER); RET(0);
}
// SetFileInformationByHandle(h, class, buf, size): FileDispositionInfo (4), FileEndOfFileInfo (6), FileBasicInfo (0, ignored)
void I_kernel32_dll_SetFileInformationByHandle(CPU *c) {
    HObj *o; int fd = fd_of(A0, &o);
    if (fd < 0) { RET(0); return; }
    switch ((uint32_t)A1) {
    case 0: RET(1); return;
    case 4: if (o) { if (rd8(A2)) o->fflags |= FLAG_DELETE_ON_CLOSE; else o->fflags &= ~FLAG_DELETE_ON_CLOSE; } RET(1); return;
    case 6: if (ftruncate(fd, (off_t)rd64(A2))) { set_last_error(errno_err(errno, NULL)); RET(0); return; } RET(1); return;
    default:
        rt_log("[files] SetFileInformationByHandle class %u not supported\n", (unsigned)A1);
        set_last_error(ERR_NOT_SUPPORTED); RET(0);
    }
}
// No other process shares these files: byte-range locks always succeed.
void I_kernel32_dll_LockFile(CPU *c) { RET(1); }
void I_kernel32_dll_UnlockFile(CPU *c) { RET(1); }
void I_kernel32_dll_LockFileEx(CPU *c) { if (AN(5)) ovl_done(AN(5), 0, 0); RET(1); }
void I_kernel32_dll_UnlockFileEx(CPU *c) { if (AN(4)) ovl_done(AN(4), 0, 0); RET(1); }

// ---------------- attributes / file operations by name ----------------
static void get_attrs(CPU *c, int wide) {
    char *win = arg_str(A0, wide); struct stat st;
    char *h = stat_path(win, &st);
    RET(h ? attrs_of(&st, base_name(h)) : 0xFFFFFFFFu);
    free(h); free(win);
}
void I_kernel32_dll_GetFileAttributesA(CPU *c) { get_attrs(c, 0); }
void I_kernel32_dll_GetFileAttributesW(CPU *c) { get_attrs(c, 1); }
// GetFileAttributesEx(name, level, WIN32_FILE_ATTRIBUTE_DATA*)
static void get_attrs_ex(CPU *c, int wide) {
    char *win = arg_str(A0, wide); struct stat st; uint64_t b = A2;
    char *h = stat_path(win, &st);
    if (h) {
        wr32(b, attrs_of(&st, base_name(h)));
        wr64(b + 4, ts_ft(st.st_birthtimespec)); wr64(b + 12, ts_ft(st.st_atimespec)); wr64(b + 20, ts_ft(st.st_mtimespec));
        uint64_t sz = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
        wr32(b + 28, (uint32_t)(sz >> 32)); wr32(b + 32, (uint32_t)sz);
    }
    RET(h != NULL);
    free(h); free(win);
}
void I_kernel32_dll_GetFileAttributesExA(CPU *c) { get_attrs_ex(c, 0); }
void I_kernel32_dll_GetFileAttributesExW(CPU *c) { get_attrs_ex(c, 1); }
static void set_attrs(CPU *c, int wide) {
    char *win = arg_str(A0, wide); struct stat st;
    char *h = stat_path(win, &st);
    if (h) chmod(h, ((uint32_t)A1 & ATTR_READONLY) ? (st.st_mode & ~0222) : (st.st_mode | S_IWUSR));
    RET(h != NULL);
    free(h); free(win);
}
void I_kernel32_dll_SetFileAttributesA(CPU *c) { set_attrs(c, 0); }
void I_kernel32_dll_SetFileAttributesW(CPU *c) { set_attrs(c, 1); }

static void path_op(CPU *c, int wide, int op) {   // 0 DeleteFile, 1 CreateDirectory, 2 RemoveDirectory
    char *win = arg_str(A0, wide), *h = host_path(win); int ok = 0; struct stat st;
    if (h) {
        int r;
        if (op == 0) r = (!stat(h, &st) && S_ISDIR(st.st_mode)) ? (errno = EISDIR, -1) : unlink(h);
        else if (op == 1) r = mkdir(h, 0755);
        else r = rmdir(h);
        ok = r == 0;
        if (!ok) set_last_error(op == 1 && errno == EEXIST ? ERR_ALREADY_EXISTS : errno_err(errno, h));
    }
    RET(ok);
    free(h); free(win);
}
void I_kernel32_dll_DeleteFileA(CPU *c) { path_op(c, 0, 0); }
void I_kernel32_dll_DeleteFileW(CPU *c) { path_op(c, 1, 0); }
void I_kernel32_dll_CreateDirectoryA(CPU *c) { path_op(c, 0, 1); }
void I_kernel32_dll_CreateDirectoryW(CPU *c) { path_op(c, 1, 1); }
void I_kernel32_dll_RemoveDirectoryA(CPU *c) { path_op(c, 0, 2); }
void I_kernel32_dll_RemoveDirectoryW(CPU *c) { path_op(c, 1, 2); }

// MoveFileEx(src, dst, flags): REPLACE_EXISTING 1, COPY_ALLOWED 2, DELAY_UNTIL_REBOOT 4
static void move_file(CPU *c, int wide) {
    char *ws = arg_str(A0, wide), *wd = arg_str(A1, wide); uint32_t fl = (uint32_t)A2;
    char *s = host_path(ws), *d = wd ? host_path(wd) : NULL; int ok = 0; struct stat st;
    if (!wd && (fl & 4)) ok = 1;   // delete at reboot: never happens
    else if (s && d) {
        if (!(fl & 1) && !stat(d, &st)) set_last_error(ERR_ALREADY_EXISTS);
        else if (!rename(s, d)) ok = 1;
        else if (errno == EXDEV && (fl & 2) && !copyfile(s, d, NULL, COPYFILE_ALL) && !unlink(s)) ok = 1;
        else set_last_error(errno_err(errno, s));
    }
    RET(ok);
    free(s); free(d); free(ws); free(wd);
}
void I_kernel32_dll_MoveFileExA(CPU *c) { move_file(c, 0); }
void I_kernel32_dll_MoveFileExW(CPU *c) { move_file(c, 1); }
void I_kernel32_dll_MoveFileA(CPU *c) { c->r8 = 2; move_file(c, 0); }
void I_kernel32_dll_MoveFileW(CPU *c) { c->r8 = 2; move_file(c, 1); }
// CopyFile(src, dst, failIfExists)
static void copy_file(CPU *c, int wide) {
    char *ws = arg_str(A0, wide), *wd = arg_str(A1, wide);
    char *s = host_path(ws), *d = host_path(wd); int ok = 0; struct stat st;
    if (s && d) {
        if (A2 && !stat(d, &st)) set_last_error(ERR_FILE_EXISTS);
        else if (stat(s, &st)) set_last_error(errno_err(errno, s));
        else if (copyfile(s, d, NULL, COPYFILE_DATA | COPYFILE_STAT)) set_last_error(errno_err(errno, d));
        else ok = 1;
    }
    RET(ok);
    free(s); free(d); free(ws); free(wd);
}
void I_kernel32_dll_CopyFileA(CPU *c) { copy_file(c, 0); }
void I_kernel32_dll_CopyFileW(CPU *c) { copy_file(c, 1); }

// ---------------- directory search ----------------
// WIN32_FIND_DATAW: attrs +0, ctime +4, atime +12, mtime +20, sizeHigh +28, sizeLow +32, name[260] +44, alt[14] +564 (592 bytes)
// WIN32_FIND_DATAA: same up to +44, name[260] +44, alt[14] +304 (320 bytes)
typedef struct { DIR *d; int wide; char pat[1024]; } Find;
static int wild_match(const char *p, const char *s) {
    for (; *p; p++, s++) {
        if (*p == '*') {
            while (p[1] == '*') p++;
            if (!p[1]) return 1;
            for (; *s; s++) if (wild_match(p + 1, s)) return 1;
            return wild_match(p + 1, s);
        }
        if (!*s) return 0;
        if (*p != '?' && tolower((unsigned char)*p) != tolower((unsigned char)*s)) return 0;
    }
    return !*s;
}
static int find_match(const char *pat, const char *name) {
    if (!strcmp(pat, "*.*") || wild_match(pat, name)) return 1;
    size_t L = strlen(pat);   // "name.*" also matches "name" (no extension)
    if (L >= 2 && pat[L - 2] == '.' && pat[L - 1] == '*') { char t[1024]; snprintf(t, sizeof t, "%.*s", (int)(L - 2), pat); return wild_match(t, name); }
    return 0;
}
static void fill_find(uint64_t d, int wide, const char *name, const struct stat *st) {
    memset(PTR(d), 0, wide ? 592 : 320);
    wr32(d, attrs_of(st, name));
    wr64(d + 4, ts_ft(st->st_birthtimespec)); wr64(d + 12, ts_ft(st->st_atimespec)); wr64(d + 20, ts_ft(st->st_mtimespec));
    uint64_t sz = S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_size;
    wr32(d + 28, (uint32_t)(sz >> 32)); wr32(d + 32, (uint32_t)sz);
    if (wide) {
        uint16_t *w = utf8_to_w16(name); size_t n = w16len(w); if (n > 259) n = 259;
        memcpy(PTR(d + 44), w, n * 2); free(w);
    } else strlcpy(PTR(d + 44), name, 260);
}
static int find_next(Find *f, uint64_t data) {
    if (!f->d) return 0;
    struct dirent *e; struct stat st;
    while ((e = readdir(f->d))) {
        if (!find_match(f->pat, e->d_name)) continue;
        if (fstatat(dirfd(f->d), e->d_name, &st, 0)) continue;   // dangling symlink
        fill_find(data, f->wide, e->d_name, &st);
        return 1;
    }
    return 0;
}
static void find_close(HObj *o) { Find *f = o->data; if (f) { if (f->d) closedir(f->d); free(f); } }

static uint64_t find_first(const char *win, uint64_t data, int wide) {
    pthread_once(&paths_once, paths_init);
    char full[4096];
    if (!win || !*win) { set_last_error(ERR_FILE_NOT_FOUND); return INVALID_HANDLE; }
    if (!win_full(win, full, sizeof full)) { set_last_error(ERR_FILENAME_TOO_LONG); return INVALID_HANDLE; }
    char *sl = strrchr(full, '\\');
    if (!sl || !sl[1]) { set_last_error(ERR_FILE_NOT_FOUND); return INVALID_HANDLE; }
    Find *f = calloc(1, sizeof *f); f->wide = wide;
    snprintf(f->pat, sizeof f->pat, "%s", sl + 1);
    if (!strpbrk(f->pat, "*?")) {
        // no wildcard: a single lookup of that exact entry
        struct stat st; char *h = stat_path(full, &st);
        free(f);
        if (!h) return INVALID_HANDLE;
        fill_find(data, wide, base_name(h), &st);
        free(h);
        HObj *o = h_alloc(HT_FIND); o->data = calloc(1, sizeof(Find)); o->close = find_close;
        return h_new(o);
    }
    if (sl == full + 2) sl[1] = 0; else *sl = 0;   // keep "X:\" for the root
    char *h = host_path(full);
    f->d = h ? opendir(h) : NULL;
    if (!f->d) { if (h) set_last_error(ERR_PATH_NOT_FOUND); free(h); free(f); return INVALID_HANDLE; }
    free(h);
    if (!find_next(f, data)) { closedir(f->d); free(f); set_last_error(ERR_FILE_NOT_FOUND); return INVALID_HANDLE; }
    HObj *o = h_alloc(HT_FIND); o->data = f; o->close = find_close;
    return h_new(o);
}
static void find_first_shim(CPU *c, int wide, uint64_t data) {
    char *win = arg_str(A0, wide);
    RET(find_first(win, data, wide));
    free(win);
}
void I_kernel32_dll_FindFirstFileA(CPU *c) { find_first_shim(c, 0, A1); }
void I_kernel32_dll_FindFirstFileW(CPU *c) { find_first_shim(c, 1, A1); }
// FindFirstFileEx(name, infoLevel, data, searchOp, filter, flags): the extra options are hints only
void I_kernel32_dll_FindFirstFileExA(CPU *c) { find_first_shim(c, 0, A2); }
void I_kernel32_dll_FindFirstFileExW(CPU *c) { find_first_shim(c, 1, A2); }
static void find_next_shim(CPU *c, int wide) {
    HObj *o = h_get(A0);
    if (!o || o->type != HT_FIND) { set_last_error(ERR_INVALID_HANDLE); RET(0); return; }
    Find *f = o->data; f->wide = wide;
    if (find_next(f, A1)) { RET(1); return; }
    set_last_error(ERR_NO_MORE_FILES); RET(0);
}
void I_kernel32_dll_FindNextFileA(CPU *c) { find_next_shim(c, 0); }
void I_kernel32_dll_FindNextFileW(CPU *c) { find_next_shim(c, 1); }
void I_kernel32_dll_FindClose(CPU *c) { I_kernel32_dll_CloseHandle(c); }

// ---------------- path queries ----------------
static void get_cwd(CPU *c, int wide) { RET(put_str(A1, (uint32_t)A0, g_wcwd, wide)); }
void I_kernel32_dll_GetCurrentDirectoryA(CPU *c) { get_cwd(c, 0); }
void I_kernel32_dll_GetCurrentDirectoryW(CPU *c) { get_cwd(c, 1); }
void I_kernel32_dll_SetCurrentDirectoryA(CPU *c) { RET(1); }   // the guest cwd stays win_dir
void I_kernel32_dll_SetCurrentDirectoryW(CPU *c) { RET(1); }
// set *filepart to the character after the last backslash of the result (NULL if it ends with one)
static void set_filepart(uint64_t buf, uint64_t fp, int wide) {
    if (!fp) return;
    uint64_t last = 0, i = 0;
    if (wide) { for (; rd16(buf + 2 * i); i++) if (rd16(buf + 2 * i) == '\\') last = buf + 2 * (i + 1); }
    else { for (; rd8(buf + i); i++) if (rd8(buf + i) == '\\') last = buf + i + 1; }
    wr64(fp, last && (wide ? rd16(last) : rd8(last)) ? last : 0);
}
// GetFullPathName(name, n, buf, *filepart)
static void full_path(CPU *c, int wide) {
    char *win = arg_str(A0, wide); char full[4096];
    if (!win || !*win) { set_last_error(ERR_INVALID_NAME); RET(0); free(win); return; }
    if (!win_full(win, full, sizeof full)) { set_last_error(ERR_FILENAME_TOO_LONG); RET(0); free(win); return; }
    uint32_t r = put_str(A2, (uint32_t)A1, full, wide);
    if (r < (uint32_t)A1) set_filepart(A2, A3, wide);
    RET(r);
    free(win);
}
void I_kernel32_dll_GetFullPathNameA(CPU *c) { full_path(c, 0); }
void I_kernel32_dll_GetFullPathNameW(CPU *c) { full_path(c, 1); }
static void temp_path(CPU *c, int wide) {
    char *h = host_path("C:\\Temp"); if (h) { mkdir_p(h); free(h); }
    RET(put_str(A1, (uint32_t)A0, "C:\\Temp\\", wide));
}
void I_kernel32_dll_GetTempPathA(CPU *c) { temp_path(c, 0); }
void I_kernel32_dll_GetTempPathW(CPU *c) { temp_path(c, 1); }
// GetTempFileNameA(path, prefix, unique, out[MAX_PATH]): with unique == 0 the file is created
void I_kernel32_dll_GetTempFileNameA(CPU *c) {
    const char *dir = PTR(A0), *pre = A1 ? PTR(A1) : ""; uint32_t u = (uint32_t)A2 & 0xFFFF;
    size_t dl = strlen(dir); const char *sep = dl && dir[dl - 1] == '\\' ? "" : "\\";
    static uint32_t counter;
    char name[1024];
    if (u) { snprintf(name, sizeof name, "%s%s%.3s%X.TMP", dir, sep, pre, u); strlcpy(PTR(A3), name, 260); RET(u); return; }
    for (int tries = 0; tries < 65535; tries++) {
        u = (__atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED) + (uint32_t)getpid()) & 0xFFFF;
        if (!u) continue;
        snprintf(name, sizeof name, "%s%s%.3s%X.TMP", dir, sep, pre, u);
        char *h = host_path(name);
        if (!h) { RET(0); return; }
        int fd = open(h, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
        int e = errno;
        free(h);
        if (fd >= 0) { close(fd); strlcpy(PTR(A3), name, 260); RET(u); return; }
        if (e != EEXIST) { set_last_error(errno_err(e, NULL)); RET(0); return; }
    }
    set_last_error(ERR_FILE_EXISTS); RET(0);
}
// SearchPath(path, file, ext, n, buf, *filepart): searches `path` (';'-separated) or the guest cwd
static void search_path(CPU *c, int wide) {
    char *path = arg_str(A0, wide), *file = arg_str(A1, wide), *ext = arg_str(A2, wide);
    uint32_t n = (uint32_t)A3; uint64_t buf = AN(4), fp = AN(5);
    char dirs[4096]; snprintf(dirs, sizeof dirs, "%s", path ? path : g_wcwd);
    int add_ext = ext && file && !strchr(base_name(file), '.');
    uint32_t r = 0; char *rest = dirs, *dir;
    while (file && !r && (dir = strsep(&rest, ";"))) {
        char cand[4096], full[4096]; struct stat st;
        int abs = (isalpha((unsigned char)file[0]) && file[1] == ':') || file[0] == '\\' || file[0] == '/';
        snprintf(cand, sizeof cand, abs ? "%2$s%3$s" : "%1$s\\%2$s%3$s", dir, file, add_ext ? ext : "");
        if (!win_full(cand, full, sizeof full)) continue;
        char *h = host_path(full);
        if (h && !stat(h, &st)) { r = put_str(buf, n, full, wide); if (r < n) set_filepart(buf, fp, wide); }
        free(h);
        if (abs) break;
    }
    if (!r) set_last_error(ERR_FILE_NOT_FOUND);
    RET(r);
    free(path); free(file); free(ext);
}
void I_kernel32_dll_SearchPathA(CPU *c) { search_path(c, 0); }
void I_kernel32_dll_SearchPathW(CPU *c) { search_path(c, 1); }
void I_kernel32_dll_GetSystemDirectoryA(CPU *c) { RET(put_str(A0, (uint32_t)A1, "C:\\Windows\\System32", 0)); }
void I_kernel32_dll_GetSystemDirectoryW(CPU *c) { RET(put_str(A0, (uint32_t)A1, "C:\\Windows\\System32", 1)); }
void I_kernel32_dll_GetWindowsDirectoryA(CPU *c) { RET(put_str(A0, (uint32_t)A1, "C:\\Windows", 0)); }
void I_kernel32_dll_GetWindowsDirectoryW(CPU *c) { RET(put_str(A0, (uint32_t)A1, "C:\\Windows", 1)); }

// ---------------- volumes ----------------
static int drive_root(const char *root) { return !root || (isalpha((unsigned char)root[0]) && root[1] == ':'); }
static void drive_type(CPU *c, int wide) { char *r = arg_str(A0, wide); RET(drive_root(r) ? 3 : 1); free(r); }   // DRIVE_FIXED / NO_ROOT_DIR
void I_kernel32_dll_GetDriveTypeA(CPU *c) { drive_type(c, 0); }
void I_kernel32_dll_GetDriveTypeW(CPU *c) { drive_type(c, 1); }
static int fs_stats(const char *win, struct statfs *sf) {
    pthread_once(&paths_once, paths_init);
    char *h = win ? host_path(win) : NULL;
    int r = statfs(h ? h : g_root, sf);
    if (r && h) r = statfs(g_root, sf);
    free(h);
    if (r) set_last_error(ERR_PATH_NOT_FOUND);
    return !r;
}
// GetDiskFreeSpaceA(root, *sectorsPerCluster, *bytesPerSector, *freeClusters, *totalClusters)
void I_kernel32_dll_GetDiskFreeSpaceA(CPU *c) {
    struct statfs sf;
    if (!fs_stats(PTR(A0), &sf)) { RET(0); return; }
    uint64_t cl = 4096, fr = (uint64_t)sf.f_bavail * sf.f_bsize / cl, tot = (uint64_t)sf.f_blocks * sf.f_bsize / cl;
    if (A1) wr32(A1, 8);
    if (A2) wr32(A2, 512);
    if (A3) wr32(A3, fr > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)fr);
    if (AN(4)) wr32(AN(4), tot > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)tot);
    RET(1);
}
// GetDiskFreeSpaceExA(dir, *availToCaller, *total, *totalFree)
void I_kernel32_dll_GetDiskFreeSpaceExA(CPU *c) {
    struct statfs sf;
    if (!fs_stats(PTR(A0), &sf)) { RET(0); return; }
    if (A1) wr64(A1, (uint64_t)sf.f_bavail * sf.f_bsize);
    if (A2) wr64(A2, (uint64_t)sf.f_blocks * sf.f_bsize);
    if (A3) wr64(A3, (uint64_t)sf.f_bfree * sf.f_bsize);
    RET(1);
}
// GetVolumeInformationA(root, volName, volNameSize, *serial, *maxComponent, *fsFlags, fsName, fsNameSize)
void I_kernel32_dll_GetVolumeInformationA(CPU *c) {
    put_fixed(A1, (uint32_t)A2, rt_game.name);
    if (A3) wr32(A3, 0xD00F2016u);
    if (AN(4)) wr32(AN(4), 255);
    if (AN(5)) wr32(AN(5), 0x2 | 0x4);   // FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK
    put_fixed(AN(6), (uint32_t)AN(7), "NTFS");
    RET(1);
}

// ---------------- FILETIME / SYSTEMTIME ----------------
// SYSTEMTIME: wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds
static void put_systime(uint64_t p, const struct tm *t, uint32_t ms) {
    wr16(p, (uint16_t)(t->tm_year + 1900)); wr16(p + 2, (uint16_t)(t->tm_mon + 1)); wr16(p + 4, (uint16_t)t->tm_wday);
    wr16(p + 6, (uint16_t)t->tm_mday); wr16(p + 8, (uint16_t)t->tm_hour); wr16(p + 10, (uint16_t)t->tm_min);
    wr16(p + 12, (uint16_t)t->tm_sec); wr16(p + 14, (uint16_t)ms);
}
static int get_systime(uint64_t p, time_t *out, uint32_t *ms) {
    struct tm t; memset(&t, 0, sizeof t);
    t.tm_year = rd16(p) - 1900; t.tm_mon = rd16(p + 2) - 1; t.tm_mday = rd16(p + 6);
    t.tm_hour = rd16(p + 8); t.tm_min = rd16(p + 10); t.tm_sec = rd16(p + 12); *ms = rd16(p + 14);
    if (t.tm_mon < 0 || t.tm_mon > 11 || t.tm_mday < 1 || t.tm_mday > 31 || t.tm_hour > 23 || t.tm_min > 59 || t.tm_sec > 59 || *ms > 999) return 0;
    *out = timegm(&t);
    return 1;
}
static time_t ft_time(uint64_t ft, uint32_t *ms) { if (ms) *ms = (uint32_t)(ft / 10000 % 1000); return (time_t)((int64_t)(ft / 10000000) - 11644473600ll); }
void I_kernel32_dll_FileTimeToSystemTime(CPU *c) {
    uint64_t ft = rd64(A0); uint32_t ms; time_t t = ft_time(ft, &ms); struct tm tm;
    if ((int64_t)ft < 0 || !gmtime_r(&t, &tm)) { set_last_error(ERR_INVALID_PARAMETER); RET(0); return; }
    put_systime(A1, &tm, ms);
    RET(1);
}
void I_kernel32_dll_SystemTimeToFileTime(CPU *c) {
    time_t t; uint32_t ms;
    if (!get_systime(A0, &t, &ms)) { set_last_error(ERR_INVALID_PARAMETER); RET(0); return; }
    wr64(A1, (uint64_t)((int64_t)t + 11644473600ll) * 10000000ull + ms * 10000ull);
    RET(1);
}
void I_kernel32_dll_FileTimeToLocalFileTime(CPU *c) {
    uint64_t ft = rd64(A0); time_t t = ft_time(ft, NULL); struct tm tm;
    localtime_r(&t, &tm);
    wr64(A1, ft + (uint64_t)((int64_t)tm.tm_gmtoff * 10000000ll));
    RET(1);
}
void I_kernel32_dll_LocalFileTimeToFileTime(CPU *c) {
    uint64_t ft = rd64(A0); time_t t = ft_time(ft, NULL); struct tm tm;
    localtime_r(&t, &tm);
    wr64(A1, ft - (uint64_t)((int64_t)tm.tm_gmtoff * 10000000ll));
    RET(1);
}
// FileTimeToDosDateTime(ft, *date, *time)
void I_kernel32_dll_FileTimeToDosDateTime(CPU *c) {
    time_t t = ft_time(rd64(A0), NULL); struct tm tm;
    if (!gmtime_r(&t, &tm) || tm.tm_year < 80 || tm.tm_year > 207) { set_last_error(ERR_INVALID_PARAMETER); RET(0); return; }
    if (A1) wr16(A1, (uint16_t)((tm.tm_year - 80) << 9 | (tm.tm_mon + 1) << 5 | tm.tm_mday));
    if (A2) wr16(A2, (uint16_t)(tm.tm_hour << 11 | tm.tm_min << 5 | tm.tm_sec / 2));
    RET(1);
}
// SystemTimeToTzSpecificLocalTime(tz or NULL, *utc, *local): a given zone applies its base Bias only
void I_kernel32_dll_SystemTimeToTzSpecificLocalTime(CPU *c) {
    time_t t; uint32_t ms; struct tm tm;
    if (!get_systime(A1, &t, &ms)) { set_last_error(ERR_INVALID_PARAMETER); RET(0); return; }
    if (A0) { t -= (time_t)(int32_t)rd32(A0) * 60; gmtime_r(&t, &tm); }
    else localtime_r(&t, &tm);
    put_systime(A2, &tm, ms);
    RET(1);
}
// TIME_ZONE_INFORMATION (172 bytes): Bias +0, StandardName[32] +4, StandardDate +68, StandardBias +84,
// DaylightName[32] +88, DaylightDate +152, DaylightBias +168. The current offset is reported as a fixed bias.
void I_kernel32_dll_GetTimeZoneInformation(CPU *c) {
    uint64_t b = A0; time_t now = time(NULL); struct tm tm;
    localtime_r(&now, &tm);
    memset(PTR(b), 0, 172);
    wr32(b, (uint32_t)(int32_t)(-tm.tm_gmtoff / 60));
    uint16_t *w = utf8_to_w16(tm.tm_zone ? tm.tm_zone : "UTC");
    size_t n = w16len(w); if (n > 31) n = 31;
    memcpy(PTR(b + 4), w, n * 2); memcpy(PTR(b + 88), w, n * 2);
    free(w);
    RET(0);   // TIME_ZONE_ID_UNKNOWN: no transition dates
}

// ---------------- console / std handles ----------------
// GetConsoleMode fails, so the CRT treats std handles as files and writes through WriteFile.
void I_kernel32_dll_GetConsoleMode(CPU *c) { set_last_error(ERR_INVALID_HANDLE); RET(0); }
void I_kernel32_dll_GetConsoleCP(CPU *c) { RET(65001); }
void I_kernel32_dll_GetConsoleOutputCP(CPU *c) { RET(65001); }
void I_kernel32_dll_AllocConsole(CPU *c) { set_last_error(ERR_ACCESS_DENIED); RET(0); }
void I_kernel32_dll_GetConsoleScreenBufferInfo(CPU *c) { set_last_error(ERR_INVALID_HANDLE); RET(0); }
void I_kernel32_dll_SetConsoleScreenBufferSize(CPU *c) { set_last_error(ERR_INVALID_HANDLE); RET(0); }
void I_kernel32_dll_SetStdHandle(CPU *c) { RET(1); }
void I_kernel32_dll_ReadConsoleW(CPU *c) { set_last_error(ERR_INVALID_HANDLE); RET(0); }
void I_kernel32_dll_PeekNamedPipe(CPU *c) { set_last_error(ERR_INVALID_HANDLE); RET(0); }
// WriteConsoleW(h, buf, nchars, *written, reserved)
void I_kernel32_dll_WriteConsoleW(CPU *c) {
    int fd = fd_of(A0, NULL); uint32_t n = (uint32_t)A2;
    if (fd < 0) { RET(0); return; }
    uint16_t *tmp = malloc((n + 1) * 2u); memcpy(tmp, PTR(A1), n * 2u); tmp[n] = 0;
    char *u = w16_to_utf8(tmp);
    io_all(fd, (uint8_t *)u, strlen(u), -1, 1);
    free(u); free(tmp);
    if (A3) wr32(A3, n);
    RET(1);
}

// GetShortPathName(long, short, cch): with 8.3 names off (the default on current Windows), the short form is the path
// itself. Returns the length copied, or the buffer size needed (with the NUL) when cch is too small.
void I_kernel32_dll_GetShortPathNameW(CPU *c) {
    const uint16_t *src = PTR(A0); size_t n = w16len(src);
    if (A2 > n && A1) { memmove(PTR(A1), src, (n + 1) * 2); RET(n); return; }
    RET(n + 1);
}
void I_kernel32_dll_GetShortPathNameA(CPU *c) {
    const char *src = PTR(A0); size_t n = strlen(src);
    if (A2 > n && A1) { memmove(PTR(A1), src, n + 1); RET(n); return; }
    RET(n + 1);
}
