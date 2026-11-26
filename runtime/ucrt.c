// The Universal C Runtime (ucrtbase.dll, imported through the api-ms-win-crt-* API sets) for games that link the
// CRT dynamically (MSVC 2015 and later, /MD). A game that links it statically carries its own translated copy and
// never calls these.
//
// Windows' C library differs from macOS' in ways the game can see, and those are kept: long is 32 bits, wchar_t is
// 16 bits (UTF-16), struct tm / struct _stat / _finddata have Windows' layouts, rand() is Microsoft's generator,
// printf takes Microsoft's size prefixes (%I64d, %ls, %S...) and its varargs come from the guest stack, and paths are
// Windows paths, mapped to the Mac the same way kernel32's are (rt_host_path).
//
// Not modelled: locales other than "C" (narrow text is passed through, as UTF-8 where it meets UTF-16), text-mode
// CR/LF translation of FILE streams, and the invalid-parameter handler (a bad parameter is logged).
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wctype.h>
#include <malloc/malloc.h>
#include "rt.h"
#include "handles.h"
#include "ucrt.h"

#define API(set, name) void I_api_ms_win_crt_##set##_l1_1_0_dll_##name(CPU *c)
#define UCRT(name) void I_ucrtbase_dll_##name(CPU *c)

// Microsoft's errno values match the POSIX ones up to ERANGE (34); a few above it differ.
int ucrt_errno_from_host(int e) {
    switch (e) {
    case EDEADLK: return 36; case ENAMETOOLONG: return 38; case ENOLCK: return 39; case ENOSYS: return 40;
    case ENOTEMPTY: return 41; case EILSEQ: return 42;
    default: return e <= 34 ? e : 22;   // EINVAL
    }
}
static __thread int t_errno;
static __thread uint32_t t_doserrno;
void ucrt_set_errno(int e) { t_errno = e; }
#define SET_ERRNO() (t_errno = ucrt_errno_from_host(errno))

// ---------------- startup and exit ----------------
// _initterm(first, last): call each non-NULL function pointer in [first, last)
API(runtime, _initterm) {
    for (uint64_t p = A0, end = A1; p < end; p += 8) { uint64_t f = rd64(p); if (f) guest_call(c, f, 0, NULL); }
}
// _initterm_e: the same, stopping at the first one that returns nonzero (which is returned)
API(runtime, _initterm_e) {
    for (uint64_t p = A0, end = A1; p < end; p += 8) {
        uint64_t f = rd64(p); if (!f) continue;
        uint32_t r = (uint32_t)guest_call(c, f, 0, NULL);
        if (r) { RET(r); return; }
    }
    RET(0);
}
// atexit and onexit tables: one process-wide list, run newest first by exit/_cexit
static pthread_mutex_t exit_mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t *exit_fns; static size_t exit_n, exit_cap;
static void add_exit(uint64_t f) {
    pthread_mutex_lock(&exit_mu);
    if (exit_n == exit_cap) { exit_cap = exit_cap ? exit_cap * 2 : 32; exit_fns = realloc(exit_fns, exit_cap * 8); }
    exit_fns[exit_n++] = f;
    pthread_mutex_unlock(&exit_mu);
}
static void run_exit_fns(CPU *c) {
    for (;;) {
        pthread_mutex_lock(&exit_mu);
        uint64_t f = exit_n ? exit_fns[--exit_n] : 0;
        pthread_mutex_unlock(&exit_mu);
        if (!f) break;
        guest_call(c, f, 0, NULL);
    }
}
// _initialize_onexit_table(table): { first, last, end } pointers; the functions are kept here instead
API(runtime, _initialize_onexit_table) { if (A0) { wr64(A0, 0); wr64(A0 + 8, 0); wr64(A0 + 16, 0); } RET(0); }
API(runtime, _register_onexit_function) { add_exit(A1); RET(0); }
API(runtime, _crt_atexit) { add_exit(A0); RET(0); }
API(runtime, _register_thread_local_exe_atexit_callback) {}
API(runtime, _cexit) { run_exit_fns(c); }
API(runtime, _c_exit) {}
API(runtime, exit) { run_exit_fns(c); rt_log("[ucrt] exit(%d)\n", (int)A0); fflush(NULL); exit((int)A0); }
API(runtime, _exit) { rt_log("[ucrt] _exit(%d)\n", (int)A0); _exit((int)A0); }
API(runtime, abort) { rt_log("[ucrt] abort()\n"); rt_backtrace(c); abort(); }
API(runtime, terminate) { rt_log("[ucrt] terminate()\n"); rt_backtrace(c); abort(); }
API(runtime, _configure_narrow_argv) { RET(0); }
API(runtime, _initialize_narrow_environment) { RET(0); }
API(runtime, _set_app_type) {}
API(runtime, _seh_filter_exe) { RET(0); }   // EXCEPTION_CONTINUE_SEARCH
// _get_narrow_winmain_command_line: the command line after the program name, as WinMain receives it
API(runtime, _get_narrow_winmain_command_line) {
    uint64_t sv = c->rax; I_kernel32_dll_GetCommandLineA(c); const char *p = PTR(c->rax); c->rax = sv;
    if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; }
    else while (*p && *p != ' ' && *p != '\t') p++;
    while (*p == ' ' || *p == '\t') p++;
    RET(G(p));
}
API(runtime, _errno) { RET(G(&t_errno)); }
API(runtime, __doserrno) { RET(G(&t_doserrno)); }
API(runtime, strerror) { RET(G(strerror((int)A0))); }
API(runtime, _getpid) { RET((uint32_t)getpid()); }
// _controlfp_s(*current, new, mask): the x87/SSE control word the CRT reports by default (all exceptions masked,
// round to nearest, 53-bit precision); changes are accepted and ignored
API(runtime, _controlfp_s) { if (A0) wr32(A0, 0x0009001F); RET(0); }
static void bad_parameter(CPU *c, const char *what) {
    static int logged; if (logged++ < 8) { rt_log("[ucrt] %s\n", what); rt_backtrace(c); }
}
API(runtime, _invalid_parameter_noinfo) { bad_parameter(c, "invalid parameter"); }
API(runtime, _invalid_parameter_noinfo_noreturn) { bad_parameter(c, "invalid parameter (fatal)"); abort(); }
API(runtime, _invoke_watson) { bad_parameter(c, "_invoke_watson"); abort(); }
API(runtime, _set_invalid_parameter_handler) { static uint64_t h; uint64_t old = h; h = A0; RET(old); }
// _wassert(message, file, line), UTF-16 strings
API(runtime, _wassert) {
    char *m = A0 ? w16_to_utf8(PTR(A0)) : NULL, *f = A1 ? w16_to_utf8(PTR(A1)) : NULL;
    rt_log("[ucrt] assertion failed: %s, %s line %u\n", m ? m : "?", f ? f : "?", (uint32_t)A2);
    rt_backtrace(c); abort();
}

// ---------------- heap ----------------
API(heap, malloc) { void *p = malloc(A0 ? A0 : 1); if (!p) t_errno = ENOMEM; RET(G(p)); }
API(heap, calloc) { void *p = calloc(A0 ? A0 : 1, A1 ? A1 : 1); if (!p) t_errno = ENOMEM; RET(G(p)); }
API(heap, realloc) {
    if (A0 && !A1) { free(PTR(A0)); RET(0); return; }   // realloc(p, 0) frees, as Microsoft's does
    void *p = realloc(PTR(A0), A1); if (!p) t_errno = ENOMEM; RET(G(p));
}
API(heap, free) { free(PTR(A0)); }
API(heap, _msize) { RET(A0 ? malloc_size(PTR(A0)) : (uint64_t)-1); }
// _aligned_malloc(size, alignment): alignment is a power of two; freed only with _aligned_free
API(heap, _aligned_malloc) {
    size_t al = A1 < 16 ? 16 : A1; void *p = NULL;
    if (posix_memalign(&p, al, A0 ? A0 : 1)) { t_errno = ENOMEM; p = NULL; }
    RET(G(p));
}
API(heap, _aligned_free) { free(PTR(A0)); }
API(heap, _aligned_realloc) {
    size_t al = A2 < 16 ? 16 : A2, n = A1;
    if (!A0) { void *p = NULL; if (posix_memalign(&p, al, n ? n : 1)) p = NULL; RET(G(p)); return; }
    if (!n) { free(PTR(A0)); RET(0); return; }
    void *p = NULL; if (posix_memalign(&p, al, n)) { t_errno = ENOMEM; RET(0); return; }
    size_t old = malloc_size(PTR(A0)); memcpy(p, PTR(A0), old < n ? old : n); free(PTR(A0)); RET(G(p));
}
API(heap, _set_new_mode) { static int m; int old = m; m = (int)A0; RET(old); }
API(heap, _callnewh) { RET(0); }

// ---------------- narrow strings and ctype ("C" locale) ----------------
static int in_byte(uint64_t v) { int c = (int)v; return c >= -1 && c <= 255; }
#define CTYPE(fn) API(string, fn) { RET(in_byte(A0) && (int)A0 >= 0 ? (fn((int)A0) ? 1 : 0) : 0); }
CTYPE(isdigit) CTYPE(isalpha) CTYPE(isspace) CTYPE(isalnum) CTYPE(islower) CTYPE(isupper) CTYPE(isxdigit)
CTYPE(isprint) CTYPE(ispunct) CTYPE(iscntrl) CTYPE(isgraph)
API(string, toupper) { int c0 = (int)A0; RET((uint32_t)(c0 >= 'a' && c0 <= 'z' ? c0 - 32 : c0)); }
API(string, tolower) { int c0 = (int)A0; RET((uint32_t)(c0 >= 'A' && c0 <= 'Z' ? c0 + 32 : c0)); }
API(string, strcmp) { RET((uint32_t)strcmp(PTR(A0), PTR(A1))); }
API(string, strncmp) { RET((uint32_t)strncmp(PTR(A0), PTR(A1), A2)); }
API(string, _stricmp) { RET((uint32_t)strcasecmp(PTR(A0), PTR(A1))); }
API(string, _strnicmp) { RET((uint32_t)strncasecmp(PTR(A0), PTR(A1), A2)); }
API(string, strcpy) { RET(G(strcpy(PTR(A0), PTR(A1)))); }
API(string, strcat) { RET(G(strcat(PTR(A0), PTR(A1)))); }
API(string, strncpy) { RET(G(strncpy(PTR(A0), PTR(A1), A2))); }
API(string, strncat) { RET(G(strncat(PTR(A0), PTR(A1), A2))); }
API(string, strpbrk) { RET(G(strpbrk(PTR(A0), PTR(A1)))); }
API(string, strspn) { RET(strspn(PTR(A0), PTR(A1))); }
API(string, strcspn) { RET(strcspn(PTR(A0), PTR(A1))); }
API(string, strlen) { RET(strlen(PTR(A0))); }
API(string, strnlen) { RET(strnlen(PTR(A0), A1)); }
API(string, _strdup) { RET(A0 ? G(strdup(PTR(A0))) : 0); }
API(string, strtok_s) {   // strtok_s(str, delim, *context)
    char *ctx = A0 ? PTR(A0) : PTR(rd64(A2)), *tok = strtok_r(ctx, PTR(A1), &ctx);
    wr64(A2, G(ctx)); RET(G(tok));
}
API(string, _strupr) { for (char *p = PTR(A0); *p; p++) *p = (char)toupper((unsigned char)*p); RET(A0); }
API(string, _strlwr) { for (char *p = PTR(A0); *p; p++) *p = (char)tolower((unsigned char)*p); RET(A0); }

// The secure _s functions: errno_t results (0, EINVAL 22, ERANGE 34, STRUNCATE 80); count _TRUNCATE ((size_t)-1)
// copies what fits. On an error the destination is emptied, as Microsoft's are.
#define TRUNCATE ((size_t)-1)
#define STRUNCATE 80
static int copy_s(void *dst, size_t dsz, const void *src, size_t count, size_t unit, size_t dlen) {
    // copies min(len(src), count) units after the first dlen units of dst (an append when dlen > 0)
    if (!dst || !dsz) return 22;
    if (!src) { memset(dst, 0, unit); return 22; }
    size_t n = 0;
    if (unit == 1) { const char *s = src; while ((count == TRUNCATE || n < count) && s[n]) n++; }
    else { const uint16_t *s = src; while ((count == TRUNCATE || n < count) && s[n]) n++; }
    if (dlen + n + 1 > dsz) {
        if (count != TRUNCATE) { memset(dst, 0, unit); return 34; }
        n = dsz - dlen - 1;
        memcpy((char *)dst + dlen * unit, src, n * unit); memset((char *)dst + (dlen + n) * unit, 0, unit);
        return STRUNCATE;
    }
    memcpy((char *)dst + dlen * unit, src, n * unit); memset((char *)dst + (dlen + n) * unit, 0, unit);
    return 0;
}
static size_t dlen_s(const void *d, size_t dsz, size_t unit) {
    size_t n = 0;
    if (unit == 1) { const char *s = d; while (n < dsz && s[n]) n++; } else { const uint16_t *s = d; while (n < dsz && s[n]) n++; }
    return n;
}
API(string, strcpy_s) { RET(copy_s(PTR(A0), A1, PTR(A2), TRUNCATE - 1, 1, 0)); }
API(string, strncpy_s) { RET(copy_s(PTR(A0), A1, PTR(A2), A3, 1, 0)); }
API(string, strcat_s) {
    size_t l = A0 ? dlen_s(PTR(A0), A1, 1) : 0;
    if (A0 && l == A1) { *(char *)PTR(A0) = 0; RET(22); return; }
    RET(copy_s(PTR(A0), A1, PTR(A2), TRUNCATE - 1, 1, l));
}
API(string, strncat_s) {
    size_t l = A0 ? dlen_s(PTR(A0), A1, 1) : 0;
    if (A0 && l == A1) { *(char *)PTR(A0) = 0; RET(22); return; }
    RET(copy_s(PTR(A0), A1, PTR(A2), A3, 1, l));
}

// ---------------- wide strings (UTF-16 wchar_t) ----------------
static size_t wlen(const uint16_t *s) { size_t n = 0; while (s[n]) n++; return n; }
// Microsoft's ctype classes for one UTF-16 unit (the wctype_t bits: _UPPER 1, _LOWER 2, _DIGIT 4, _SPACE 8,
// _PUNCT 0x10, _CONTROL 0x20, _BLANK 0x40, _HEX 0x80, _ALPHA 0x100 plus the letter bits)
static uint32_t wclass(uint32_t ch) {
    if (ch == 0xFFFF) return 0;
    uint32_t m = 0;
    if (iswupper(ch)) m |= 1;
    if (iswlower(ch)) m |= 2;
    if (ch >= '0' && ch <= '9') m |= 4;
    if (iswspace(ch)) m |= 8;
    if (iswpunct(ch)) m |= 0x10;
    if (iswcntrl(ch)) m |= 0x20;
    if (ch == ' ' || ch == '\t') m |= 0x40;
    if (iswxdigit(ch)) m |= 0x80;
    if (iswalpha(ch)) m |= 0x100;
    return m;
}
API(string, iswctype) { RET((wclass((uint16_t)A0) & (uint32_t)A1) ? 1 : 0); }
API(string, iswprint) { uint32_t ch = (uint16_t)A0; RET(ch != 0xFFFF && iswprint(ch) ? 1 : 0); }
API(string, iswalpha) { RET((wclass((uint16_t)A0) & 0x103) ? 1 : 0); }
API(string, iswdigit) { RET((wclass((uint16_t)A0) & 4) ? 1 : 0); }
API(string, iswspace) { RET((wclass((uint16_t)A0) & 8) ? 1 : 0); }
API(string, iswalnum) { RET((wclass((uint16_t)A0) & 0x107) ? 1 : 0); }
API(string, iswupper) { RET((wclass((uint16_t)A0) & 1) ? 1 : 0); }
API(string, iswlower) { RET((wclass((uint16_t)A0) & 2) ? 1 : 0); }
// wctype(name): the class mask for a class name ("alpha", "digit"...), 0 for an unknown one
API(string, wctype) {
    static const struct { const char *n; uint32_t m; } k[] = {
        { "alnum", 0x107 }, { "alpha", 0x103 }, { "blank", 0x40 }, { "cntrl", 0x20 }, { "digit", 4 }, { "graph", 0x117 },
        { "lower", 2 }, { "print", 0x157 }, { "punct", 0x10 }, { "space", 8 }, { "upper", 1 }, { "xdigit", 0x80 } };
    const char *n = PTR(A0);
    for (size_t i = 0; n && i < sizeof k / sizeof *k; i++) if (!strcmp(n, k[i].n)) { RET(k[i].m); return; }
    RET(0);
}
API(string, towupper) { uint32_t ch = (uint16_t)A0; RET(ch == 0xFFFF ? ch : (uint16_t)towupper(ch)); }
API(string, towlower) { uint32_t ch = (uint16_t)A0; RET(ch == 0xFFFF ? ch : (uint16_t)towlower(ch)); }
API(string, wcslen) { RET(wlen(PTR(A0))); }
API(string, wcsnlen) { const uint16_t *s = PTR(A0); size_t n = 0; while (n < A1 && s[n]) n++; RET(n); }
API(string, wcscmp) {
    const uint16_t *a = PTR(A0), *b = PTR(A1);
    while (*a && *a == *b) { a++; b++; }
    RET((uint32_t)(*a < *b ? -1 : *a > *b));
}
API(string, wcsncmp) {
    const uint16_t *a = PTR(A0), *b = PTR(A1); size_t n = A2;
    while (n && *a && *a == *b) { a++; b++; n--; }
    RET((uint32_t)(!n ? 0 : *a < *b ? -1 : *a > *b));
}
static uint16_t wfold(uint16_t ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }
API(string, _wcsicmp) {
    const uint16_t *a = PTR(A0), *b = PTR(A1);
    while (*a && wfold(*a) == wfold(*b)) { a++; b++; }
    RET((uint32_t)(wfold(*a) - wfold(*b)));
}
API(string, _wcsnicmp) {
    const uint16_t *a = PTR(A0), *b = PTR(A1); size_t n = A2;
    while (n && *a && wfold(*a) == wfold(*b)) { a++; b++; n--; }
    RET((uint32_t)(n ? wfold(*a) - wfold(*b) : 0));
}
API(string, wcsncpy) {
    uint16_t *d = PTR(A0); const uint16_t *s = PTR(A1); size_t n = A2, i = 0;
    for (; i < n && s[i]; i++) d[i] = s[i];
    for (; i < n; i++) d[i] = 0;
    RET(A0);
}
API(string, wcscpy) { uint16_t *d = PTR(A0); const uint16_t *s = PTR(A1); size_t i = 0; do d[i] = s[i]; while (s[i++]); RET(A0); }
API(string, wcscat) { uint16_t *d = PTR(A0); d += wlen(d); const uint16_t *s = PTR(A1); size_t i = 0; do d[i] = s[i]; while (s[i++]); RET(A0); }
API(string, wcscpy_s) { RET(copy_s(PTR(A0), A1, PTR(A2), TRUNCATE - 1, 2, 0)); }
API(string, wcsncpy_s) { RET(copy_s(PTR(A0), A1, PTR(A2), A3, 2, 0)); }
API(string, wcscat_s) {
    size_t l = A0 ? dlen_s(PTR(A0), A1, 2) : 0;
    if (A0 && l == A1) { *(uint16_t *)PTR(A0) = 0; RET(22); return; }
    RET(copy_s(PTR(A0), A1, PTR(A2), TRUNCATE - 1, 2, l));
}
API(string, wcsncat_s) {
    size_t l = A0 ? dlen_s(PTR(A0), A1, 2) : 0;
    if (A0 && l == A1) { *(uint16_t *)PTR(A0) = 0; RET(22); return; }
    RET(copy_s(PTR(A0), A1, PTR(A2), A3, 2, l));
}
API(string, _wcsdup) {
    if (!A0) { RET(0); return; }
    size_t n = (wlen(PTR(A0)) + 1) * 2; void *p = malloc(n); memcpy(p, PTR(A0), n); RET(G(p));
}
API(string, _wcsupr) { for (uint16_t *p = PTR(A0); *p; p++) *p = (uint16_t)towupper(*p); RET(A0); }
API(string, _wcslwr) { for (uint16_t *p = PTR(A0); *p; p++) *p = (uint16_t)towlower(*p); RET(A0); }
API(string, wcschr) {
    const uint16_t *s = PTR(A0); uint16_t ch = (uint16_t)A1;
    for (;; s++) { if (*s == ch) { RET(G(s)); return; } if (!*s) break; }
    RET(0);
}
API(string, wcspbrk) {
    for (const uint16_t *s = PTR(A0); *s; s++) for (const uint16_t *k = PTR(A1); *k; k++) if (*s == *k) { RET(G(s)); return; }
    RET(0);
}

// ---------------- conversions ----------------
// strtol / strtoul are 32-bit (long is 32 bits on Windows): out-of-range values clamp, with ERANGE
static void set_end(uint64_t endp, const char *base, const char *end) { if (endp) wr64(endp, G(end ? end : base)); }
API(convert, strtol) {
    char *end; errno = 0; long long v = strtoll(PTR(A0), &end, (int)A2); set_end(A1, PTR(A0), end);
    if (v > INT32_MAX) { v = INT32_MAX; t_errno = 34; } else if (v < INT32_MIN) { v = INT32_MIN; t_errno = 34; }
    else if (errno) SET_ERRNO();
    RET((uint32_t)(int32_t)v);
}
API(convert, strtoul) {
    char *end; errno = 0; const char *s = PTR(A0);
    unsigned long long v = strtoull(s, &end, (int)A2); set_end(A1, s, end);
    while (isspace((unsigned char)*s)) s++;
    int neg = *s == '-';
    unsigned long long mag = neg ? (unsigned long long)-(long long)v : v;
    if (errno == ERANGE || mag > UINT32_MAX) { v = UINT32_MAX; t_errno = 34; }
    RET((uint32_t)v);
}
API(convert, strtoll) { char *end; errno = 0; long long v = strtoll(PTR(A0), &end, (int)A2); set_end(A1, PTR(A0), end); if (errno) SET_ERRNO(); RET(v); }
API(convert, strtoull) { char *end; errno = 0; unsigned long long v = strtoull(PTR(A0), &end, (int)A2); set_end(A1, PTR(A0), end); if (errno) SET_ERRNO(); RET(v); }
API(convert, _strtoi64) { I_api_ms_win_crt_convert_l1_1_0_dll_strtoll(c); }
API(convert, _strtoui64) { I_api_ms_win_crt_convert_l1_1_0_dll_strtoull(c); }
API(convert, _strtoi64_l) { I_api_ms_win_crt_convert_l1_1_0_dll_strtoll(c); }
API(convert, _strtoui64_l) { I_api_ms_win_crt_convert_l1_1_0_dll_strtoull(c); }
API(convert, strtod) { char *end; errno = 0; double v = strtod(PTR(A0), &end); set_end(A1, PTR(A0), end); if (errno) SET_ERRNO(); RETD(v); }
API(convert, _strtod_l) { I_api_ms_win_crt_convert_l1_1_0_dll_strtod(c); }
API(convert, strtof) { char *end; errno = 0; float v = strtof(PTR(A0), &end); set_end(A1, PTR(A0), end); if (errno) SET_ERRNO(); RETF(v); }
API(convert, atoi) { RET((uint32_t)(int32_t)strtol(PTR(A0), NULL, 10)); }
API(convert, atol) { RET((uint32_t)(int32_t)strtol(PTR(A0), NULL, 10)); }
API(convert, _atoi64) { RET(strtoll(PTR(A0), NULL, 10)); }
API(convert, atof) { RETD(strtod(PTR(A0), NULL)); }
API(convert, wcstol) {
    char *s = w16_to_utf8(PTR(A0)), *end; long long v = strtoll(s, &end, (int)A2);
    if (A1) { size_t used = (size_t)(end - s); const uint16_t *w = PTR(A0); size_t k = 0, b = 0;
              while (b < used && w[k]) { uint16_t u = w[k++]; b += u < 0x80 ? 1 : u < 0x800 ? 2 : (u >= 0xD800 && u < 0xDC00) ? (k++, 4) : 3; }
              wr64(A1, A0 + 2 * k); }
    free(s);
    if (v > INT32_MAX) { v = INT32_MAX; t_errno = 34; } else if (v < INT32_MIN) { v = INT32_MIN; t_errno = 34; }
    RET((uint32_t)(int32_t)v);
}
API(convert, _wtoi) { char *s = w16_to_utf8(PTR(A0)); int v = (int)strtol(s, NULL, 10); free(s); RET((uint32_t)v); }
API(convert, _wtof) { char *s = w16_to_utf8(PTR(A0)); double v = strtod(s, NULL); free(s); RETD(v); }
// Multibyte <-> wide in the "C" locale: one byte is one character (0-255)
API(convert, mbstowcs) {   // mbstowcs(dst, src, n): characters converted, without the null
    const unsigned char *s = PTR(A1); uint16_t *d = PTR(A0); size_t n = A2, i = 0;
    if (!d) { RET(strlen((const char *)s)); return; }
    for (; i < n && s[i]; i++) d[i] = s[i];
    if (i < n) d[i] = 0;
    RET(i);
}
API(convert, wcstombs) {   // wcstombs(dst, src, n): bytes written, -1 for a character outside 0-255
    const uint16_t *s = PTR(A1); char *d = PTR(A0); size_t n = A2, i = 0;
    for (; (!d || i < n) && s[i]; i++) {
        if (s[i] > 255) { t_errno = 42; RET((uint64_t)-1); return; }
        if (d) d[i] = (char)s[i];
    }
    if (d && i < n) d[i] = 0;
    RET(i);
}
// wcstombs_s(*converted, dst, dstsz, src, count): *converted includes the null
API(convert, wcstombs_s) {
    const uint16_t *s = PTR(A3); char *d = PTR(A1); size_t dsz = A2, count = AN(4), i = 0;
    for (; (count == TRUNCATE || i < count) && s[i]; i++) {
        if (s[i] > 255) { if (d && dsz) d[0] = 0; t_errno = 42; RET(42); return; }
        if (d) { if (i + 1 >= dsz) { if (count == TRUNCATE) break; d[0] = 0; if (A0) wr64(A0, 0); RET(34); return; } d[i] = (char)s[i]; }
    }
    if (d) d[i] = 0;
    if (A0) wr64(A0, i + 1);
    RET(0);
}
API(convert, mbstowcs_s) {   // mbstowcs_s(*converted, dst, dstsz, src, count)
    const unsigned char *s = PTR(A3); uint16_t *d = PTR(A1); size_t dsz = A2, count = AN(4), i = 0;
    for (; (count == TRUNCATE || i < count) && s[i]; i++) {
        if (d) { if (i + 1 >= dsz) { if (count == TRUNCATE) break; d[0] = 0; if (A0) wr64(A0, 0); RET(34); return; } d[i] = s[i]; }
    }
    if (d) d[i] = 0;
    if (A0) wr64(A0, i + 1);
    RET(0);
}
// the restartable forms: the state is unused in the "C" locale
API(convert, mbrtowc) {   // mbrtowc(*wc, s, n, state)
    const unsigned char *s = PTR(A1);
    if (!s) { RET(0); return; }
    if (!A2) { RET((uint64_t)-2); return; }
    if (A0) *(uint16_t *)PTR(A0) = *s;
    RET(*s ? 1 : 0);
}
API(convert, mbsrtowcs_s) {   // mbsrtowcs_s(*converted, dst, dstsz, *src, count, state)
    uint64_t sp = rd64(A3); const unsigned char *s = PTR(sp); uint16_t *d = PTR(A1); size_t dsz = A2, count = AN(4), i = 0;
    for (; (count == TRUNCATE || i < count) && s[i]; i++) {
        if (d) { if (i + 1 >= dsz) { if (count == TRUNCATE) break; d[0] = 0; RET(34); return; } d[i] = s[i]; }
    }
    if (d) { d[i] = 0; wr64(A3, s[i] ? sp + i : 0); }
    if (A0) wr64(A0, i + 1);
    RET(0);
}
API(convert, wcsrtombs) {   // wcsrtombs(dst, *src, n, state)
    uint64_t sp = rd64(A1); const uint16_t *s = PTR(sp); char *d = PTR(A0); size_t n = A2, i = 0;
    for (; (!d || i < n) && s[i]; i++) {
        if (s[i] > 255) { t_errno = 42; RET((uint64_t)-1); return; }
        if (d) d[i] = (char)s[i];
    }
    if (d) { if (i < n) d[i] = 0; wr64(A1, s[i] ? sp + 2 * i : 0); }
    RET(i);
}
API(convert, wcsrtombs_s) {   // wcsrtombs_s(*converted, dst, dstsz, *src, count, state)
    uint64_t sp = rd64(A3); const uint16_t *s = PTR(sp); char *d = PTR(A1); size_t dsz = A2, count = AN(4), i = 0;
    for (; (count == TRUNCATE || i < count) && s[i]; i++) {
        if (s[i] > 255) { if (d && dsz) d[0] = 0; t_errno = 42; RET(42); return; }
        if (d) { if (i + 1 >= dsz) { if (count == TRUNCATE) break; d[0] = 0; RET(34); return; } d[i] = (char)s[i]; }
    }
    if (d) { d[i] = 0; wr64(A3, s[i] ? sp + 2 * i : 0); }
    if (A0) wr64(A0, i + 1);
    RET(0);
}

// ---------------- math ----------------
#define MATH1(fn) API(math, fn) { RETD(fn(AD(0))); }
#define MATH2(fn) API(math, fn) { RETD(fn(AD(0), AD(1))); }
#define MATHF1(fn) API(math, fn) { RETF(fn(AF(0))); }
#define MATHF2(fn) API(math, fn) { RETF(fn(AF(0), AF(1))); }
MATH1(sin) MATH1(cos) MATH1(tan) MATH1(asin) MATH1(acos) MATH1(atan) MATH1(sinh) MATH1(cosh) MATH1(tanh)
MATH1(exp) MATH1(exp2) MATH1(log) MATH1(log10) MATH1(log2) MATH1(sqrt) MATH1(floor) MATH1(ceil) MATH1(round)
MATH1(trunc) MATH1(fabs) MATH1(cbrt) MATH1(log1p) MATH1(expm1)
MATH2(pow) MATH2(atan2) MATH2(fmod) MATH2(hypot) MATH2(fmin) MATH2(fmax)
MATHF1(sinf) MATHF1(cosf) MATHF1(tanf) MATHF1(asinf) MATHF1(acosf) MATHF1(atanf) MATHF1(sinhf) MATHF1(coshf)
MATHF1(tanhf) MATHF1(expf) MATHF1(exp2f) MATHF1(logf) MATHF1(log10f) MATHF1(log2f) MATHF1(sqrtf) MATHF1(floorf)
MATHF1(ceilf) MATHF1(roundf) MATHF1(truncf) MATHF1(fabsf)
MATHF2(powf) MATHF2(atan2f) MATHF2(fmodf) MATHF2(hypotf) MATHF2(fminf) MATHF2(fmaxf)
API(math, ldexp) { RETD(ldexp(AD(0), (int)A1)); }
API(math, frexp) { int e; double m = frexp(AD(0), &e); if (A1) wr32(A1, (uint32_t)e); RETD(m); }
API(math, modf) { double ip; double f = modf(AD(0), &ip); if (A1) memcpy(PTR(A1), &ip, 8); RETD(f); }
API(math, _finite) { RET(isfinite(AD(0)) ? 1 : 0); }
API(math, _isnan) { RET(isnan(AD(0)) ? 1 : 0); }
API(math, lround) { RET((uint32_t)(int32_t)lround(AD(0))); }   // long: 32 bits
API(math, lroundf) { RET((uint32_t)(int32_t)lroundf(AF(0))); }
API(math, llround) { RET((uint64_t)llround(AD(0))); }
API(math, __setusermatherr) {}
API(math, _fdclass) { RET((uint32_t)fpclassify(AF(0))); }
API(math, _dclass) { int k = fpclassify(AD(0)); RET((uint32_t)(k == FP_NAN ? 2 : k == FP_INFINITE ? 1 : k == FP_ZERO ? 0 : k == FP_SUBNORMAL ? -2 : -1)); }

// ---------------- utility ----------------
static __thread uint32_t t_rand = 1;
API(utility, srand) { t_rand = (uint32_t)A0; }
API(utility, rand) { t_rand = t_rand * 214013u + 2531011u; RET((t_rand >> 16) & 0x7FFF); }   // Microsoft's generator
// qsort / bsearch with the guest's comparison function
static __thread CPU *t_cmp_cpu; static __thread uint64_t t_cmp_fn;
static int guest_cmp(const void *a, const void *b) {
    uint64_t args[2] = { G(a), G(b) };
    return (int)(uint32_t)guest_call(t_cmp_cpu, t_cmp_fn, 2, args);
}
API(utility, qsort) {
    CPU *sc = t_cmp_cpu; uint64_t sf = t_cmp_fn;
    t_cmp_cpu = c; t_cmp_fn = A3;
    if (A1 > 1) mergesort(PTR(A0), A1, A2, guest_cmp) == 0 || (qsort(PTR(A0), A1, A2, guest_cmp), 0);
    t_cmp_cpu = sc; t_cmp_fn = sf;
}
API(utility, bsearch) {   // bsearch(key, base, num, width, compare)
    uint64_t key = A0, base = A1, num = A2, w = A3, fn = AN(4);
    while (num) {
        uint64_t mid = base + (num / 2) * w, args[2] = { key, mid };
        int r = (int)(uint32_t)guest_call(c, fn, 2, args);
        if (!r) { RET(mid); return; }
        if (r < 0) num /= 2; else { base = mid + w; num -= num / 2 + 1; }
    }
    RET(0);
}
API(utility, abs) { int v = (int)A0; RET((uint32_t)(v < 0 ? -v : v)); }
API(utility, labs) { int v = (int)A0; RET((uint32_t)(v < 0 ? -v : v)); }
API(utility, llabs) { int64_t v = (int64_t)A0; RET((uint64_t)(v < 0 ? -v : v)); }

// ---------------- environment and locale ----------------
API(environment, getenv) { RET(A0 ? G(rt_guest_env(PTR(A0))) : 0); }
static uint64_t c_locale[4];   // an opaque _locale_t: only ever passed back to the *_l functions, which ignore it
API(locale, _create_locale) { RET(G(c_locale)); }
API(locale, _free_locale) {}
API(locale, _configthreadlocale) { RET(2); }   // _DISABLE_PER_THREAD_LOCALE: the one global "C" locale
API(locale, ___mb_cur_max_func) { RET(1); }
API(locale, setlocale) { static char cl[] = "C"; RET(G(cl)); }
API(locale, localeconv) {
    // struct lconv: decimal_point ".", the rest empty / CHAR_MAX
    static char dot[] = ".", empty[] = "";
    static uint64_t lc[12];
    if (!lc[0]) { lc[0] = G(dot); for (int i = 1; i < 6; i++) lc[i] = G(empty); }
    RET(G(lc));
}

// ---------------- time ----------------
// Windows' struct tm is nine ints (no tm_gmtoff / tm_zone)
static void tm_to_guest(uint64_t g, const struct tm *t) {
    int v[9] = { t->tm_sec, t->tm_min, t->tm_hour, t->tm_mday, t->tm_mon, t->tm_year, t->tm_wday, t->tm_yday, t->tm_isdst };
    memcpy(PTR(g), v, sizeof v);
}
static void tm_from_guest(struct tm *t, uint64_t g) {
    int v[9]; memcpy(v, PTR(g), sizeof v); memset(t, 0, sizeof *t);
    t->tm_sec = v[0]; t->tm_min = v[1]; t->tm_hour = v[2]; t->tm_mday = v[3]; t->tm_mon = v[4]; t->tm_year = v[5];
    t->tm_wday = v[6]; t->tm_yday = v[7]; t->tm_isdst = v[8];
}
static __thread int t_tmbuf[9];
static __thread char t_timestr[32];
API(time, _time64) { int64_t t = time(NULL); if (A0) wr64(A0, (uint64_t)t); RET((uint64_t)t); }
API(time, _time32) { int64_t t = time(NULL); if (A0) wr32(A0, (uint32_t)t); RET((uint32_t)t); }
API(time, _mktime64) {
    struct tm t; tm_from_guest(&t, A0); time_t r = mktime(&t);
    if (r == (time_t)-1) { RET((uint64_t)-1); return; }
    tm_to_guest(A0, &t); RET((uint64_t)r);
}
API(time, _mkgmtime64) {
    struct tm t; tm_from_guest(&t, A0); time_t r = timegm(&t);
    if (r == (time_t)-1) { RET((uint64_t)-1); return; }
    tm_to_guest(A0, &t); RET((uint64_t)r);
}
API(time, _gmtime64) {
    time_t t = (time_t)rd64(A0); struct tm r;
    if (!gmtime_r(&t, &r)) { t_errno = 22; RET(0); return; }
    tm_to_guest(G(t_tmbuf), &r); RET(G(t_tmbuf));
}
API(time, _gmtime64_s) {
    if (!A0 || !A1) { RET(22); return; }
    time_t t = (time_t)rd64(A1); struct tm r;
    if (!gmtime_r(&t, &r)) { memset(PTR(A0), 0xFF, 36); RET(22); return; }
    tm_to_guest(A0, &r); RET(0);
}
API(time, _localtime64) {
    time_t t = (time_t)rd64(A0); struct tm r;
    if (!localtime_r(&t, &r)) { t_errno = 22; RET(0); return; }
    tm_to_guest(G(t_tmbuf), &r); RET(G(t_tmbuf));
}
API(time, _localtime64_s) {
    if (!A0 || !A1) { RET(22); return; }
    time_t t = (time_t)rd64(A1); struct tm r;
    if (!localtime_r(&t, &r)) { memset(PTR(A0), 0xFF, 36); RET(22); return; }
    tm_to_guest(A0, &r); RET(0);
}
API(time, _difftime64) { RETD((double)((int64_t)A0 - (int64_t)A1)); }
API(time, asctime) {
    struct tm t; tm_from_guest(&t, A0);
    asctime_r(&t, t_timestr); RET(G(t_timestr));
}
API(time, _ctime64) {
    time_t t = (time_t)rd64(A0); struct tm r;
    if (!localtime_r(&t, &r)) { RET(0); return; }
    asctime_r(&r, t_timestr); RET(G(t_timestr));
}
// strftime(buf, max, format, tm): Microsoft's '#' flag (no leading zeros) is dropped
API(time, strftime) {
    struct tm t; tm_from_guest(&t, A3);
    const char *f = PTR(A2); size_t fl = strlen(f); char *f2 = malloc(fl + 1), *o = f2;
    for (size_t i = 0; i < fl; i++) { if (f[i] == '#' && i && f[i - 1] == '%') continue; *o++ = f[i]; }
    *o = 0;
    size_t n = strftime(PTR(A0), A1, f2, &t); free(f2); RET(n);
}
// clock(): milliseconds since the process started (CLOCKS_PER_SEC is 1000 on Windows), wall time as Windows has it
static struct timespec clock0;
__attribute__((constructor)) static void clock_start(void) { clock_gettime(CLOCK_MONOTONIC, &clock0); }
API(time, clock) {
    struct timespec n; clock_gettime(CLOCK_MONOTONIC, &n);
    RET((uint32_t)((n.tv_sec - clock0.tv_sec) * 1000 + (n.tv_nsec - clock0.tv_nsec) / 1000000));
}
// _ftime64(struct __timeb64 *): { time 0, millitm 8 (u16), timezone 10 (minutes west), dstflag 12 }
API(time, _ftime64) {
    struct timeval tv; gettimeofday(&tv, NULL); time_t s = tv.tv_sec; struct tm lt; localtime_r(&s, &lt);
    wr64(A0, (uint64_t)tv.tv_sec); wr16(A0 + 8, (uint16_t)(tv.tv_usec / 1000));
    wr16(A0 + 10, (uint16_t)(int16_t)(-lt.tm_gmtoff / 60 + (lt.tm_isdst > 0 ? 60 : 0))); wr16(A0 + 12, (uint16_t)(lt.tm_isdst > 0));
}
