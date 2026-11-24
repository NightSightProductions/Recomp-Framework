#include "com32.h"
// kernel32 for 32-bit guests: handles, synchronization, threads, files (with overlapped and ReadFileEx/APC I/O),
// memory, time, INI files.
#include "rt32.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <fnmatch.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <mach/mach_time.h>

#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_NO_MORE_FILES 18
#define ERROR_HANDLE_EOF 38
#define ERROR_ALREADY_EXISTS 183
#define ERROR_IO_PENDING 997
#define WAIT_TIMEOUT 0x102
#define WAIT_FAILED 0xFFFFFFFFu
#define INVALID_HANDLE 0xFFFFFFFFu

// ---------------- handles ----------------
enum { H_FREE, H_FILE, H_EVENT, H_SEM, H_MUTEX, H_THREAD, H_FIND };
typedef struct {
    int type;
    int fd;
    int manual, signaled;              // event
    int count, max;                    // semaphore
    uint32_t owner, recursion;         // mutex (owner tid)
    RtThread *thread; int done; uint32_t exit_code;
    DIR *dir; char pattern[256], dirpath[1024];
    int overlapped;
    char name[128];
    pthread_cond_t cv; int cv_init, waiters;   // single-object waiters sleep here
} Handle;
#define NHANDLES 8192
static Handle handles[NHANDLES];
static pthread_mutex_t h_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t h_cv = PTHREAD_COND_INITIALIZER;
static int multi_waiters;   // threads in WaitForMultipleObjects (they sleep on h_cv)   // broadcast whenever any waitable object changes
#define HVAL(i) (0x100u + 4u * (uint32_t)(i))
static Handle *hget(uint32_t h) {
    if (h < 0x100 || (h & 3)) return NULL;
    uint32_t i = (h - 0x100) / 4;
    return i < NHANDLES && handles[i].type != H_FREE ? &handles[i] : NULL;
}
static uint32_t hnew(int type) {
    pthread_mutex_lock(&h_mu);
    for (int i = 1; i < NHANDLES; i++) if (handles[i].type == H_FREE) {
        memset(&handles[i], 0, sizeof handles[i]);
        handles[i].type = type; handles[i].fd = -1;
        pthread_mutex_unlock(&h_mu);
        return HVAL(i);
    }
    pthread_mutex_unlock(&h_mu);
    rt_fatal("out of handles");
}
static Handle *hnamed(int type, const char *name) {
    if (!name || !*name) return NULL;
    for (int i = 1; i < NHANDLES; i++) if (handles[i].type == type && !strcmp(handles[i].name, name)) return &handles[i];
    return NULL;
}

// ---------------- waiting ----------------
static int signaled(Handle *o, uint32_t tid) {
    switch (o->type) {
    case H_EVENT: return o->signaled;
    case H_SEM: return o->count > 0;
    case H_MUTEX: return !o->owner || o->owner == tid;
    case H_THREAD: return o->done;
    default: return 1;
    }
}
static void acquire(Handle *o, uint32_t tid) {
    if (o->type == H_EVENT && !o->manual) o->signaled = 0;
    else if (o->type == H_SEM) o->count--;
    else if (o->type == H_MUTEX) { o->owner = tid; o->recursion++; }
}
static void deadline(struct timespec *ts, uint32_t ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000; ts->tv_nsec += (long)(ms % 1000) * 1000000;
    if (ts->tv_nsec >= 1000000000) { ts->tv_sec++; ts->tv_nsec -= 1000000000; }
}
void rt_run_apcs(void);
static int apc_pending(void);
static uint32_t wait_many(int n, const uint32_t *hs, int all, uint32_t ms, int alertable) {
    uint32_t tid = rt_thread() ? rt_thread()->tid : 0;
    struct timespec ts; if (ms != 0xFFFFFFFFu) deadline(&ts, ms);
    pthread_mutex_lock(&h_mu);
    for (;;) {
        Handle *o[64];
        for (int i = 0; i < n; i++) { o[i] = hget(hs[i]); if (!o[i]) { pthread_mutex_unlock(&h_mu); LAST_ERROR = ERROR_INVALID_HANDLE; return WAIT_FAILED; } }
        if (all) {
            int ok = 1; for (int i = 0; i < n; i++) ok &= signaled(o[i], tid);
            if (ok) { for (int i = 0; i < n; i++) acquire(o[i], tid); pthread_mutex_unlock(&h_mu); return 0; }
        } else {
            for (int i = 0; i < n; i++) if (signaled(o[i], tid)) { acquire(o[i], tid); pthread_mutex_unlock(&h_mu); return (uint32_t)i; }
        }
        if (alertable && apc_pending()) { pthread_mutex_unlock(&h_mu); rt_run_apcs(); return 0xC0; }   // WAIT_IO_COMPLETION
        if (ms == 0) { pthread_mutex_unlock(&h_mu); return WAIT_TIMEOUT; }
        pthread_cond_t *cv = &h_cv;
        if (n == 1) { if (!o[0]->cv_init) { pthread_cond_init(&o[0]->cv, NULL); o[0]->cv_init = 1; } cv = &o[0]->cv; o[0]->waiters++; }
        else multi_waiters++;
        int r = ms == 0xFFFFFFFFu ? pthread_cond_wait(cv, &h_mu) : pthread_cond_timedwait(cv, &h_mu, &ts);
        if (n == 1) o[0]->waiters--; else multi_waiters--;
        if (r == ETIMEDOUT) { pthread_mutex_unlock(&h_mu); return WAIT_TIMEOUT; }
    }
}
// an object changed state: wake its own waiters, and the multi-object waiters if there are any (h_mu held)
static void kick_obj(Handle *o) {
    if (o && o->cv_init && o->waiters) pthread_cond_broadcast(&o->cv);
    if (multi_waiters || !o) pthread_cond_broadcast(&h_cv);
}
static void kick(void) { kick_obj(NULL); }

SHIM(kernel32_WaitForSingleObject, 2) { uint32_t h = ARG(0); return wait_many(1, &h, 0, ARG(1), 0); }
SHIM(kernel32_WaitForMultipleObjects, 4) {
    uint32_t n = ARG(0), hs[64];
    if (n > 64) n = 64;
    for (uint32_t i = 0; i < n; i++) hs[i] = rd32(ARG(1) + 4 * i);
    return wait_many((int)n, hs, ARG(2) != 0, ARG(3), 0);
}
SHIM(kernel32_CreateEventA, 4) {
    const char *name = STR(3);
    pthread_mutex_lock(&h_mu); Handle *ex = hnamed(H_EVENT, name); pthread_mutex_unlock(&h_mu);
    if (ex) { LAST_ERROR = ERROR_ALREADY_EXISTS; return HVAL(ex - handles); }
    uint32_t h = hnew(H_EVENT); Handle *o = hget(h);
    o->manual = ARG(1) != 0; o->signaled = ARG(2) != 0;
    if (name) snprintf(o->name, sizeof o->name, "%s", name);
    LAST_ERROR = 0;
    return h;
}
SHIM(kernel32_SetEvent, 1) { pthread_mutex_lock(&h_mu); Handle *o = hget(ARG(0)); if (o) { o->signaled = 1; kick_obj(o); } pthread_mutex_unlock(&h_mu); return o != NULL; }
SHIM(kernel32_ResetEvent, 1) { pthread_mutex_lock(&h_mu); Handle *o = hget(ARG(0)); if (o) o->signaled = 0; pthread_mutex_unlock(&h_mu); return o != NULL; }
SHIM(kernel32_CreateSemaphoreA, 4) {
    uint32_t h = hnew(H_SEM); Handle *o = hget(h);
    o->count = (int)ARG(1); o->max = (int)ARG(2);
    return h;
}
SHIM(kernel32_ReleaseSemaphore, 3) {
    pthread_mutex_lock(&h_mu);
    Handle *o = hget(ARG(0)); int ok = 0;
    if (o && o->type == H_SEM) {
        if (ARG(2)) wr32(ARG(2), (uint32_t)o->count);
        if (o->count + (int)ARG(1) <= o->max) { o->count += (int)ARG(1); ok = 1; kick_obj(o); }
    }
    pthread_mutex_unlock(&h_mu);
    return ok;
}
SHIM(kernel32_CreateMutexA, 3) {
    const char *name = STR(2);
    pthread_mutex_lock(&h_mu); Handle *ex = hnamed(H_MUTEX, name); pthread_mutex_unlock(&h_mu);
    if (ex) { LAST_ERROR = ERROR_ALREADY_EXISTS; return HVAL(ex - handles); }
    uint32_t h = hnew(H_MUTEX); Handle *o = hget(h);
    if (ARG(1)) { o->owner = rt_thread()->tid; o->recursion = 1; }
    if (name) snprintf(o->name, sizeof o->name, "%s", name);
    LAST_ERROR = 0;
    return h;
}
SHIM(kernel32_ReleaseMutex, 1) {
    pthread_mutex_lock(&h_mu);
    Handle *o = hget(ARG(0)); int ok = 0;
    if (o && o->type == H_MUTEX && o->owner == rt_thread()->tid) { if (!--o->recursion) o->owner = 0; ok = 1; kick_obj(o); }
    pthread_mutex_unlock(&h_mu);
    return ok;
}
SHIM(kernel32_CloseHandle, 1) {
    pthread_mutex_lock(&h_mu);
    Handle *o = hget(ARG(0));
    if (o) {
        if (o->fd >= 0) close(o->fd);
        if (o->dir) closedir(o->dir);
        if (o->type != H_THREAD || o->done) o->type = H_FREE;   // a running thread keeps its slot until it exits
    }
    pthread_mutex_unlock(&h_mu);
    return o != NULL;
}

// ---------------- critical sections ----------------
// The guest CRITICAL_SECTION (24 bytes) holds only what Windows keeps there -- DebugInfo, LockCount, RecursionCount,
// OwningThread, LockSemaphore (0), SpinCount -- because games read or overlap those fields (RE HD's objects embed one
// whose LockSemaphore overlaps a list link that must stay 0). The host mutex is found in a table keyed by the
// guest address: lock-free lookups, inserts under a lock, entries never removed (a re-initialized section at the
// same address reuses its mutex).
#define CSN (1u << 17)
static struct { uint32_t key; pthread_mutex_t *m; } cs_tab[CSN];
static pthread_mutex_t cs_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *cs_get(uint32_t cs) {
    uint32_t i = ((cs >> 2) * 2654435761u) & (CSN - 1);
    for (;;) {
        uint32_t k = __atomic_load_n(&cs_tab[i].key, __ATOMIC_ACQUIRE);
        if (k == cs) return cs_tab[i].m;
        if (k == 0) {
            pthread_mutex_lock(&cs_mu);
            if (__atomic_load_n(&cs_tab[i].key, __ATOMIC_ACQUIRE) == 0) {
                pthread_mutex_t *m = malloc(sizeof *m);
                pthread_mutexattr_t a; pthread_mutexattr_init(&a); pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
                pthread_mutex_init(m, &a);
                cs_tab[i].m = m;
                __atomic_store_n(&cs_tab[i].key, cs, __ATOMIC_RELEASE);
                pthread_mutex_unlock(&cs_mu);
                return m;
            }
            pthread_mutex_unlock(&cs_mu);
            continue;   // someone filled this slot: look at it again
        }
        i = (i + 1) & (CSN - 1);
    }
}
static void cs_init_fields(uint32_t cs) {
    wr32(cs + 0x00, 0xFFFFFFFFu);   // DebugInfo: -1, "no debug info" (Windows 8+)
    wr32(cs + 0x04, 0xFFFFFFFFu);   // LockCount
    wr32(cs + 0x08, 0); wr32(cs + 0x0C, 0); wr32(cs + 0x10, 0); wr32(cs + 0x14, 0);
}
SHIM(kernel32_InitializeCriticalSection, 1) { cs_init_fields(ARG(0)); cs_get(ARG(0)); return 0; }
SHIM(kernel32_DeleteCriticalSection, 1) { return 0; }
SHIM(kernel32_EnterCriticalSection, 1) {
    uint32_t cs = ARG(0); pthread_mutex_lock(cs_get(cs));
    wr32(cs + 0x0C, rt_thread()->tid); wr32(cs + 0x08, rd32(cs + 0x08) + 1);
    return 0;
}
SHIM(kernel32_TryEnterCriticalSection, 1) {
    uint32_t cs = ARG(0);
    if (pthread_mutex_trylock(cs_get(cs))) return 0;
    wr32(cs + 0x0C, rt_thread()->tid); wr32(cs + 0x08, rd32(cs + 0x08) + 1);
    return 1;
}
SHIM(kernel32_LeaveCriticalSection, 1) {
    uint32_t cs = ARG(0);
    uint32_t r = rd32(cs + 0x08) - 1; wr32(cs + 0x08, r);
    if (!r) wr32(cs + 0x0C, 0);
    pthread_mutex_unlock(cs_get(cs));
    return 0;
}
SHIM(kernel32_InitializeSListHead, 1) { wr64(ARG(0), 0); return 0; }

// ---------------- threads ----------------
RtThread *rt_thread_new(uint32_t stack_size);
void rt_thread_attach(RtThread *t);
typedef struct { RtThread *t; uint32_t start, param, h; int suspended; pthread_mutex_t mu; pthread_cond_t cv; } ThreadStart;
static void *thread_main(void *p) {
    ThreadStart *s = p;
    rt_thread_attach(s->t);
    pthread_mutex_lock(&s->mu);
    while (s->suspended) pthread_cond_wait(&s->cv, &s->mu);
    pthread_mutex_unlock(&s->mu);
    uint32_t r = guest_call(s->t->cpu, s->start, 1, &s->param);
    pthread_mutex_lock(&h_mu);
    Handle *o = hget(s->h);
    if (o) { o->done = 1; o->exit_code = r; }
    kick_obj(o);
    pthread_mutex_unlock(&h_mu);
    return NULL;
}
static ThreadStart *thread_starts[NHANDLES];
SHIM(kernel32_CreateThread, 6) {
    uint32_t stack = ARG(1), start = ARG(2), param = ARG(3), flags = ARG(4), tidp = ARG(5);
    RtThread *t = rt_thread_new(stack ? stack : 0x100000);
    uint32_t h = hnew(H_THREAD);
    Handle *o = hget(h); o->thread = t; t->handle = h;
    ThreadStart *s = calloc(1, sizeof *s);
    s->t = t; s->start = start; s->param = param; s->h = h; s->suspended = (flags & 4) != 0;
    pthread_mutex_init(&s->mu, NULL); pthread_cond_init(&s->cv, NULL);
    thread_starts[(h - 0x100) / 4] = s;
    if (tidp) wr32(tidp, t->tid);
    pthread_attr_t a; pthread_attr_init(&a); pthread_attr_setstacksize(&a, 64u << 20);   // host stack: translated frames are big
    pthread_create(&t->pt, &a, thread_main, s);
    if (rt_verbose) rt_log("[k32] CreateThread start=0x%x param=0x%x tid=%u%s", start, param, t->tid, s->suspended ? " (suspended)" : "");
    return h;
}
SHIM(kernel32_ResumeThread, 1) {
    uint32_t h = ARG(0);
    Handle *o = hget(h);
    if (!o || o->type != H_THREAD) return 0xFFFFFFFFu;
    ThreadStart *s = thread_starts[(h - 0x100) / 4];
    uint32_t prev = 0;
    if (s) { pthread_mutex_lock(&s->mu); prev = s->suspended; s->suspended = 0; pthread_cond_signal(&s->cv); pthread_mutex_unlock(&s->mu); }
    return prev;
}
SHIM(kernel32_GetExitCodeThread, 2) {
    Handle *o = hget(ARG(0));
    if (!o || o->type != H_THREAD) return 0;
    wr32(ARG(1), o->done ? o->exit_code : 259);   // STILL_ACTIVE
    return 1;
}
SHIM(kernel32_SetThreadPriority, 2) { return 1; }
SHIM(kernel32_SetThreadIdealProcessor, 2) { return 0; }
SHIM(kernel32_GetCurrentThreadId, 0) { return rt_thread()->tid; }
SHIM(kernel32_GetCurrentProcessId, 0) { return 0x10; }
SHIM(kernel32_GetCurrentProcess, 0) { return 0xFFFFFFFFu; }
SHIM(kernel32_Sleep, 1) {
    uint32_t ms = ARG(0);
    if (!ms) sched_yield(); else usleep(ms * 1000u);
    return 0;
}

// APCs (ReadFileEx completion routines): run on the issuing thread when it waits alertably
typedef struct Apc { struct Apc *next; uint32_t fn, a0, a1, a2; } Apc;
static _Thread_local Apc *apc_head, *apc_tail;
static int apc_pending(void) { return apc_head != NULL; }
static void apc_queue(uint32_t fn, uint32_t a0, uint32_t a1, uint32_t a2) {
    Apc *p = malloc(sizeof *p); *p = (Apc){NULL, fn, a0, a1, a2};
    if (apc_tail) apc_tail->next = p; else apc_head = p;
    apc_tail = p;
}
void rt_run_apcs(void) {
    while (apc_head) {
        Apc *p = apc_head; apc_head = p->next; if (!apc_head) apc_tail = NULL;
        uint32_t args[3] = {p->a0, p->a1, p->a2};
        guest_call(rt_cpu(), p->fn, 3, args);
        free(p);
    }
}
SHIM(kernel32_SleepEx, 2) {
    uint32_t ms = ARG(0);
    if (ARG(1) && apc_pending()) { rt_run_apcs(); return 0xC0; }
    if (!ms) sched_yield(); else usleep(ms * 1000u);
    if (ARG(1) && apc_pending()) { rt_run_apcs(); return 0xC0; }
    return 0;
}

// ---------------- files ----------------
static uint32_t file_error(void) {
    switch (errno) {
    case ENOENT: return ERROR_FILE_NOT_FOUND;
    case ENOTDIR: return ERROR_PATH_NOT_FOUND;
    case EACCES: case EPERM: return ERROR_ACCESS_DENIED;
    case EEXIST: return 80;   // ERROR_FILE_EXISTS
    default: return 31;       // ERROR_GEN_FAILURE
    }
}
static int trace_files = -1;
SHIM(kernel32_CreateFileA, 7) {
    if (trace_files < 0) trace_files = getenv("RT_TRACE_FILES") != NULL;
    char p[1024]; rt_host_path(STR(0), p, sizeof p);
    uint32_t access = ARG(1), disp = ARG(4), flags = ARG(5);
    int o = (access & 0x40000000u) ? ((access & 0x80000000u) ? O_RDWR : O_WRONLY) : O_RDONLY;
    switch (disp) {
    case 1: o |= O_CREAT | O_EXCL; break;    // CREATE_NEW
    case 2: o |= O_CREAT | O_TRUNC; break;   // CREATE_ALWAYS
    case 4: o |= O_CREAT; break;             // OPEN_ALWAYS
    case 5: o |= O_TRUNC; break;             // TRUNCATE_EXISTING
    default: break;                          // OPEN_EXISTING
    }
    int fd = open(p, o, 0644);
    if (fd < 0) { if (trace_files) rt_log("[file] CreateFileA %s -> %s", p, strerror(errno)); LAST_ERROR = file_error(); return INVALID_HANDLE; }
    uint32_t h = hnew(H_FILE); Handle *hd = hget(h);
    hd->fd = fd; hd->overlapped = (flags & 0x40000000u) != 0;
    if (trace_files) rt_log("[file] CreateFileA %s -> 0x%x%s", p, h, hd->overlapped ? " (overlapped)" : "");
    LAST_ERROR = (disp == 2 || disp == 4) ? 0 : 0;
    return h;
}
// OVERLAPPED (20 bytes): Internal(status), InternalHigh(bytes), Offset, OffsetHigh, hEvent
static int64_t ov_offset(uint32_t ov) { return (int64_t)(((uint64_t)rd32(ov + 12) << 32) | rd32(ov + 8)); }
static void ov_done(uint32_t ov, uint32_t status, uint32_t bytes) {
    wr32(ov + 0, status); wr32(ov + 4, bytes);
    uint32_t ev = rd32(ov + 16);
    if (ev) { pthread_mutex_lock(&h_mu); Handle *e = hget(ev); if (e) { e->signaled = 1; kick_obj(e); } pthread_mutex_unlock(&h_mu); }
}
SHIM(kernel32_ReadFile, 5) {
    Handle *f = hget(ARG(0));
    uint32_t buf = ARG(1), n = ARG(2), outp = ARG(3), ov = ARG(4);
    if (!f || f->type != H_FILE) { LAST_ERROR = ERROR_INVALID_HANDLE; return 0; }
    WATCH_BULK(buf, n, "ReadFile");
    if (trace_files > 0) rt_log("[file] ReadFile h=0x%x n=%u ov=%s off=%lld event=0x%x (from 0x%x)", ARG(0), n, ov ? "yes" : "no",
                                ov ? (long long)ov_offset(ov) : -1ll, ov ? rd32(ov + 16) : 0, rd32(c->esp));
    ssize_t r = ov ? pread(f->fd, G2H(buf), n, ov_offset(ov)) : read(f->fd, G2H(buf), n);
    if (r < 0) { LAST_ERROR = file_error(); return 0; }
    if (outp) wr32(outp, (uint32_t)r);
    if (ov) {
        ov_done(ov, r == 0 && n ? 0xC0000011u : 0, (uint32_t)r);   // STATUS_END_OF_FILE
        if (r == 0 && n) { LAST_ERROR = ERROR_HANDLE_EOF; return 0; }
    }
    return 1;
}
SHIM(kernel32_ReadFileEx, 5) {
    Handle *f = hget(ARG(0));
    uint32_t buf = ARG(1), n = ARG(2), ov = ARG(3), done = ARG(4);
    if (!f || f->type != H_FILE) { LAST_ERROR = ERROR_INVALID_HANDLE; return 0; }
    WATCH_BULK(buf, n, "ReadFileEx");
    if (trace_files > 0) rt_log("[file] ReadFileEx h=0x%x n=%u off=%lld (from 0x%x)", ARG(0), n, (long long)ov_offset(ov), rd32(c->esp));
    ssize_t r = pread(f->fd, G2H(buf), n, ov_offset(ov));
    uint32_t err = r < 0 ? file_error() : (r == 0 && n ? ERROR_HANDLE_EOF : 0);
    wr32(ov + 0, err ? 0xC0000011u : 0); wr32(ov + 4, r > 0 ? (uint32_t)r : 0);
    apc_queue(done, err, r > 0 ? (uint32_t)r : 0, ov);
    LAST_ERROR = 0;
    return 1;
}
SHIM(kernel32_GetOverlappedResult, 4) {
    if (trace_files > 0) rt_log("[file] GetOverlappedResult h=0x%x wait=%u -> %u bytes", ARG(0), ARG(3), rd32(ARG(1) + 4));
    uint32_t ov = ARG(1);
    if (ARG(2)) wr32(ARG(2), rd32(ov + 4));
    if (rd32(ov) == 0xC0000011u) { LAST_ERROR = ERROR_HANDLE_EOF; return 0; }
    return 1;
}
SHIM(kernel32_WriteFile, 5) {
    Handle *f = hget(ARG(0));
    uint32_t buf = ARG(1), n = ARG(2), outp = ARG(3), ov = ARG(4);
    int fd = f && f->type == H_FILE ? f->fd : (ARG(0) == 0xFFFFFFF5u || ARG(0) == 0xFFFFFFF4u ? 2 : -1);
    if (fd < 0) { LAST_ERROR = ERROR_INVALID_HANDLE; return 0; }
    ssize_t r = ov ? pwrite(fd, G2H(buf), n, ov_offset(ov)) : write(fd, G2H(buf), n);
    if (r < 0) { LAST_ERROR = file_error(); return 0; }
    if (outp) wr32(outp, (uint32_t)r);
    if (ov) ov_done(ov, 0, (uint32_t)r);
    return 1;
}
SHIM(kernel32_SetFilePointer, 4) {
    Handle *f = hget(ARG(0));
    if (!f || f->type != H_FILE) { LAST_ERROR = ERROR_INVALID_HANDLE; return 0xFFFFFFFFu; }
    int64_t off = (int32_t)ARG(1);
    if (ARG(2)) off = (int64_t)(((uint64_t)rd32(ARG(2)) << 32) | ARG(1));
    off_t r = lseek(f->fd, off, ARG(3) == 0 ? SEEK_SET : ARG(3) == 1 ? SEEK_CUR : SEEK_END);
    if (r < 0) { LAST_ERROR = 131; return 0xFFFFFFFFu; }
    if (ARG(2)) wr32(ARG(2), (uint32_t)((uint64_t)r >> 32));
    LAST_ERROR = 0;
    return (uint32_t)r;
}
SHIM(kernel32_SetEndOfFile, 1) {
    Handle *f = hget(ARG(0));
    if (!f || f->type != H_FILE) return 0;
    return ftruncate(f->fd, lseek(f->fd, 0, SEEK_CUR)) == 0;
}
SHIM(kernel32_GetFileSize, 2) {
    Handle *f = hget(ARG(0)); struct stat st;
    if (!f || f->type != H_FILE || fstat(f->fd, &st)) { LAST_ERROR = ERROR_INVALID_HANDLE; return 0xFFFFFFFFu; }
    if (ARG(1)) wr32(ARG(1), (uint32_t)((uint64_t)st.st_size >> 32));
    return (uint32_t)st.st_size;
}
static uint32_t attrs_of(struct stat *st) { return S_ISDIR(st->st_mode) ? 0x10 : 0x80; }   // DIRECTORY / NORMAL
SHIM(kernel32_GetFileAttributesA, 1) {
    char p[1024]; struct stat st;
    if (stat(rt_host_path(STR(0), p, sizeof p), &st)) { LAST_ERROR = file_error(); return 0xFFFFFFFFu; }
    return attrs_of(&st);
}
SHIM(kernel32_DeleteFileA, 1) { char p[1024]; if (unlink(rt_host_path(STR(0), p, sizeof p))) { LAST_ERROR = file_error(); return 0; } return 1; }
SHIM(kernel32_CreateDirectoryA, 2) {
    char p[1024];
    if (mkdir(rt_host_path(STR(0), p, sizeof p), 0755)) { LAST_ERROR = errno == EEXIST ? ERROR_ALREADY_EXISTS : file_error(); return 0; }
    return 1;
}
SHIM(kernel32_RemoveDirectoryA, 1) { char p[1024]; if (rmdir(rt_host_path(STR(0), p, sizeof p))) { LAST_ERROR = file_error(); return 0; } return 1; }
SHIM(kernel32_MoveFileA, 2) {
    char a[1024], b[1024];
    if (rename(rt_host_path(STR(0), a, sizeof a), rt_host_path(STR(1), b, sizeof b))) { LAST_ERROR = file_error(); return 0; }
    return 1;
}
SHIM(kernel32_CopyFileA, 3) {
    char a[1024], b[1024];
    rt_host_path(STR(0), a, sizeof a); rt_host_path(STR(1), b, sizeof b);
    if (ARG(2) && access(b, F_OK) == 0) { LAST_ERROR = 80; return 0; }
    int in = open(a, O_RDONLY); if (in < 0) { LAST_ERROR = file_error(); return 0; }
    int out = open(b, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (out < 0) { close(in); LAST_ERROR = file_error(); return 0; }
    char buf[65536]; ssize_t r;
    while ((r = read(in, buf, sizeof buf)) > 0) write(out, buf, (size_t)r);
    close(in); close(out);
    return 1;
}
SHIM(kernel32_GetDiskFreeSpaceA, 5) {
    struct statfs s; if (statfs(rt_data_dir[0] ? rt_data_dir : ".", &s)) return 0;
    uint64_t freeb = (uint64_t)s.f_bavail * s.f_bsize, tot = (uint64_t)s.f_blocks * s.f_bsize;
    uint32_t spc = 8, bps = 512, cl = spc * bps;
    if (ARG(1)) wr32(ARG(1), spc);
    if (ARG(2)) wr32(ARG(2), bps);
    if (ARG(3)) wr32(ARG(3), (uint32_t)(freeb / cl > 0xFFFFFFFFull ? 0xFFFFFFFFu : freeb / cl));
    if (ARG(4)) wr32(ARG(4), (uint32_t)(tot / cl > 0xFFFFFFFFull ? 0xFFFFFFFFu : tot / cl));
    return 1;
}
// WIN32_FIND_DATAA: attrs, 3 FILETIMEs, sizeHigh, sizeLow, 2 reserved, cFileName[260], cAlternateFileName[14]
static void unix_to_filetime(time_t t, uint32_t ft) { uint64_t v = ((uint64_t)t + 11644473600ull) * 10000000ull; wr32(ft, (uint32_t)v); wr32(ft + 4, (uint32_t)(v >> 32)); }
static int find_next(Handle *f, uint32_t fd) {
    struct dirent *e;
    while ((e = readdir(f->dir))) {
        if (fnmatch(f->pattern, e->d_name, FNM_CASEFOLD)) continue;
        char full[1400]; struct stat st;
        snprintf(full, sizeof full, "%s/%s", f->dirpath, e->d_name);
        if (stat(full, &st)) continue;
        memset(G2H(fd), 0, 320);
        wr32(fd, attrs_of(&st));
        unix_to_filetime(st.st_birthtime, fd + 4); unix_to_filetime(st.st_atime, fd + 12); unix_to_filetime(st.st_mtime, fd + 20);
        wr32(fd + 28, (uint32_t)((uint64_t)st.st_size >> 32)); wr32(fd + 32, (uint32_t)st.st_size);
        snprintf((char *)G2H(fd + 44), 260, "%s", e->d_name);
        return 1;
    }
    return 0;
}
SHIM(kernel32_FindFirstFileA, 2) {
    char p[1024]; rt_host_path(STR(0), p, sizeof p);
    char *slash = strrchr(p, '/');
    uint32_t h = hnew(H_FIND); Handle *f = hget(h);
    if (slash) { *slash = 0; snprintf(f->dirpath, sizeof f->dirpath, "%s", *p ? p : "/"); snprintf(f->pattern, sizeof f->pattern, "%s", slash + 1); }
    else { snprintf(f->dirpath, sizeof f->dirpath, "."); snprintf(f->pattern, sizeof f->pattern, "%s", p); }
    if (!strcmp(f->pattern, "*.*")) strcpy(f->pattern, "*");
    f->dir = opendir(f->dirpath);
    if (!f->dir || !find_next(f, ARG(1))) { f->type = H_FREE; if (f->dir) closedir(f->dir); f->dir = NULL; LAST_ERROR = ERROR_FILE_NOT_FOUND; return INVALID_HANDLE; }
    return h;
}
SHIM(kernel32_FindNextFileA, 2) {
    Handle *f = hget(ARG(0));
    if (!f || f->type != H_FIND) return 0;
    if (!find_next(f, ARG(1))) { LAST_ERROR = ERROR_NO_MORE_FILES; return 0; }
    return 1;
}
SHIM(kernel32_FindClose, 1) {
    Handle *f = hget(ARG(0));
    if (!f || f->type != H_FIND) return 0;
    if (f->dir) closedir(f->dir);
    f->dir = NULL; f->type = H_FREE;
    return 1;
}
static char cwd_win[260];
SHIM(kernel32_GetCurrentDirectoryA, 2) {
    if (!cwd_win[0]) snprintf(cwd_win, sizeof cwd_win, "%s", rt_game.win_dir);
    uint32_t n = (uint32_t)strlen(cwd_win);
    if (ARG(0) <= n) return n + 1;
    memcpy(G2H(ARG(1)), cwd_win, n + 1);
    return n;
}
SHIM(kernel32_SetCurrentDirectoryA, 1) { snprintf(cwd_win, sizeof cwd_win, "%s", STR(0)); return 1; }

// ---------------- INI files ----------------
static int ini_find(FILE *f, const char *sec, const char *key, char *out, size_t n) {
    char line[1024]; int in = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        s[strcspn(s, "\r\n")] = 0;
        if (*s == '[') { char *e = strchr(s, ']'); if (e) *e = 0; in = !strcasecmp(s + 1, sec); continue; }
        if (!in) continue;
        char *eq = strchr(s, '='); if (!eq) continue;
        *eq = 0; char *k = s; char *ke = eq; while (ke > k && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = 0;
        if (!strcasecmp(k, key)) { char *v = eq + 1; while (*v == ' ') v++; snprintf(out, n, "%s", v); return 1; }
    }
    return 0;
}
SHIM(kernel32_GetPrivateProfileStringA, 6) {
    const char *sec = STR(0), *key = STR(1), *def = STR(2);
    uint32_t out = ARG(3), n = ARG(4);
    char p[1024], v[1024] = "";
    rt_host_path(STR(5), p, sizeof p);
    FILE *f = fopen(p, "r");
    if (trace_files < 0) trace_files = getenv("RT_TRACE_FILES") != NULL;
    if (trace_files) rt_log("[file] GetPrivateProfileString [%s] %s in %s (%s)", sec ? sec : "", key ? key : "", STR(5), f ? "found file" : strerror(errno));
    int found = f && sec && key && ini_find(f, sec, key, v, sizeof v);
    if (f) fclose(f);
    if (!found) snprintf(v, sizeof v, "%s", def ? def : "");
    if (!n) return 0;
    size_t len = strlen(v); if (len > n - 1) len = n - 1;
    memcpy(G2H(out), v, len); wr8(out + (uint32_t)len, 0);
    return (uint32_t)len;
}
SHIM(kernel32_WritePrivateProfileStringA, 4) {
    const char *sec = STR(0), *key = STR(1), *val = STR(2);
    char p[1024]; rt_host_path(STR(3), p, sizeof p);
    if (trace_files < 0) trace_files = getenv("RT_TRACE_FILES") != NULL;
    if (trace_files) rt_log("[file] WritePrivateProfileString [%s] %s=%s in %s -> %s", sec ? sec : "", key ? key : "", val ? val : "", STR(3), p);
    FILE *f = fopen(p, "r");
    char *buf = NULL; size_t len = 0;
    if (f) { fseek(f, 0, SEEK_END); len = (size_t)ftell(f); fseek(f, 0, SEEK_SET); buf = malloc(len + 1); len = fread(buf, 1, len, f); buf[len] = 0; fclose(f); }
    FILE *o = fopen(p, "w"); if (!o) { free(buf); return 0; }
    int in = 0, done = 0, seen_sec = 0;
    char *save = NULL;
    for (char *line = buf ? strtok_r(buf, "\n", &save) : NULL; line; line = strtok_r(NULL, "\n", &save)) {
        char *s = line; s[strcspn(s, "\r")] = 0;
        if (*s == '[') {
            if (in && !done && key && val) { fprintf(o, "%s=%s\r\n", key, val); done = 1; }
            char name[256]; snprintf(name, sizeof name, "%s", s + 1); char *e = strchr(name, ']'); if (e) *e = 0;
            in = !strcasecmp(name, sec); if (in) seen_sec = 1;
            if (in && !key) continue;
        } else if (in && key) {
            char *eq = strchr(s, '=');
            if (eq) { char k[256]; snprintf(k, sizeof k, "%.*s", (int)(eq - s), s); if (!strcasecmp(k, key)) { if (val && !done) fprintf(o, "%s=%s\r\n", key, val); done = 1; continue; } }
        } else if (in && !key) continue;
        fprintf(o, "%s\r\n", s);
    }
    if (!done && key && val) { if (!seen_sec || !in) fprintf(o, "[%s]\r\n", sec); fprintf(o, "%s=%s\r\n", key, val); }
    fclose(o); free(buf);
    return 1;
}

// ---------------- memory ----------------
SHIM(kernel32_VirtualAlloc, 4) {
    uint32_t a = gvm_alloc(ARG(0), ARG(1), (ARG(2) & 0x1000) != 0, ARG(3));
    if (!a) LAST_ERROR = 8;   // ERROR_NOT_ENOUGH_MEMORY
    return a;
}
SHIM(kernel32_VirtualFree, 3) {
    if (ARG(2) & 0x8000) return gvm_free(ARG(0));   // MEM_RELEASE
    return 1;                                      // MEM_DECOMMIT: keep the pages
}
SHIM(kernel32_HeapAlloc, 3) {
    uint32_t p = (ARG(1) & 8) ? gcalloc(1, ARG(2)) : gmalloc(ARG(2));   // HEAP_ZERO_MEMORY
    return p;
}
SHIM(kernel32_HeapFree, 3) { gfree(ARG(2)); return 1; }
SHIM(kernel32_GetProcessHeap, 0) { return rt_process_heap; }
SHIM(kernel32_GlobalAlloc, 2) { return (ARG(0) & 0x40) ? gcalloc(1, ARG(1)) : gmalloc(ARG(1)); }
SHIM(kernel32_GlobalFree, 1) { gfree(ARG(0)); return 0; }
SHIM(kernel32_GlobalLock, 1) { return ARG(0); }
SHIM(kernel32_GlobalUnlock, 1) { return 1; }

// ---------------- time ----------------
SHIM(kernel32_QueryPerformanceFrequency, 1) { wr64(ARG(0), 10000000ull); return 1; }
SHIM(kernel32_QueryPerformanceCounter, 1) {
    static mach_timebase_info_data_t tb; if (!tb.denom) mach_timebase_info(&tb);
    uint64_t ns = mach_absolute_time() * tb.numer / tb.denom;
    wr64(ARG(0), ns / 100);
    return 1;
}
SHIM(kernel32_GetSystemTimeAsFileTime, 1) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t v = ((uint64_t)ts.tv_sec + 11644473600ull) * 10000000ull + (uint64_t)ts.tv_nsec / 100;
    wr64(ARG(0), v);
    return 0;
}
SHIM(kernel32_FileTimeToLocalFileTime, 2) {
    uint64_t v = rd64(ARG(0)); time_t t = (time_t)(v / 10000000ull - 11644473600ull);
    struct tm lt; localtime_r(&t, &lt);
    wr64(ARG(1), v + (uint64_t)((int64_t)lt.tm_gmtoff * 10000000ll));
    return 1;
}
SHIM(kernel32_FileTimeToSystemTime, 2) {
    uint64_t v = rd64(ARG(0)); time_t t = (time_t)(v / 10000000ull - 11644473600ull);
    struct tm g; gmtime_r(&t, &g);
    uint32_t st = ARG(1);
    wr16(st, (uint16_t)(g.tm_year + 1900)); wr16(st + 2, (uint16_t)(g.tm_mon + 1)); wr16(st + 4, (uint16_t)g.tm_wday);
    wr16(st + 6, (uint16_t)g.tm_mday); wr16(st + 8, (uint16_t)g.tm_hour); wr16(st + 10, (uint16_t)g.tm_min);
    wr16(st + 12, (uint16_t)g.tm_sec); wr16(st + 14, (uint16_t)((v / 10000) % 1000));
    return 1;
}

// ---------------- process / system ----------------
static uint32_t cmdline_a;
extern char rt_cmdline[1024];
SHIM(kernel32_GetCommandLineA, 0) { if (!cmdline_a) cmdline_a = gstrdup(rt_cmdline); return cmdline_a; }
SHIM(kernel32_GetModuleHandleA, 1) {
    const char *n = STR(0);
    if (!n || !strcasecmp(n, rt_game.exe)) return gimage_base;
    LAST_ERROR = 126; return 0;
}
SHIM(kernel32_GetModuleHandleW, 1) {
    char n[260]; if (!ARG(0)) return gimage_base;
    w_to_utf8(WSTR(0), n, sizeof n);
    if (!strcasecmp(n, rt_game.exe)) return gimage_base;
    LAST_ERROR = 126; return 0;
}
SHIM(kernel32_K32GetModuleFileNameExA, 4) {
    char p[512]; snprintf(p, sizeof p, "%s\\%s", rt_game.win_dir, rt_game.exe);
    uint32_t n = ARG(3); size_t len = strlen(p); if (len >= n) len = n - 1;
    memcpy(G2H(ARG(2)), p, len); wr8(ARG(2) + (uint32_t)len, 0);
    return (uint32_t)len;
}
SHIM(kernel32_GetStartupInfoW, 1) { memset(G2H(ARG(0)), 0, 68); wr32(ARG(0), 68); return 0; }
SHIM(kernel32_GetSystemInfo, 1) {
    uint32_t s = ARG(0); memset(G2H(s), 0, 36);
    wr16(s, 0);                // PROCESSOR_ARCHITECTURE_INTEL
    wr32(s + 4, 0x1000);       // page size
    wr32(s + 8, 0x10000); wr32(s + 12, 0x7FFEFFFF);
    wr32(s + 16, 0xFF);        // active processor mask
    wr32(s + 20, 8);           // processors
    wr32(s + 24, 586);
    wr32(s + 28, 0x10000);     // allocation granularity
    wr16(s + 32, 6); wr16(s + 34, 0x2A07);
    return 0;
}
SHIM(kernel32_IsProcessorFeaturePresent, 1) {
    switch (ARG(0)) {
    case 1: case 2: case 3: case 6: case 7: case 8: case 10: case 13: case 23: return 1;   // FP, MMX, XMMI, XMMI64, SSE3, fastfail...
    default: return 0;
    }
}
SHIM(kernel32_SetUnhandledExceptionFilter, 1) { return 0; }
SHIM(kernel32_DebugBreak, 0) { rt_log("[k32] DebugBreak from guest"); return 0; }
SHIM(kernel32_GetLastError, 0) { return LAST_ERROR; }
SHIM(kernel32_GetUserDefaultLangID, 0) { return 0x0409; }
// (OSVERSIONINFOEXA *, DWORD typeMask, DWORDLONG conditionMask): the 64-bit mask takes two stack slots
SHIM(kernel32_VerifyVersionInfoA, 4) { return 1; }   // "at least" checks: we are a modern Windows
RAWSHIM(kernel32_VerSetConditionMask) {   // (ULONGLONG mask, DWORD type, BYTE cond) -> ULONGLONG, stdcall 16 bytes
    uint64_t m = ARG64(0); uint32_t type = ARG(2); uint8_t cond = (uint8_t)ARG(3);
    for (int k = 0; k < 8; k++) if (type & (1u << k)) m |= (uint64_t)(cond & 7) << (3 * k);
    c->eax = (uint32_t)m; c->edx = (uint32_t)(m >> 32); c->esp += 16;
}
SHIM(kernel32_ExitProcess, 1) { rt_log("[k32] ExitProcess(%u)", ARG(0)); com_callsites_dump(); fflush(NULL); _exit((int)ARG(0)); }
SHIM(kernel32_CreateProcessA, 10) { LAST_ERROR = 2; return 0; }
SHIM(kernel32_MultiByteToWideChar, 6) {
    uint32_t src = ARG(2), dst = ARG(4); int32_t sl = (int32_t)ARG(3), dl = (int32_t)ARG(5);
    const char *s = gp(src); if (!s) return 0;
    size_t n = sl < 0 ? strlen(s) + 1 : (size_t)sl;
    uint16_t *tmp = malloc((n + 1) * 2 + 8);
    // CP_ACP/1252 and UTF-8: decode UTF-8 when it's valid, else Latin-1
    char *z = malloc(n + 1); memcpy(z, s, n); z[n] = 0;
    size_t k = 0;
    if (ARG(0) == 65001) { utf8_to_w(z, tmp, n + 2); k = w_len(tmp); if (sl < 0 || (n && !s[n - 1])) k++; }
    else { for (size_t i = 0; i < n; i++) tmp[k++] = (uint8_t)s[i]; }
    free(z);
    if (!dl) { free(tmp); return (uint32_t)k; }
    if ((size_t)dl < k) { free(tmp); LAST_ERROR = 122; return 0; }
    memcpy(G2H(dst), tmp, k * 2);
    free(tmp);
    return (uint32_t)k;
}
