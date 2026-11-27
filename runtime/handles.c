// Kernel objects behind Windows HANDLEs: events, mutexes, semaphores, threads (files use the same table).
// One mutex (hmu) guards object state. A waiting thread sleeps on its own condition variable and is
// registered on each object it waits for; a state change wakes only that object's waiters (a semaphore
// release wakes as many as it adds). A shared condition broadcast to every waiter made the job system's
// constant semaphore releases wake all ~20 workers each time, piling them up on hmu.
#include "rt.h"
#include "handles.h"
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <mach/mach_time.h>

static pthread_mutex_t hmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hcv = PTHREAD_COND_INITIALIZER;
#define NH 65536
static HObj *htab[NH];

uint64_t h_new(HObj *o) {
    pthread_mutex_lock(&hmu);
    o->refs = 1;
    for (int i = 1; i < NH; i++) if (!htab[i]) { htab[i] = o; o->handle = (uint64_t)i * 4; pthread_mutex_unlock(&hmu); return (uint64_t)i * 4; }
    pthread_mutex_unlock(&hmu);
    rt_log("[win32] handle table full\n"); abort();
}
HObj *h_get(uint64_t h) {
    uint64_t i = h / 4;
    if (h & 3 || i == 0 || i >= NH) return NULL;
    return htab[i];
}
HObj *h_alloc(int type) { HObj *o = calloc(1, sizeof(HObj)); o->type = type; return o; }
static void h_release(uint64_t h) {
    pthread_mutex_lock(&hmu);
    HObj *o = h_get(h);
    if (o && --o->refs == 0) {
        htab[h / 4] = NULL;
        pthread_mutex_unlock(&hmu);
        if (o->close) o->close(o);
        free(o->name);
        free(o);
        return;
    }
    pthread_mutex_unlock(&hmu);
}
void h_lock(void) { pthread_mutex_lock(&hmu); }
void h_unlock(void) { pthread_mutex_unlock(&hmu); }
void h_signal_all(void) { pthread_cond_broadcast(&hcv); }

typedef struct WNode { pthread_cond_t *cv; struct WNode *next; } WNode;
void h_wake(HObj *o) { for (WNode *n = o->waiters; n; n = n->next) pthread_cond_signal(n->cv); }
static void wake_n(HObj *o, int64_t k) { for (WNode *n = o->waiters; n && k > 0; n = n->next, k--) pthread_cond_signal(n->cv); }
static pthread_cond_t *self_cv(void) {
    static __thread pthread_cond_t *cv;
    if (!cv) { cv = malloc(sizeof *cv); pthread_cond_init(cv, NULL); }
    return cv;
}

void I_kernel32_dll_CloseHandle(CPU *c) { h_release(A0); RET(1); }
void I_kernel32_dll_DuplicateHandle(CPU *c) {
    // (srcProc, src, dstProc, *dst, access, inherit, options)
    uint64_t src = A1;
    if (src == ~1ull) src = thread_self_handle();
    // the standard handles (GetStdHandle's 'STD0'..'STD2' values) are no objects: the duplicate is the same value.
    // The UCRT's _dup (stdout redirection) duplicates them, and its failure path indexes the fd table with -1.
    if ((src >> 32) >= 0x53544430u && (src >> 32) <= 0x53544432u && !(uint32_t)src) {
        if (A3) wr64(A3, src);
        RET(1); return;
    }
    pthread_mutex_lock(&hmu);
    HObj *o = h_get(src);
    if (o) o->refs++;
    pthread_mutex_unlock(&hmu);
    if (A3) wr64(A3, o ? src : 0);
    RET(o != NULL);
}

// ---------------- waiting ----------------
static int signaled(HObj *o, uint32_t tid) {
    switch (o->type) {
    case HT_EVENT: return o->state != 0;
    case HT_SEMAPHORE: return o->count > 0;
    case HT_MUTEX: return o->owner == 0 || o->owner == tid;
    case HT_THREAD: return o->state != 0;
    case HT_TIMER: return o->state != 0;
    case HT_FILE: return 1;
    default: return 1;
    }
}
static void acquire(HObj *o, uint32_t tid) {
    if (o->type == HT_EVENT && !o->manual) o->state = 0;
    else if (o->type == HT_SEMAPHORE) o->count--;
    else if (o->type == HT_MUTEX) { o->owner = tid; o->recursion++; }
    else if (o->type == HT_TIMER && !o->manual) o->state = 0;
}
static void deadline(struct timespec *ts, uint32_t ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000; ts->tv_nsec += (long)(ms % 1000) * 1000000;
    if (ts->tv_nsec >= 1000000000) { ts->tv_sec++; ts->tv_nsec -= 1000000000; }
}
// The process main thread owns AppKit. When the game runs its loop on another thread and the main
// thread just waits for it, the wait must keep the main run loop going: window calls from the game
// thread are dispatched to it, and it pumps input events into the game thread's message queue.
extern void cocoa_pump(int wait_ms);
static int past(const struct timespec *t) {
    struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec > t->tv_sec || (now.tv_sec == t->tv_sec && now.tv_nsec >= t->tv_nsec);
}
// what each thread is blocked on (for the watchdog)
#define MAXW_T 1024
static struct { uint32_t tid; int n, all; uint32_t ms; uint64_t h[4]; } waiting[MAXW_T];
static void note_wait(uint32_t tid, int n, const uint64_t *hs, int all, uint32_t ms) {
    int i = (int)(tid / 4) % MAXW_T;
    waiting[i].tid = tid; waiting[i].n = n; waiting[i].all = all; waiting[i].ms = ms;
    for (int k = 0; k < n && k < 4; k++) waiting[i].h[k] = hs[k];
}
void h_describe_waits(uint32_t tid, char *out, size_t sz) {
    int i = (int)(tid / 4) % MAXW_T;
    out[0] = 0;
    if (waiting[i].tid != tid || !waiting[i].n) return;
    static const char *tn[] = { "?", "event", "mutex", "sem", "thread", "file", "timer", "find", "other" };
    size_t o = (size_t)snprintf(out, sz, " WAIT%s(%s", waiting[i].all ? "ALL" : "", waiting[i].ms == 0xFFFFFFFFu ? "inf" : "timed");
    for (int k = 0; k < waiting[i].n && k < 4 && o < sz; k++) {
        HObj *o_ = h_get(waiting[i].h[k]);
        o += (size_t)snprintf(out + o, sz - o, " %llx:%s/%d", (unsigned long long)waiting[i].h[k], o_ && o_->type <= 8 ? tn[o_->type] : "gone",
                              o_ ? (o_->type == HT_SEMAPHORE ? (int)o_->count : o_->type == HT_MUTEX ? (int)o_->owner : o_->state) : -1);
    }
    if (o < sz) snprintf(out + o, sz - o, ")");
}
uint32_t h_wait(int n, const uint64_t *hs, int all, uint32_t ms) {
    uint32_t tid = rt_thread_id();
    if (n > 64) n = 64;
    note_wait(tid, n, hs, all, ms);
    struct timespec ts; deadline(&ts, ms);
    int on_main = pthread_main_np();
    static uint64_t next_pump;   // main thread only
    pthread_cond_t *cv = self_cv();
    WNode nodes[64]; HObj *reg[64]; int registered = 0;
    uint32_t result = 0x102;   // WAIT_TIMEOUT
    HObj *freelist = NULL;
    pthread_mutex_lock(&hmu);
    for (;;) {
        HObj *objs[64]; int ok = 0, first = -1, bad = 0;
        for (int i = 0; i < n; i++) {
            objs[i] = h_get(hs[i] == ~1ull ? thread_self_handle() : hs[i]);
            if (!objs[i]) { bad = 1; break; }
            if (signaled(objs[i], tid)) { ok++; if (first < 0) first = i; }
        }
        if (bad) { set_last_error(6); result = 0xFFFFFFFFu; break; }
        if (all ? ok == n : ok > 0) {
            if (all) for (int i = 0; i < n; i++) acquire(objs[i], tid);
            else acquire(objs[first], tid);
            result = all ? 0 : (uint32_t)first;
            break;
        }
        if (ms == 0) break;
        if (!registered) {   // register on every object; hold a reference so CloseHandle can't free it under us
            for (int i = 0; i < n; i++) { reg[i] = objs[i]; nodes[i].cv = cv; nodes[i].next = objs[i]->waiters; objs[i]->waiters = &nodes[i]; objs[i]->refs++; }
            registered = 1;
            continue;   // re-check once registered
        }
        if (on_main) {
            // Wait in 4 ms slices and run the main run loop every 4 ms (driven by elapsed time, so frequent
            // wakeups can't starve it; AppKit calls from game threads, e.g. ShowCursor, wait on it).
            uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
            if (now >= next_pump) {
                next_pump = now + 4000000;
                pthread_mutex_unlock(&hmu); cocoa_pump(0); pthread_mutex_lock(&hmu);
                continue;
            }
            if (ms != 0xFFFFFFFFu && past(&ts)) break;
            struct timespec slice; deadline(&slice, 4);
            if (ms != 0xFFFFFFFFu && (slice.tv_sec > ts.tv_sec || (slice.tv_sec == ts.tv_sec && slice.tv_nsec > ts.tv_nsec))) slice = ts;
            pthread_cond_timedwait(cv, &hmu, &slice);
            continue;
        }
        if (ms == 0xFFFFFFFFu) pthread_cond_wait(cv, &hmu);
        else if (pthread_cond_timedwait(cv, &hmu, &ts) == ETIMEDOUT) {
            // last look: a wakeup may have raced the timeout
            int ok2 = 0, f2 = -1;
            for (int i = 0; i < n; i++) { HObj *o = h_get(hs[i] == ~1ull ? thread_self_handle() : hs[i]); if (o && signaled(o, tid)) { ok2++; if (f2 < 0) f2 = i; } }
            if (all ? ok2 == n : ok2 > 0) continue;
            break;
        }
    }
    if (registered) {
        for (int i = 0; i < n; i++) {
            HObj *o = reg[i];
            for (WNode **pp = &o->waiters; *pp; pp = &(*pp)->next) if (*pp == &nodes[i]) { *pp = nodes[i].next; break; }
            if (--o->refs == 0) {   // closed while we waited: we held the last reference
                if (o->handle && htab[o->handle / 4] == o) htab[o->handle / 4] = NULL;
                o->waiters = (WNode *)freelist; freelist = o;   // free after unlocking
            }
        }
        // a consumed wakeup meant for another waiter (semaphore/auto-reset event) must not be lost
        for (int i = 0; i < n; i++) if (reg[i]->refs > 0 && signaled(reg[i], 0) && reg[i]->waiters) h_wake(reg[i]);
    }
    pthread_mutex_unlock(&hmu);
    while (freelist) { HObj *o = freelist; freelist = (HObj *)o->waiters; if (o->close) o->close(o); free(o->name); free(o); }
    waiting[(tid / 4) % MAXW_T].n = 0;
    return result;
}
void I_kernel32_dll_WaitForSingleObject(CPU *c) { uint64_t h = A0; RET(h_wait(1, &h, 0, (uint32_t)A1)); }
void I_kernel32_dll_WaitForSingleObjectEx(CPU *c) { uint64_t h = A0; RET(h_wait(1, &h, 0, (uint32_t)A1)); }
void I_kernel32_dll_WaitForMultipleObjects(CPU *c) {
    uint32_t n = (uint32_t)A0; uint64_t hs[64];
    for (uint32_t i = 0; i < n && i < 64; i++) hs[i] = rd64(A1 + 8 * i);
    RET(h_wait((int)n, hs, (int)A2, (uint32_t)A3));
}
void I_kernel32_dll_WaitForMultipleObjectsEx(CPU *c) { I_kernel32_dll_WaitForMultipleObjects(c); }

// ---------------- events / mutexes / semaphores ----------------
static uint64_t make_event(int manual, int initial) {
    HObj *o = h_alloc(HT_EVENT); o->manual = manual; o->state = initial; return h_new(o);
}
void I_kernel32_dll_CreateEventW(CPU *c) { RET(make_event((int)A1, (int)A2)); }
void I_kernel32_dll_CreateEventA(CPU *c) { RET(make_event((int)A1, (int)A2)); }
void I_kernel32_dll_CreateEventExW(CPU *c) { uint32_t f = (uint32_t)A2; RET(make_event(f & 1, (f >> 1) & 1)); }
void I_kernel32_dll_SetEvent(CPU *c) {
    pthread_mutex_lock(&hmu); HObj *o = h_get(A0); if (o) { o->state = 1; h_wake(o); } pthread_mutex_unlock(&hmu);
    RET(o != NULL);
}
void I_kernel32_dll_ResetEvent(CPU *c) {
    pthread_mutex_lock(&hmu); HObj *o = h_get(A0); if (o) o->state = 0; pthread_mutex_unlock(&hmu); RET(o != NULL);
}
void I_kernel32_dll_PulseEvent(CPU *c) { I_kernel32_dll_SetEvent(c); }
void I_kernel32_dll_CreateMutexW(CPU *c) {
    HObj *o = h_alloc(HT_MUTEX);
    if (A1) { o->owner = rt_thread_id(); o->recursion = 1; }
    RET(h_new(o));
}
void I_kernel32_dll_CreateMutexA(CPU *c) { I_kernel32_dll_CreateMutexW(c); }
void I_kernel32_dll_ReleaseMutex(CPU *c) {
    pthread_mutex_lock(&hmu); HObj *o = h_get(A0);
    if (o && o->owner == rt_thread_id() && --o->recursion == 0) { o->owner = 0; h_wake(o); }
    pthread_mutex_unlock(&hmu); RET(o != NULL);
}
static uint64_t make_sem(int64_t initial, int64_t max) {
    HObj *o = h_alloc(HT_SEMAPHORE); o->count = initial; o->max = max; return h_new(o);
}
void I_kernel32_dll_CreateSemaphoreW(CPU *c) { RET(make_sem((int32_t)A1, (int32_t)A2)); }
void I_kernel32_dll_CreateSemaphoreA(CPU *c) { RET(make_sem((int32_t)A1, (int32_t)A2)); }
void I_kernel32_dll_CreateSemaphoreExW(CPU *c) { RET(make_sem((int32_t)A1, (int32_t)A2)); }
void I_kernel32_dll_ReleaseSemaphore(CPU *c) {
    pthread_mutex_lock(&hmu); HObj *o = h_get(A0);
    if (o) { if (A2) wr32(A2, (uint32_t)o->count); o->count += (int32_t)A1; if (o->max && o->count > o->max) o->count = o->max; wake_n(o, (int32_t)A1); }
    pthread_mutex_unlock(&hmu); RET(o != NULL);
}

// ---------------- SRW locks / condition variables / init-once (guest structs hold host pointers) ----------------
typedef struct { pthread_mutex_t m; pthread_cond_t c; int readers, writer; } SRW;
static SRW *srw_of(uint64_t p) {
    SRW *s = PTR(rd64(p));
    if (!s) {
        SRW *n = calloc(1, sizeof *n); pthread_mutex_init(&n->m, NULL); pthread_cond_init(&n->c, NULL);
        uint64_t z = 0;
        if (!__atomic_compare_exchange_n(P64(p), &z, G(n), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) free(n);
        s = PTR(rd64(p));
    }
    return s;
}
static void srw_lock(SRW *s, int excl) {
    pthread_mutex_lock(&s->m);
    if (excl) { while (s->writer || s->readers) pthread_cond_wait(&s->c, &s->m); s->writer = 1; }
    else { while (s->writer) pthread_cond_wait(&s->c, &s->m); s->readers++; }
    pthread_mutex_unlock(&s->m);
}
static int srw_try(SRW *s, int excl) {
    int ok;
    pthread_mutex_lock(&s->m);
    if (excl) { ok = !s->writer && !s->readers; if (ok) s->writer = 1; }
    else { ok = !s->writer; if (ok) s->readers++; }
    pthread_mutex_unlock(&s->m);
    return ok;
}
static void srw_unlock(SRW *s, int excl) {
    pthread_mutex_lock(&s->m);
    if (excl) s->writer = 0; else s->readers--;
    pthread_cond_broadcast(&s->c);
    pthread_mutex_unlock(&s->m);
}
void I_kernel32_dll_InitializeSRWLock(CPU *c) { wr64(A0, 0); }
void I_kernel32_dll_AcquireSRWLockExclusive(CPU *c) { srw_lock(srw_of(A0), 1); }
void I_kernel32_dll_AcquireSRWLockShared(CPU *c) { srw_lock(srw_of(A0), 0); }
void I_kernel32_dll_ReleaseSRWLockExclusive(CPU *c) { srw_unlock(srw_of(A0), 1); }
void I_kernel32_dll_ReleaseSRWLockShared(CPU *c) { srw_unlock(srw_of(A0), 0); }
void I_kernel32_dll_TryAcquireSRWLockExclusive(CPU *c) { RET(srw_try(srw_of(A0), 1)); }
void I_kernel32_dll_TryAcquireSRWLockShared(CPU *c) { RET(srw_try(srw_of(A0), 0)); }

typedef struct { pthread_mutex_t m; pthread_cond_t c; uint64_t seq; } CV;
static CV *cv_of(uint64_t p) {
    CV *s = PTR(rd64(p));
    if (!s) {
        CV *n = calloc(1, sizeof *n); pthread_mutex_init(&n->m, NULL); pthread_cond_init(&n->c, NULL);
        uint64_t z = 0;
        if (!__atomic_compare_exchange_n(P64(p), &z, G(n), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) free(n);
        s = PTR(rd64(p));
    }
    return s;
}
void I_kernel32_dll_InitializeConditionVariable(CPU *c) { wr64(A0, 0); }
void I_kernel32_dll_WakeConditionVariable(CPU *c) { CV *v = cv_of(A0); pthread_mutex_lock(&v->m); v->seq++; pthread_cond_signal(&v->c); pthread_mutex_unlock(&v->m); }
void I_kernel32_dll_WakeAllConditionVariable(CPU *c) { CV *v = cv_of(A0); pthread_mutex_lock(&v->m); v->seq++; pthread_cond_broadcast(&v->c); pthread_mutex_unlock(&v->m); }
// release the lock, wait for a wake (or timeout), reacquire; lost wakeups are impossible because
// the waiter holds the condition's mutex before it releases the caller's lock
static int cv_sleep(CV *v, uint32_t ms, void (*unlock)(void *), void (*lock)(void *), void *lk) {
    struct timespec ts; deadline(&ts, ms);
    pthread_mutex_lock(&v->m);
    uint64_t s0 = v->seq;
    unlock(lk);
    int timed_out = 0;
    while (v->seq == s0 && !timed_out) {
        if (ms == 0xFFFFFFFFu) pthread_cond_wait(&v->c, &v->m);
        else if (pthread_cond_timedwait(&v->c, &v->m, &ts) == ETIMEDOUT) timed_out = 1;
    }
    pthread_mutex_unlock(&v->m);
    lock(lk);
    if (timed_out) { set_last_error(1460); return 0; }   // ERROR_TIMEOUT
    return 1;
}
static void srw_unlock_x(void *s) { srw_unlock(s, 1); }
static void srw_lock_x(void *s) { srw_lock(s, 1); }
static void srw_unlock_s(void *s) { srw_unlock(s, 0); }
static void srw_lock_s(void *s) { srw_lock(s, 0); }
void I_kernel32_dll_SleepConditionVariableSRW(CPU *c) {
    int shared = (uint32_t)A3 & 1;   // CONDITION_VARIABLE_LOCKMODE_SHARED
    SRW *s = srw_of(A1);
    RET(cv_sleep(cv_of(A0), (uint32_t)A2, shared ? srw_unlock_s : srw_unlock_x, shared ? srw_lock_s : srw_lock_x, s));
}
void rt_cs_enter(CPU *c, uint64_t cs);
void rt_cs_leave(CPU *c, uint64_t cs);
typedef struct { CPU *c; uint64_t cs; } CSRef;
static void cs_unlock(void *p) { CSRef *r = p; rt_cs_leave(r->c, r->cs); }
static void cs_lock(void *p) { CSRef *r = p; rt_cs_enter(r->c, r->cs); }
void I_kernel32_dll_SleepConditionVariableCS(CPU *c) {
    CSRef r = { c, A1 };
    RET(cv_sleep(cv_of(A0), (uint32_t)A2, cs_unlock, cs_lock, &r));
}

// InitOnceExecuteOnce(once, fn(once, param, ctx), param, ctx). Each INIT_ONCE is its own: 0 not run, 1 running,
// 2 done. The thread that moves it from 0 to 1 runs fn; others calling for the same object wait until it is done
// (or back to 0 when fn failed, and then try themselves). Nothing is held while fn runs, so a callback may run
// other one-time inits or wait for threads that do.
static pthread_mutex_t once_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t once_cv = PTHREAD_COND_INITIALIZER;
void I_kernel32_dll_InitOnceExecuteOnce(CPU *c) {
    uint64_t once = A0, fn = A1, param = A2, ctx = A3;
    uint64_t *w = PTR(once);
    for (;;) {
        uint64_t v = __atomic_load_n(w, __ATOMIC_ACQUIRE);
        if (v == 2) { RET(1); return; }
        if (v == 0) {
            uint64_t z = 0;
            if (__atomic_compare_exchange_n(w, &z, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) break;
            continue;
        }
        pthread_mutex_lock(&once_mu);
        while (__atomic_load_n(w, __ATOMIC_ACQUIRE) == 1) pthread_cond_wait(&once_cv, &once_mu);
        pthread_mutex_unlock(&once_mu);
    }
    uint64_t a[3] = { once, param, ctx };
    int r = (int)(guest_call(c, fn, 3, a) & 0xFFFFFFFF) != 0;
    pthread_mutex_lock(&once_mu);
    __atomic_store_n(w, r ? 2 : 0, __ATOMIC_RELEASE);
    pthread_cond_broadcast(&once_cv);
    pthread_mutex_unlock(&once_mu);
    RET(r);
}
void I_kernel32_dll_InitOnceInitialize(CPU *c) { wr64(A0, 0); }

// Fiber-local storage: no per-fiber data needed by the CRT; map onto TLS slots
extern void I_kernel32_dll_TlsAlloc(CPU *), I_kernel32_dll_TlsFree(CPU *), I_kernel32_dll_TlsGetValue(CPU *), I_kernel32_dll_TlsSetValue(CPU *);
void I_kernel32_dll_FlsAlloc(CPU *c) { I_kernel32_dll_TlsAlloc(c); }
void I_kernel32_dll_FlsFree(CPU *c) { I_kernel32_dll_TlsFree(c); }
void I_kernel32_dll_FlsGetValue(CPU *c) { I_kernel32_dll_TlsGetValue(c); }
void I_kernel32_dll_FlsSetValue(CPU *c) { I_kernel32_dll_TlsSetValue(c); }
void I_kernel32_dll_FlushProcessWriteBuffers(CPU *c) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
void I_kernel32_dll_GetCurrentProcessorNumber(CPU *c) { RET(0); }

// ---------------- threads ----------------
typedef struct { CPU *cpu; uint64_t start, param; HObj *obj; uint64_t handle; } ThreadStart;
static void *thread_main(void *p) {
    ThreadStart *ts = p;
    rt_thread_signals();
    rt_set_cur(ts->cpu);
    h_lock(); while (ts->obj->suspended) pthread_cond_wait(&hcv, &hmu); h_unlock();
    uint64_t a[1] = { ts->param };
    uint64_t r = guest_call(ts->cpu, ts->start, 1, a);
    h_lock(); ts->obj->state = 1; ts->obj->exit_code = (uint32_t)r; h_wake(ts->obj); h_unlock();
    return NULL;
}
static __thread uint64_t self_handle;
uint64_t thread_self_handle(void) {
    if (!self_handle) { HObj *o = h_alloc(HT_THREAD); o->tid = rt_thread_id(); self_handle = h_new(o); }
    return self_handle;
}
// CreateThread(sec, stack, start, param, flags, *tid)
void I_kernel32_dll_CreateThread(CPU *c) {
    uint64_t stack = A1 ? A1 : (1u << 20), start = A2, param = A3; uint32_t flags = (uint32_t)AN(4); uint64_t ptid = AN(5);
    if (stack < (1u << 20)) stack = 1u << 20;
    ThreadStart *ts = calloc(1, sizeof *ts);
    ts->cpu = cpu_new(stack);
    ts->start = start; ts->param = param;
    ts->obj = h_alloc(HT_THREAD);
    ts->obj->suspended = (flags & 4) != 0;   // CREATE_SUSPENDED
    ts->obj->tid = rd32(ts->cpu->gsbase + 0x48);
    ts->obj->refs = 0;
    uint64_t h = h_new(ts->obj);
    ts->obj->refs = 2;   // the caller's handle + the running thread
    if (ptid) wr32(ptid, ts->obj->tid);
    pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setstacksize(&at, 8u << 20);   // host stack for nested C frames
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    if (pthread_create(&t, &at, thread_main, ts)) { RET(0); return; }
    ts->obj->pt = t;
    RET(h);
}
void I_kernel32_dll_OpenThread(CPU *c) {
    uint32_t tid = (uint32_t)A2; uint64_t h = 0;
    h_lock();
    for (uint64_t i = 1; i < 65536 && !h; i++) { HObj *o = h_get(i * 4); if (o && o->type == HT_THREAD && o->tid == tid) { o->refs++; h = i * 4; } }
    h_unlock();
    if (!h && tid == rt_thread_id()) h = thread_self_handle();
    if (!h) set_last_error(87);
    RET(h);
}
void I_kernel32_dll_ResumeThread(CPU *c) {
    h_lock(); HObj *o = h_get(A0); uint32_t prev = o ? o->suspended : 0; if (o) o->suspended = 0; h_signal_all(); h_unlock();
    RET(prev);
}
void I_kernel32_dll_SuspendThread(CPU *c) { RET(0); }
void I_kernel32_dll_GetExitCodeThread(CPU *c) {
    h_lock(); HObj *o = h_get(A0); if (A1) wr32(A1, o && o->state ? o->exit_code : 259); h_unlock(); RET(o != NULL);
}
void I_kernel32_dll_GetThreadId(CPU *c) { HObj *o = h_get(A0 == ~1ull ? thread_self_handle() : A0); RET(o ? o->tid : 0); }
void I_kernel32_dll_SetThreadPriority(CPU *c) { RET(1); }
void I_kernel32_dll_GetThreadPriority(CPU *c) { RET(0); }
void I_kernel32_dll_SetThreadAffinityMask(CPU *c) { RET(rt_cpu_mask()); }
void I_kernel32_dll_SetThreadIdealProcessor(CPU *c) { RET(0); }
void I_kernel32_dll_SetThreadDescription(CPU *c) { RET(0); }
void I_kernel32_dll_SetThreadPriorityBoost(CPU *c) { RET(1); }
void I_kernel32_dll_SetPriorityClass(CPU *c) { RET(1); }
void I_kernel32_dll_GetPriorityClass(CPU *c) { RET(0x20); }
void I_kernel32_dll_GetProcessAffinityMask(CPU *c) { if (A1) wr64(A1, rt_cpu_mask()); if (A2) wr64(A2, rt_cpu_mask()); RET(1); }
void I_kernel32_dll_ExitThread(CPU *c) {
    rt_log("[win32] ExitThread(%u)\n", (unsigned)A0);
    pthread_exit(NULL);
}

// ---------------- waitable timers (libdispatch timer sources) ----------------
#include <dispatch/dispatch.h>
static void timer_close(HObj *o) {
    if (o->data) { dispatch_source_cancel(o->data); dispatch_release(o->data); o->data = NULL; }
}
static void timer_fire(void *p) {
    HObj *o = p;
    pthread_mutex_lock(&hmu); o->state = 1; h_wake(o); pthread_mutex_unlock(&hmu);
}
// CreateWaitableTimer[Ex](sec, manualReset, name) — the Ex form takes (sec, name, flags, access)
void I_kernel32_dll_CreateWaitableTimerA(CPU *c) { HObj *o = h_alloc(HT_TIMER); o->manual = (int)A1 != 0; o->close = timer_close; RET(h_new(o)); }
void I_kernel32_dll_CreateWaitableTimerW(CPU *c) { I_kernel32_dll_CreateWaitableTimerA(c); }
void I_kernel32_dll_CreateWaitableTimerExW(CPU *c) { HObj *o = h_alloc(HT_TIMER); o->manual = (uint32_t)A2 & 1; o->close = timer_close; RET(h_new(o)); }
// SetWaitableTimer(h, *dueTime, periodMs, completionRoutine, arg, resume): dueTime < 0 is relative (100 ns
// units), >= 0 an absolute FILETIME. Completion routines (APCs) are not supported.
void I_kernel32_dll_SetWaitableTimer(CPU *c) {
    HObj *o = h_get(A0);
    if (!o || o->type != HT_TIMER) { set_last_error(6); RET(0); return; }
    if (A3) rt_log("[win32] SetWaitableTimer: completion routine ignored\n");
    int64_t due = (int64_t)rd64(A1); uint32_t period = (uint32_t)A2;
    int64_t ns;
    if (due < 0) ns = -due * 100;
    else {
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        int64_t now = ((int64_t)ts.tv_sec + 11644473600ll) * 10000000ll + ts.tv_nsec / 100;
        ns = due > now ? (due - now) * 100 : 0;
    }
    pthread_mutex_lock(&hmu);
    timer_close(o);
    o->state = 0;
    dispatch_source_t s = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, DISPATCH_TIMER_STRICT,
                                                 dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0));
    dispatch_set_context(s, o);
    dispatch_source_set_event_handler_f(s, timer_fire);
    dispatch_source_set_timer(s, dispatch_time(DISPATCH_TIME_NOW, ns), period ? (uint64_t)period * 1000000ull : DISPATCH_TIME_FOREVER, 0);
    o->data = s;
    pthread_mutex_unlock(&hmu);
    dispatch_resume(s);
    RET(1);
}
void I_kernel32_dll_SetWaitableTimerEx(CPU *c) { I_kernel32_dll_SetWaitableTimer(c); }
void I_kernel32_dll_CancelWaitableTimer(CPU *c) {
    HObj *o = h_get(A0);
    if (!o || o->type != HT_TIMER) { set_last_error(6); RET(0); return; }
    pthread_mutex_lock(&hmu); timer_close(o); pthread_mutex_unlock(&hmu);
    RET(1);
}
