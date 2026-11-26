#include <stdatomic.h>
// kernel32: process/startup, memory, strings, time, synchronization basics.
#include "rt.h"
#include "game.h"
#include <pthread.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <mach/mach_time.h>
#include <malloc/malloc.h>
#include <sched.h>
#include <errno.h>

extern uint64_t g_process_heap;
static uint16_t *g_cmdline_w;
static char *g_cmdline_a;

// ---------------- UTF-16 helpers ----------------
size_t w16len(const uint16_t *s) { size_t n = 0; if (s) while (s[n]) n++; return n; }
char *w16_to_utf8(const uint16_t *s) {
    size_t n = w16len(s);
    char *o = malloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++) {
        uint32_t u = s[i];
        if (u >= 0xD800 && u < 0xDC00 && i + 1 < n) { u = 0x10000 + ((u - 0xD800) << 10) + (s[i + 1] - 0xDC00); i++; }
        if (u < 0x80) *p++ = (char)u;
        else if (u < 0x800) { *p++ = (char)(0xC0 | u >> 6); *p++ = (char)(0x80 | (u & 63)); }
        else if (u < 0x10000) { *p++ = (char)(0xE0 | u >> 12); *p++ = (char)(0x80 | (u >> 6 & 63)); *p++ = (char)(0x80 | (u & 63)); }
        else { *p++ = (char)(0xF0 | u >> 18); *p++ = (char)(0x80 | (u >> 12 & 63)); *p++ = (char)(0x80 | (u >> 6 & 63)); *p++ = (char)(0x80 | (u & 63)); }
    }
    *p = 0;
    return o;
}
uint16_t *utf8_to_w16(const char *s) {
    size_t n = strlen(s);
    uint16_t *o = malloc((n + 1) * 2), *p = o;
    const unsigned char *q = (const unsigned char *)s;
    while (*q) {
        uint32_t u;
        if (*q < 0x80) u = *q++;
        else if ((*q & 0xE0) == 0xC0) { u = (*q & 31) << 6 | (q[1] & 63); q += 2; }
        else if ((*q & 0xF0) == 0xE0) { u = (*q & 15) << 12 | (q[1] & 63) << 6 | (q[2] & 63); q += 3; }
        else { u = (*q & 7) << 18 | (q[1] & 63) << 12 | (q[2] & 63) << 6 | (q[3] & 63); q += 4; }
        if (u >= 0x10000) { u -= 0x10000; *p++ = (uint16_t)(0xD800 + (u >> 10)); *p++ = (uint16_t)(0xDC00 + (u & 1023)); }
        else *p++ = (uint16_t)u;
    }
    *p = 0;
    return o;
}

// ---------------- startup ----------------
void win32_init(int argc, char **argv) {
    char buf[4096]; snprintf(buf, sizeof buf, "%s", rt_game.exe);
    for (int i = 1; i < argc; i++) { strlcat(buf, " ", sizeof buf); strlcat(buf, argv[i], sizeof buf); }
    g_cmdline_a = strdup(buf);
    g_cmdline_w = utf8_to_w16(buf);
    g_process_heap = 0x4845415000000001ull;   // pseudo handle; HeapAlloc ignores it
}
void I_kernel32_dll_GetCommandLineA(CPU *c) { RET(G(g_cmdline_a)); }
void I_kernel32_dll_GetCommandLineW(CPU *c) { RET(G(g_cmdline_w)); }
void I_kernel32_dll_GetStartupInfoW(CPU *c) { memset(PTR(A0), 0, 104); wr32(A0, 104); }
void I_kernel32_dll_IsDebuggerPresent(CPU *c) { RET(0); }
void I_kernel32_dll_IsProcessorFeaturePresent(CPU *c) {
    uint32_t f = (uint32_t)A0;   // PF_XMMI64 (10), PF_SSE3 (13), PF_FASTFAIL (23)...
    RET(f == 6 || f == 10 || f == 13 || f == 3 || f == 8 || f == 12);
}
void I_kernel32_dll_SetUnhandledExceptionFilter(CPU *c) { RET(0); }
void I_kernel32_dll_UnhandledExceptionFilter(CPU *c) { RET(0); }
void I_kernel32_dll_ExitProcess(CPU *c) { rt_log("[win32] ExitProcess(%u)\n", (unsigned)A0); exit((int)A0); }
void I_kernel32_dll_TerminateProcess(CPU *c) {
    rt_log("[win32] TerminateProcess(0x%x) on thread %u\n", (unsigned)A1, rt_thread_id());
    if ((uint32_t)A1 >= 0xC0000000u) rt_backtrace(c);   // NTSTATUS error: e.g. 0xC0000409 = /GS cookie or __fastfail
    exit((int)A1);
}
void I_kernel32_dll_GetVersionExA(CPU *c) { wr32(A0 + 4, 10); wr32(A0 + 8, 0); wr32(A0 + 12, 19045); wr32(A0 + 16, 2); RET(1); }
void I_kernel32_dll_GetVersionExW(CPU *c) { wr32(A0 + 4, 10); wr32(A0 + 8, 0); wr32(A0 + 12, 19045); wr32(A0 + 16, 2); RET(1); }

// ---------------- time ----------------
static uint64_t filetime_now(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec + 11644473600ull) * 10000000ull + (uint64_t)ts.tv_nsec / 100;
}
void I_kernel32_dll_GetSystemTimeAsFileTime(CPU *c) { wr64(A0, filetime_now()); }
void I_kernel32_dll_GetSystemTimePreciseAsFileTime(CPU *c) { wr64(A0, filetime_now()); }
void I_kernel32_dll_QueryPerformanceFrequency(CPU *c) { wr64(A0, 1000000000ull); RET(1); }
void I_kernel32_dll_QueryPerformanceCounter(CPU *c) { wr64(A0, clock_gettime_nsec_np(CLOCK_UPTIME_RAW)); RET(1); }
void I_kernel32_dll_GetTickCount(CPU *c) { RET((uint32_t)(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000)); }
void I_kernel32_dll_GetTickCount64(CPU *c) { RET(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000); }
static void long_sleep_note(CPU *c, uint32_t ms) {
    if (ms <= 1000) return;
    rt_log("[win32] Sleep(%u ms) on thread %u\n", ms, rt_thread_id());
    rt_backtrace(c);
}
// usleep takes at most ~4295 s per call and the multiplication overflows past 4294 ms: sleep in nanoseconds
static void sleep_ms(uint32_t ms) {
    if (ms == 0xFFFFFFFFu) { for (;;) pause(); }   // INFINITE
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };
    while (nanosleep(&ts, &ts) && errno == EINTR) {}
}
void I_kernel32_dll_Sleep(CPU *c) { uint32_t ms = (uint32_t)A0; long_sleep_note(c, ms); if (ms) sleep_ms(ms); else sched_yield(); }
void I_kernel32_dll_SleepEx(CPU *c) { uint32_t ms = (uint32_t)A0; long_sleep_note(c, ms); if (ms) sleep_ms(ms); else sched_yield(); RET(0); }
// The engine waits for frame/job completion in `while (flag) SwitchToThread();` loops. Yielding in a tight
// loop keeps a core busy (and on Apple Silicon competes with the job workers for performance cores), so once a
// thread has yielded many times in a row within microseconds it naps briefly instead: at most ~20 us of extra
// wake-up latency, and the core is free meanwhile. RT_SPIN_YIELD=1 restores plain yielding.
void I_kernel32_dll_SwitchToThread(CPU *c) {
    static int plain = -1; if (plain < 0) plain = getenv("RT_SPIN_YIELD") != NULL;
    static __thread uint64_t last_ns; static __thread uint32_t run;
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    run = now - last_ns < 50000 ? run + 1 : 0;   // consecutive calls less than 50 us apart: a wait loop
    last_ns = now;
    static int stats = -1; if (stats < 0) stats = getenv("RT_YIELD_STATS") != NULL;
    if (stats) {
        static _Atomic uint64_t calls, naps; calls++; if (run > 64) naps++;
        if (calls % 200000 == 0) rt_log("[yield] %llu calls, %llu naps\n", (unsigned long long)calls, (unsigned long long)naps);
    }
    if (!plain && run > 64) { struct timespec ts = { 0, 20000 }; nanosleep(&ts, NULL); }
    else sched_yield();
    RET(1);
}

// ---------------- heap: process heap maps to malloc (guest pointers are host pointers) ----------------
// Each block carries a 16-byte header with the size the program asked for: HeapSize (and the CRT's _msize)
// must return exactly that, not malloc's rounded-up size, or code that derives an element count from it
// walks into uninitialized memory. The header keeps the block 16-byte aligned, as Windows heaps are.
#define HEAP_ZERO_MEMORY 0x08
#define HEAP_REALLOC_IN_PLACE_ONLY 0x10
#define HDR 16
#define HMAGIC 0x48454150424c4b31ull   // "HEAPBLK1"
static void *hblock(void *raw, size_t n) { uint64_t *h = raw; h[0] = n; h[1] = HMAGIC; return (char *)raw + HDR; }
static uint64_t *hhdr(void *p) { uint64_t *h = (uint64_t *)((char *)p - HDR); return h[1] == HMAGIC ? h : NULL; }
void *rt_heap_alloc(size_t n, int zero) {
    void *raw = zero ? calloc(1, n + HDR) : malloc(n + HDR);
    return raw ? hblock(raw, n) : NULL;
}
void rt_heap_free(void *p) {
    if (!p) return;
    uint64_t *h = hhdr(p);
    if (h) { h[1] = 0; free(h); } else free(p);   // a block not made here (runtime-allocated buffers)
}
size_t rt_heap_size(void *p) { uint64_t *h = hhdr(p); return h ? h[0] : malloc_size(p); }
void *rt_heap_realloc(void *old, size_t n, int zero) {
    if (!old) return rt_heap_alloc(n, zero);
    uint64_t *h = hhdr(old);
    if (!h) return realloc(old, n ? n : 1);
    size_t on = h[0], cap = malloc_size(h) - HDR;
    if (n <= cap) { if (zero && n > on) memset((char *)old + on, 0, n - on); h[0] = n; return old; }
    void *raw = realloc(h, n + HDR);
    if (!raw) return NULL;
    if (zero && n > on) memset((char *)raw + HDR + on, 0, n - on);
    return hblock(raw, n);
}
void I_kernel32_dll_GetProcessHeap(CPU *c) { RET(g_process_heap); }
void I_kernel32_dll_HeapCreate(CPU *c) { RET(g_process_heap); }
void I_kernel32_dll_HeapDestroy(CPU *c) { RET(1); }
void I_kernel32_dll_HeapAlloc(CPU *c) { RET(G(rt_heap_alloc(A2, (A1 & HEAP_ZERO_MEMORY) != 0))); }
void I_kernel32_dll_HeapReAlloc(CPU *c) {
    void *old = PTR(A2); size_t n = A3; uint32_t fl = (uint32_t)A1;
    if (!old) { RET(G(rt_heap_alloc(n, (fl & HEAP_ZERO_MEMORY) != 0))); return; }
    uint64_t *h = hhdr(old);
    if (!h) { RET(G(realloc(old, n ? n : 1))); return; }
    size_t on = h[0], cap = malloc_size(h) - HDR;
    if (n <= cap) {   // fits in the block: in place, as Windows would
        if ((fl & HEAP_ZERO_MEMORY) && n > on) memset((char *)old + on, 0, n - on);
        h[0] = n; RET(G(old)); return;
    }
    if (fl & HEAP_REALLOC_IN_PLACE_ONLY) { set_last_error(8); RET(0); return; }   // must not move: fail
    void *raw = realloc(h, n + HDR);
    if (!raw) { RET(0); return; }
    if ((fl & HEAP_ZERO_MEMORY) && n > on) memset((char *)raw + HDR + on, 0, n - on);
    RET(G(hblock(raw, n)));
}
void I_kernel32_dll_HeapFree(CPU *c) { rt_heap_free(PTR(A2)); RET(1); }
void I_kernel32_dll_HeapSize(CPU *c) {
    if (!A2) { RET(~0ull); return; }
    uint64_t *h = hhdr(PTR(A2));
    RET(h ? h[0] : malloc_size(PTR(A2)));
}
void I_kernel32_dll_HeapValidate(CPU *c) { RET(1); }
void I_kernel32_dll_HeapSetInformation(CPU *c) { RET(1); }
void I_kernel32_dll_LocalFree(CPU *c) { rt_heap_free(PTR(A0)); RET(0); }
void I_kernel32_dll_GlobalFree(CPU *c) { rt_heap_free(PTR(A0)); RET(0); }
void I_kernel32_dll_LocalAlloc(CPU *c) { RET(G(rt_heap_alloc(A1, (A0 & 0x40) != 0))); }
void I_kernel32_dll_GlobalAlloc(CPU *c) { RET(G(rt_heap_alloc(A1, (A0 & 0x40) != 0))); }

// ---------------- virtual memory ----------------
// Reservations are tracked so release frees all of one and VirtualQuery can describe it. Memory is always
// readable/writable once reserved (committing is free); decommitting maps fresh zero pages over the range,
// because Windows hands out zeroed pages when they are committed again and allocators rely on that.
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
typedef struct { uint64_t base, size; } Region;
static Region regions[65536]; static int nregions;
static pthread_mutex_t vmu = PTHREAD_MUTEX_INITIALIZER;
static Region *region_of(uint64_t a) {
    for (int i = 0; i < nregions; i++) if (a >= regions[i].base && a < regions[i].base + regions[i].size) return &regions[i];
    return NULL;
}
void I_kernel32_dll_VirtualAlloc(CPU *c) {
    uint64_t addr = A0, size = (A1 + 0xFFF) & ~0xFFFull; uint32_t type = (uint32_t)A2;
    if (addr && !(type & MEM_RESERVE)) {   // commit inside an earlier reservation: already readable/writable
        RET(addr & ~0xFFFull); return;
    }
    if (addr) addr &= ~0xFFFFull;          // reservations start on the 64 KB allocation granularity
    void *p;
    if (addr) p = mmap(PTR(addr), size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    else {   // Windows reservations are 64 KB aligned, and allocators rely on it (UE4's FMallocBinned2 finds a
             // block's header by masking its address to 64 KB); mmap only aligns to the 16 KB page, so over-map and trim
        size_t over = size + 0x10000, pg = (size_t)getpagesize();
        char *raw = mmap(NULL, over, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (raw == MAP_FAILED) p = MAP_FAILED;
        else {
            uint64_t lo = G(raw), al = (lo + 0xFFFF) & ~0xFFFFull, end = lo + over, aend = (al + size + pg - 1) & ~(uint64_t)(pg - 1);
            if (al > lo) munmap(raw, al - lo);
            if (end > aend) munmap(PTR(aend), end - aend);
            p = PTR(al);
        }
    }
    if (p == MAP_FAILED || (addr && G(p) != addr)) {   // a fixed address that is not free fails, as on Windows
        if (p != MAP_FAILED) munmap(p, size);
        set_last_error(487); RET(0); return;            // ERROR_INVALID_ADDRESS
    }
    pthread_mutex_lock(&vmu);
    if (nregions < 65536) regions[nregions++] = (Region){ G(p), size };
    pthread_mutex_unlock(&vmu);
    RET(G(p));
}
void I_kernel32_dll_VirtualFree(CPU *c) {
    uint64_t a = A0; uint32_t type = (uint32_t)A2;
    pthread_mutex_lock(&vmu);
    Region *r = region_of(a);
    if (type & MEM_RELEASE) {
        if (r && r->base == a) { munmap(PTR(r->base), r->size); *r = regions[--nregions]; }
        pthread_mutex_unlock(&vmu);
        RET(1); return;
    }
    pthread_mutex_unlock(&vmu);
    // MEM_DECOMMIT: fresh zero pages (and the old ones go back to the system)
    uint64_t lo = a & ~0xFFFull, hi = (a + A1 + 0xFFF) & ~0xFFFull;
    if (!A1 && r) hi = r->base + r->size;   // size 0: the whole region from that address
    if (hi > lo) mmap(PTR(lo), hi - lo, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    RET(1);
}
void I_kernel32_dll_VirtualProtect(CPU *c) { if (A3) wr32(A3, 0x04); RET(1); }
// VirtualQuery(addr, MEMORY_BASIC_INFORMATION*, size): BaseAddress +0, AllocationBase +8, AllocationProtect +16,
// RegionSize +24, State +32, Protect +36, Type +40. Inside a tracked reservation: the rest of it, committed.
void I_kernel32_dll_VirtualQuery(CPU *c) {
    uint64_t b = A1, page = A0 & ~0xFFFull; memset(PTR(b), 0, 48);
    pthread_mutex_lock(&vmu);
    Region *r = region_of(A0);
    uint64_t base = r ? r->base : page, size = r ? r->base + r->size - page : 0x1000;
    pthread_mutex_unlock(&vmu);
    wr64(b, page); wr64(b + 8, base); wr32(b + 16, 4);
    wr64(b + 24, size); wr32(b + 32, MEM_COMMIT); wr32(b + 36, 4); wr32(b + 40, r ? 0x20000 : 0x1000000);   // MEM_PRIVATE / MEM_IMAGE
    RET(48);
}
void I_kernel32_dll_GetSystemInfo(CPU *c) {
    uint64_t b = A0; memset(PTR(b), 0, 48);
    wr16(b, 9);                     // PROCESSOR_ARCHITECTURE_AMD64
    wr32(b + 4, 0x1000);            // page size
    wr64(b + 8, 0x10000); wr64(b + 16, 0x7FFFFFFEFFFFull);
    wr64(b + 24, rt_cpu_mask());    // active processor mask
    wr32(b + 32, rt_ncpu());        // number of processors
    wr32(b + 36, 8664); wr32(b + 40, 0x10000); wr16(b + 44, 6); wr16(b + 46, 0x3A09);
}

// ---------------- CPU topology (host cores; logical CPUs = cores, no SMT) ----------------
#include <sys/sysctl.h>
static uint32_t sysctl_u32(const char *name, uint32_t dflt) {
    uint64_t v = 0; size_t n = sizeof v;
    if (sysctlbyname(name, &v, &n, NULL, 0) || !n) return dflt;
    return n == 4 ? (uint32_t)*(uint32_t *)&v : (uint32_t)v;
}
uint32_t rt_ncpu(void) {
    static uint32_t n;
    if (!n) { uint32_t k = sysctl_u32("hw.logicalcpu", 8); const char *e = getenv("RT_NCPU"); if (e && atoi(e) > 0) k = (uint32_t)atoi(e); n = k ? (k > 64 ? 64 : k) : 8; }   // RT_NCPU: override (debugging)
    return n;
}
uint64_t rt_cpu_mask(void) { uint32_t n = rt_ncpu(); return n >= 64 ? ~0ull : (1ull << n) - 1; }
void I_kernel32_dll_GetActiveProcessorCount(CPU *c) { RET(rt_ncpu()); }
void I_kernel32_dll_GetMaximumProcessorCount(CPU *c) { RET(rt_ncpu()); }

// GetLogicalProcessorInformation(SYSTEM_LOGICAL_PROCESSOR_INFORMATION*, *bytes). Each 32-byte entry:
// ProcessorMask +0, Relationship +8 (core 0, NUMA node 1, cache 2, package 3), union +16
// (core: Flags; cache: Level, Associativity, LineSize, Size, Type). Performance levels become core clusters,
// each with its own shared L2; cores get private L1 data and instruction caches.
void I_kernel32_dll_GetLogicalProcessorInformation(CPU *c) {
    uint64_t buf = A0, plen = A1;
    uint32_t n = rt_ncpu(), line = sysctl_u32("hw.cachelinesize", 64), nlev = sysctl_u32("hw.nperflevels", 1);
    if (nlev < 1) nlev = 1;
    if (nlev > 4) nlev = 4;
    struct { uint64_t mask; uint32_t rel; uint8_t level, assoc; uint16_t line; uint32_t size, type; } e[64 * 3 + 16];
    int k = 0; uint32_t cpu = 0;
    for (uint32_t lv = 0; lv < nlev && cpu < n; lv++) {
        char key[64];
        #define LV(field, dflt) (snprintf(key, sizeof key, nlev > 1 ? "hw.perflevel%u." field : "hw." field, lv), sysctl_u32(key, dflt))
        uint32_t cores = nlev > 1 ? LV("physicalcpu", n) : n, l1d = LV("l1dcachesize", 65536), l1i = LV("l1icachesize", 131072);
        uint32_t l2 = LV("l2cachesize", 4u << 20), per_l2 = nlev > 1 ? LV("cpusperl2", cores) : cores;
        #undef LV
        if (cpu + cores > n) cores = n - cpu;
        if (!per_l2) per_l2 = cores;
        for (uint32_t i = 0; i < cores; i++) {
            uint64_t m = 1ull << (cpu + i);
            e[k++] = (typeof(e[0])){ m, 0, 0, 0, 0, 0, 0 };                // core (Flags 0: no SMT)
            e[k++] = (typeof(e[0])){ m, 2, 1, 8, (uint16_t)line, l1d, 2 };  // L1 data
            e[k++] = (typeof(e[0])){ m, 2, 1, 8, (uint16_t)line, l1i, 1 };  // L1 instruction
        }
        for (uint32_t i = 0; i < cores; i += per_l2) {
            uint32_t span = cores - i < per_l2 ? cores - i : per_l2;
            uint64_t m = (span >= 64 ? ~0ull : (1ull << span) - 1) << (cpu + i);
            e[k++] = (typeof(e[0])){ m, 2, 2, 16, (uint16_t)line, l2, 0 }; // shared L2 (unified)
        }
        cpu += cores;
    }
    e[k++] = (typeof(e[0])){ rt_cpu_mask(), 3, 0, 0, 0, 0, 0 };            // package
    e[k++] = (typeof(e[0])){ rt_cpu_mask(), 1, 0, 0, 0, 0, 0 };            // NUMA node 0
    uint32_t need = (uint32_t)k * 32;
    if (!buf || rd32(plen) < need) { wr32(plen, need); set_last_error(122); RET(0); return; }   // ERROR_INSUFFICIENT_BUFFER
    memset(PTR(buf), 0, need);
    for (int i = 0; i < k; i++) {
        uint64_t p = buf + 32ull * i;
        wr64(p, e[i].mask); wr32(p + 8, e[i].rel);
        if (e[i].rel == 2) { wr8(p + 16, e[i].level); wr8(p + 17, e[i].assoc); wr16(p + 18, e[i].line); wr32(p + 20, e[i].size); wr32(p + 24, e[i].type); }
    }
    wr32(plen, need);
    RET(1);
}

// ---------------- critical sections ----------------
// The lock lives in the guest's 40-byte CRITICAL_SECTION itself, like on Windows (no host allocation,
// no pointer chase): +8 LockCount = futex word (0 free, 1 held, 2 held with waiters),
// +12 RecursionCount, +16 OwningThread = guest thread id (so it follows the thread, not the fiber).
// Uncontended enter/leave is one CAS; contended waits park in the kernel (os_sync_wait_on_address).
#include <os/os_sync_wait_on_address.h>
static inline uint32_t cs_self(CPU *c) { return rd32(c->gsbase + 0x48); }
static void cs_wait(_Atomic uint32_t *w) {
    uint32_t v = 0;
    for (int i = 0; i < 64; i++) {   // brief spin: most guest critical sections are short
        v = atomic_load_explicit(w, memory_order_relaxed);
        if (v == 0 && atomic_compare_exchange_weak_explicit(w, &v, 1, memory_order_acquire, memory_order_relaxed)) return;
        __builtin_arm_yield();
    }
    v = atomic_exchange_explicit(w, 2, memory_order_acquire);
    while (v != 0) {
        os_sync_wait_on_address(w, 2, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE);
        v = atomic_exchange_explicit(w, 2, memory_order_acquire);
    }
}
void rt_cs_enter(CPU *c, uint64_t cs) {
    uint32_t me = cs_self(c);
    _Atomic uint32_t *w = (_Atomic uint32_t *)P32(cs + 8);
    if (atomic_load_explicit((_Atomic uint64_t *)P64(cs + 16), memory_order_relaxed) == me) { (*P32(cs + 12))++; return; }
    uint32_t z = 0;
    if (!atomic_compare_exchange_strong_explicit(w, &z, 1, memory_order_acquire, memory_order_relaxed)) cs_wait(w);
    atomic_store_explicit((_Atomic uint64_t *)P64(cs + 16), me, memory_order_relaxed);
    *P32(cs + 12) = 1;
}
int rt_cs_try(CPU *c, uint64_t cs) {
    uint32_t me = cs_self(c);
    if (atomic_load_explicit((_Atomic uint64_t *)P64(cs + 16), memory_order_relaxed) == me) { (*P32(cs + 12))++; return 1; }
    uint32_t z = 0;
    if (!atomic_compare_exchange_strong_explicit((_Atomic uint32_t *)P32(cs + 8), &z, 1, memory_order_acquire, memory_order_relaxed)) return 0;
    atomic_store_explicit((_Atomic uint64_t *)P64(cs + 16), me, memory_order_relaxed);
    *P32(cs + 12) = 1;
    return 1;
}
void rt_cs_leave(CPU *c, uint64_t cs) {
    (void)c;
    if (--(*P32(cs + 12))) return;
    atomic_store_explicit((_Atomic uint64_t *)P64(cs + 16), 0, memory_order_relaxed);
    if (atomic_exchange_explicit((_Atomic uint32_t *)P32(cs + 8), 0, memory_order_release) == 2)
        os_sync_wake_by_address_any((void *)P32(cs + 8), 4, OS_SYNC_WAKE_BY_ADDRESS_NONE);
}
void I_kernel32_dll_InitializeCriticalSection(CPU *c) { memset(PTR(A0), 0, 40); }
void I_kernel32_dll_InitializeCriticalSectionAndSpinCount(CPU *c) { memset(PTR(A0), 0, 40); RET(1); }
void I_kernel32_dll_InitializeCriticalSectionEx(CPU *c) { memset(PTR(A0), 0, 40); RET(1); }
void I_kernel32_dll_EnterCriticalSection(CPU *c) { rt_cs_enter(c, A0); }
void I_kernel32_dll_TryEnterCriticalSection(CPU *c) { RET(rt_cs_try(c, A0)); }
void I_kernel32_dll_LeaveCriticalSection(CPU *c) { rt_cs_leave(c, A0); }
void I_kernel32_dll_DeleteCriticalSection(CPU *c) { }

// ---------------- environment / locale ----------------
static const uint16_t env_block[] = { 0, 0 };
void I_kernel32_dll_GetEnvironmentStringsW(CPU *c) { RET(G(env_block)); }
void I_kernel32_dll_FreeEnvironmentStringsW(CPU *c) { RET(1); }
// The guest environment: with rt_game.windows_env, the usual Windows variables, pointing into the virtual C: drive (files.c maps C:\users\Player
// and C:\Temp under ~/Library/Application Support/<data_name>/c), plus host variables meant for the translated
// graphics stack (DXVK_*, MESA_*, VKD3D_*). Windows variable names are case-insensitive.
const char *rt_guest_env(const char *name) {
    static const struct { const char *n, *v; } fixed[] = {
        { "LOCALAPPDATA", "C:\\users\\Player\\AppData\\Local" }, { "APPDATA", "C:\\users\\Player\\AppData\\Roaming" },
        { "USERPROFILE", "C:\\users\\Player" }, { "HOMEDRIVE", "C:" }, { "HOMEPATH", "\\users\\Player" },
        { "USERNAME", "Player" }, { "TEMP", "C:\\Temp" }, { "TMP", "C:\\Temp" }, { "ProgramData", "C:\\ProgramData" },
        { "ALLUSERSPROFILE", "C:\\ProgramData" }, { "PUBLIC", "C:\\users\\Public" }, { "SystemDrive", "C:" },
        { "SystemRoot", "C:\\Windows" }, { "windir", "C:\\Windows" }, { "OS", "Windows_NT" },
        { "PROCESSOR_ARCHITECTURE", "AMD64" }, { "COMPUTERNAME", "MAC" },
    };
    if (rt_game.windows_env) {
        for (size_t i = 0; i < sizeof fixed / sizeof *fixed; i++) if (!strcasecmp(name, fixed[i].n)) return fixed[i].v;
    }
    if (rt_game.windows_env && !strcasecmp(name, "NUMBER_OF_PROCESSORS")) { static char nb[16]; snprintf(nb, sizeof nb, "%u", rt_ncpu()); return nb; }
    if (!strncasecmp(name, "DXVK_", 5) || !strncasecmp(name, "MESA_", 5) || !strncasecmp(name, "VKD3D_", 6)) return getenv(name);
    return NULL;
}
// GetEnvironmentVariable(name, buffer, size): characters copied (without the null), or the size needed (with it)
void I_kernel32_dll_GetEnvironmentVariableA(CPU *c) {
    const char *v = A0 ? rt_guest_env(PTR(A0)) : NULL;
    if (!v) { set_last_error(203); RET(0); return; }   // ERROR_ENVVAR_NOT_FOUND
    uint32_t n = (uint32_t)strlen(v), cap = (uint32_t)A2;
    if (!A1 || cap <= n) { RET(n + 1); return; }
    memcpy(PTR(A1), v, n + 1); RET(n);
}
void I_kernel32_dll_GetEnvironmentVariableW(CPU *c) {
    char *nm = A0 ? w16_to_utf8(PTR(A0)) : NULL; const char *v = nm ? rt_guest_env(nm) : NULL; free(nm);
    if (!v) { set_last_error(203); RET(0); return; }
    uint16_t *w = utf8_to_w16(v); uint32_t n = (uint32_t)w16len(w), cap = (uint32_t)A2;
    if (!A1 || cap <= n) { free(w); RET(n + 1); return; }
    memcpy(PTR(A1), w, (n + 1) * 2); free(w); RET(n);
}
void I_kernel32_dll_SetEnvironmentVariableA(CPU *c) { RET(1); }
void I_kernel32_dll_SetEnvironmentVariableW(CPU *c) { RET(1); }
void I_kernel32_dll_GetACP(CPU *c) { RET(65001); }
void I_kernel32_dll_GetOEMCP(CPU *c) { RET(65001); }
void I_kernel32_dll_IsValidCodePage(CPU *c) { RET(1); }
void I_kernel32_dll_GetCPInfo(CPU *c) {
    uint64_t b = A1; memset(PTR(b), 0, 20); wr32(b, 4); wr8(b + 4, '?'); RET(1);
}
void I_kernel32_dll_GetUserDefaultLCID(CPU *c) { RET(0x409); }
void I_kernel32_dll_GetUserDefaultLangID(CPU *c) { RET(0x409); }
void I_kernel32_dll_GetSystemDefaultLangID(CPU *c) { RET(0x409); }
void I_kernel32_dll_GetUserDefaultUILanguage(CPU *c) { RET(0x409); }

// MultiByteToWideChar(cp, flags, src, srclen, dst, dstlen) - treated as UTF-8 (or Latin-1 for cp 1252)
void I_kernel32_dll_MultiByteToWideChar(CPU *c) {
    const char *s = PTR(A2); int sl = (int)A3; uint64_t dst = AN(4); int dl = (int)AN(5);
    size_t n = sl < 0 ? strlen(s) + 1 : (size_t)sl;
    char *tmp = malloc(n + 1); memcpy(tmp, s, n); tmp[n] = 0;
    uint16_t *w = utf8_to_w16(tmp);
    size_t wn = w16len(w) + (sl < 0 ? 1 : 0);
    if (sl >= 0) { // embedded NULs: count them
        size_t k = 0; for (size_t i = 0; i < n; i++) if (!tmp[i]) k++;
        wn += k;
    }
    if (dl) { size_t m = wn < (size_t)dl ? wn : (size_t)dl; memcpy(PTR(dst), w, m * 2); }
    free(tmp); free(w);
    RET(dl && (size_t)dl < wn ? 0 : wn);
}
// WideCharToMultiByte(cp, flags, src, srclen, dst, dstlen, default, used)
void I_kernel32_dll_WideCharToMultiByte(CPU *c) {
    // encoded by length, not as a C string: an explicit srclen may include NULs (the CRT converts its whole
    // environment block, "a=b\0c=d\0\0", in one call, and an empty block is a single NUL)
    const uint16_t *s = PTR(A2); int sl = (int)A3; uint64_t dst = AN(4); int dl = (int)AN(5);
    size_t n = sl < 0 ? w16len(s) + 1 : (size_t)sl;
    char *u = malloc(n * 3 + 1); size_t un = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t ch = s[i];
        if (ch >= 0xD800 && ch < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000)
            ch = 0x10000 + ((ch - 0xD800) << 10) + (s[++i] - 0xDC00);
        else if (ch >= 0xD800 && ch < 0xE000) ch = 0xFFFD;
        if (ch < 0x80) u[un++] = (char)ch;
        else if (ch < 0x800) { u[un++] = (char)(0xC0 | ch >> 6); u[un++] = (char)(0x80 | (ch & 63)); }
        else if (ch < 0x10000) { u[un++] = (char)(0xE0 | ch >> 12); u[un++] = (char)(0x80 | (ch >> 6 & 63)); u[un++] = (char)(0x80 | (ch & 63)); }
        else { u[un++] = (char)(0xF0 | ch >> 18); u[un++] = (char)(0x80 | (ch >> 12 & 63)); u[un++] = (char)(0x80 | (ch >> 6 & 63)); u[un++] = (char)(0x80 | (ch & 63)); }
    }
    if (AN(7)) wr32(AN(7), 0);
    if (dl && (size_t)dl < un) { free(u); set_last_error(122); RET(0); return; }   // ERROR_INSUFFICIENT_BUFFER
    if (dl) memcpy(PTR(dst), u, un);
    free(u);
    RET(un);
}
void I_kernel32_dll_GetStringTypeW(CPU *c) {
    const uint16_t *s = PTR(A1); int n = (int)A2; uint64_t out = A3;
    if (n < 0) n = (int)w16len(s) + 1;
    for (int i = 0; i < n; i++) {
        uint16_t ch = s[i], t = 0;
        if (ch >= 'A' && ch <= 'Z') t = 0x1 | 0x100;
        else if (ch >= 'a' && ch <= 'z') t = 0x2 | 0x100;
        else if (ch >= '0' && ch <= '9') t = 0x4;
        else if (ch == ' ' || (ch >= 9 && ch <= 13)) t = 0x8 | (ch == ' ' ? 0x40 : 0);
        else if (ch < 32 || ch == 127) t = 0x20;
        else if (ch < 128) t = 0x10;
        else t = 0x100;
        wr16(out + 2 * i, t);
    }
    RET(1);
}
// LCMapStringEx/LCMapStringW: upper/lower case mapping only
static void lcmap(CPU *c, uint32_t flags, const uint16_t *s, int sl, uint64_t dst, int dl) {
    if (sl < 0) sl = (int)w16len(s) + 1;
    if (!dl) { RET(sl); return; }
    for (int i = 0; i < sl && i < dl; i++) {
        uint16_t ch = s[i];
        if ((flags & 0x200) && ch >= 'a' && ch <= 'z') ch -= 32;       // LCMAP_UPPERCASE
        if ((flags & 0x100) && ch >= 'A' && ch <= 'Z') ch += 32;       // LCMAP_LOWERCASE
        wr16(dst + 2 * i, ch);
    }
    RET(sl);
}
void I_kernel32_dll_LCMapStringW(CPU *c) { lcmap(c, (uint32_t)A1, PTR(A2), (int)A3, AN(4), (int)AN(5)); }

// HeapWalk(heap, entry): heaps are malloc underneath and cannot be enumerated: no more entries
void I_kernel32_dll_HeapWalk(CPU *c) { set_last_error(259); RET(0); }   // ERROR_NO_MORE_ITEMS

// RtlPcToFileHeader(pc, *base): the image containing pc. MSVC's x64 C++ throw uses it, since the throw info is
// image-relative; a 0 base makes every catch miss.
void I_kernel32_dll_RtlPcToFileHeader(CPU *c) {
    uint64_t pc = A0, base = 0;
    if (pc >= gimage_base && pc < gimage_base + gimage_size) base = gimage_base;
    else { const GModule *m = rt_module_at(pc); if (m) base = m->base; }
    if (A1) wr64(A1, base);
    RET(base);
}

// ANSI variants (older MSVC CRTs, e.g. VS2010's, initialize through these)
static const char env_block_a[] = { 0, 0 };
void I_kernel32_dll_GetEnvironmentStrings(CPU *c) { RET(G(env_block_a)); }
void I_kernel32_dll_FreeEnvironmentStringsA(CPU *c) { RET(1); }
void I_kernel32_dll_GetStartupInfoA(CPU *c) { memset(PTR(A0), 0, 104); wr32(A0, 104); }
void I_kernel32_dll_SetHandleCount(CPU *c) { RET(A0); }
// GetVersion: build << 16 | minor << 8 | major (high bit clear: NT), matching GetVersionEx
void I_kernel32_dll_GetVersion(CPU *c) { RET((19045u << 16) | 10u); }
static uint16_t ctype_of(unsigned ch) {
    if (ch >= 'A' && ch <= 'Z') return 0x1 | 0x100;
    if (ch >= 'a' && ch <= 'z') return 0x2 | 0x100;
    if (ch >= '0' && ch <= '9') return 0x4 | 0x80;   // digit, hex digit
    if (ch == ' ' || (ch >= 9 && ch <= 13)) return 0x8 | (ch == ' ' ? 0x40 : 0x20);
    if (ch < 32 || ch == 127) return 0x20;
    if (ch < 128) return 0x10;
    return 0x100;
}
// GetStringTypeA(lcid, type, src, n, out): CT_CTYPE1 only
void I_kernel32_dll_GetStringTypeA(CPU *c) {
    const uint8_t *s = PTR(A2); int n = (int)A3; uint64_t out = AN(4);
    if (n < 0) n = (int)strlen((const char *)s) + 1;
    for (int i = 0; i < n; i++) wr16(out + 2 * i, ctype_of(s[i]));
    RET(1);
}
// LCMapStringA(lcid, flags, src, srclen, dst, dstlen): upper/lower case mapping only
void I_kernel32_dll_LCMapStringA(CPU *c) {
    uint32_t flags = (uint32_t)A1; const char *s = PTR(A2); int sl = (int)A3; uint64_t dst = AN(4); int dl = (int)AN(5);
    if (sl < 0) sl = (int)strlen(s) + 1;
    if (!dl) { RET(sl); return; }
    for (int i = 0; i < sl && i < dl; i++) {
        uint8_t ch = (uint8_t)s[i];
        if ((flags & 0x200) && ch >= 'a' && ch <= 'z') ch -= 32;
        if ((flags & 0x100) && ch >= 'A' && ch <= 'Z') ch += 32;
        wr8(dst + i, ch);
    }
    RET(sl < dl ? sl : dl);
}
// GetLocaleInfoA(lcid, type, buf, n): the few values a CRT asks for, as en-US
void I_kernel32_dll_GetLocaleInfoA(CPU *c) {
    uint32_t t = (uint32_t)A1 & 0xFFFF; uint64_t buf = A2; int n = (int)A3;
    const char *v = "";
    switch (t) {
    case 0x0001: v = "0409"; break;      // LOCALE_ILANGUAGE
    case 0x0004: case 0x1001: v = "English"; break;
    case 0x0007: case 0x1002: v = "United States"; break;
    case 0x0059: v = "en"; break;        // LOCALE_SISO639LANGNAME
    case 0x005A: v = "US"; break;        // LOCALE_SISO3166CTRYNAME
    case 0x000B: v = "437"; break;       // LOCALE_IDEFAULTCODEPAGE
    case 0x1004: v = "1252"; break;      // LOCALE_IDEFAULTANSICODEPAGE
    case 0x000E: v = "."; break;         // LOCALE_SDECIMAL
    case 0x000F: v = ","; break;         // LOCALE_STHOUSAND
    case 0x0010: v = "3;0"; break;       // LOCALE_SGROUPING
    }
    int len = (int)strlen(v) + 1;
    if (!n) { RET(len); return; }
    if (n < len) { set_last_error(122); RET(0); return; }
    memcpy(PTR(buf), v, (size_t)len);
    RET(len);
}
// CompareStringW(lcid, flags, s1, n1, s2, n2): ordinal, NORM_IGNORECASE (1) folds ASCII; 1/2/3 = less/equal/greater
void I_kernel32_dll_CompareStringW(CPU *c) {
    uint32_t fl = (uint32_t)A1; const uint16_t *a = PTR(A2), *b = PTR(AN(4));
    int na = (int)A3, nb = (int)AN(5);
    if (na < 0) na = (int)w16len(a);
    if (nb < 0) nb = (int)w16len(b);
    for (int i = 0; i < na && i < nb; i++) {
        unsigned x = a[i], y = b[i];
        if (fl & 1) { if (x - 'A' < 26u) x += 32; if (y - 'A' < 26u) y += 32; }
        if (x != y) { RET(x < y ? 1 : 3); return; }
    }
    RET(na == nb ? 2 : na < nb ? 1 : 3);
}
void I_kernel32_dll_LCMapStringEx(CPU *c) { lcmap(c, (uint32_t)A1, PTR(A2), (int)A3, AN(4), (int)AN(5)); }

// ---------------- module / dynamic loading ----------------
// path of a module handle: the exe, a translated DLL (next to it), or a pseudo system DLL
static const char *module_name(uint64_t h);
static void module_path(uint64_t h, char *out, size_t n) {
    const GModule *m = h ? rt_module_at(h) : NULL;
    const char *sys = h ? module_name(h) : NULL;
    if (m) snprintf(out, n, "%s\\%s.dll", rt_game.win_dir, m->name);
    else if (sys) snprintf(out, n, "C:\\Windows\\System32\\%s.dll", sys);
    else snprintf(out, n, "%s\\%s", rt_game.win_dir, rt_game.exe);
    for (char *q = out; *q; q++) if (*q == '/') *q = '\\';   // rt_game.exe uses '/': Windows code splits paths at '\\'
}
void I_kernel32_dll_GetModuleFileNameW(CPU *c) {
    char p[512]; module_path(A0, p, sizeof p);
    uint16_t *w = utf8_to_w16(p); size_t n = w16len(w), m = A2;
    if (m) { size_t k = n < m - 1 ? n : m - 1; memcpy(PTR(A1), w, k * 2); wr16(A1 + 2 * k, 0); }
    free(w); RET(n);
}
void I_kernel32_dll_GetModuleFileNameA(CPU *c) {
    char p[512]; module_path(A0, p, sizeof p);
    size_t n = strlen(p), m = A2;
    if (m) { size_t k = n < m - 1 ? n : m - 1; memcpy(PTR(A1), p, k); wr8(A1 + k, 0); }
    RET(n);
}
// Dynamic loading: system DLLs are pseudo modules whose exports are our native shims.
// GetProcAddress(module, "Name") -> I_<dll>_dll_<Name>, looked up with dlsym in this executable.
#include <dlfcn.h>
#include <ctype.h>
#define PSEUDO_MOD_BASE 0x7FE000000000ull
static const char *known_dlls[] = { "kernel32", "kernelbase", "ntdll", "user32", "gdi32", "advapi32", "shell32", "ole32",
    "oleaut32", "shlwapi", "winmm", "xinput1_4", "xinput1_3", "xinput9_1_0", "xaudio2_9", "xaudio2_8", "xaudio2_7",
    "dinput8", "vulkan-1", "bcrypt", "dbghelp", "uxtheme", "dwmapi", "imm32", "setupapi", "ws2_32", "wsock32",
    "winhttp", "iphlpapi", "steam_api64", "bink2w64", "version", "powrprof", "combase",
    "cchromaeditorlibrary", "pdh", "security", "secur32", "sspicli", NULL };   // Razer Chroma plugin shipped with the game: every export reports "not initialized"
static void dll_base(const char *name, char *out, size_t n) {
    // "C:\x\KERNEL32.DLL" -> "kernel32"; api-ms-win-core-* -> kernel32
    const char *b = name; for (const char *p = name; *p; p++) if (*p == '\\' || *p == '/') b = p + 1;
    size_t k = 0; for (; b[k] && k < n - 1; k++) out[k] = (char)tolower((unsigned char)b[k]); out[k] = 0;
    char *dot = strrchr(out, '.'); if (dot && (!strcmp(dot, ".dll") || !strcmp(dot, ".drv"))) *dot = 0;
    if (!strncmp(out, "api-ms-win-", 11) || !strncmp(out, "ext-ms-win-", 11)) snprintf(out, n, "kernel32");
}
static uint64_t pseudo_module(const char *name) {
    char b[128]; dll_base(name, b, sizeof b);
    for (int i = 0; known_dlls[i]; i++) if (!strcmp(known_dlls[i], b)) return PSEUDO_MOD_BASE + 0x10000ull * (i + 1);
    rt_log("[win32] LoadLibrary(%s) -> not available\n", name);
    set_last_error(126);
    return 0;
}
// Translated DLLs shipped with the game (gen_<name>/): mapped at their base on first LoadLibrary, then DllMain.
static uint64_t real_module(CPU *c, const char *name, int load) {
    char b[128]; dll_base(name, b, sizeof b);
    const GModule *m = rt_find_module(b);
    if (!m) return 0;
    if (rt_module_loaded(m)) return m->base;
    if (!load) return 0;
    char win[1024];
    int has_dir = strchr(name, '\\') || strchr(name, '/') || strchr(name, ':');
    const char *dot = strrchr(name, '.');
    snprintf(win, sizeof win, "%s%s%s%s", has_dir ? "" : rt_game.win_dir, has_dir ? "" : "\\", name, dot && !strpbrk(dot, "\\/") ? "" : ".dll");
    char *host = rt_module_file(m, win);
    int ok = host && rt_load_module(m, host);
    free(host);
    if (!ok) { set_last_error(126); return 0; }
    if (m->entry) {
        uint64_t a[3] = { m->base, 1, 0 };   // DllMain(hinst, DLL_PROCESS_ATTACH, NULL)
        if (!(uint32_t)guest_call(c, m->entry, 3, a)) { rt_log("[win32] %s: DllMain failed\n", m->name); set_last_error(1114); return 0; }
    }
    return m->base;
}
static uint64_t load_library(CPU *c, const char *name) {
    // No Steam app ID (game.c): UE4's Steam plugin loads steam_api64.dll by its full ThirdParty path and must be told
    // "not there" (it does not survive SteamAPI_Init failing), while the game's own delay-load asks by bare name and
    // must get the DLL (a delay-load failure throws). The loaded DLL's SteamAPI_Init then reports false.
    char b[128]; dll_base(name, b, sizeof b);
    if (!rt_game.steam_app_id && !strcasecmp(b, "steam_api64") && (strchr(name, '\\') || strchr(name, '/'))) {
        rt_log("[win32] LoadLibrary(%s) -> refused (no Steam app ID: engine plugin disabled)\n", name); set_last_error(126); return 0;
    }
    uint64_t h = real_module(c, name, 1); return h ? h : pseudo_module(name);
}
static uint64_t module_handle(CPU *c, const char *name) {
    uint64_t h = real_module(c, name, 0);
    if (h) return h;
    char b[128]; dll_base(name, b, sizeof b);
    if (rt_find_module(b)) { set_last_error(126); return 0; }   // a translated DLL that is not loaded yet
    return pseudo_module(name);
}
static const char *module_name(uint64_t h) {
    if (h >= PSEUDO_MOD_BASE + 0x10000 && h < PSEUDO_MOD_BASE + 0x10000ull * 64) {
        uint64_t i = (h - PSEUDO_MOD_BASE) / 0x10000 - 1;
        return known_dlls[i];
    }
    return NULL;
}
void I_kernel32_dll_LoadLibraryA(CPU *c) { RET(load_library(c, PTR(A0))); }
void I_kernel32_dll_LoadLibraryW(CPU *c) { char *s = w16_to_utf8(PTR(A0)); RET(load_library(c, s)); free(s); }
void I_kernel32_dll_LoadLibraryExW(CPU *c) { char *s = w16_to_utf8(PTR(A0)); RET(load_library(c, s)); free(s); }
void I_kernel32_dll_LoadLibraryExA(CPU *c) { RET(load_library(c, PTR(A0))); }
void I_kernel32_dll_GetModuleHandleW(CPU *c) { if (!A0) { RET(gimage_base); return; } char *s = w16_to_utf8(PTR(A0)); RET(module_handle(c, s)); free(s); }
void I_kernel32_dll_GetModuleHandleA(CPU *c) { RET(A0 ? module_handle(c, PTR(A0)) : gimage_base); }
void I_kernel32_dll_GetModuleHandleExW(CPU *c) {
    uint64_t h = gimage_base;
    if (A0 & 4) { const GModule *m = rt_module_at(A1); if (m) h = m->base; }   // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
    else if (A1) { char *s = w16_to_utf8(PTR(A1)); h = module_handle(c, s); free(s); }
    if (A2) wr64(A2, h);
    RET(h != 0);
}
void I_kernel32_dll_FreeLibrary(CPU *c) { RET(1); }
static void chroma_stub(CPU *c) { RET(0); }   // FALSE / RZRESULT 0 / NULL, depending on the export
void I_kernel32_dll_GetProcAddress(CPU *c) {
    const GModule *rm = rt_module_at(A0);
    if (rm && A0 == rm->base) {   // translated DLL: its own export table
        uint64_t f = rt_module_export(A0, A1);
        if (!f) { rt_log("[win32] GetProcAddress(%s, %s) -> not exported\n", rm->name, A1 >> 16 ? (const char *)PTR(A1) : "#ordinal"); set_last_error(127); }
        RET(f); return;
    }
    const char *mod = module_name(A0);
    if (!mod || !(A1 >> 16)) {
        rt_log("[win32] GetProcAddress(%llx, %s) -> 0\n", (unsigned long long)A0, A1 >> 16 ? (const char *)PTR(A1) : "#ordinal");
        set_last_error(127); RET(0); return;
    }
    char sym[256], m2[64]; snprintf(m2, sizeof m2, "%s", mod);
    for (char *p = m2; *p; p++) if (*p == '-') *p = '_';
    if (!strcmp(m2, "kernelbase")) snprintf(m2, sizeof m2, "kernel32");
    snprintf(sym, sizeof sym, "I_%s_dll_%s", m2, (const char *)PTR(A1));
    void *f = dlsym(RTLD_DEFAULT, sym);
    if (!f && !strcmp(m2, "cchromaeditorlibrary")) { RET(rt_host_fn(chroma_stub, "CChromaEditorLibrary.dll!*")); return; }
    if (!f) {
        rt_log("[win32] GetProcAddress(%s, %s) -> not implemented\n", mod, (const char *)PTR(A1));
        set_last_error(127); RET(0); return;
    }
    RET(rt_host_fn((gfn)f, strdup(sym)));
}

// ---------------- interlocked singly-linked lists / misc ----------------
void I_kernel32_dll_EncodePointer(CPU *c) { RET(A0); }
void I_kernel32_dll_DecodePointer(CPU *c) { RET(A0); }
// Debug output, with identical repeated lines collapsed (some messages repeat every frame):
// the first 3 are shown, then one summary per 1000.
static void debug_out(const char *s) {
    static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    static struct { uint64_t hash; uint64_t count; } seen[512];
    uint64_t h = 1469598103934665603ull;
    for (const char *p = s; *p; p++) h = (h ^ (uint8_t)*p) * 1099511628211ull;
    pthread_mutex_lock(&mu);
    int i = (int)(h % 512);
    if (seen[i].hash != h) { seen[i].hash = h; seen[i].count = 0; }
    uint64_t n = ++seen[i].count;
    pthread_mutex_unlock(&mu);
    if (n <= 3) rt_log("[debug] %s", s);
    else if (n % 1000 == 0) rt_log("[debug] (repeated %llu times) %s", (unsigned long long)n, s);
}
void I_kernel32_dll_OutputDebugStringA(CPU *c) { debug_out(PTR(A0)); }
void I_kernel32_dll_OutputDebugStringW(CPU *c) { char *s = w16_to_utf8(PTR(A0)); debug_out(s); free(s); }
void I_kernel32_dll_RaiseException(CPU *c) {
    if ((uint32_t)A0 == 0x406D1388u) {   // MSVC "set thread name": THREADNAME_INFO {type, name, tid, flags}
        uint64_t info = A3;
        if (info && (uint32_t)rd64(info) == 0x1000) {
            const char *name = PTR(rd64(info + 8));
            uint32_t tid = (uint32_t)rd64(info + 16);
            if (name && (tid == 0xFFFFFFFFu || tid == rt_thread_id())) pthread_setname_np(name);
            rt_log("[win32] thread %u named \"%s\"\n", tid == 0xFFFFFFFFu ? rt_thread_id() : tid, name ? name : "");
        }
        return;   // handled: the game's __except block would ignore it
    }
    rt_log("[win32] RaiseException(code 0x%x, flags %u, %u args) from 0x%llx\n", (unsigned)A0, (unsigned)A1, (unsigned)A2, (unsigned long long)rd64(c->rsp));
    rt_backtrace(c);
    abort();
}

// ---------------- std handles / SList / misc startup ----------------
void I_kernel32_dll_GetStdHandle(CPU *c) {
    int32_t n = (int32_t)A0;   // -10 in, -11 out, -12 err
    RET(n == -10 ? 0x5354443000000000ull : n == -11 ? 0x5354443100000000ull : 0x5354443200000000ull);
}
void I_kernel32_dll_InitializeSListHead(CPU *c) { memset(PTR(A0), 0, 16); }
static pthread_mutex_t slist_mu = PTHREAD_MUTEX_INITIALIZER;
void I_kernel32_dll_InterlockedPushEntrySList(CPU *c) {
    pthread_mutex_lock(&slist_mu);
    uint64_t old = rd64(A0); wr64(A1, old); wr64(A0, A1); wr16(A0 + 8, rd16(A0 + 8) + 1);
    pthread_mutex_unlock(&slist_mu); RET(old);
}
void I_kernel32_dll_InterlockedPopEntrySList(CPU *c) {
    pthread_mutex_lock(&slist_mu);
    uint64_t top = rd64(A0); if (top) { wr64(A0, rd64(top)); wr16(A0 + 8, rd16(A0 + 8) - 1); }
    pthread_mutex_unlock(&slist_mu); RET(top);
}
void I_kernel32_dll_InterlockedFlushSList(CPU *c) {
    pthread_mutex_lock(&slist_mu);
    uint64_t top = rd64(A0); wr64(A0, 0); wr16(A0 + 8, 0);
    pthread_mutex_unlock(&slist_mu); RET(top);
}
void I_kernel32_dll_RtlCaptureContext(CPU *c) { memset(PTR(A0), 0, 0x4d0); }
void I_kernel32_dll_RtlLookupFunctionEntry(CPU *c) { if (A1) wr64(A1, gimage_base); RET(0); }
void I_kernel32_dll_RtlVirtualUnwind(CPU *c) { RET(0); }

void I_kernel32_dll_GetFileType(CPU *c) {
    uint64_t h = A0;
    RET((h >> 32) == 0x53544430 || (h >> 32) == 0x53544431 || (h >> 32) == 0x53544432 ? 2 : 1);   // console : disk
}
// MEMORYSTATUSEX (64 bytes)
void I_kernel32_dll_GlobalMemoryStatusEx(CPU *c) {
    uint64_t b = A0, total = 16ull << 30, avail = 12ull << 30;
    wr32(b + 4, 25);                       // dwMemoryLoad
    wr64(b + 8, total); wr64(b + 16, avail);
    wr64(b + 24, total * 2); wr64(b + 32, avail * 2);
    wr64(b + 40, 128ull << 40); wr64(b + 48, 120ull << 40); wr64(b + 56, 0);
    RET(1);
}
void I_kernel32_dll_GlobalMemoryStatus(CPU *c) {
    uint64_t b = A0; wr32(b, 56); wr32(b + 4, 25);
    wr64(b + 8, 16ull << 30); wr64(b + 16, 12ull << 30); wr64(b + 24, 32ull << 30); wr64(b + 32, 24ull << 30);
    wr64(b + 40, 128ull << 40); wr64(b + 48, 120ull << 40);
}

// GlobalAlloc/LocalAlloc return plain pointers, so the "handle" is the memory itself
void I_kernel32_dll_GlobalLock(CPU *c) { RET(A0); }
void I_kernel32_dll_GlobalUnlock(CPU *c) { RET(1); }
void I_kernel32_dll_GlobalHandle(CPU *c) { RET(A0); }
void I_kernel32_dll_GlobalFlags(CPU *c) { RET(0); }
size_t rt_heap_size(void *p);
void *rt_heap_realloc(void *p, size_t n, int zero);
void I_kernel32_dll_GlobalSize(CPU *c) { RET(A0 ? rt_heap_size(PTR(A0)) : 0); }
void I_kernel32_dll_LocalSize(CPU *c) { RET(A0 ? rt_heap_size(PTR(A0)) : 0); }
// GlobalReAlloc/LocalReAlloc(mem, bytes, flags): GMEM_ZEROINIT 0x40 (fixed memory only: handles are pointers)
void I_kernel32_dll_GlobalReAlloc(CPU *c) { RET(G(rt_heap_realloc(PTR(A0), A1, ((uint32_t)A2 & 0x40) != 0))); }
void I_kernel32_dll_LocalReAlloc(CPU *c) { RET(G(rt_heap_realloc(PTR(A0), A1, ((uint32_t)A2 & 0x40) != 0))); }

// ---------------- version checks ----------------
// VerSetConditionMask(mask, typeMask, condition): 3 bits per type, at the position of typeMask's lowest set bit
void I_kernel32_dll_VerSetConditionMask(CPU *c) {
    uint64_t mask = A0; uint32_t type = (uint32_t)A1; uint8_t cond = (uint8_t)A2;
    if (type) { int idx = __builtin_ctz(type); if (idx < 8) mask |= (uint64_t)(cond & 7) << (idx * 3); }
    RET(mask);
}
// VerifyVersionInfoA(OSVERSIONINFOEXA*, typeMask, conditionMask) against the Windows 10 the runtime reports
// (10.0.19045, service pack 0). OSVERSIONINFOEXA: dwMajorVersion +4, dwMinorVersion +8, dwBuildNumber +12,
// dwPlatformId +16, szCSDVersion[128] +20, wServicePackMajor +148, wServicePackMinor +150.
static int ver_cond(uint64_t mask, int idx, uint64_t have, uint64_t want) {
    switch ((mask >> (idx * 3)) & 7) {
    case 1: return have == want;   // VER_EQUAL
    case 2: return have > want;    // VER_GREATER
    case 3: return have >= want;   // VER_GREATER_EQUAL
    case 4: return have < want;    // VER_LESS
    case 5: return have <= want;   // VER_LESS_EQUAL
    }
    return 1;
}
// The W form is the same up to szCSDVersion, which is WCHAR[128]: wServicePackMajor is at +276.
static void verify_version(CPU *c, uint32_t sp_off);
void I_kernel32_dll_VerifyVersionInfoA(CPU *c) { verify_version(c, 148); }
void I_kernel32_dll_VerifyVersionInfoW(CPU *c) { verify_version(c, 276); }
static void verify_version(CPU *c, uint32_t sp_off) {
    uint64_t vi = A0, mask = A2; uint32_t type = (uint32_t)A1;   // (vi, typeMask, conditionMask): all in registers
    // major.minor.servicepack compare together when they're all asked for, as Windows does
    uint64_t have = ((uint64_t)10 << 32), want = ((uint64_t)rd32(vi + 4) << 32) | ((uint64_t)rd32(vi + 8) << 16) | rd16(vi + sp_off);
    int ok = 1;
    if (type & 0x23) {   // VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR
        int idx = (type & 0x2) ? 1 : (type & 0x1) ? 0 : 5;
        ok = ver_cond(mask, idx, have, want);
    }
    if (ok && (type & 0x4)) ok = ver_cond(mask, 2, 19045, rd32(vi + 12));     // VER_BUILDNUMBER
    if (ok && (type & 0x8)) ok = ver_cond(mask, 3, 2, rd32(vi + 16));         // VER_PLATFORMID: VER_PLATFORM_WIN32_NT
    if (!ok) set_last_error(1150);                                            // ERROR_OLD_WIN_VERSION
    RET(ok);
}

// ---------------- file mappings ----------------
// CreateFileMappingA(file, sa, protect, sizeHigh, sizeLow, name): anonymous (file = INVALID_HANDLE_VALUE) memory, or a
// file's contents read into memory (a private copy: writes through the view are not written back). Named mappings are
// shared within the process; a second create of a name returns the same object with ERROR_ALREADY_EXISTS.
#include "handles.h"
#include <sys/stat.h>
typedef struct { void *mem; uint64_t size; char name[128]; } Mapping;
static pthread_mutex_t map_mu = PTHREAD_MUTEX_INITIALIZER;
static struct { char name[128]; uint64_t handle; } named_maps[64];   // named mappings, for a second create of a name
static void mapping_close(HObj *o) {
    Mapping *m = o->data;
    if (m) {
        pthread_mutex_lock(&map_mu);
        for (int i = 0; i < 64; i++) if (named_maps[i].handle == o->handle) named_maps[i].handle = 0;
        pthread_mutex_unlock(&map_mu);
        free(m->mem); free(m);
    }
    o->data = NULL;
}
void I_kernel32_dll_CreateFileMappingA(CPU *c) {
    uint64_t file = A0, size = ((uint64_t)(uint32_t)A3 << 32) | (uint32_t)AN(4), pname = AN(5);
    const char *name = pname ? (const char *)PTR(pname) : NULL;
    if (name && *name) {   // the same name again: the same mapping
        pthread_mutex_lock(&map_mu);
        for (int i = 0; i < 64; i++) {
            if (!named_maps[i].handle || strcmp(named_maps[i].name, name)) continue;
            HObj *o = h_get(named_maps[i].handle);
            if (o && o->close == mapping_close) {
                o->refs++; uint64_t h = named_maps[i].handle;
                pthread_mutex_unlock(&map_mu); set_last_error(183); RET(h); return;   // ERROR_ALREADY_EXISTS
            }
        }
        pthread_mutex_unlock(&map_mu);
    }
    Mapping *m = calloc(1, sizeof *m);
    if (file != ~0ull && file) {
        HObj *f = h_get(file);
        if (!f || f->type != HT_FILE) { free(m); set_last_error(6); RET(0); return; }   // ERROR_INVALID_HANDLE
        struct stat st; if (fstat(f->fd, &st)) { free(m); set_last_error(5); RET(0); return; }
        if (!size) size = (uint64_t)st.st_size;
        m->mem = calloc(1, size ? size : 1);
        if (m->mem && st.st_size) pread(f->fd, m->mem, (size_t)((uint64_t)st.st_size < size ? (uint64_t)st.st_size : size), 0);
    } else {
        if (!size) { free(m); set_last_error(87); RET(0); return; }   // ERROR_INVALID_PARAMETER
        m->mem = calloc(1, size);
    }
    if (!m->mem) { free(m); set_last_error(8); RET(0); return; }   // ERROR_NOT_ENOUGH_MEMORY
    m->size = size;
    if (name) snprintf(m->name, sizeof m->name, "%s", name);
    HObj *o = h_alloc(HT_OTHER);
    o->data = m; o->close = mapping_close;
    uint64_t h = h_new(o);
    if (name && *name) {
        pthread_mutex_lock(&map_mu);
        for (int i = 0; i < 64; i++) if (!named_maps[i].handle) { snprintf(named_maps[i].name, sizeof named_maps[i].name, "%s", name); named_maps[i].handle = h; break; }
        pthread_mutex_unlock(&map_mu);
    }
    set_last_error(0);
    RET(h);
}
// MapViewOfFile(mapping, access, offsetHigh, offsetLow, bytes): views share the mapping's memory
void I_kernel32_dll_MapViewOfFile(CPU *c) {
    HObj *o = h_get(A0);
    if (!o || o->close != mapping_close || !o->data) { set_last_error(6); RET(0); return; }
    Mapping *m = o->data; uint64_t off = ((uint64_t)(uint32_t)A2 << 32) | (uint32_t)A3;
    if (off > m->size) { set_last_error(87); RET(0); return; }
    RET(G((uint8_t *)m->mem + off));
}
void I_kernel32_dll_MapViewOfFileEx(CPU *c) { I_kernel32_dll_MapViewOfFile(c); }
void I_kernel32_dll_UnmapViewOfFile(CPU *c) { RET(1); }   // the memory belongs to the mapping (freed when it closes)

// ---------------- messages and processes ----------------
// FormatMessageA(flags, source, id, lang, buffer, size, args): system messages as "Error <n>." (no message
// tables); FORMAT_MESSAGE_ALLOCATE_BUFFER (0x100) returns a LocalAlloc'd buffer through buffer
void I_kernel32_dll_FormatMessageA(CPU *c) {
    uint32_t flags = (uint32_t)A0, id = (uint32_t)A2, size = (uint32_t)AN(5); uint64_t buf = AN(4);
    char text[96];
    if (flags & 0x800) { set_last_error(317); RET(0); return; }   // FROM_HMODULE: no message tables (ERROR_MR_MID_NOT_FOUND)
    if (flags & 0x400) snprintf(text, sizeof text, "%s", (const char *)PTR(A1));   // FROM_STRING (inserts left as is)
    else snprintf(text, sizeof text, id == 0 ? "The operation completed successfully.\r\n" : "Error %u.\r\n", id);
    size_t n = strlen(text);
    if (flags & 0x100) {
        char *p = rt_heap_alloc(n + 1 > size ? n + 1 : size, 0);
        if (!p) { set_last_error(8); RET(0); return; }
        memcpy(p, text, n + 1); wr64(buf, G(p));
    } else {
        if (!buf || size <= n) { set_last_error(122); RET(0); return; }   // ERROR_INSUFFICIENT_BUFFER
        memcpy(PTR(buf), text, n + 1);
    }
    RET(n);
}
#define SELF_PID 0x1000   // what GetCurrentProcessId reports (teb.c)
// OpenProcess(access, inherit, pid): this process only (its pseudo handle); GetProcessId(handle)
void I_kernel32_dll_OpenProcess(CPU *c) { if ((uint32_t)A2 == SELF_PID) { RET(~0ull); return; } set_last_error(87); RET(0); }
void I_kernel32_dll_GetProcessId(CPU *c) { if (A0 == ~0ull) { RET(SELF_PID); return; } set_last_error(6); RET(0); }

// ---------------- psapi: this process and its modules ----------------
// EnumProcesses(pids, bytes, *needed)
void I_psapi_dll_EnumProcesses(CPU *c) {
    if ((uint32_t)A1 >= 4 && A0) wr32(A0, SELF_PID);
    if (A2) wr32(A2, 4);
    RET(1);
}
// EnumProcessModules(process, modules, bytes, *needed): the executable's image
void I_psapi_dll_EnumProcessModules(CPU *c) {
    if ((uint32_t)A2 >= 8 && A1) wr64(A1, gimage_base);
    if (A3) wr32(A3, 8);
    RET(1);
}
// GetModuleBaseNameA(process, module, name, size): the module file's name, as GetModuleFileName gives it
void I_psapi_dll_GetModuleBaseNameA(CPU *c) {
    char p[512]; module_path(A1 ? A1 : gimage_base, p, sizeof p);
    const char *b = strrchr(p, '\\'); b = b ? b + 1 : p;
    uint32_t n = (uint32_t)A3; if (!n || !A2) { RET(0); return; }
    size_t l = strlen(b); if (l >= n) l = n - 1;
    memcpy(PTR(A2), b, l); wr8(A2 + l, 0);
    RET(l);
}

// GetProfileIntA(app, key, default): there is no win.ini, so the default
void I_kernel32_dll_GetProfileIntA(CPU *c) { RET((uint32_t)A2); }

// GetThreadTimes(thread, *creation, *exit, *kernel, *user): FILETIMEs in 100 ns units. The calling thread's own
// CPU times come from Mach (GetCurrentThread's pseudo handle, the usual caller); other threads report zero times.
#include <mach/mach.h>
void I_kernel32_dll_GetThreadTimes(CPU *c) {
    uint64_t kern = 0, user = 0;
    if (A0 == ~1ull) {
        thread_basic_info_data_t info; mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
        mach_port_t self = mach_thread_self();
        if (thread_info(self, THREAD_BASIC_INFO, (thread_info_t)&info, &n) == KERN_SUCCESS) {
            user = (uint64_t)info.user_time.seconds * 10000000ull + (uint64_t)info.user_time.microseconds * 10ull;
            kern = (uint64_t)info.system_time.seconds * 10000000ull + (uint64_t)info.system_time.microseconds * 10ull;
        }
        mach_port_deallocate(mach_task_self(), self);
    }
    if (A1) wr64(A1, 0);
    if (A2) wr64(A2, 0);
    if (A3) wr64(A3, kern);
    if (AN(4)) wr64(AN(4), user);
    RET(1);
}

// Add/RemoveVectoredExceptionHandler: guest exceptions are never dispatched to handlers here (a fault is reported by
// the runtime's own crash handler), so registration only hands back a non-NULL cookie, as the caller checks for one.
void I_kernel32_dll_AddVectoredExceptionHandler(CPU *c) { static uint64_t cookie; RET(G(&cookie)); }
void I_kernel32_dll_RemoveVectoredExceptionHandler(CPU *c) { RET(1); }
