// win32 runtime core: the guest address space, image loader, import binding, indirect dispatch, guest heap,
// threads/TEB, CPU helpers (CPUID, x87/SSE rounding, 80-bit floats) and crash reporting.
#include "rt32.h"
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <execinfo.h>

int rt_verbose;
static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
void rt_log(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    pthread_mutex_lock(&log_mu);
    vfprintf(stderr, fmt, ap); fputc('\n', stderr);
    pthread_mutex_unlock(&log_mu);
    va_end(ap);
}
void rt_fatal(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[rt] fatal: "); vfprintf(stderr, fmt, ap); fputc('\n', stderr);
    va_end(ap);
    abort();
}

// ---------------- guest address space ----------------
// The whole 4 GiB window is reserved PROT_NONE at GUEST_BASE. vm_* hands out 64 KiB-granular regions of it, the
// way VirtualAlloc does; everything the guest allocates (heap, stacks, TEBs) comes from there.
// The window is never re-mmapped after startup (only mprotect and madvise): a GPU buffer wrapping guest memory
// (rt_guest_window_hook, e.g. a Metal renderer's newBufferWithBytesNoCopy) would keep seeing the old pages. Released
// regions are marked dirty and zeroed when they are handed out again.
#define VM_GRAN   0x10000u
#define VM_LO     0x01000000u            // above the image (0x400000 + ~10 MB)
#define VM_HI     0xFF000000u            // host-function trampolines live above
#define VM_UNITS  ((VM_HI - VM_LO) / VM_GRAN)
static uint32_t vm_owner[VM_UNITS];      // unit -> first unit of its allocation + 1 (0 = free)
static uint32_t vm_len[VM_UNITS];        // at the first unit: allocation length in units
static uint8_t  vm_commit_prot[VM_UNITS];
static uint8_t  vm_dirty[VM_UNITS];      // released since its last use: zero it before handing it out
static pthread_mutex_t vm_mu = PTHREAD_MUTEX_INITIALIZER;
static uint32_t vm_hint = 0;

static int host_prot(uint32_t p) {
    switch (p & 0xFF) {
    case 0x01: return PROT_NONE;                       // PAGE_NOACCESS
    case 0x02: case 0x10: case 0x20: return PROT_READ;  // READONLY, EXECUTE, EXECUTE_READ
    default:   return PROT_READ | PROT_WRITE;          // READWRITE, EXECUTE_READWRITE, WRITECOPY...
    }
}

uint32_t gvm_alloc(uint32_t addr, uint32_t size, int commit, uint32_t prot) {
    if (!size) return 0;
    uint32_t units = (uint32_t)(((uint64_t)size + VM_GRAN - 1) / VM_GRAN);
    pthread_mutex_lock(&vm_mu);
    uint32_t first = 0;
    if (addr) {
        uint32_t u = (addr & ~(VM_GRAN - 1)) < VM_LO ? 0 : ((addr & ~(VM_GRAN - 1)) - VM_LO) / VM_GRAN;
        if (addr >= VM_LO && u < VM_UNITS && vm_owner[u]) {
            // commit inside an existing reservation
            uint32_t a0 = addr & ~0xFFFu, a1 = (uint32_t)(((uint64_t)addr + size + 0xFFF) & ~0xFFFull);
            if (commit) mprotect(G2H(a0), a1 - a0, host_prot(prot));
            pthread_mutex_unlock(&vm_mu);
            return addr & ~0xFFFu;
        }
        if (addr < VM_LO || u + units > VM_UNITS) { pthread_mutex_unlock(&vm_mu); return 0; }
        for (uint32_t k = 0; k < units; k++) if (vm_owner[u + k]) { pthread_mutex_unlock(&vm_mu); return 0; }
        first = u;
    } else {
        uint32_t run = 0, u = vm_hint, scanned = 0;
        for (; scanned < VM_UNITS; scanned++, u++) {
            if (u >= VM_UNITS) { u = 0; run = 0; }
            if (vm_owner[u]) { run = 0; continue; }
            if (++run == units) { first = u + 1 - units; break; }
        }
        if (run != units) { pthread_mutex_unlock(&vm_mu); return 0; }
        vm_hint = first + units;
    }
    for (uint32_t k = 0; k < units; k++) vm_owner[first + k] = first + 1;
    vm_len[first] = units;
    vm_commit_prot[first] = (uint8_t)prot;
    uint32_t ga = VM_LO + first * VM_GRAN;
    // fresh memory reads as zero, like VirtualAlloc's
    for (uint32_t k = 0; k < units; k++)
        if (vm_dirty[first + k]) {
            uint8_t *h = G2H(ga + k * VM_GRAN);
            mprotect(h, VM_GRAN, PROT_READ | PROT_WRITE);
            madvise(h, VM_GRAN, MADV_FREE_REUSE);       // pages marked reusable can otherwise still be discarded later
            memset(h, 0, VM_GRAN); mprotect(h, VM_GRAN, PROT_NONE);
            vm_dirty[first + k] = 0;
        }
    if (commit) mprotect(G2H(ga), (size_t)units * VM_GRAN, host_prot(prot));
    pthread_mutex_unlock(&vm_mu);
    return ga;
}

int gvm_free(uint32_t addr) {
    if (addr < VM_LO || addr >= VM_HI) return 0;
    pthread_mutex_lock(&vm_mu);
    uint32_t u = (addr - VM_LO) / VM_GRAN;
    if (!vm_owner[u] || vm_owner[u] != u + 1) { pthread_mutex_unlock(&vm_mu); return 0; }
    uint32_t n = vm_len[u];
    for (uint32_t k = 0; k < n; k++) { vm_owner[u + k] = 0; vm_dirty[u + k] = 1; }
    mprotect(G2H(addr), (size_t)n * VM_GRAN, PROT_READ | PROT_WRITE);
    madvise(G2H(addr), (size_t)n * VM_GRAN, MADV_FREE_REUSABLE);    // give the pages back; zeroed on reuse
    mprotect(G2H(addr), (size_t)n * VM_GRAN, PROT_NONE);
    if (u < vm_hint) vm_hint = u;
    pthread_mutex_unlock(&vm_mu);
    return 1;
}

int gvm_protect(uint32_t addr, uint32_t size, uint32_t prot) {
    uint32_t a0 = addr & ~0xFFFu;
    uint64_t a1 = ((uint64_t)addr + size + 0xFFF) & ~0xFFFull;
    return mprotect(G2H(a0), (size_t)(a1 - a0), host_prot(prot)) == 0;
}

int gvm_query(uint32_t addr, uint32_t *base, uint32_t *size, uint32_t *state, uint32_t *prot) {
    if (addr < VM_LO || addr >= VM_HI) { *base = addr & ~0xFFFFu; *size = VM_GRAN; *state = 0x10000; *prot = 1; return 1; }   // MEM_FREE
    uint32_t u = (addr - VM_LO) / VM_GRAN;
    if (!vm_owner[u]) {
        uint32_t e = u; while (e < VM_UNITS && !vm_owner[e]) e++;
        *base = VM_LO + u * VM_GRAN; *size = (e - u) * VM_GRAN; *state = 0x10000; *prot = 1; return 1;
    }
    uint32_t f = vm_owner[u] - 1;
    *base = VM_LO + f * VM_GRAN; *size = vm_len[f] * VM_GRAN; *state = 0x1000; *prot = vm_commit_prot[f] ? vm_commit_prot[f] : 4;
    return 1;
}

// ---------------- guest heap ----------------
// Size classes of 16-byte steps up to 1 KiB, then powers of two up to 256 KiB, carved from 4 MiB arenas; larger
// blocks are their own vm regions. Each block has an 8-byte header {size class or 0xFFFF, size}.
#define NCLASS 80
static uint32_t heap_free[NCLASS];
static uint32_t arena_cur, arena_end;
static pthread_mutex_t heap_mu = PTHREAD_MUTEX_INITIALIZER;
static uint32_t class_size(int k) { return k < 64 ? 16u * (uint32_t)(k + 1) : 1024u << (k - 63); }
static int size_class(uint32_t n) {
    if (n <= 1024) return n ? (int)((n + 15) / 16) - 1 : 0;
    int k = 64; uint32_t s = 2048;
    while (s < n) { s <<= 1; k++; }
    return k < NCLASS ? k : -1;
}
uint32_t gmalloc(uint32_t n) {
    int k = size_class(n);
    if (k < 0 || class_size(k) > 256 * 1024) {
        uint32_t a = gvm_alloc(0, n + 16, 1, 4);
        if (!a) return 0;
        wrs32(a + 8, 0xFFFF); wrs32(a + 12, n);   // same header slots (p-8, p-4) as class blocks
        return a + 16;   // 16-byte aligned like the x86 CRT
    }
    uint32_t cs = class_size(k);
    pthread_mutex_lock(&heap_mu);
    uint32_t p = heap_free[k];
    if (p) heap_free[k] = rds32(p);
    else {
        uint32_t need = cs + 16;
        if (arena_cur + need > arena_end) {
            uint32_t a = gvm_alloc(0, 4u << 20, 1, 4);
            if (!a) { pthread_mutex_unlock(&heap_mu); return 0; }
            arena_cur = a; arena_end = a + (4u << 20);
        }
        p = arena_cur + 16;
        arena_cur += need;
    }
    pthread_mutex_unlock(&heap_mu);
    wrs32(p - 8, (uint32_t)k); wrs32(p - 4, n);
    return p;
}
uint32_t gmsize(uint32_t p) { return p ? rds32(p - 4) : 0; }
void gfree(uint32_t p) {
    if (!p) return;
    uint32_t k = rds32(p - 8);
    if (k == 0xFFFF) { gvm_free(p - 16); return; }
    if (k >= NCLASS) { rt_log("[heap] free of bad pointer 0x%x", p); return; }
    pthread_mutex_lock(&heap_mu);
    wrs32(p, heap_free[k]); heap_free[k] = p;
    pthread_mutex_unlock(&heap_mu);
}
uint32_t gcalloc(uint32_t n, uint32_t sz) {
    uint64_t t = (uint64_t)n * sz;
    if (t > 0xFFFFFFF0u) return 0;
    uint32_t p = gmalloc((uint32_t)t);
    if (p) memset(G2H(p), 0, (size_t)t);
    return p;
}
uint32_t grealloc(uint32_t p, uint32_t n) {
    if (!p) return gmalloc(n);
    if (!n) { gfree(p); return 0; }
    uint32_t old = gmsize(p);
    uint32_t k = rds32(p - 8);
    if (k < NCLASS && n <= class_size((int)k)) { wrs32(p - 4, n); return p; }
    uint32_t q = gmalloc(n);
    if (!q) return 0;
    memcpy(G2H(q), G2H(p), old < n ? old : n);
    gfree(p);
    return q;
}
uint32_t gstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    uint32_t p = gmalloc((uint32_t)n);
    memcpy(G2H(p), s, n);
    return p;
}

// ---------------- host functions callable from the guest ----------------
// Import shims and runtime callbacks get synthetic guest addresses in [HOSTFN_BASE, +16*NHOSTFN): calling one
// (an IAT slot, a GetProcAddress result) dispatches to the native function.
#define HOSTFN_BASE 0xFF000000u
#define NHOSTFN 65536
static gfn hostfns[NHOSTFN];
static void (*hostfns_ctx[NHOSTFN])(CPU *, uintptr_t);
static uintptr_t hostctx[NHOSTFN];
static const char *hostnames[NHOSTFN];
static int nhostfn;
uint32_t rt_host_fn_ctx(void (*f)(CPU *, uintptr_t), uintptr_t ctx, const char *name) {
    int i = __atomic_fetch_add(&nhostfn, 1, __ATOMIC_SEQ_CST);
    if (i >= NHOSTFN) rt_fatal("too many host functions");
    hostfns_ctx[i] = f; hostctx[i] = ctx; hostnames[i] = name;
    return HOSTFN_BASE + 16u * (uint32_t)i;
}
uint32_t rt_host_fn(gfn f, const char *name) {
    for (int i = 0; i < nhostfn; i++) if (hostfns[i] == f) return HOSTFN_BASE + 16u * (uint32_t)i;
    int i = __atomic_fetch_add(&nhostfn, 1, __ATOMIC_SEQ_CST);
    if (i >= NHOSTFN) rt_fatal("too many host functions");
    hostfns[i] = f; hostnames[i] = name;
    return HOSTFN_BASE + 16u * (uint32_t)i;
}

// ---------------- dispatch ----------------
gfn *rt_fast_tab; uint32_t rt_fast_lo, rt_fast_n;

static const char *func_name(uint32_t a, char *buf, size_t n) {
    if (a >= HOSTFN_BASE && a < HOSTFN_BASE + 16u * NHOSTFN) {
        const char *s = hostnames[(a - HOSTFN_BASE) / 16];
        snprintf(buf, n, "%s", s ? s : "host fn"); return buf;
    }
    int lo = 0, hi = ngfuncs - 1, best = -1;
    while (lo <= hi) { int m = (lo + hi) / 2; if (gfuncs[m].addr <= a) { best = m; lo = m + 1; } else hi = m - 1; }
    if (best < 0) snprintf(buf, n, "0x%x", a);
    else snprintf(buf, n, "F_%x+0x%x", gfuncs[best].addr, a - gfuncs[best].addr);
    return buf;
}

static void guest_backtrace(CPU *c) {
    char b[96];
    fprintf(stderr, "[rt]   in %s  eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n",
            func_name(c->fn, b, sizeof b), c->eax, c->ecx, c->edx, c->ebx, c->esp, c->ebp, c->esi, c->edi);
    fprintf(stderr, "[rt]   stack:");
    for (int k = 0; k < 24; k++) {
        uint32_t a = c->esp + 4 * k;
        if (a < c->stack_lo || a + 4 > c->stack_hi) break;
        uint32_t v = rds32(a);
        if ((v >= gimage_base && v < gimage_base + gimage_size)) fprintf(stderr, " [%d]%s", k, func_name(v, b, sizeof b));
    }
    fprintf(stderr, "\n");
}

void call_ind_slow(CPU *c, uint32_t t) {
    if (t >= HOSTFN_BASE && t < HOSTFN_BASE + 16u * NHOSTFN && (hostfns[(t - HOSTFN_BASE) / 16] || hostfns_ctx[(t - HOSTFN_BASE) / 16])) {
        uint32_t i = (t - HOSTFN_BASE) / 16;
        if (hostfns[i]) hostfns[i](c); else hostfns_ctx[i](c, hostctx[i]);
        c->esp += 4;   // the guest `ret` of a native function: pop the return address the caller pushed
        return;
    }
    int lo = 0, hi = ngfuncs - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2;
        if (gfuncs[m].addr == t) { gfuncs[m].fn(c); return; }
        if (gfuncs[m].addr < t) lo = m + 1; else hi = m - 1;
    }
    char b[96];
    fprintf(stderr, "[rt] indirect call/jump to unknown address 0x%x (return address %s)\n", t, func_name(rds32(c->esp), b, sizeof b));
    guest_backtrace(c);
    abort();
}

void bad_insn(CPU *c, uint32_t a, const char *what) {
    char b[96];
    fprintf(stderr, "[rt] unsupported instruction at 0x%x (%s): %s\n", a, func_name(a, b, sizeof b), what);
    guest_backtrace(c);
    abort();
}
void bad_jump(CPU *c, uint32_t t, uint32_t from) {
    fprintf(stderr, "[rt] bad jump to 0x%x at 0x%x\n", t, from); guest_backtrace(c); abort();
}
void missing_func(CPU *c, uint32_t t, uint32_t from) {
    // not found by the translator's discovery: try the dispatch table (a start found only at run time is a bug
    // to report, so the translator can learn its pattern)
    char b[96];
    fprintf(stderr, "[rt] call to untranslated code 0x%x from 0x%x (%s)\n", t, from, func_name(from, b, sizeof b));
    guest_backtrace(c);
    abort();
}
void cpu_int(CPU *c, uint32_t a, int n) {
    if (n == 0x29) { fprintf(stderr, "[rt] __fastfail(%u) at 0x%x\n", c->ecx, a); guest_backtrace(c); abort(); }
    fprintf(stderr, "[rt] int 0x%x at 0x%x\n", n, a); guest_backtrace(c); abort();
}

static int lax = -1;
void unimpl_import(CPU *c, const char *name) {
    if (lax < 0) lax = getenv("RT_STRICT") == NULL;
    char b[96];
    if (!lax) {
        fprintf(stderr, "[rt] unimplemented import %s (called from %s)\n", name, func_name(rds32(c->esp), b, sizeof b));
        guest_backtrace(c);
        abort();
    }
    static const char *seen[2048]; static int nseen;
    for (int i = 0; i < nseen; i++) if (seen[i] == name) { c->eax = 0; return; }
    if (nseen < 2048) seen[nseen++] = name;
    fprintf(stderr, "[lax] %s (from %s) -> 0   (stdcall arguments are NOT popped)\n", name, func_name(rds32(c->esp), b, sizeof b));
    c->eax = 0;
}

// ---------------- CPU helpers ----------------
void cpu_cpuid(CPU *c) {
    uint32_t leaf = c->eax, a = 0, b = 0, cc = 0, d = 0;
    switch (leaf) {
    case 0: a = 1; b = 0x756e6547; d = 0x49656e69; cc = 0x6c65746e; break;   // "GenuineIntel", max leaf 1
    case 1:
        a = 0x000206A7;                    // family 6 model 42 (a Sandy Bridge-class part, before AVX use)
        b = (8u << 16) | (1u << 8);        // 8 logical processors, clflush 8*8
        cc = (1u << 0) | (1u << 9) | (1u << 13);   // SSE3, SSSE3, CMPXCHG16B
        d = (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15) | (1u << 19) | (1u << 23) | (1u << 24) | (1u << 25) | (1u << 26);
        break;                             // FPU TSC CX8 CMOV CLFSH MMX FXSR SSE SSE2 (no SSE4/AVX: the translator doesn't do them)
    case 0x80000000: a = 0x80000004; break;
    case 0x80000002: case 0x80000003: case 0x80000004: {
        static const char brand[48] = "Apple Silicon (recompiled)";
        const uint32_t *w = (const uint32_t *)(brand + 16 * (leaf - 0x80000002));
        a = w[0]; b = w[1]; cc = w[2]; d = w[3];
        break;
    }
    default: break;
    }
    c->eax = a; c->ebx = b; c->ecx = cc; c->edx = d;
}

double fpu_round(CPU *c, double v) {
    switch ((c->fcw >> 10) & 3) {
    case 0: return nearbyint(v);
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}
double sse_round(CPU *c, double v) {
    switch ((c->mxcsr >> 13) & 3) {
    case 0: return nearbyint(v);
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}
double rd80(uint32_t a) {
    uint64_t m = rds64(a); uint16_t se = rds16(a + 8);
    int s = se >> 15, e = se & 0x7FFF;
    if (!e && !m) return s ? -0.0 : 0.0;
    if (e == 0x7FFF) return (m << 1) ? NAN : (s ? -INFINITY : INFINITY);
    double v = ldexp((double)m, e - 16383 - 63);
    return s ? -v : v;
}
void wr80(uint32_t a, double v) {
    uint16_t se = signbit(v) ? 0x8000 : 0; uint64_t m = 0;
    if (v != v) { se |= 0x7FFF; m = 0xC000000000000000ull; }
    else if (isinf(v)) { se |= 0x7FFF; m = 0x8000000000000000ull; }
    else if (v != 0) {
        int e; double f = frexp(fabs(v), &e);   // f in [0.5, 1)
        m = (uint64_t)ldexp(f, 64);
        se |= (uint16_t)(e - 1 + 16383);
    }
    wrs64(a, m); wrs16(a + 8, se);
}

// ---------------- debugging ----------------
uint32_t rt_watch_addr;
void rt_watch_bulk(uint32_t dst, uint32_t n, const char *who) {
    if (rt_watch_addr - dst < n) {
        CPU *c = rt_cpu(); char b[96];
        rt_log("[watch] %s writes 0x%x..0x%x over 0x%x (called from %s)", who, dst, dst + n, rt_watch_addr,
               c ? func_name(rds32(c->esp), b, sizeof b) : "?");
    }
}

// a place for debugger breakpoints: probes call it (e.g. when an object of interest is constructed)
__attribute__((noinline)) void rt_debug_hook(uint32_t a) { __asm__ volatile("" ::: "memory"); (void)a; }

// ---------------- threads and TEBs ----------------
static pthread_key_t thread_key;
uint32_t rt_peb, rt_process_heap;
static uint32_t next_tid = 0x100;
RtThread *rt_thread(void) { return pthread_getspecific(thread_key); }
CPU *rt_cpu(void) { RtThread *t = rt_thread(); return t ? t->cpu : NULL; }

uint32_t rt_teb_alloc(RtThread *t, uint32_t stack_lo, uint32_t stack_hi) {
    uint32_t teb = gvm_alloc(0, 0x2000, 1, 4);
    wr32(teb + 0x00, 0xFFFFFFFFu);        // ExceptionList: end of the SEH chain
    wr32(teb + 0x04, stack_hi);           // StackBase
    wr32(teb + 0x08, stack_lo);           // StackLimit
    wr32(teb + 0x18, teb);                // Self
    wr32(teb + 0x20, 0x10);               // ClientId.UniqueProcess
    wr32(teb + 0x24, t->tid);             // ClientId.UniqueThread
    wr32(teb + 0x2C, teb + 0x1000);       // ThreadLocalStoragePointer (static TLS array; the exe has none)
    wr32(teb + 0x30, rt_peb);             // ProcessEnvironmentBlock
    t->teb = teb;
    return teb;
}

RtThread *rt_thread_new(uint32_t stack_size) {
    RtThread *t = calloc(1, sizeof *t);
    CPU *c = calloc(1, sizeof *c);
    if (stack_size < 0x10000) stack_size = 0x100000;
    uint32_t stk = gvm_alloc(0, stack_size, 1, 4);
    if (!stk) rt_fatal("out of guest memory for a %u-byte stack", stack_size);
    c->stack_lo = stk; c->stack_hi = stk + stack_size;
    c->esp = c->stack_hi - 64;
    c->fcw = 0x27F;       // MSVC CRT default: double precision, round to nearest, all exceptions masked
    c->mxcsr = 0x1F80;
    c->thread = t;
    t->cpu = c;
    t->tid = __atomic_fetch_add(&next_tid, 4, __ATOMIC_SEQ_CST);
    c->fsbase = rt_teb_alloc(t, c->stack_lo, c->stack_hi);
    return t;
}
void rt_thread_attach(RtThread *t) { pthread_setspecific(thread_key, t); }

uint32_t guest_call(CPU *c, uint32_t addr, int nargs, const uint32_t *args) {
    uint32_t esp0 = c->esp;
    for (int i = nargs - 1; i >= 0; i--) PUSH(c, args[i]);
    PUSH(c, 0xFFFFFFF0u);   // return address nobody returns to (the C call returns instead)
    call_ind(c, addr);
    c->esp = esp0;          // cdecl or stdcall alike
    return c->eax;
}

// ---------------- crash reporting ----------------
static void crash_handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    uintptr_t fa = (uintptr_t)si->si_addr;
    CPU *c = rt_cpu();
    fprintf(stderr, "\n[rt] signal %d at host address %p", sig, si->si_addr);
    if (fa >= GUEST_BASE && fa < GUEST_BASE + (1ull << 32)) fprintf(stderr, " (guest 0x%x)", (uint32_t)(fa - GUEST_BASE));
    fprintf(stderr, "\n");
    if (c) guest_backtrace(c);
    void *bt[32]; int n = backtrace(bt, 32); backtrace_symbols_fd(bt, n, 2);
    signal(sig, SIG_DFL);
    raise(sig);
}

// ---------------- image loading ----------------
static void build_dispatch(void) {
    uint32_t lo = 0xFFFFFFFFu, hi = 0;
    for (int i = 0; i < ngsections; i++) if (gsections[i].flags & 0x20000000) {
        if (gsections[i].va < lo) lo = gsections[i].va;
        if (gsections[i].va + gsections[i].vsize > hi) hi = gsections[i].va + gsections[i].vsize;
    }
    rt_fast_lo = lo; rt_fast_n = (hi - lo + 15) / 16;
    rt_fast_tab = calloc(rt_fast_n, sizeof(gfn));
    int unaligned = 0;
    for (int i = 0; i < ngfuncs; i++) {
        uint32_t off = gfuncs[i].addr - lo;
        if (!(off & 15) && off / 16 < rt_fast_n) rt_fast_tab[off / 16] = gfuncs[i].fn; else unaligned++;
    }
    if (rt_verbose) rt_log("[rt] dispatch: %d functions, %d off the 16-byte grid", ngfuncs, unaligned);
}

void rt_bind_imports(void);   // imports.c: IAT slots -> host trampolines

static void load_image(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) rt_fatal("can't open the game image %s: %s", path, strerror(errno));
    // header page (the CRT and Steam read the PE header through GetModuleHandle(NULL))
    mprotect(G2H(gimage_base), (gimage_size + 0xFFF) & ~0xFFFu, PROT_READ | PROT_WRITE);   // untouched: reads as zero
    pread(fd, G2H(gimage_base), 0x1000, 0);
    for (int i = 0; i < ngsections; i++) {
        const GSection *s = &gsections[i];
        uint32_t n = s->fsize < s->vsize ? s->fsize : s->vsize;
        if (!s->vsize) n = s->fsize;
        if (n && pread(fd, G2H(s->va), n, s->foff) != (ssize_t)n) rt_fatal("short read of section %s", s->name);
    }
    close(fd);
}

static void process_init(void) {
    // PEB: BeingDebugged = 0, ImageBaseAddress, ProcessHeap, OS version 6.1 (Windows 7) for VerifyVersionInfo paths
    rt_peb = gvm_alloc(0, 0x1000, 1, 4);
    wr32(rt_peb + 0x08, gimage_base);
    rt_process_heap = 0x00350000u;   // a handle value; HeapAlloc ignores which heap
    wr32(rt_peb + 0x18, rt_process_heap);
    wr32(rt_peb + 0xA4, 6); wr32(rt_peb + 0xA8, 1); wr16(rt_peb + 0xAC, 7601);
}

char rt_game_dir[1024], rt_data_dir[1024], rt_exe_dir[1024];
void (*rt_guest_window_hook)(void *base, uint64_t size);
int rt_game_main(int argc, char **argv);   // game.c: settings, then rt_run

#include <mach-o/dyld.h>
#include <libgen.h>
void rt_init(const char *image_path) {
    if (getenv("RT_WATCH")) rt_watch_addr = (uint32_t)strtoul(getenv("RT_WATCH"), NULL, 16);
    pthread_key_create(&thread_key, NULL);
    { char exe[1024]; uint32_t n = sizeof exe; if (_NSGetExecutablePath(exe, &n) == 0) snprintf(rt_exe_dir, sizeof rt_exe_dir, "%s", dirname(exe)); }
    char found[2048];
    if (!image_path) {   // rt_game.image: app bundle Resources, next to the binary, one folder up (build/<binary>)
        const char *rel[] = {"/../Resources/", "/", "/../"};
        for (int i = 0; i < 3 && !image_path; i++) {
            snprintf(found, sizeof found, "%s%s%s", rt_exe_dir, rel[i], rt_game.image);
            if (access(found, R_OK) == 0) image_path = found;
        }
        if (!image_path) rt_fatal("the game image %s was not found next to %s (build it with the game project's Makefile)", rt_game.image, rt_exe_dir);
    }
    void *want = (void *)(uintptr_t)GUEST_BASE;
    // mapped read/write (lazily, nothing is committed) so a GPU API can wrap it, then protected
    void *m = mmap(want, 1ull << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (m != want) rt_fatal("couldn't reserve the guest address space at %p (got %p)", want, m);
    if (rt_guest_window_hook) rt_guest_window_hook(m, 1ull << 32);
    mprotect(m, 1ull << 32, PROT_NONE);
    struct sigaction sa = {0};
    sa.sa_sigaction = crash_handler; sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); sigaction(SIGILL, &sa, NULL); sigaction(SIGFPE, &sa, NULL);
    load_image(image_path);
    build_dispatch();
    process_init();
    rt_bind_imports();
}

void rt_cocoa_run(void (*fn)(void));
static void game_main(void);
void rt_run(void) { rt_cocoa_run(game_main); }   // AppKit keeps the main thread; the guest runs on a game thread
static void game_main(void) {
    RtThread *t = rt_thread_new(0x400000);   // 4 MiB main stack (the exe's SizeOfStackReserve is 1 MiB; be generous)
    rt_thread_attach(t);
    CPU *c = t->cpu;
    if (rt_verbose) rt_log("[rt] entering guest entry point 0x%x", gentry);
    guest_call(c, gentry, 0, NULL);
    rt_log("[rt] guest entry point returned 0x%x", c->eax);
    exit((int)c->eax);
}
