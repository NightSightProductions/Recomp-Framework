// Instruction fuzzer harness for the win32 translator (see w32_fuzz.py). Built twice: -arch x86_64 -DX86 runs the
// original bytes under Rosetta (tests/fuzz_x86.S); -arch arm64 runs their translation against cpu32.h. Both read
// inputs.bin and write one record per trial: registers, XMM registers and up to 64 changed bytes of the buffer.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#define BUF 0x20000000u
#define BUF_SIZE (1u << 20)
#define WIN (64u << 10)
typedef struct { uint64_t g[16]; uint8_t x[256]; } State;
typedef struct { uint64_t g[16]; uint8_t x[256]; uint64_t pad; uint32_t n; struct { uint32_t off; uint8_t v; } __attribute__((packed)) ch[64]; } __attribute__((packed)) Rec;
static uint8_t *buf, ref[WIN];
static void fill(uint32_t seed) {
    uint32_t s = seed | 1;
    for (uint32_t i = 0; i < WIN; i++) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; ref[i] = (uint8_t)s; }
    memcpy(buf + BUF_SIZE / 2 - WIN / 2, ref, WIN);
}
static void diffs(Rec *r) {
    r->n = 0;
    uint8_t *w = buf + BUF_SIZE / 2 - WIN / 2;
    for (uint32_t i = 0; i < WIN && r->n < 64; i++) if (w[i] != ref[i]) { r->ch[r->n].off = i; r->ch[r->n].v = w[i]; r->n++; }
}
#ifdef X86
void run_snippet(State *s, void *code);
#define CODE_HOST 0x150000000ull
#else
#include "cpu32.h"
extern const gfn fuzz_fns[]; extern const int fuzz_n;
gfn *rt_fast_tab; uint32_t rt_fast_lo, rt_fast_n;
void call_ind_slow(CPU *c, uint32_t t) { fprintf(stderr, "call_ind 0x%x\n", t); exit(2); }
void bad_insn(CPU *c, uint32_t a, const char *w) { c->eax = 0xBAD1BAD1u; }
void bad_jump(CPU *c, uint32_t t, uint32_t f) { exit(3); }
void missing_func(CPU *c, uint32_t t, uint32_t f) { exit(4); }
void cpu_cpuid(CPU *c) { }
void cpu_int(CPU *c, uint32_t a, int n) { exit(5); }
void unimpl_import(CPU *c, const char *n) { exit(6); }
double sse_round(CPU *c, double v) { return __builtin_nearbyint(v); }
double fpu_round(CPU *c, double v) { return __builtin_nearbyint(v); }
double rd80(uint32_t a) { return 0; }
void wr80(uint32_t a, double v) { }
#define STACK 0x30000000u
#endif
static sigjmp_buf jb;
static void on_fault(int sig) { siglongjmp(jb, sig); }
int main(int argc, char **argv) {
    char p[1024];
    signal(SIGSEGV, on_fault); signal(SIGBUS, on_fault); signal(SIGILL, on_fault); signal(SIGFPE, on_fault);
#ifdef X86
    buf = mmap((void *)(uintptr_t)BUF, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
#else
    buf = mmap((void *)(uintptr_t)(GUEST_BASE + BUF), BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    mmap((void *)(uintptr_t)(GUEST_BASE + STACK), 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
#endif
    if (buf == MAP_FAILED) { perror("buf"); return 1; }
    snprintf(p, sizeof p, "%s/inputs.bin", argv[1]);
    FILE *in = fopen(p, "rb"); uint32_t nt, ntr, slot; fread(&nt, 4, 1, in); fread(&ntr, 4, 1, in); fread(&slot, 4, 1, in);
#ifdef X86
    snprintf(p, sizeof p, "%s/code.bin", argv[1]);
    FILE *cf = fopen(p, "rb"); fseek(cf, 0, SEEK_END); long cl = ftell(cf); fseek(cf, 0, SEEK_SET);
    uint8_t *code = mmap((void *)CODE_HOST, (size_t)cl + 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    fread(code, 1, (size_t)cl, cf); fclose(cf);
#endif
    Rec r;
    for (uint32_t t = 0; t < nt; t++)
        for (uint32_t k = 0; k < ntr; k++) {
            State s; uint32_t seed;
            fread(s.g, 8, 16, in); fread(s.x, 1, 256, in); fread(&seed, 4, 1, in);
            fill(seed);
            memset(&r, 0, sizeof r);
            if (sigsetjmp(jb, 1)) { r.n = 0xFFFFFFFFu; fwrite(&r, sizeof r, 1, stdout); continue; }
#ifdef X86
            run_snippet(&s, (void *)(CODE_HOST + (uint64_t)t * slot));
#else
            static CPU c; memset(&c, 0, sizeof c);
            uint32_t *gp[8] = { &c.eax, &c.ecx, &c.edx, &c.ebx, &c.esp, &c.ebp, &c.esi, &c.edi };
            for (int i = 0; i < 8; i++) *gp[i] = (uint32_t)s.g[i];
            memcpy(c.xmm, s.x, 128);
            c.mxcsr = 0x1F80; c.fcw = 0x27F;
            c.esp = STACK + 0x8000; c.esp -= 4; wr32(c.esp, 0x1234);
            fuzz_fns[t](&c);
            for (int i = 0; i < 8; i++) s.g[i] = *gp[i];
            memcpy(s.x, c.xmm, 128);
#endif
            memset(&r, 0, sizeof r);
            for (int i = 0; i < 8; i++) r.g[i] = s.g[i] & 0xFFFFFFFFu;
            r.g[4] = 0;
            memcpy(r.x, s.x, 128);
            diffs(&r);
            fwrite(&r, sizeof r, 1, stdout);
        }
    return 0;
}
