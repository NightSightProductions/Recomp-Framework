// C++ exceptions (MSVC x64, __CxxFrameHandler3 tables) for translated code.
// A throw walks the guest stack with the image's .pdata unwind codes, the way RtlVirtualUnwind does, restoring the
// non-volatile registers frame by frame. The first frame whose try block has a matching catch takes it: the frames
// below it run their destructors (unwind map actions), the catch object is built in the catching frame, and the
// catch block (a funclet) runs as a guest call on the stack below the throw, where the thrown object still lives.
// The catch block returns where the function goes on; that address is a function of its own (the translator makes
// every catch continuation a start), and the catching function's native frame holds a host jmp_buf set at its entry
// (rt_eh_site in funcs.h). The runtime jumps back into that frame with the frame's registers and runs the
// continuation, which returns as the catching function would have.
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include "rt.h"
#include "tables.h"

#define FH3_MAGIC_MIN 0x19930520u
#define FH3_MAGIC_MAX 0x19930522u
#define MAX_FRAMES 512

typedef struct { uint64_t gpr[16]; XMM xmm[16]; uint64_t pc; } Ctx;

// ---- native frames of functions that catch: a per-thread stack ordered by guest rsp ----
typedef struct { uint64_t rsp; jmp_buf host; } EhSite;
static __thread EhSite *t_sites; static __thread int t_nsites, t_capsites;
static __thread Ctx t_resume_ctx; static __thread uint64_t t_resume_at;

jmp_buf *rt_eh_prepare(CPU *c) {
    uint64_t sp = c->rsp;
    while (t_nsites && t_sites[t_nsites - 1].rsp <= sp) t_nsites--;   // frames at or below this one have returned
    if (t_nsites == t_capsites) {
        t_capsites = t_capsites ? t_capsites * 2 : 64;
        t_sites = realloc(t_sites, (size_t)t_capsites * sizeof *t_sites);
    }
    t_sites[t_nsites].rsp = sp;
    return &t_sites[t_nsites++].host;
}
void rt_eh_resumed(CPU *c) {
    memcpy(&c->rax, t_resume_ctx.gpr, sizeof t_resume_ctx.gpr);
    memcpy(c->xmm, t_resume_ctx.xmm, sizeof t_resume_ctx.xmm);
    gfn f = rt_find_func(t_resume_at);
    if (!f) { rt_log("[eh] catch continuation 0x%llx is not a translated function\n", (unsigned long long)t_resume_at); abort(); }
    f(c);
}

// ---- image lookups ----
static uint64_t module_base(uint64_t pc) {
    if (pc >= gimage_base && pc < gimage_base + gimage_size) return gimage_base;
    const GModule *m = rt_module_at(pc);
    return m ? m->base : 0;
}
// the RUNTIME_FUNCTION covering pc: begin, end and unwind info as guest addresses
static int find_rf(uint64_t base, uint64_t pc, uint64_t *beg, uint64_t *end, uint64_t *ui) {
    if (rd16(base) != 0x5A4D) return 0;
    uint64_t nt = base + rd32(base + 0x3C), opt = nt + 24;
    uint64_t dir = opt + 112 + 3 * 8;
    uint32_t rva = rd32(dir), size = rd32(dir + 4);
    if (!rva || !size) return 0;
    uint32_t off = (uint32_t)(pc - base);
    int64_t lo = 0, hi = size / 12 - 1;
    while (lo <= hi) {
        int64_t mid = (lo + hi) / 2;
        uint64_t e = base + rva + 12 * (uint64_t)mid;
        uint32_t b = rd32(e), en = rd32(e + 4);
        if (off < b) hi = mid - 1;
        else if (off >= en) lo = mid + 1;
        else {
            uint32_t u = rd32(e + 8);
            if (u & 1) { uint64_t e2 = base + (u & ~1u); b = rd32(e2); en = rd32(e2 + 4); u = rd32(e2 + 8); }
            *beg = base + b; *end = base + en; *ui = base + u;
            return 1;
        }
    }
    return 0;
}
static uint32_t ui_codes_end(uint64_t ui) { uint8_t n = rd8(ui + 2); return 4 + ((n + 1u) & ~1u) * 2; }

// the establisher frame of a function at its current point (frame register based when it has one)
static uint64_t establisher(const Ctx *x, uint64_t ui) {
    uint8_t fr = rd8(ui + 3);
    return (fr & 15) ? x->gpr[fr & 15] - (uint64_t)(fr >> 4) * 16 : x->gpr[4];
}

// RtlVirtualUnwind: undo the function's prologue, then pop the return address
static int vunwind(uint64_t base, uint64_t beg, uint64_t ui, Ctx *x) {
    uint64_t off_in = x->pc - beg; int first = 1;
    for (int depth = 0; depth < 32; depth++) {
        uint8_t flags = rd8(ui) >> 3, prolog = rd8(ui + 1), cnt = rd8(ui + 2), fr = rd8(ui + 3);
        uint64_t frame = (fr & 15) ? x->gpr[fr & 15] - (uint64_t)(fr >> 4) * 16 : x->gpr[4];
        for (int i = 0; i < cnt;) {
            uint8_t at = rd8(ui + 4 + 2 * i), op = rd8(ui + 5 + 2 * i), uop = op & 15, info = op >> 4;
            int skip = first && off_in < prolog && at > off_in;   // inside the prologue: not done yet
            int n = 1;
            switch (uop) {
            case 0: if (!skip) { x->gpr[info] = rd64(x->gpr[4]); x->gpr[4] += 8; } break;   // PUSH_NONVOL
            case 1:   // ALLOC_LARGE
                if (info == 0) { n = 2; if (!skip) x->gpr[4] += (uint64_t)rd16(ui + 4 + 2 * (i + 1)) * 8; }
                else { n = 3; if (!skip) x->gpr[4] += rd32(ui + 4 + 2 * (i + 1)); }
                break;
            case 2: if (!skip) x->gpr[4] += (uint64_t)info * 8 + 8; break;   // ALLOC_SMALL
            case 3: if (!skip) x->gpr[4] = frame; break;                     // SET_FPREG
            case 4: n = 2; if (!skip) x->gpr[info] = rd64(frame + (uint64_t)rd16(ui + 4 + 2 * (i + 1)) * 8); break;
            case 5: n = 3; if (!skip) x->gpr[info] = rd64(frame + rd32(ui + 4 + 2 * (i + 1))); break;
            case 6: n = 1; break;    // EPILOG (version 2)
            case 7: n = 2; break;    // spare
            case 8: n = 2; if (!skip) { uint64_t a = frame + (uint64_t)rd16(ui + 4 + 2 * (i + 1)) * 16;
                                        x->xmm[info].q[0] = rd64(a); x->xmm[info].q[1] = rd64(a + 8); } break;
            case 9: n = 3; if (!skip) { uint64_t a = frame + rd32(ui + 4 + 2 * (i + 1));
                                        x->xmm[info].q[0] = rd64(a); x->xmm[info].q[1] = rd64(a + 8); } break;
            case 10:   // PUSH_MACHFRAME: an interrupt frame, never in compiled code that throws
                return 0;
            default: return 0;
            }
            i += n;
        }
        if (!(flags & 4)) break;   // UNW_FLAG_CHAININFO: the primary function's codes follow
        uint64_t rf = ui + ui_codes_end(ui);
        beg = base + rd32(rf); ui = base + rd32(rf + 8);
        first = 0;
    }
    x->pc = rd64(x->gpr[4]); x->gpr[4] += 8;
    return 1;
}
// the primary unwind info (holding the handler) of a possibly chained one
static uint64_t primary_ui(uint64_t base, uint64_t ui) {
    for (int d = 0; d < 32 && (rd8(ui) >> 3) & 4; d++) ui = base + rd32(ui + ui_codes_end(ui) + 8);
    return ui;
}
// the __CxxFrameHandler3 FuncInfo of a function, or 0
static uint64_t fh3_funcinfo(uint64_t base, uint64_t ui) {
    ui = primary_ui(base, ui);
    if (!((rd8(ui) >> 3) & 3)) return 0;   // no exception/termination handler
    uint64_t p = ui + ui_codes_end(ui);
    uint64_t fi = base + rd32(p + 4);
    uint32_t magic = rd32(fi);
    return (magic >= FH3_MAGIC_MIN && magic <= FH3_MAGIC_MAX) ? fi : 0;
}
static int fh3_state(uint64_t base, uint64_t fi, uint64_t pc) {
    uint32_t n = rd32(fi + 20); uint64_t map = base + rd32(fi + 24);
    uint32_t off = (uint32_t)(pc - base); int st = -1;
    for (uint32_t k = 0; k < n; k++) { if (rd32(map + 8 * k) > off) break; st = (int32_t)rd32(map + 8 * k + 4); }
    return st;
}
// run the unwind map actions (destructors) from state `from` down to `to`
static void fh3_unwind(CPU *c, uint64_t base, uint64_t fi, int from, int to, uint64_t est) {
    uint64_t umap = base + rd32(fi + 8); int maxst = (int32_t)rd32(fi + 4);
    for (int guard = 0; from > to && from < maxst && guard < 4096; guard++) {
        uint64_t e = umap + 8 * (uint64_t)from;
        int next = (int32_t)rd32(e); uint32_t act = rd32(e + 4);
        if (act) { uint64_t a[2] = { 0, est }; guest_call(c, base + act, 2, a); }
        from = next;
    }
}

static const char *td_name(uint64_t td) { return (const char *)PTR(td + 16); }

// a matching catch for the thrown type: the handler entry and the CatchableType it binds to (0 for catch(...))
static int fh3_match(uint64_t base, uint64_t fi, int state, uint64_t tbase, uint64_t ti,
                     uint64_t *try_out, uint64_t *catch_out, uint64_t *ct_out) {
    uint32_t ntry = rd32(fi + 12); uint64_t tmap = base + rd32(fi + 16);
    uint64_t cta = ti ? tbase + rd32(ti + 12) : 0; uint32_t nct = cta ? rd32(cta) : 0;
    for (uint32_t t = 0; t < ntry; t++) {
        uint64_t tb = tmap + 20 * (uint64_t)t;
        int lo = (int32_t)rd32(tb), hi = (int32_t)rd32(tb + 4);
        if (state < lo || state > hi) continue;
        uint32_t ncatch = rd32(tb + 12); uint64_t hs = base + rd32(tb + 16);
        for (uint32_t h = 0; h < ncatch; h++) {
            uint64_t ht = hs + 20 * (uint64_t)h;
            uint32_t ptype = rd32(ht + 4);
            if (!ptype || !rd8(base + ptype + 16)) { *try_out = tb; *catch_out = ht; *ct_out = 0; return 1; }   // catch (...)
            for (uint32_t k = 0; k < nct; k++) {
                uint64_t ct = tbase + rd32(cta + 4 + 4 * k);
                uint64_t td = tbase + rd32(ct + 4);
                if (td == base + ptype || !strcmp(td_name(td), td_name(base + ptype))) {
                    *try_out = tb; *catch_out = ht; *ct_out = ct; return 1;
                }
            }
        }
    }
    return 0;
}

// the thrown object as the catch's type sees it (base class subobject)
static uint64_t adjust(uint64_t obj, uint64_t ct) {
    int32_t mdisp = (int32_t)rd32(ct + 8), pdisp = (int32_t)rd32(ct + 12), vdisp = (int32_t)rd32(ct + 16);
    uint64_t r = obj + mdisp;
    if (pdisp >= 0) r += (int64_t)(int32_t)rd32(rd64(obj + pdisp) + vdisp) + pdisp;
    return r;
}
static void build_catch_object(CPU *c, uint64_t base, uint64_t tbase, uint64_t ht, uint64_t ct, uint64_t est, uint64_t obj) {
    uint32_t adj = rd32(ht), ptype = rd32(ht + 4); int32_t disp = (int32_t)rd32(ht + 8);
    if (!ct || !ptype || !disp) return;
    uint64_t dst = est + disp; uint32_t props = rd32(ct);
    if (adj & 8) { wr64(dst, adjust(obj, ct)); return; }                       // by reference
    if (props & 1) {                                                           // simple type (a pointer too)
        uint32_t size = rd32(ct + 20);
        memcpy(PTR(dst), PTR(obj), size);
        if (size == 8 && rd32(ct + 4) && strchr(td_name(tbase + rd32(ct + 4)), 'P')) { uint64_t p = rd64(dst); if (p) wr64(dst, adjust(p, ct)); }
        return;
    }
    uint32_t copy = rd32(ct + 24);
    if (copy) {
        uint64_t a[3] = { dst, adjust(obj, ct), 1 };
        guest_call(c, tbase + copy, (props & 4) ? 3 : 2, a);
    } else memcpy(PTR(dst), PTR(adjust(obj, ct)), rd32(ct + 20));
}

// the exception being handled by a catch block on this thread (for `throw;`), and the frames above that catch
typedef struct { uint64_t obj, ti; Ctx above; int have_above; } Active;
static __thread Active t_active[16]; static __thread int t_nactive;

static void log_type(const char *what, uint64_t tbase, uint64_t ti) {
    const char *name = "?";
    if (ti) { uint64_t cta = tbase + rd32(ti + 12); if (rd32(cta)) name = td_name(tbase + rd32(tbase + rd32(cta + 4) + 4)); }
    rt_log("[eh] %s %s\n", what, name);
}

// Dispatch a throw from the import call in c (rsp at the return address). Returns only if nothing catches it.
void rt_cxx_throw(CPU *c, uint64_t obj, uint64_t ti) {
    int rethrow = !ti;
    if (rethrow) {
        if (!t_nactive) { rt_log("[eh] rethrow with no exception being handled\n"); return; }
        obj = t_active[t_nactive - 1].obj; ti = t_active[t_nactive - 1].ti;
    }
    uint64_t tbase = module_base(ti); if (!tbase) tbase = gimage_base;

    typedef struct { Ctx x; uint64_t base, beg, ui, fi, est; int state; } Frame;
    static __thread Frame *fr; if (!fr) fr = malloc(sizeof(Frame) * MAX_FRAMES);
    Ctx x; memcpy(x.gpr, &c->rax, sizeof x.gpr); memcpy(x.xmm, c->xmm, sizeof x.xmm);
    x.pc = rd64(x.gpr[4]); x.gpr[4] += 8;
    int nf = 0, found = -1, outer_used = 0;
    uint64_t try_e = 0, ht = 0, ct = 0;
    while (nf < MAX_FRAMES) {
        uint64_t base = module_base(x.pc), beg, end, ui;
        if (!base) {
            // left the guest code this catch funclet runs in: a rethrow (or a new throw) from inside a catch block
            // continues in the frames above the function whose catch is running
            if (t_nactive && !outer_used && t_active[t_nactive - 1].have_above) { x = t_active[t_nactive - 1].above; outer_used = 1; continue; }
            break;
        }
        if (!find_rf(base, x.pc - 1, &beg, &end, &ui)) {   // leaf function: only the return address
            x.pc = rd64(x.gpr[4]); x.gpr[4] += 8; continue;
        }
        Frame *f = &fr[nf++];
        f->x = x; f->base = base; f->beg = beg; f->ui = ui; f->est = establisher(&x, ui);
        f->fi = fh3_funcinfo(base, ui); f->state = f->fi ? fh3_state(base, f->fi, x.pc) : -1;
        if (f->fi && fh3_match(base, f->fi, f->state, tbase, ti, &try_e, &ht, &ct)) { found = nf - 1; break; }
        if (!vunwind(base, beg, ui, &x)) break;
    }
    if (found < 0) { log_type(rethrow ? "uncaught rethrow of" : "uncaught exception", tbase, ti); return; }

    Frame *cf = &fr[found];
    static int nlogged; if (nlogged < 64) { nlogged++; log_type("caught", tbase, ti); rt_log("[eh]   by 0x%llx, %d frames up\n", (unsigned long long)cf->beg, found); }
    // the frames above the catching function, for a throw from inside its catch block
    Ctx above = cf->x; int have_above = vunwind(cf->base, cf->beg, cf->ui, &above);
    uint64_t entry_rsp = above.gpr[4] - 8;   // the catching function's rsp at entry (its return address)

    build_catch_object(c, cf->base, tbase, ht, ct, cf->est, obj);
    // destructors of the frames being left, innermost first, then this frame's down to its try block
    for (int i = 0; i < found; i++)
        if (fr[i].fi) fh3_unwind(c, fr[i].base, fr[i].fi, fr[i].state, -1, fr[i].est);
    fh3_unwind(c, cf->base, cf->fi, cf->state, (int32_t)rd32(try_e), cf->est);

    // the catch block
    if (t_nactive < 16) { Active *a = &t_active[t_nactive++]; a->obj = obj; a->ti = ti; a->above = above; a->have_above = have_above; }
    uint64_t args[2] = { 0, cf->est };
    uint64_t cont = guest_call(c, cf->base + rd32(ht + 12), 2, args);
    if (t_nactive) t_nactive--;
    uint32_t dtor = rd32(ti + 4);
    if (dtor) { uint64_t a[1] = { obj }; guest_call(c, tbase + dtor, 1, a); }

    // back into the catching function's native frame, at the continuation
    int s = t_nsites - 1;
    while (s >= 0 && t_sites[s].rsp != entry_rsp) s--;
    if (s < 0) { rt_log("[eh] catching function 0x%llx has no native frame (rsp 0x%llx)\n", (unsigned long long)cf->beg, (unsigned long long)entry_rsp); abort(); }
    t_nsites = s + 1;
    t_resume_ctx = cf->x; t_resume_at = cont;
    _longjmp(t_sites[s].host, 1);
}
