#include "com32.h"
#include <time.h>

#define COM_MAGIC 0xC0C0A32Bu
#define NOBJ (1 << 20)
static ComObj **objs;
static uint32_t nobj = 1, free_head;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

typedef struct { const ComClass *cls; int idx; } Slot;

// RT_COM_CALLSITES=1: count every COM call by (method, guest return address) and write the histogram to
// <data dir>/com_callsites.txt at exit (tools/callsites.py maps return addresses to the calling functions)
#define CS_N (1 << 16)
typedef struct { const Slot *slot; uint32_t ret; uint64_t n; } CallSite;
static CallSite *cs_tab; static pthread_mutex_t cs_mu = PTHREAD_MUTEX_INITIALIZER;
static void cs_dump(void) {
    char p[1200]; snprintf(p, sizeof p, "%s/com_callsites.txt", rt_data_dir);
    FILE *f = fopen(p, "w"); if (!f) return;
    pthread_mutex_lock(&cs_mu);
    for (int i = 0; i < CS_N; i++) if (cs_tab[i].slot)
        fprintf(f, "%llu %08x %s::%s\n", (unsigned long long)cs_tab[i].n, cs_tab[i].ret, cs_tab[i].slot->cls->name, cs_tab[i].slot->cls->methods[cs_tab[i].slot->idx].name);
    pthread_mutex_unlock(&cs_mu);
    fclose(f);
    rt_log("[com] call sites written to %s", p);
}
static void cs_count(const Slot *s, uint32_t ret) {
    pthread_mutex_lock(&cs_mu);
    if (!cs_tab) { cs_tab = calloc(CS_N, sizeof *cs_tab); atexit(cs_dump); }
    uint32_t h = (ret * 2654435761u ^ (uint32_t)((uintptr_t)s >> 3)) & (CS_N - 1);
    for (int k = 0; k < CS_N; k++, h = (h + 1) & (CS_N - 1)) {
        CallSite *e = &cs_tab[h];
        if (!e->slot) { e->slot = s; e->ret = ret; }
        if (e->slot == s && e->ret == ret) { e->n++; break; }
    }
    static uint64_t calls, last; int dump = 0;
    if ((++calls & 0xFFFF) == 0) { uint64_t t = (uint64_t)time(NULL); if (t - last >= 10) { last = t; dump = 1; } }
    pthread_mutex_unlock(&cs_mu);
    if (dump) cs_dump();
}
void com_callsites_dump(void) { if (cs_tab) cs_dump(); }

static void trampoline(CPU *c, uintptr_t ctx) {
    const Slot *s = (const Slot *)ctx;
    const ComMethod *m = &s->cls->methods[s->idx];
    ComObj *self = com_host(ARG(0));
    uint32_t r;
    static int sites = -1;
    if (sites < 0) sites = getenv("RT_COM_CALLSITES") != NULL;
    if (sites) cs_count(s, rd32(c->esp));
    if (!self) { rt_log("[com] %s::%s on a foreign object 0x%x", s->cls->name, m->name, ARG(0)); r = 0x80004003u; }
    else if (m->fn) r = m->fn(c, self, m);
    else {
        static const char *seen[1024]; static int nseen;
        int known = 0;
        for (int i = 0; i < nseen; i++) if (seen[i] == m->name) known = 1;
        if (!known && nseen < 1024) { seen[nseen++] = m->name; rt_log("[com] unimplemented %s::%s -> 0x%x", s->cls->name, m->name, m->dflt); }
        r = m->dflt;
    }
    static int trace = -1;
    if (trace < 0) trace = getenv("RT_TRACE_COM") != NULL;
    if (trace && (!m->fn || m->fn != (ComFn)0)) {
        char args[96] = ""; size_t n = 0;
        for (int i = 1; i < m->nargs && n < sizeof args - 12; i++) n += (size_t)snprintf(args + n, sizeof args - n, "%s%x", i > 1 ? "," : "", ARG(i));
        rt_log("[com] %s::%s(%s) -> 0x%x", s->cls->name, m->name, args, r);
    }
    c->eax = r;
    c->esp += 4u * m->nargs;
}

static uint32_t build_vtable(const ComClass *cls) {
    uint32_t vt = gcalloc((uint32_t)cls->nmethods, 4);
    Slot *slots = calloc((size_t)cls->nmethods, sizeof *slots);
    for (int i = 0; i < cls->nmethods; i++) {
        slots[i] = (Slot){cls, i};
        char *nm = malloc(128); snprintf(nm, 128, "%s::%s", cls->name, cls->methods[i].name);
        wr32(vt + 4u * (uint32_t)i, rt_host_fn_ctx(trampoline, (uintptr_t)&slots[i], nm));
    }
    return vt;
}

uint32_t com_wrap(ComObj *o, const ComClass *cls) {
    pthread_mutex_lock(&mu);
    if (!objs) objs = calloc(NOBJ, sizeof *objs);
    if (!cls->vtable) ((ComClass *)cls)->vtable = build_vtable(cls);
    uint32_t idx;
    if (free_head) { idx = free_head; free_head = (uint32_t)(uintptr_t)objs[idx]; }
    else { if (nobj >= NOBJ) rt_fatal("too many COM objects"); idx = nobj++; }
    objs[idx] = o;
    pthread_mutex_unlock(&mu);
    o->cls = cls; o->refs = 1;
    o->guest = gcalloc(1, 16);
    wr32(o->guest, cls->vtable); wr32(o->guest + 4, COM_MAGIC); wr32(o->guest + 8, idx);
    return o->guest;
}

ComObj *com_host(uint32_t g) {
    if (!g || rd32(g + 4) != COM_MAGIC) return NULL;
    uint32_t idx = rd32(g + 8);
    return idx && idx < nobj ? objs[idx] : NULL;
}

uint32_t com_addref(ComObj *o) { return (uint32_t)__atomic_add_fetch(&o->refs, 1, __ATOMIC_SEQ_CST); }
uint32_t com_release(ComObj *o) {
    int r = __atomic_sub_fetch(&o->refs, 1, __ATOMIC_SEQ_CST);
    if (r == 0) {
        uint32_t g = o->guest, idx = rd32(g + 8);
        if (o->cls->destroy) o->cls->destroy(o);
        pthread_mutex_lock(&mu);
        objs[idx] = (ComObj *)(uintptr_t)free_head; free_head = idx;
        pthread_mutex_unlock(&mu);
        wr32(g + 4, 0);
        gfree(g);
    }
    return (uint32_t)(r < 0 ? 0 : r);
}
void com_unwrap_free(ComObj *o) {
    uint32_t g = o->guest, idx = rd32(g + 8);
    pthread_mutex_lock(&mu);
    objs[idx] = (ComObj *)(uintptr_t)free_head; free_head = idx;
    pthread_mutex_unlock(&mu);
    wr32(g + 4, 0);
    gfree(g);
}
uint32_t com_QueryInterface(CPU *c, ComObj *self, const ComMethod *m) {
    // the game asks for the interface it already has (or a base): hand back this object
    if (M(2)) { wr32(M(2), self->guest); com_addref(self); }
    return 0;
}
uint32_t com_AddRef(CPU *c, ComObj *self, const ComMethod *m) { return com_addref(self); }
uint32_t com_Release(CPU *c, ComObj *self, const ComMethod *m) { return com_release(self); }
