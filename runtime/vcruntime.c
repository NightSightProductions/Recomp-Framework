// vcruntime140.dll: the compiler's support library for games that link the C runtime dynamically (see ucrt.c).
// Memory and string primitives, setjmp/longjmp (the translator turns each call to setjmp into a site of its own,
// runtime/setjmp.c), RTTI (dynamic_cast and type_info), std::exception's string handling, and C++ exceptions,
// dispatched to the guest's catch blocks (runtime/cxxeh.c); one nothing catches ends the game with its type logged.
#include <string.h>
#include "rt.h"
#include "ucrt.h"

void rt_cxx_throw(CPU *c, uint64_t obj, uint64_t ti);

#define VC(name) void I_vcruntime140_dll_##name(CPU *c)

VC(memcpy) { memcpy(PTR(A0), PTR(A1), A2); RET(A0); }
VC(memmove) { memmove(PTR(A0), PTR(A1), A2); RET(A0); }
VC(memset) { memset(PTR(A0), (int)A1, A2); RET(A0); }
VC(memcmp) { RET((uint32_t)memcmp(PTR(A0), PTR(A1), A2)); }
VC(memchr) { RET(G(memchr(PTR(A0), (int)A1, A2))); }
VC(strchr) { RET(G(strchr(PTR(A0), (int)A1))); }
VC(strrchr) { RET(G(strrchr(PTR(A0), (int)A1))); }
VC(strstr) { RET(G(strstr(PTR(A0), PTR(A1)))); }
VC(wcschr) {
    const uint16_t *s = PTR(A0); uint16_t ch = (uint16_t)A1;
    for (;; s++) { if (*s == ch) { RET(G(s)); return; } if (!*s) break; }
    RET(0);
}
VC(wcsrchr) {
    const uint16_t *s = PTR(A0), *last = NULL; uint16_t ch = (uint16_t)A1;
    for (;; s++) { if (*s == ch) last = s; if (!*s) break; }
    RET(G(last));
}
VC(wcsstr) {
    const uint16_t *h = PTR(A0), *n = PTR(A1);
    if (!*n) { RET(A0); return; }
    for (; *h; h++) {
        size_t k = 0; while (n[k] && h[k] == n[k]) k++;
        if (!n[k]) { RET(G(h)); return; }
    }
    RET(0);
}

// longjmp(buf, value): back to the matching setjmp site; __intrinsic_setjmp itself never runs as a call
VC(longjmp) { rt_longjmp(c, A0, (uint32_t)A1); }
VC(__intrinsic_setjmp) { rt_log("[vcruntime] setjmp called outside a translated setjmp site\n"); RET(0); }

VC(_purecall) { rt_log("[vcruntime] pure virtual function call\n"); rt_backtrace(c); abort(); }
VC(__std_terminate) { rt_log("[vcruntime] std::terminate\n"); rt_backtrace(c); abort(); }

// std::exception keeps its message in __std_exception_data { const char *what; bool do_free; }
VC(__std_exception_copy) {   // (from, to)
    const char *w = PTR(rd64(A0)); int dofree = rd8(A0 + 8);
    if (dofree && w) { wr64(A1, G(strdup(w))); wr8(A1 + 8, 1); }
    else { wr64(A1, G(w)); wr8(A1 + 8, 0); }
}
VC(__std_exception_destroy) {
    if (rd8(A0 + 8)) free(PTR(rd64(A0)));
    wr64(A0, 0); wr8(A0 + 8, 0);
}

// type_info: { vftable, undecorated-name cache, decorated name (".?AVfoo@@") at +16 }
static const char *ti_name(uint64_t ti) { return PTR(ti + 16); }
VC(__std_type_info_compare) {
    if (A0 == A1) { RET(0); return; }
    RET((uint32_t)strcmp(ti_name(A0) + 1, ti_name(A1) + 1));
}
VC(__std_type_info_name) { RET(G(ti_name(A0))); }
VC(__std_type_info_hash) {   // FNV-1a over the decorated name, as the CRT does
    uint64_t h = 0xcbf29ce484222325ull;
    for (const unsigned char *p = (const unsigned char *)ti_name(A0) + 1; *p; p++) { h ^= *p; h *= 0x100000001b3ull; }
    RET(h);
}

// ---------------- dynamic_cast (Microsoft x64 RTTI, image-relative offsets) ----------------
// vftable[-1] -> CompleteObjectLocator { sig 1, offset, cdOffset, rva TypeDescriptor, rva ClassHierarchyDescriptor,
// rva self }; ClassHierarchyDescriptor { sig, attributes, numBaseClasses, rva BaseClassArray }; BaseClassDescriptor
// { rva TypeDescriptor, numContainedBases, PMD { mdisp, pdisp, vdisp }, attributes, rva ClassHierarchyDescriptor }.
static int same_type(uint64_t a, uint64_t b) { return a == b || !strcmp(ti_name(a), ti_name(b)); }
static int64_t pmd_offset(uint64_t obj, uint64_t pmd) {
    int32_t mdisp = (int32_t)rd32(pmd), pdisp = (int32_t)rd32(pmd + 4), vdisp = (int32_t)rd32(pmd + 8);
    int64_t off = mdisp;
    if (pdisp >= 0) { uint64_t vbt = rd64(obj + pdisp); off += pdisp + (int32_t)rd32(vbt + vdisp); }
    return off;
}
// __RTDynamicCast(inptr, VfDelta, SrcType, TargetType, isReference)
VC(__RTDynamicCast) {
    uint64_t in = A0, target = A3; int is_ref = (int)AN(4);
    if (!in) { RET(0); return; }
    uint64_t col = rd64(rd64(in) - 8);
    uint32_t offset = rd32(col + 4), cd = rd32(col + 8);
    uint64_t base = col - rd32(col + 20);   // image base: the locator's own rva
    uint64_t complete = in - offset;
    if (cd) {
        static int logged; if (!logged++) rt_log("[vcruntime] dynamic_cast through a virtual base (cdOffset %u)\n", cd);
        complete -= (int32_t)rd32(in - cd);
    }
    uint64_t chd = base + rd32(col + 16);
    uint32_t nbase = rd32(chd + 8); uint64_t arr = base + rd32(chd + 12);
    for (uint32_t k = 0; k < nbase; k++) {
        uint64_t bcd = base + rd32(arr + 4 * k);
        if (same_type(base + rd32(bcd), target)) { RET(complete + (uint64_t)pmd_offset(complete, bcd + 8)); return; }
    }
    if (is_ref) { rt_log("[vcruntime] dynamic_cast to %s: std::bad_cast\n", ti_name(target)); rt_backtrace(c); abort(); }
    RET(0);
}
// __RTtypeid(obj): the type_info of the object's most-derived type
VC(__RTtypeid) {
    if (!A0) { rt_log("[vcruntime] typeid of a null pointer\n"); rt_backtrace(c); abort(); }
    uint64_t col = rd64(rd64(A0) - 8);
    RET(col - rd32(col + 20) + rd32(col + 12));
}
// __RTCastToVoid(obj): the complete object
VC(__RTCastToVoid) {
    if (!A0) { RET(0); return; }
    uint64_t col = rd64(rd64(A0) - 8);
    RET(A0 - rd32(col + 4));
}

// ---------------- C++ exceptions ----------------
// _CxxThrowException(object, ThrowInfo *): ThrowInfo { attributes, rva unwind, rva forward-compat,
// rva CatchableTypeArray { count, rva CatchableType[] } }, CatchableType { properties, rva TypeDescriptor, ... }
VC(_CxxThrowException) {
    const char *name = "?";
    uint64_t ti = A1;
    if (ti) {
        const GModule *m = rt_module_at(ti);
        uint64_t base = m ? m->base : gimage_base;
        uint64_t cta = base + rd32(ti + 12);
        if (rd32(cta)) { uint64_t ct = base + rd32(cta + 4); name = ti_name(base + rd32(ct + 4)); }
    }
    rt_cxx_throw(c, A0, A1);   // returns only when no catch takes it
    rt_log("[vcruntime] C++ exception thrown: %s\n", name);
    // its message, when the object holds one: std::exception keeps a pointer after the vftable, others inline text
    if (A0) {
        const char *cand[2] = { PTR(A0 + 8), NULL };
        uint64_t p = rd64(A0 + 8); if (p > 0x10000 && p >> 47 == 0) cand[1] = PTR(p);
        for (int k = 0; k < 2; k++) {
            const unsigned char *s = (const unsigned char *)cand[k]; if (!s) continue;
            int n = 0; while (n < 512 && s[n] >= 0x20 && s[n] < 0x7f) n++;
            if (n >= 4 && (!s[n] || n == 512)) { rt_log("[vcruntime]   \"%.*s\"\n", n, s); break; }
        }
    }
    rt_backtrace(c);
    abort();
}
// The language-specific handlers named in unwind data: only reached by exception dispatch, which never continues
VC(__CxxFrameHandler3) { RET(1); }   // ExceptionContinueSearch
VC(__CxxFrameHandler4) { RET(1); }
VC(__C_specific_handler) { RET(1); }
