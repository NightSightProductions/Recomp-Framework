// msvcp140.dll: the parts of Microsoft's C++ standard library that games import when they link it dynamically.
// Much of <iostream> is inline in the game, which reads and writes the objects directly, so the objects keep
// Microsoft's x64 layouts:
//   basic_streambuf<char> (0x68): vftable, _Gfirst, _Pfirst, _IGfirst, _IPfirst, _Gnext, _Pnext, _IGnext, _IPnext,
//     _Gcount, _Pcount (int), _IGcount, _IPcount, _Plocale. The get/put pointers are reached through the _IG*/_IP*
//     indirections, which point back into the object.
//   ios_base (0x48): vftable, _Stdstr, _Mystate, _Except, _Fmtfl, _Prec, _Wide, _Arr, _Calls, _Ploc;
//   basic_ios<char> (0x60): ios_base, _Mystrbuf, _Tiestr, _Fillch;
//   basic_ostream<char>: a vbptr, with basic_ios as its virtual base (found through vbtable[1]).
// Locales are the "C" locale; a locale object is an opaque block the game only passes around.
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rt.h"
#include "ucrt.h"

#define CP(name) void I_msvcp140_dll_##name(CPU *c)
// symbols: I_msvcp140_dll_ + the decorated name with every character outside [A-Za-z0-9_] as '_'

// ---------------- basic_streambuf ----------------
enum { SB_VFT = 0, SB_GFIRST = 8, SB_PFIRST = 16, SB_IGFIRST = 24, SB_IPFIRST = 32, SB_GNEXT = 40, SB_PNEXT = 48,
       SB_IGNEXT = 56, SB_IPNEXT = 64, SB_GCOUNT = 72, SB_PCOUNT = 76, SB_IGCOUNT = 80, SB_IPCOUNT = 88, SB_PLOCALE = 96 };
// vftable slots of basic_streambuf
enum { V_DTOR, V_LOCK, V_UNLOCK, V_OVERFLOW, V_PBACKFAIL, V_SHOWMANYC, V_UNDERFLOW, V_UFLOW, V_XSGETN, V_XSPUTN,
       V_SEEKOFF, V_SEEKPOS, V_SETBUF, V_SYNC, V_IMBUE, NV };
#define EOF_ (-1)
static uint64_t gnext(uint64_t s) { return rd64(rd64(s + SB_IGNEXT)); }
static uint64_t gfirst(uint64_t s) { return rd64(rd64(s + SB_IGFIRST)); }
static int32_t gcount(uint64_t s) { return (int32_t)rd32(rd64(s + SB_IGCOUNT)); }
static uint64_t pnext(uint64_t s) { return rd64(rd64(s + SB_IPNEXT)); }
static uint64_t pfirst(uint64_t s) { return rd64(rd64(s + SB_IPFIRST)); }
static int32_t pcount(uint64_t s) { return (int32_t)rd32(rd64(s + SB_IPCOUNT)); }
static uint64_t vcall(CPU *c, uint64_t obj, int slot, int n, uint64_t a1, uint64_t a2) {
    uint64_t args[3] = { obj, a1, a2 };
    return guest_call(c, rd64(rd64(obj) + 8ull * slot), n + 1, args);
}
static uint64_t new_locale(void) { return G(calloc(1, 64)); }

// The base class's own virtual functions, for the vftable the constructor installs (a derived class replaces it)
static void sb_v_dtor(CPU *c) { RET(A0); }
static void sb_v_nop(CPU *c) {}
static void sb_v_eof(CPU *c) { RET((uint32_t)EOF_); }
static void sb_v_zero(CPU *c) { RET(0); }
static void sb_v_seek(CPU *c) { wr64(A0, (uint64_t)-1); wr64(A0 + 8, 0); wr64(A0 + 16, 0); RET(A0); }   // fpos -1 (hidden result)
static void sb_v_setbuf(CPU *c) { RET(A0); }
static uint64_t sb_vftable(void) {
    static uint64_t vft[NV]; static gfn fns[NV];
    if (!vft[0]) {
        fns[V_DTOR] = sb_v_dtor; fns[V_LOCK] = sb_v_nop; fns[V_UNLOCK] = sb_v_nop; fns[V_OVERFLOW] = sb_v_eof;
        fns[V_PBACKFAIL] = sb_v_eof; fns[V_SHOWMANYC] = sb_v_zero; fns[V_UNDERFLOW] = sb_v_eof; fns[V_UFLOW] = sb_v_eof;
        fns[V_XSGETN] = sb_v_zero; fns[V_XSPUTN] = sb_v_zero; fns[V_SEEKOFF] = sb_v_seek; fns[V_SEEKPOS] = sb_v_seek;
        fns[V_SETBUF] = sb_v_setbuf; fns[V_SYNC] = sb_v_zero; fns[V_IMBUE] = sb_v_nop;
        for (int i = NV - 1; i >= 0; i--) vft[i] = rt_host_fn(fns[i], "std::basic_streambuf (vftable)");
    }
    return G(vft);
}
// basic_streambuf(): the pointers reached through themselves, all empty
CP(__0___basic_streambuf_DU__char_traits_D_std___std__IEAA_XZ) {
    uint64_t s = A0;
    memset(PTR(s), 0, 0x68);
    wr64(s + SB_VFT, sb_vftable());
    wr64(s + SB_IGFIRST, s + SB_GFIRST); wr64(s + SB_IPFIRST, s + SB_PFIRST);
    wr64(s + SB_IGNEXT, s + SB_GNEXT); wr64(s + SB_IPNEXT, s + SB_PNEXT);
    wr64(s + SB_IGCOUNT, s + SB_GCOUNT); wr64(s + SB_IPCOUNT, s + SB_PCOUNT);
    wr64(s + SB_PLOCALE, new_locale());
    RET(s);
}
CP(__1___basic_streambuf_DU__char_traits_D_std___std__UEAA_XZ) { free(PTR(rd64(A0 + SB_PLOCALE))); wr64(A0 + SB_PLOCALE, 0); }
CP(_eback____basic_streambuf_DU__char_traits_D_std___std__IEBAPEADXZ) { RET(gfirst(A0)); }
CP(_gptr____basic_streambuf_DU__char_traits_D_std___std__IEBAPEADXZ) { RET(gnext(A0)); }
CP(_egptr____basic_streambuf_DU__char_traits_D_std___std__IEBAPEADXZ) { RET(gnext(A0) + (int64_t)gcount(A0)); }
CP(_pbase____basic_streambuf_DU__char_traits_D_std___std__IEBAPEADXZ) { RET(pfirst(A0)); }
CP(_pptr____basic_streambuf_DU__char_traits_D_std___std__IEBAPEADXZ) { RET(pnext(A0)); }
CP(_epptr____basic_streambuf_DU__char_traits_D_std___std__IEBAPEADXZ) { RET(pnext(A0) + (int64_t)pcount(A0)); }
// setg(first, next, last)
CP(_setg____basic_streambuf_DU__char_traits_D_std___std__IEAAXPEAD00_Z) {
    wr64(rd64(A0 + SB_IGFIRST), A1); wr64(rd64(A0 + SB_IGNEXT), A2); wr32(rd64(A0 + SB_IGCOUNT), (uint32_t)(A3 - A2));
}
// setp(first, last) and setp(first, next, last)
CP(_setp____basic_streambuf_DU__char_traits_D_std___std__IEAAXPEAD0_Z) {
    wr64(rd64(A0 + SB_IPFIRST), A1); wr64(rd64(A0 + SB_IPNEXT), A1); wr32(rd64(A0 + SB_IPCOUNT), (uint32_t)(A2 - A1));
}
CP(_setp____basic_streambuf_DU__char_traits_D_std___std__IEAAXPEAD00_Z) {
    wr64(rd64(A0 + SB_IPFIRST), A1); wr64(rd64(A0 + SB_IPNEXT), A2); wr32(rd64(A0 + SB_IPCOUNT), (uint32_t)(A3 - A2));
}
CP(_gbump____basic_streambuf_DU__char_traits_D_std___std__IEAAXH_Z) {
    int32_t n = (int32_t)A1;
    wr32(rd64(A0 + SB_IGCOUNT), (uint32_t)(gcount(A0) - n)); wr64(rd64(A0 + SB_IGNEXT), gnext(A0) + (int64_t)n);
}
// _Pninc(): the current put position, then one past it
CP(__Pninc____basic_streambuf_DU__char_traits_D_std___std__IEAAPEADXZ) {
    uint64_t p = pnext(A0);
    wr32(rd64(A0 + SB_IPCOUNT), (uint32_t)(pcount(A0) - 1)); wr64(rd64(A0 + SB_IPNEXT), p + 1);
    RET(p);
}
CP(__Lock____basic_streambuf_DU__char_traits_D_std___std__UEAAXXZ) {}
CP(__Unlock____basic_streambuf_DU__char_traits_D_std___std__UEAAXXZ) {}
CP(_sync____basic_streambuf_DU__char_traits_D_std___std__MEAAHXZ) { RET(0); }
CP(_showmanyc____basic_streambuf_DU__char_traits_D_std___std__MEAA_JXZ) { RET(0); }
CP(_setbuf____basic_streambuf_DU__char_traits_D_std___std__MEAAPEAV12_PEAD_J_Z) { RET(A0); }
CP(_imbue____basic_streambuf_DU__char_traits_D_std___std__MEAAXAEBVlocale_2__Z) {}
// uflow(): underflow(), then take the character
CP(_uflow____basic_streambuf_DU__char_traits_D_std___std__MEAAHXZ) {
    uint32_t r = (uint32_t)vcall(c, A0, V_UNDERFLOW, 0, 0, 0);
    if ((int32_t)r == EOF_) { RET(r); return; }
    uint64_t g = gnext(A0);
    wr32(rd64(A0 + SB_IGCOUNT), (uint32_t)(gcount(A0) - 1)); wr64(rd64(A0 + SB_IGNEXT), g + 1);
    RET(rd8(g));
}
// xsgetn(dst, count): from the get area, then a character at a time through uflow
CP(_xsgetn____basic_streambuf_DU__char_traits_D_std___std__MEAA_JPEAD_J_Z) {
    uint64_t s = A0, dst = A1; int64_t want = (int64_t)A2, got = 0;
    while (got < want) {
        int32_t n = gcount(s);
        if (n > 0) {
            int64_t k = want - got < n ? want - got : n;
            memcpy(PTR(dst + got), PTR(gnext(s)), (size_t)k);
            wr32(rd64(s + SB_IGCOUNT), (uint32_t)(n - (int32_t)k)); wr64(rd64(s + SB_IGNEXT), gnext(s) + k);
            got += k;
        } else {
            uint32_t ch = (uint32_t)vcall(c, s, V_UFLOW, 0, 0, 0);
            if ((int32_t)ch == EOF_) break;
            wr8(dst + got++, (uint8_t)ch);
        }
    }
    RET((uint64_t)got);
}
// xsputn(src, count): into the put area, then a character at a time through overflow
static int64_t xsputn(CPU *c, uint64_t s, uint64_t src, int64_t want) {
    int64_t put = 0;
    while (put < want) {
        int32_t n = pcount(s);
        if (n > 0) {
            int64_t k = want - put < n ? want - put : n;
            memcpy(PTR(pnext(s)), PTR(src + put), (size_t)k);
            wr32(rd64(s + SB_IPCOUNT), (uint32_t)(n - (int32_t)k)); wr64(rd64(s + SB_IPNEXT), pnext(s) + k);
            put += k;
        } else {
            uint32_t r = (uint32_t)vcall(c, s, V_OVERFLOW, 1, rd8(src + put), 0);
            if ((int32_t)r == EOF_) break;
            put++;
        }
    }
    return put;
}
CP(_xsputn____basic_streambuf_DU__char_traits_D_std___std__MEAA_JPEBD_J_Z) { RET((uint64_t)xsputn(c, A0, A1, (int64_t)A2)); }
CP(_sputn____basic_streambuf_DU__char_traits_D_std___std__QEAA_JPEBD_J_Z) { RET(vcall(c, A0, V_XSPUTN, 2, A1, A2)); }
CP(_sputc____basic_streambuf_DU__char_traits_D_std___std__QEAAHD_Z) {
    uint8_t ch = (uint8_t)A1;
    if (pcount(A0) > 0) {
        uint64_t p = pnext(A0); wr8(p, ch);
        wr32(rd64(A0 + SB_IPCOUNT), (uint32_t)(pcount(A0) - 1)); wr64(rd64(A0 + SB_IPNEXT), p + 1);
        RET(ch); return;
    }
    RET(vcall(c, A0, V_OVERFLOW, 1, ch, 0));
}

// ---------------- ios_base / basic_ios ----------------
enum { IB_VFT = 0, IB_STDSTR = 8, IB_STATE = 0x10, IB_EXCEPT = 0x14, IB_FLAGS = 0x18, IB_PREC = 0x20, IB_WIDE = 0x28,
       IB_ARR = 0x30, IB_CALLS = 0x38, IB_PLOC = 0x40, IOS_STRBUF = 0x48, IOS_TIE = 0x50, IOS_FILL = 0x58 };
enum { F_UPPER = 4, F_SHOWBASE = 8, F_SHOWPOINT = 0x10, F_SHOWPOS = 0x20, F_LEFT = 0x40, F_INTERNAL = 0x100,
       F_OCT = 0x400, F_HEX = 0x800, F_SCI = 0x1000, F_FIXED = 0x2000, F_UNITBUF = 2, F_SKIPWS = 1, F_DEC = 0x200 };
enum { GOOD = 0, EOFBIT = 1, FAILBIT = 2, BADBIT = 4 };
static void ios_vdtor(CPU *c) { RET(A0); }
static uint64_t ios_vftable(void) {
    static uint64_t vft[1];
    if (!vft[0]) vft[0] = rt_host_fn(ios_vdtor, "std::basic_ios (vftable)");
    return G(vft);
}
static void ios_clear(uint64_t ios, uint32_t st) {
    if (!rd64(ios + IOS_STRBUF)) st |= BADBIT;
    wr32(ios + IB_STATE, st & 0x17);
}
// basic_ios(): an ios with no stream buffer yet (init comes from the stream's constructor)
CP(__0___basic_ios_DU__char_traits_D_std___std__IEAA_XZ) {
    memset(PTR(A0), 0, 0x60);
    wr64(A0 + IB_VFT, ios_vftable());
    RET(A0);
}
CP(__1___basic_ios_DU__char_traits_D_std___std__UEAA_XZ) { free(PTR(rd64(A0 + IB_PLOC))); wr64(A0 + IB_PLOC, 0); }
// basic_ios::init(strbuf, isstd), done by basic_ostream's constructor
static void ios_init(uint64_t ios, uint64_t sb) {
    wr64(ios + IB_STDSTR, 0); wr32(ios + IB_EXCEPT, 0); wr32(ios + IB_FLAGS, F_SKIPWS | F_DEC);
    wr64(ios + IB_PREC, 6); wr64(ios + IB_WIDE, 0); wr64(ios + IB_ARR, 0); wr64(ios + IB_CALLS, 0);
    if (!rd64(ios + IB_PLOC)) wr64(ios + IB_PLOC, new_locale());
    wr64(ios + IOS_STRBUF, sb); wr64(ios + IOS_TIE, 0); wr8(ios + IOS_FILL, ' ');
    ios_clear(ios, GOOD);
}
CP(_fill____basic_ios_DU__char_traits_D_std___std__QEBADXZ) { RET(rd8(A0 + IOS_FILL)); }
CP(_rdbuf____basic_ios_DU__char_traits_D_std___std__QEBAPEAV__basic_streambuf_DU__char_traits_D_std___2_XZ) { RET(rd64(A0 + IOS_STRBUF)); }
CP(_tie____basic_ios_DU__char_traits_D_std___std__QEBAPEAV__basic_ostream_DU__char_traits_D_std___2_XZ) { RET(rd64(A0 + IOS_TIE)); }
CP(_setstate____basic_ios_DU__char_traits_D_std___std__QEAAXH_N_Z) { ios_clear(A0, rd32(A0 + IB_STATE) | (uint32_t)A1); }
CP(_width_ios_base_std__QEAA_J_J_Z) { uint64_t old = rd64(A0 + IB_WIDE); wr64(A0 + IB_WIDE, A1); RET(old); }
CP(_width_ios_base_std__QEBA_JXZ) { RET(rd64(A0 + IB_WIDE)); }
CP(_flags_ios_base_std__QEBAHXZ) { RET(rd32(A0 + IB_FLAGS)); }
CP(_good_ios_base_std__QEBA_NXZ) { RET(rd32(A0 + IB_STATE) == 0); }
// setprecision(n): _Smanip<streamsize> { void (*fn)(ios_base &, streamsize), n }, returned through a hidden pointer
static void set_prec(CPU *c) { wr64(A0 + IB_PREC, A1); }
CP(_setprecision_std__YA_AU___Smanip__J_1__J_Z) { wr64(A0, rt_host_fn(set_prec, "std::setprecision")); wr64(A0 + 8, A1); RET(A0); }

// ---------------- basic_ostream ----------------
static uint64_t os_ios(uint64_t os) { return os + (int64_t)(int32_t)rd32(rd64(os) + 4); }
static void os_vdtor(CPU *c) { RET(A0); }
// basic_ostream(strbuf, isstd) [, most-derived flag]: as most-derived it sets its vbptr and constructs basic_ios
// right after it; otherwise the derived class already has. Then init.
CP(__0___basic_ostream_DU__char_traits_D_std___std__QEAA_PEAV__basic_streambuf_DU__char_traits_D_std___1__N_Z) {
    uint64_t os = A0, sb = A1;
    if ((uint32_t)A3) {
        static int32_t vbtable[2] = { 0, 8 };
        static uint64_t vft[1];
        if (!vft[0]) vft[0] = rt_host_fn(os_vdtor, "std::basic_ostream (vftable)");
        wr64(os, G(vbtable));
        memset(PTR(os + 8), 0, 0x60);
        wr64(os + 8, G(vft));
    }
    ios_init(os_ios(os), sb);
    RET(os);
}
CP(__1___basic_ostream_DU__char_traits_D_std___std__UEAA_XZ) {}
static void os_flush(CPU *c, uint64_t os) {
    uint64_t ios = os_ios(os), sb = rd64(ios + IOS_STRBUF);
    if (sb && (int32_t)(uint32_t)vcall(c, sb, V_SYNC, 0, 0, 0) == -1) ios_clear(ios, rd32(ios + IB_STATE) | BADBIT);
}
CP(_flush____basic_ostream_DU__char_traits_D_std___std__QEAAAEAV12_XZ) { os_flush(c, A0); RET(A0); }
CP(__Osfx____basic_ostream_DU__char_traits_D_std___std__QEAAXXZ) {
    uint64_t ios = os_ios(A0);
    if (!rd32(ios + IB_STATE) && (rd32(ios + IB_FLAGS) & F_UNITBUF)) os_flush(c, A0);
}
// a formatted field: padded to width() with fill(), left / internal / right, then width(0)
static void os_put_field(CPU *c, uint64_t os, const char *s, size_t n) {
    uint64_t ios = os_ios(os), sb = rd64(ios + IOS_STRBUF);
    if (rd32(ios + IB_STATE) || !sb) { ios_clear(ios, rd32(ios + IB_STATE) | FAILBIT); return; }
    int64_t w = (int64_t)rd64(ios + IB_WIDE), pad = w > (int64_t)n ? w - (int64_t)n : 0;
    uint32_t fl = rd32(ios + IB_FLAGS); uint8_t fill = rd8(ios + IOS_FILL);
    char *out = malloc(n + (size_t)pad + 1); size_t k = 0, pre = 0;
    if (pad && (fl & F_INTERNAL) && n && (s[0] == '+' || s[0] == '-')) pre = 1;
    if (pad && (fl & F_INTERNAL) && n > 1 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) pre = 2;
    if (!(fl & F_LEFT)) { memcpy(out, s, pre); k = pre; if (!(fl & F_INTERNAL)) { k = 0; pre = 0; } memset(out + k, fill, (size_t)pad); k += (size_t)pad; }
    memcpy(out + k, s + pre, n - pre); k += n - pre;
    if (fl & F_LEFT) { memset(out + k, fill, (size_t)pad); k += (size_t)pad; }
    int64_t put = (int64_t)vcall(c, sb, V_XSPUTN, 2, G(out), k);
    free(out);
    wr64(ios + IB_WIDE, 0);
    if (put != (int64_t)k) ios_clear(ios, rd32(ios + IB_STATE) | BADBIT);
}
// operator<<(double)
CP(__6___basic_ostream_DU__char_traits_D_std___std__QEAAAEAV01_N_Z) {
    uint64_t ios = os_ios(A0); uint32_t fl = rd32(ios + IB_FLAGS); int64_t prec = (int64_t)rd64(ios + IB_PREC);
    char spec[16], *p = spec; *p++ = '%';
    if (fl & F_SHOWPOS) *p++ = '+';
    if (fl & F_SHOWPOINT) *p++ = '#';
    *p++ = '.'; *p++ = '*';
    uint32_t ff = fl & (F_SCI | F_FIXED);
    char cv = ff == F_FIXED ? 'f' : ff == F_SCI ? 'e' : ff == (F_SCI | F_FIXED) ? 'a' : 'g';
    if (fl & F_UPPER) cv = (char)(cv - 32);
    *p++ = cv; *p = 0;
    if (cv == 'g' || cv == 'G') { if (prec <= 0) prec = prec < 0 ? 6 : 1; }
    char buf[512]; int n = snprintf(buf, sizeof buf, spec, (int)(prec > 300 ? 300 : prec), AD(1));
    os_put_field(c, A0, buf, (size_t)(n < (int)sizeof buf ? n : (int)sizeof buf - 1));
    RET(A0);
}
// operator<<(long long)
CP(__6___basic_ostream_DU__char_traits_D_std___std__QEAAAEAV01__J_Z) {
    uint64_t ios = os_ios(A0); uint32_t fl = rd32(ios + IB_FLAGS); int64_t v = (int64_t)A1;
    char buf[64]; int n;
    if (fl & (F_OCT | F_HEX)) {
        const char *f = (fl & F_HEX) ? ((fl & F_UPPER) ? ((fl & F_SHOWBASE) ? "%#llX" : "%llX") : ((fl & F_SHOWBASE) ? "%#llx" : "%llx"))
                                     : ((fl & F_SHOWBASE) ? "%#llo" : "%llo");
        n = snprintf(buf, sizeof buf, f, (unsigned long long)v);
    } else n = snprintf(buf, sizeof buf, (fl & F_SHOWPOS) ? "%+lld" : "%lld", (long long)v);
    os_put_field(c, A0, buf, (size_t)n);
    RET(A0);
}

// ---------------- threads, time, errors ----------------
CP(_Thrd_id) { RET(rt_thread_id()); }
// _Thrd_sleep(const xtime *until): { int64 sec, long nsec }, an absolute UTC time
CP(_Thrd_sleep) {
    struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    int64_t ns = ((int64_t)rd64(A0) - now.tv_sec) * 1000000000ll + ((int32_t)rd32(A0 + 8) - now.tv_nsec);
    if (ns > 0) { struct timespec d = { ns / 1000000000ll, ns % 1000000000ll }; nanosleep(&d, NULL); }
}
CP(_Thrd_yield) { sched_yield(); }
// the same clock as QueryPerformanceCounter/Frequency (kernel32.c)
CP(_Query_perf_frequency) { RET(1000000000ull); }
CP(_Query_perf_counter) { RET(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)); }
// _Xtime_get_ticks(): 100 ns units since 1970
CP(_Xtime_get_ticks) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); RET((uint64_t)t.tv_sec * 10000000ull + (uint64_t)t.tv_nsec / 100); }
CP(__Random_device_std__YAIXZ) { RET(arc4random()); }
static pthread_mutex_t sp_mu = PTHREAD_MUTEX_INITIALIZER;
CP(_Lock_shared_ptr_spin_lock) { pthread_mutex_lock(&sp_mu); }
CP(_Unlock_shared_ptr_spin_lock) { pthread_mutex_unlock(&sp_mu); }
// std::mutex's in-place storage: the type is kept; lock/unlock aren't imported by the games that use only these
CP(_Mtx_init_in_situ) { memset(PTR(A0), 0, 8); wr32(A0, (uint32_t)A1); }
CP(_Mtx_destroy_in_situ) {}
static void cxx_error(CPU *c, const char *what, uint64_t msg) {
    rt_log("[msvcp] std::%s%s%s\n", what, msg ? ": " : "", msg ? (const char *)PTR(msg) : "");
    rt_backtrace(c); abort();
}
CP(__Xout_of_range_std__YAXPEBD_Z) { cxx_error(c, "out_of_range", A0); }
CP(__Xlength_error_std__YAXPEBD_Z) { cxx_error(c, "length_error", A0); }
CP(__Xbad_alloc_std__YAXXZ) { cxx_error(c, "bad_alloc", 0); }
CP(__Xbad_function_call_std__YAXXZ) { cxx_error(c, "bad_function_call", 0); }
CP(__Xinvalid_argument_std__YAXPEBD_Z) { cxx_error(c, "invalid_argument", A0); }
CP(__Xruntime_error_std__YAXPEBD_Z) { cxx_error(c, "runtime_error", A0); }
