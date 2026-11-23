#include "com32.h"
// Universal CRT / VC runtime for 32-bit guests (api-ms-win-crt-*, vcruntime140, msvcp140): startup tables,
// heap, strings, stdio on host files, printf/scanf over guest va_lists, and the x87 / SSE2 math entry points.
#include "rt32.h"
#include <ctype.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

char rt_cmdline[1024] = "game.exe";   // the game project sets the real one

// ---------------- startup ----------------
static uint32_t atexit_fns[1024]; static int natexit;
static pthread_mutex_t atexit_mu = PTHREAD_MUTEX_INITIALIZER;
static void add_atexit(uint32_t f) { pthread_mutex_lock(&atexit_mu); if (natexit < 1024) atexit_fns[natexit++] = f; pthread_mutex_unlock(&atexit_mu); }
static void run_atexit(void) {
    CPU *c = rt_cpu();
    while (natexit > 0) { uint32_t f = atexit_fns[--natexit]; if (f && c) guest_call(c, f, 0, NULL); }
}
CSHIM(crt__initterm) {
    for (uint32_t p = ARG(0); p < ARG(1); p += 4) { uint32_t f = rd32(p); if (f) guest_call(c, f, 0, NULL); }
    return 0;
}
CSHIM(crt__initterm_e) {
    for (uint32_t p = ARG(0); p < ARG(1); p += 4) {
        uint32_t f = rd32(p);
        if (f) { uint32_t r = guest_call(c, f, 0, NULL); if (r) return r; }
    }
    return 0;
}
CSHIM(crt__initialize_onexit_table) { if (ARG(0)) memset(G2H(ARG(0)), 0, 12); return 0; }
CSHIM(crt__register_onexit_function) { add_atexit(ARG(1)); return 0; }
CSHIM(crt__crt_atexit) { add_atexit(ARG(0)); return 0; }
CSHIM(crt__register_thread_local_exe_atexit_callback) { return 0; }
CSHIM(crt__initialize_narrow_environment) { return 0; }
CSHIM(crt__configure_narrow_argv) { return 0; }
CSHIM(crt__get_narrow_winmain_command_line) {
    static uint32_t s;
    if (!s) {
        const char *p = rt_cmdline;
        if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; } else while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        s = gstrdup(p);
    }
    return s;
}
CSHIM(crt__set_app_type) { return 0; }
CSHIM(crt__set_fmode) { return 0; }
CSHIM(crt___p__commode) { static uint32_t p; if (!p) p = gcalloc(1, 4); return p; }
CSHIM(crt__set_new_mode) { return 0; }
CSHIM(crt__configthreadlocale) { return 1; }
CSHIM(crt___setusermatherr) { return 0; }
CSHIM(crt__controlfp_s) {
    // (unsigned *current, unsigned new, unsigned mask): the game only sets precision/rounding; report the default
    uint32_t cur = 0x0009001Fu;
    uint32_t nw = ARG(1), mask = ARG(2);
    if (mask & 0x300) {   // _MCW_RC: rounding -> x87 and SSE control
        uint32_t rc = (nw >> 8) & 3;   // _RC_NEAR 0, _RC_DOWN 0x100, _RC_UP 0x200, _RC_CHOP 0x300
        c->fcw = (uint16_t)((c->fcw & ~0xC00u) | (rc << 10));
        c->mxcsr = (c->mxcsr & ~0x6000u) | (rc << 13);
    }
    if (ARG(0)) wr32(ARG(0), cur);
    return 0;
}
CSHIM(crt__seh_filter_exe) { return 0; }
CSHIM(crt__except_handler4_common) { return 1; }   // ExceptionContinueSearch: no SEH is ever raised
CSHIM(crt___current_exception) { static uint32_t p; if (!p) p = gcalloc(1, 8); return p; }
CSHIM(crt___current_exception_context) { static uint32_t p; if (!p) p = gcalloc(1, 8); return p; }
CSHIM(crt_terminate) { rt_fatal("terminate() called by the game"); }
CSHIM(crt__purecall) { rt_fatal("pure virtual function call"); }
CSHIM(crt__Xlength_error_std__YAXPBD_Z) { rt_fatal("std::length_error: %s", STR(0) ? STR(0) : "?"); }
CSHIM(crt__cexit) { rt_log("[crt] _cexit from 0x%x", rd32(c->esp)); run_atexit(); return 0; }
CSHIM(crt__c_exit) { return 0; }
CSHIM(crt_exit) { rt_log("[crt] exit(%d) from 0x%x", (int)ARG(0), rd32(c->esp)); run_atexit(); com_callsites_dump(); fflush(NULL); _exit((int)ARG(0)); }
CSHIM(crt__exit) { rt_log("[crt] _exit(%d) from 0x%x", (int)ARG(0), rd32(c->esp)); com_callsites_dump(); fflush(NULL); _exit((int)ARG(0)); }
CSHIM(crt__errno) {
    uint32_t teb = c->fsbase;
    return teb + 0xF00;   // a per-thread int inside the TEB page
}

// ---------------- heap ----------------
CSHIM(crt_malloc) { return gmalloc(ARG(0)); }
CSHIM(crt_calloc) { return gcalloc(ARG(0), ARG(1)); }
CSHIM(crt_realloc) { return grealloc(ARG(0), ARG(1)); }
CSHIM(crt_free) { gfree(ARG(0)); return 0; }

// ---------------- memory / strings ----------------
CSHIM(crt_memcpy) { WATCH_BULK(ARG(0), ARG(2), "memcpy"); if (ARG(2)) memmove(G2H(ARG(0)), G2H(ARG(1)), ARG(2)); return ARG(0); }
CSHIM(crt_memmove) { WATCH_BULK(ARG(0), ARG(2), "memmove"); if (ARG(2)) memmove(G2H(ARG(0)), G2H(ARG(1)), ARG(2)); return ARG(0); }
CSHIM(crt_memset) { WATCH_BULK(ARG(0), ARG(2), "memset"); if (ARG(2)) memset(G2H(ARG(0)), (int)ARG(1), ARG(2)); return ARG(0); }
CSHIM(crt_memcmp) { return ARG(2) ? (uint32_t)memcmp(G2H(ARG(0)), G2H(ARG(1)), ARG(2)) : 0; }
CSHIM(crt_memchr) { void *p = ARG(2) ? memchr(G2H(ARG(0)), (int)ARG(1), ARG(2)) : NULL; return hg(p); }
CSHIM(crt_strchr) { return hg(strchr(STR(0), (int)ARG(1))); }
CSHIM(crt_strrchr) { return hg(strrchr(STR(0), (int)ARG(1))); }
CSHIM(crt_strstr) { return hg(strstr(STR(0), STR(1))); }
CSHIM(crt_wcsstr) {
    const uint16_t *h = WSTR(0), *n = WSTR(1);
    size_t nl = w_len(n);
    if (!nl) return ARG(0);
    for (; *h; h++) if (!memcmp(h, n, nl * 2)) return hg(h);
    return 0;
}
CSHIM(crt_strncpy) { strncpy(G2H(ARG(0)), STR(1), ARG(2)); return ARG(0); }
CSHIM(crt_strncat) { strncat(G2H(ARG(0)), STR(1), ARG(2)); return ARG(0); }
CSHIM(crt_strncmp) { return (uint32_t)strncmp(STR(0), STR(1), ARG(2)); }
CSHIM(crt__stricmp) { return (uint32_t)strcasecmp(STR(0), STR(1)); }
CSHIM(crt__strnicmp) { return (uint32_t)strncasecmp(STR(0), STR(1), ARG(2)); }
CSHIM(crt__strupr) { for (char *p = G2H(ARG(0)); *p; p++) *p = (char)toupper((unsigned char)*p); return ARG(0); }
CSHIM(crt_tolower) { return (uint32_t)tolower((int)ARG(0)); }
CSHIM(crt_toupper) { return (uint32_t)toupper((int)ARG(0)); }
CSHIM(crt_isdigit) { return (uint32_t)(ARG(0) < 256 && isdigit((int)ARG(0))); }
CSHIM(crt_isupper) { return (uint32_t)(ARG(0) < 256 && isupper((int)ARG(0))); }
static _Thread_local uint32_t strtok_next;
CSHIM(crt_strtok) {
    uint32_t s = ARG(0) ? ARG(0) : strtok_next;
    const char *d = STR(1);
    if (!s) return 0;
    char *p = G2H(s);
    p += strspn(p, d);
    if (!*p) { strtok_next = 0; return 0; }
    char *e = p + strcspn(p, d);
    if (*e) { *e = 0; strtok_next = H2G(e + 1); } else strtok_next = 0;
    return H2G(p);
}
CSHIM(crt_atoi) { return (uint32_t)atoi(STR(0)); }
CSHIM(crt_strtol) {
    char *end; long v = strtol(STR(0), &end, (int)ARG(2));
    if (ARG(1)) wr32(ARG(1), H2G(end));
    if (v > INT32_MAX) v = INT32_MAX; if (v < INT32_MIN) v = INT32_MIN;
    return (uint32_t)(int32_t)v;
}
RAWSHIM(crt_atof) { FPUSH(c, atof(STR(0))); }
CSHIM(crt_mbstowcs) {
    const char *s = STR(1); size_t n = strlen(s);
    if (!ARG(0)) return (uint32_t)n;
    uint32_t k = 0;
    for (; k < ARG(2) && k <= n; k++) wr16(ARG(0) + 2 * k, (uint8_t)s[k]);
    return k > n ? (uint32_t)n : k;
}
static _Thread_local uint32_t rand_state = 1;
CSHIM(crt_rand) { rand_state = rand_state * 214013u + 2531011u; return (rand_state >> 16) & 0x7FFF; }
// qsort: the comparator must only ever see pointers into the guest's array (host qsort may sort through a
// temporary host buffer), so sort in place in guest memory: quicksort with insertion sort for short ranges.
static int q_cmp(CPU *c, uint32_t cmp, uint32_t a, uint32_t b) { uint32_t args[2] = {a, b}; return (int32_t)guest_call(c, cmp, 2, args); }
static void q_swap(uint32_t a, uint32_t b, uint32_t w) {
    if (a == b) return;
    uint8_t *x = G2H(a), *y = G2H(b), t;
    for (uint32_t i = 0; i < w; i++) { t = x[i]; x[i] = y[i]; y[i] = t; }
}
static void q_sort(CPU *c, uint32_t base, uint32_t n, uint32_t w, uint32_t cmp) {
    while (n > 8) {
        uint32_t mid = base + (n / 2) * w, last = base + (n - 1) * w;
        // median of three to the front, then Hoare-style partition around it
        if (q_cmp(c, cmp, mid, base) < 0) q_swap(mid, base, w);
        if (q_cmp(c, cmp, last, base) < 0) q_swap(last, base, w);
        if (q_cmp(c, cmp, last, mid) < 0) q_swap(last, mid, w);
        q_swap(base, mid, w);   // pivot at base
        uint32_t i = 1, j = n - 1;
        for (;;) {
            while (i <= j && q_cmp(c, cmp, base + i * w, base) < 0) i++;
            while (j >= i && q_cmp(c, cmp, base + j * w, base) > 0) j--;
            if (i >= j) break;
            q_swap(base + i * w, base + j * w, w); i++; j--;
        }
        q_swap(base, base + j * w, w);
        // recurse into the smaller half, loop on the larger
        if (j < n - j - 1) { q_sort(c, base, j, w, cmp); base += (j + 1) * w; n -= j + 1; }
        else { q_sort(c, base + (j + 1) * w, n - j - 1, w, cmp); n = j; }
    }
    for (uint32_t i = 1; i < n; i++)
        for (uint32_t k = i; k > 0 && q_cmp(c, cmp, base + (k - 1) * w, base + k * w) > 0; k--) q_swap(base + (k - 1) * w, base + k * w, w);
}
CSHIM(crt_qsort) {
    if (ARG(1) > 1 && ARG(2)) q_sort(c, ARG(0), ARG(1), ARG(2), ARG(3));
    return 0;
}

// ---------------- time ----------------
RAWSHIM(crt__time64) {
    int64_t t = (int64_t)time(NULL);
    if (ARG(0)) wr64(ARG(0), (uint64_t)t);
    c->eax = (uint32_t)t; c->edx = (uint32_t)((uint64_t)t >> 32);
}
static uint32_t tm_buf(void) { return rt_cpu()->fsbase + 0xF40; }   // per-thread struct tm (9 ints) in the TEB page
CSHIM(crt__localtime64) {
    time_t t = (time_t)(int64_t)rd64(ARG(0)); struct tm lt;
    if (!localtime_r(&t, &lt)) return 0;
    uint32_t b = tm_buf();
    int v[9] = {lt.tm_sec, lt.tm_min, lt.tm_hour, lt.tm_mday, lt.tm_mon, lt.tm_year, lt.tm_wday, lt.tm_yday, lt.tm_isdst};
    for (int k = 0; k < 9; k++) wr32(b + 4 * k, (uint32_t)v[k]);
    return b;
}
RAWSHIM(crt__mktime64) {
    uint32_t b = ARG(0); struct tm lt = {0};
    lt.tm_sec = (int)rd32(b); lt.tm_min = (int)rd32(b + 4); lt.tm_hour = (int)rd32(b + 8); lt.tm_mday = (int)rd32(b + 12);
    lt.tm_mon = (int)rd32(b + 16); lt.tm_year = (int)rd32(b + 20); lt.tm_isdst = (int)rd32(b + 32);
    int64_t t = (int64_t)mktime(&lt);
    c->eax = (uint32_t)t; c->edx = (uint32_t)((uint64_t)t >> 32);
}

// ---------------- stdio ----------------
#define NFILES 256
static FILE *files[NFILES];
#define FILE_G(i) (0x7FFE0000u + 0x40u * (uint32_t)(i))   // FILE* values the guest sees (never dereferenced)
static FILE *fget(uint32_t g) {
    if (g < 0x7FFE0000u) return NULL;
    uint32_t i = (g - 0x7FFE0000u) / 0x40;
    return i < NFILES ? files[i] : NULL;
}
CSHIM(crt_fopen) {
    char p[1024]; rt_host_path(STR(0), p, sizeof p);
    char mode[16]; snprintf(mode, sizeof mode, "%s", STR(1));
    for (char *m = mode; *m; m++) if (*m == 't') *m = 'b';
    FILE *f = fopen(p, mode);
    if (getenv("RT_TRACE_FILES")) rt_log("[file] fopen %s (%s) -> %s", p, mode, f ? "ok" : "fail");
    if (!f) return 0;
    for (int i = 1; i < NFILES; i++) if (!files[i]) { files[i] = f; return FILE_G(i); }
    fclose(f); return 0;
}
CSHIM(crt_fclose) {
    FILE *f = fget(ARG(0)); if (!f) return (uint32_t)-1;
    files[(ARG(0) - 0x7FFE0000u) / 0x40] = NULL;
    return (uint32_t)fclose(f);
}
CSHIM(crt_fread) { WATCH_BULK(ARG(0), ARG(1) * ARG(2), "fread"); FILE *f = fget(ARG(3)); return f ? (uint32_t)fread(G2H(ARG(0)), ARG(1), ARG(2), f) : 0; }
CSHIM(crt_fseek) { FILE *f = fget(ARG(0)); return f ? (uint32_t)fseeko(f, (int32_t)ARG(1), (int)ARG(2)) : (uint32_t)-1; }
CSHIM(crt__fseeki64) { FILE *f = fget(ARG(0)); return f ? (uint32_t)fseeko(f, (off_t)(int64_t)ARG64(1), (int)ARG(3)) : (uint32_t)-1; }
CSHIM(crt_ftell) { FILE *f = fget(ARG(0)); return f ? (uint32_t)ftello(f) : (uint32_t)-1; }
CSHIM(crt_rename) { char a[1024], b[1024]; return (uint32_t)rename(rt_host_path(STR(0), a, sizeof a), rt_host_path(STR(1), b, sizeof b)); }
CSHIM(crt_remove) { char a[1024]; return (uint32_t)remove(rt_host_path(STR(0), a, sizeof a)); }

// ---------------- printf / scanf over guest va_lists ----------------
typedef struct { char *buf; size_t cap, len; } Out;
static void out_put(Out *o, const char *s, size_t n) {
    if (o->len + n + 1 > o->cap) { o->cap = (o->len + n + 1) * 2; o->buf = realloc(o->buf, o->cap); }
    memcpy(o->buf + o->len, s, n); o->len += n; o->buf[o->len] = 0;
}
// format into a host UTF-8 buffer; wide: the guest's %s/%c are UTF-16 (and %hs/%S narrow)
static char *gfmt(const char *fmt, uint32_t ap, int wide) {
    Out o = {0};
    out_put(&o, "", 0);
    for (const char *p = fmt; *p; ) {
        if (*p != '%') { const char *q = strchr(p, '%'); size_t n = q ? (size_t)(q - p) : strlen(p); out_put(&o, p, n); p += n; continue; }
        if (p[1] == '%') { out_put(&o, "%", 1); p += 2; continue; }
        char spec[64]; int k = 0; spec[k++] = *p++;
        while (*p && strchr("-+ #0", *p) && k < 40) spec[k++] = *p++;
        if (*p == '*') { k += snprintf(spec + k, 12, "%d", (int32_t)rd32(ap)); ap += 4; p++; } else while (isdigit((unsigned char)*p) && k < 40) spec[k++] = *p++;
        if (*p == '.') { spec[k++] = *p++; if (*p == '*') { k += snprintf(spec + k, 12, "%d", (int32_t)rd32(ap)); ap += 4; p++; } else while (isdigit((unsigned char)*p) && k < 50) spec[k++] = *p++; }
        int len64 = 0, lng = 0, shrt = 0;
        for (;;) {
            if (p[0] == 'I' && p[1] == '6' && p[2] == '4') { len64 = 1; p += 3; }
            else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') { p += 3; }
            else if (*p == 'l' && p[1] == 'l') { len64 = 1; p += 2; }
            else if (*p == 'l' || *p == 'w') { lng = 1; p++; }
            else if (*p == 'h') { shrt = 1; p++; }
            else if (*p == 'L' || *p == 'z' || *p == 'j' || *p == 't' || *p == 'I') { if (*p == 'j') len64 = 1; p++; }
            else break;
        }
        char t = *p ? *p++ : 0; char tmp[512];
        switch (t) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
            if (len64) { uint64_t v = rd64(ap); ap += 8; spec[k++] = 'l'; spec[k++] = 'l'; spec[k++] = t; spec[k] = 0; snprintf(tmp, sizeof tmp, spec, v); }
            else { uint32_t v = rd32(ap); ap += 4; spec[k++] = t; spec[k] = 0;
                   if (t == 'd' || t == 'i') snprintf(tmp, sizeof tmp, spec, shrt ? (int)(int16_t)v : (int)(int32_t)v);
                   else snprintf(tmp, sizeof tmp, spec, shrt ? (unsigned)(uint16_t)v : v); }
            out_put(&o, tmp, strlen(tmp)); break;
        }
        case 'p': { uint32_t v = rd32(ap); ap += 4; snprintf(tmp, sizeof tmp, "%08X", v); out_put(&o, tmp, strlen(tmp)); break; }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            double v = rdd(ap); ap += 8; spec[k++] = t; spec[k] = 0; snprintf(tmp, sizeof tmp, spec, v); out_put(&o, tmp, strlen(tmp)); break;
        }
        case 'c': case 'C': {
            uint32_t v = rd32(ap); ap += 4;
            int w = (t == 'C') ? !wide : (wide ? !shrt : lng);
            char u[8]; uint16_t ws[2] = {(uint16_t)v, 0};
            if (w) w_to_utf8(ws, u, sizeof u); else { u[0] = (char)v; u[1] = 0; }
            spec[k++] = 's'; spec[k] = 0; snprintf(tmp, sizeof tmp, spec, u); out_put(&o, tmp, strlen(tmp)); break;
        }
        case 's': case 'S': {
            uint32_t v = rd32(ap); ap += 4;
            int w = (t == 'S') ? !wide : (wide ? !shrt : lng);
            const char *s = "(null)"; char *heap = NULL;
            if (v) {
                if (w) { size_t n = w_len(G2H(v)); heap = malloc(n * 4 + 1); w_to_utf8(G2H(v), heap, n * 4 + 1); s = heap; }
                else s = G2H(v);
            }
            spec[k++] = 's'; spec[k] = 0;
            int n = snprintf(NULL, 0, spec, s); char *b = malloc((size_t)n + 1); snprintf(b, (size_t)n + 1, spec, s);
            out_put(&o, b, (size_t)n); free(b); free(heap);
            break;
        }
        case 'n': { uint32_t v = rd32(ap); ap += 4; if (v) wr32(v, (uint32_t)o.len); break; }
        default: out_put(&o, spec, (size_t)k); if (t) out_put(&o, &t, 1); break;
        }
    }
    return o.buf;
}
static uint32_t put_narrow(uint32_t buf, uint32_t cap, const char *s, int std_behavior) {
    size_t n = strlen(s);
    if (!buf || !cap) return (uint32_t)n;
    size_t w = n < cap - 1 ? n : cap - 1;
    memcpy(G2H(buf), s, w); wr8(buf + (uint32_t)w, 0);
    return (n >= cap && !std_behavior) ? 0xFFFFFFFFu : (uint32_t)n;
}
// __stdio_common_vsprintf(u64 options, char *buf, size_t count, const char *fmt, locale, va_list)
CSHIM(crt___stdio_common_vsprintf) {
    char *s = gfmt(STR(4), ARG(6), 0);
    uint32_t r = put_narrow(ARG(2), ARG(3), s, (ARG(0) & 2) != 0);
    free(s); return r;
}
// __stdio_common_vsnprintf_s(u64 options, char *buf, size_t size, size_t count, const char *fmt, locale, va_list)
CSHIM(crt___stdio_common_vsnprintf_s) {
    char *s = gfmt(STR(5), ARG(7), 0);
    uint32_t size = ARG(3), count = ARG(4), buf = ARG(2);
    size_t n = strlen(s), lim = count == 0xFFFFFFFFu ? size - 1 : (count < size - 1 ? count : size - 1);
    size_t w = n < lim ? n : lim;
    if (buf && size) { memcpy(G2H(buf), s, w); wr8(buf + (uint32_t)w, 0); }
    free(s);
    return n > lim ? 0xFFFFFFFFu : (uint32_t)n;
}
// __stdio_common_vswprintf(u64 options, wchar_t *buf, size_t count, const wchar_t *fmt, locale, va_list)
CSHIM(crt___stdio_common_vswprintf) {
    size_t fl = w_len(WSTR(4)); char *f8 = malloc(fl * 4 + 1); w_to_utf8(WSTR(4), f8, fl * 4 + 1);
    char *s = gfmt(f8, ARG(6), 1); free(f8);
    size_t n8 = strlen(s); uint16_t *w = malloc((n8 + 2) * 2); utf8_to_w(s, w, n8 + 2); free(s);
    size_t n = w_len(w); uint32_t buf = ARG(2), cap = ARG(3), r;
    if (!buf || !cap) r = (uint32_t)n;
    else { size_t k = n < cap - 1 ? n : cap - 1; memcpy(G2H(buf), w, k * 2); wr16(buf + 2 * (uint32_t)k, 0); r = (n >= cap && !(ARG(0) & 2)) ? 0xFFFFFFFFu : (uint32_t)n; }
    free(w); return r;
}
// (in all __stdio_common_* entry points the u64 options take stack slots 0-1, so the buffer is ARG(2))

// scanf: conversions write through guest pointers taken from the va_list (an array of pointers)
static int gscan(const char *in, const char *fmt, uint32_t ap, int wide_args) {
    const char *s = in; int assigned = 0;
    for (const char *p = fmt; *p; ) {
        if (isspace((unsigned char)*p)) { while (isspace((unsigned char)*s)) s++; p++; continue; }
        if (*p != '%') { if (*s != *p) break; s++; p++; continue; }
        p++;
        if (*p == '%') { if (*s != '%') break; s++; p++; continue; }
        int suppress = 0, width = 0, len64 = 0, shrt = 0, lng = 0;
        if (*p == '*') { suppress = 1; p++; }
        while (isdigit((unsigned char)*p)) width = width * 10 + (*p++ - '0');
        for (;;) {
            if (p[0] == 'I' && p[1] == '6' && p[2] == '4') { len64 = 1; p += 3; }
            else if (*p == 'l' && p[1] == 'l') { len64 = 1; p += 2; }
            else if (*p == 'l' || *p == 'L') { lng = 1; p++; }
            else if (*p == 'h') { shrt = 1; p++; }
            else break;
        }
        char t = *p++;
        if (t != 'c' && t != '[' && t != 'n') while (isspace((unsigned char)*s)) s++;
        if (!*s && t != 'n') break;
        char field[512]; size_t fl = 0;
        size_t maxw = width ? (size_t)width : sizeof field - 1;
        if (t == 'n') { if (!suppress) { wr32(rd32(ap), (uint32_t)(s - in)); ap += 4; } continue; }
        if (t == 'c') {
            size_t n = width ? (size_t)width : 1;
            if (strlen(s) < n) break;
            if (!suppress) { uint32_t dst = rd32(ap); ap += 4; for (size_t i = 0; i < n; i++) { if (wide_args && !shrt) wr16(dst + 2 * (uint32_t)i, (uint8_t)s[i]); else wr8(dst + (uint32_t)i, (uint8_t)s[i]); } assigned++; }
            s += n; continue;
        }
        if (t == 's' || t == '[') {
            char set[256] = {0}; int neg = 0;
            if (t == '[') {
                if (*p == '^') { neg = 1; p++; }
                if (*p == ']') { set[']'] = 1; p++; }
                while (*p && *p != ']') { if (p[1] == '-' && p[2] && p[2] != ']') { for (int ch = (unsigned char)p[0]; ch <= (unsigned char)p[2]; ch++) set[ch] = 1; p += 3; } else set[(unsigned char)*p++] = 1; }
                if (*p == ']') p++;
            }
            while (*s && fl < maxw && (t == 's' ? !isspace((unsigned char)*s) : (set[(unsigned char)*s] ^ neg))) field[fl++] = *s++;
            if (!fl) break;
            field[fl] = 0;
            if (!suppress) {
                uint32_t dst = rd32(ap); ap += 4;
                if ((wide_args && !shrt) || lng) { for (size_t i = 0; i <= fl; i++) wr16(dst + 2 * (uint32_t)i, (uint8_t)field[i]); }
                else memcpy(G2H(dst), field, fl + 1);
                assigned++;
            }
            continue;
        }
        // numbers
        while (*s && fl < maxw && fl < sizeof field - 1 && (isalnum((unsigned char)*s) || strchr("+-.", *s))) field[fl++] = *s++;
        field[fl] = 0;
        char *end = field;
        if (t == 'f' || t == 'e' || t == 'g' || t == 'E' || t == 'G' || t == 'a') {
            double v = strtod(field, &end);
            if (end == field) break;
            if (!suppress) { uint32_t dst = rd32(ap); ap += 4; if (lng) wrd(dst, v); else wrf(dst, (float)v); assigned++; }
        } else {
            int base = t == 'x' || t == 'X' ? 16 : t == 'o' ? 8 : t == 'i' ? 0 : 10;
            long long v = (t == 'u' || t == 'x' || t == 'X' || t == 'o') ? (long long)strtoull(field, &end, base) : strtoll(field, &end, base);
            if (end == field) break;
            if (!suppress) {
                uint32_t dst = rd32(ap); ap += 4;
                if (len64) wr64(dst, (uint64_t)v); else if (shrt) wr16(dst, (uint16_t)v); else wr32(dst, (uint32_t)v);
                assigned++;
            }
        }
        s -= fl - (size_t)(end - field);   // give back what the number didn't use
    }
    return assigned;
}
// __stdio_common_vsscanf(u64 options, const char *buf, size_t count, const char *fmt, locale, va_list)
CSHIM(crt___stdio_common_vsscanf) { return (uint32_t)gscan(STR(2), STR(4), ARG(6), 0); }
CSHIM(crt___stdio_common_vswscanf) {
    size_t a = w_len(WSTR(2)), b = w_len(WSTR(4));
    char *in = malloc(a * 4 + 1), *f = malloc(b * 4 + 1);
    w_to_utf8(WSTR(2), in, a * 4 + 1); w_to_utf8(WSTR(4), f, b * 4 + 1);
    int r = gscan(in, f, ARG(6), 1);
    free(in); free(f);
    return (uint32_t)r;
}

// ---------------- math ----------------
// __libm_sse2_*: argument(s) and result in xmm0 (xmm1 second), the SSE2 calling convention of MSVC's libm
#define SSE2D(name, expr) RAWSHIM(crt___libm_sse2_##name) { double x = c->xmm[0].d[0], y = c->xmm[1].d[0]; (void)y; c->xmm[0].d[0] = (expr); }
#define SSE2F(name, expr) RAWSHIM(crt___libm_sse2_##name) { float x = c->xmm[0].f[0], y = c->xmm[1].f[0]; (void)y; c->xmm[0].f[0] = (expr); }
SSE2D(sin, sin(x)) SSE2D(cos, cos(x)) SSE2D(pow, pow(x, y)) SSE2D(atan2, atan2(x, y)) SSE2D(log, log(x)) SSE2D(log10, log10(x))
SSE2F(sinf, sinf(x)) SSE2F(cosf, cosf(x)) SSE2F(tanf, tanf(x)) SSE2F(acosf, acosf(x)) SSE2F(asinf, asinf(x)) SSE2F(atanf, atanf(x))
SSE2F(expf, expf(x)) SSE2F(logf, logf(x)) SSE2F(log10f, log10f(x)) SSE2F(powf, powf(x, y))
// _CI*: x87 intrinsic forms, argument(s) on the x87 stack, result in st0
#define CI1(name, expr) RAWSHIM(crt__CI##name) { double x = ST(0); ST(0) = (expr); }
#define CI2(name, expr) RAWSHIM(crt__CI##name) { double y = ST(0), x = ST(1); FPOP(c); ST(0) = (expr); }
CI1(sin, sin(x)) CI1(cos, cos(x)) CI1(acos, acos(x)) CI1(atan, atan(x)) CI1(sqrt, sqrt(x)) CI1(exp, exp(x)) CI1(log, log(x))
CI2(pow, pow(x, y)) CI2(fmod, fmod(x, y))
// cdecl doubles on the stack, result in st0
RAWSHIM(crt_sin) { FPUSH(c, sin(ARGD(0))); }
RAWSHIM(crt_cos) { FPUSH(c, cos(ARGD(0))); }
RAWSHIM(crt_floor) { FPUSH(c, floor(ARGD(0))); }
RAWSHIM(crt_ceil) { FPUSH(c, ceil(ARGD(0))); }
RAWSHIM(crt_ldexp) { FPUSH(c, ldexp(ARGD(0), (int)ARG(2))); }
CSHIM(crt__finite) { return isfinite(ARGD(0)) ? 1 : 0; }
CSHIM(crt__isnan) { return isnan(ARGD(0)) ? 1 : 0; }
