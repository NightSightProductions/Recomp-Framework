// UCRT stdio and filesystem (api-ms-win-crt-stdio / -filesystem): printf and scanf in Microsoft's dialect,
// FILE streams, low-level file descriptors, _stat, _findfirst and friends. See ucrt.c.
//
// A guest FILE * points at a GFile here (the UCRT's own FILE is opaque to programs, so nothing reads into it).
// stdout and stderr go to the runtime's log. Guest file descriptors are host file descriptors.
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rt.h"
#include "handles.h"
#include "ucrt.h"

#define API(set, name) void I_api_ms_win_crt_##set##_l1_1_0_dll_##name(CPU *c)
#define TRUNCATE ((size_t)-1)

// ---------------- output buffer (bytes or UTF-16 units) ----------------
typedef struct { int wide; size_t n, cap; void *p; } Out;
static void out_room(Out *o, size_t k) {
    size_t u = o->wide ? 2 : 1;
    if (o->n + k + 1 > o->cap) { o->cap = (o->n + k + 1) * 2 + 64; o->p = realloc(o->p, o->cap * u); }
}
static void out_unit(Out *o, uint32_t ch) {
    out_room(o, 1);
    if (o->wide) ((uint16_t *)o->p)[o->n++] = (uint16_t)ch; else ((char *)o->p)[o->n++] = (char)ch;
}
static void out_rep(Out *o, uint32_t ch, int k) { while (k-- > 0) out_unit(o, ch); }
// a narrow (UTF-8) string, at most prec characters
static void out_narrow(Out *o, const char *s, size_t len) {
    if (!o->wide) { out_room(o, len); memcpy((char *)o->p + o->n, s, len); o->n += len; return; }
    char *t = strndup(s, len); uint16_t *w = utf8_to_w16(t); free(t);
    for (size_t i = 0; w[i]; i++) out_unit(o, w[i]);
    free(w);
}
static void out_wide(Out *o, const uint16_t *s, size_t len) {
    if (o->wide) { out_room(o, len); memcpy((uint16_t *)o->p + o->n, s, len * 2); o->n += len; return; }
    uint16_t *t = malloc((len + 1) * 2); memcpy(t, s, len * 2); t[len] = 0;
    char *u = w16_to_utf8(t); free(t);
    out_narrow(o, u, strlen(u)); free(u);
}
static void out_pad(Out *o, size_t start, int width, int left) {
    // pad the field written since `start` to `width` units, with spaces (left- or right-justified)
    int have = (int)(o->n - start);
    if (have >= width) return;
    int k = width - have;
    if (left) { out_rep(o, ' ', k); return; }
    out_room(o, (size_t)k);
    size_t u = o->wide ? 2 : 1;
    memmove((char *)o->p + (start + k) * u, (char *)o->p + start * u, (size_t)have * u);
    for (int i = 0; i < k; i++) { if (o->wide) ((uint16_t *)o->p)[start + i] = ' '; else ((char *)o->p)[start + i] = ' '; }
    o->n += k;
}

// ---------------- printf ----------------
#define OPT_LEGACY_WIDE 4   // _CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS: in wide functions %s/%c are wide
void *ucrt_format(int wide, uint64_t opts, const void *fmtp, uint64_t va, size_t *len) {
    Out o = { wide, 0, 0, NULL };
    const uint8_t *f8 = fmtp; const uint16_t *f16 = fmtp;
    size_t i = 0;
    #define FC(k) (wide ? (uint32_t)f16[k] : (uint32_t)f8[k])
    #define NEXT() (va += 8, rd64(va - 8))
    out_room(&o, 0);
    for (;;) {
        uint32_t ch = FC(i);
        if (!ch) break;
        if (ch != '%') { out_unit(&o, ch); i++; continue; }
        i++;
        char flags[8]; int nf = 0, left = 0, zero = 0;
        for (;;) {
            uint32_t k = FC(i);
            if (k == '-' || k == '+' || k == ' ' || k == '#' || k == '0') {
                if (k == '-') left = 1;
                if (k == '0') zero = 1;
                if (nf < 6) flags[nf++] = (char)k;
                i++;
            } else break;
        }
        flags[nf] = 0;
        int width = -1, prec = -1;
        if (FC(i) == '*') { width = (int)(uint32_t)NEXT(); i++; if (width < 0) { left = 1; width = -width; } }
        else { while (FC(i) >= '0' && FC(i) <= '9') { width = (width < 0 ? 0 : width) * 10 + (int)(FC(i) - '0'); i++; } }
        if (FC(i) == '.') {
            i++; prec = 0;
            if (FC(i) == '*') { prec = (int)(uint32_t)NEXT(); i++; if (prec < 0) prec = -1; }
            else while (FC(i) >= '0' && FC(i) <= '9') { prec = prec * 10 + (int)(FC(i) - '0'); i++; }
        }
        // size: 1 char, 2 short, 4 int/long, 8 long long / pointer-sized; sz_wide: l/w; sz_narrow: h
        int size = 4, sz_wide = 0, sz_narrow = 0;
        for (;;) {
            uint32_t k = FC(i);
            if (k == 'h') { if (FC(i + 1) == 'h') { size = 1; i += 2; } else { size = 2; sz_narrow = 1; i++; } }
            else if (k == 'l') { if (FC(i + 1) == 'l') { size = 8; i += 2; } else { size = 4; sz_wide = 1; i++; } }
            else if (k == 'w') { sz_wide = 1; i++; }
            else if (k == 'L') { size = 8; i++; }
            else if (k == 'j' || k == 'z' || k == 't') { size = 8; i++; }
            else if (k == 'I') {
                if (FC(i + 1) == '6' && FC(i + 2) == '4') { size = 8; i += 3; }
                else if (FC(i + 1) == '3' && FC(i + 2) == '2') { size = 4; i += 3; }
                else { size = 8; i++; }
            } else break;
        }
        uint32_t cv = FC(i);
        if (!cv) break;
        i++;
        char spec[48];
        switch (cv) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
            uint64_t v = NEXT();
            int sgn = cv == 'd' || cv == 'i';
            if (size == 1) v = sgn ? (uint64_t)(int64_t)(int8_t)v : (uint8_t)v;
            else if (size == 2) v = sgn ? (uint64_t)(int64_t)(int16_t)v : (uint16_t)v;
            else if (size == 4) v = sgn ? (uint64_t)(int64_t)(int32_t)v : (uint32_t)v;
            char p[24] = "", w[24] = "";
            if (width >= 0) snprintf(w, sizeof w, "%d", width);
            if (prec >= 0) snprintf(p, sizeof p, ".%d", prec);
            snprintf(spec, sizeof spec, "%%%s%s%sll%c", flags, w, p, (char)cv);
            char buf[160]; int n = snprintf(buf, sizeof buf, spec, v);
            out_narrow(&o, buf, n < (int)sizeof buf ? (size_t)n : sizeof buf - 1);
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            uint64_t bits = NEXT(); double d; memcpy(&d, &bits, 8);
            char p[24] = "", w[24] = "";
            if (width >= 0) snprintf(w, sizeof w, "%d", width);
            if (prec >= 0) snprintf(p, sizeof p, ".%d", prec);
            snprintf(spec, sizeof spec, "%%%s%s%s%c", flags, w, p, (char)cv);
            int n = snprintf(NULL, 0, spec, d);
            char *buf = malloc((size_t)n + 1); snprintf(buf, (size_t)n + 1, spec, d);
            out_narrow(&o, buf, (size_t)n); free(buf);
            break;
        }
        case 'p': {   // Microsoft: 16 uppercase hex digits, no 0x
            char buf[24]; snprintf(buf, sizeof buf, "%016llX", (unsigned long long)NEXT());
            size_t st = o.n; out_narrow(&o, buf, 16); out_pad(&o, st, width, left);
            break;
        }
        case 'c': case 'C': {
            int w = wide ? ((opts & OPT_LEGACY_WIDE) ? cv == 'c' : cv == 'C') : cv == 'C';
            if (sz_wide) w = 1; else if (sz_narrow) w = 0;
            uint64_t v = NEXT(); size_t st = o.n;
            if (w) { uint16_t u = (uint16_t)v; out_wide(&o, &u, 1); }
            else { char b = (char)v; if (wide) out_unit(&o, (uint8_t)b); else out_narrow(&o, &b, 1); }
            out_pad(&o, st, width, left);
            break;
        }
        case 's': case 'S': case 'Z': {
            int w = wide ? ((opts & OPT_LEGACY_WIDE) ? cv == 's' : cv == 'S') : cv == 'S';
            if (sz_wide) w = 1; else if (sz_narrow) w = 0;
            uint64_t p = NEXT(); size_t st = o.n;
            if (cv == 'Z' && p) {   // ANSI_STRING / UNICODE_STRING: { u16 Length (bytes), u16 Max, ptr Buffer }
                uint16_t bl = rd16(p); uint64_t b = rd64(p + 8);
                if (w) out_wide(&o, PTR(b), bl / 2); else out_narrow(&o, PTR(b), bl);
            } else if (!p) out_narrow(&o, w ? "(null)" : "(null)", 6);
            else if (w) { const uint16_t *s = PTR(p); size_t n = 0; while ((prec < 0 || (int)n < prec) && s[n]) n++; out_wide(&o, s, n); }
            else { const char *s = PTR(p); size_t n = prec < 0 ? strlen(s) : strnlen(s, (size_t)prec); out_narrow(&o, s, n); }
            out_pad(&o, st, width, left);
            break;
        }
        case 'n': {
            uint64_t p = NEXT();
            if (p) { if (size == 8) wr64(p, o.n); else if (size == 2) wr16(p, (uint16_t)o.n); else if (size == 1) wr8(p, (uint8_t)o.n); else wr32(p, (uint32_t)o.n); }
            break;
        }
        case '%': out_unit(&o, '%'); break;
        default: out_unit(&o, '%'); out_unit(&o, cv); break;
        }
        (void)zero;
    }
    #undef FC
    #undef NEXT
    out_room(&o, 0);
    if (o.wide) ((uint16_t *)o.p)[o.n] = 0; else ((char *)o.p)[o.n] = 0;
    *len = o.n;
    return o.p;
}

// The sprintf family. options bit 1 (_CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR): C99 snprintf (truncate,
// return the full length); otherwise Microsoft's _vsnprintf (-1 when it doesn't fit, no null when it exactly fits).
static int64_t put_sprintf(int wide, uint64_t opts, uint64_t buf, size_t count, const void *src, size_t n) {
    size_t u = wide ? 2 : 1;
    if (!buf) return (int64_t)n;
    if (opts & 2) {
        if (count) { size_t k = n < count - 1 ? n : count - 1; memcpy(PTR(buf), src, k * u); memset((char *)PTR(buf) + k * u, 0, u); }
        return (int64_t)n;
    }
    if (n < count) { memcpy(PTR(buf), src, (n + 1) * u); return (int64_t)n; }
    memcpy(PTR(buf), src, count * u);
    if (n == count && !(opts & 1)) return (int64_t)n;
    if (count && (opts & 1)) memset((char *)PTR(buf) + (count - 1) * u, 0, u);
    return -1;
}
// __stdio_common_vsprintf(options, buffer, count, format, locale, va)
API(stdio, __stdio_common_vsprintf) {
    size_t n; void *s = ucrt_format(0, A0, PTR(A3), AN(5), &n);
    RET((uint64_t)put_sprintf(0, A0, A1, A2, s, n)); free(s);
}
API(stdio, __stdio_common_vswprintf) {
    size_t n; void *s = ucrt_format(1, A0, PTR(A3), AN(5), &n);
    RET((uint64_t)put_sprintf(1, A0, A1, A2, s, n)); free(s);
}
// __stdio_common_vsprintf_s(options, buffer, count, format, locale, va): the whole result or an error
static int64_t put_sprintf_s(int wide, uint64_t buf, size_t count, const void *src, size_t n) {
    size_t u = wide ? 2 : 1;
    if (!buf || !count) { ucrt_set_errno(22); return -1; }
    if (n >= count) { memset(PTR(buf), 0, u); ucrt_set_errno(34); return -1; }
    memcpy(PTR(buf), src, (n + 1) * u); return (int64_t)n;
}
API(stdio, __stdio_common_vsprintf_s) {
    size_t n; void *s = ucrt_format(0, A0, PTR(A3), AN(5), &n);
    RET((uint64_t)put_sprintf_s(0, A1, A2, s, n)); free(s);
}
API(stdio, __stdio_common_vswprintf_s) {
    size_t n; void *s = ucrt_format(1, A0, PTR(A3), AN(5), &n);
    RET((uint64_t)put_sprintf_s(1, A1, A2, s, n)); free(s);
}
// __stdio_common_vsnprintf_s(options, buffer, bufcount, maxcount, format, locale, va)
static int64_t put_snprintf_s(int wide, uint64_t buf, size_t cap, size_t maxc, const void *src, size_t n) {
    size_t u = wide ? 2 : 1;
    if (!buf || !cap) { ucrt_set_errno(22); return -1; }
    size_t lim = maxc == TRUNCATE ? cap - 1 : (maxc < cap ? maxc : cap - 1);
    if (n <= lim) { memcpy(PTR(buf), src, (n + 1) * u); return (int64_t)n; }
    if (maxc == TRUNCATE || maxc < cap) { memcpy(PTR(buf), src, lim * u); memset((char *)PTR(buf) + lim * u, 0, u); return -1; }
    memset(PTR(buf), 0, u); ucrt_set_errno(34); return -1;
}
API(stdio, __stdio_common_vsnprintf_s) {
    size_t n; void *s = ucrt_format(0, A0, PTR(AN(4)), AN(6), &n);
    RET((uint64_t)put_snprintf_s(0, A1, A2, A3, s, n)); free(s);
}
API(stdio, __stdio_common_vsnwprintf_s) {
    size_t n; void *s = ucrt_format(1, A0, PTR(AN(4)), AN(6), &n);
    RET((uint64_t)put_snprintf_s(1, A1, A2, A3, s, n)); free(s);
}

// ---------------- FILE streams ----------------
#define GFILE_MAGIC 0x454C4946u   // "FILE"
typedef struct { uint64_t placeholder; uint32_t magic; int fd; FILE *f; int text, std; } GFile;
static GFile g_std[3] = { { 0, GFILE_MAGIC, 0, NULL, 1, 1 }, { 0, GFILE_MAGIC, 1, NULL, 1, 2 }, { 0, GFILE_MAGIC, 2, NULL, 1, 3 } };
static GFile *gf(uint64_t p) {
    GFile *g = PTR(p);
    if (!g || g->magic != GFILE_MAGIC) { ucrt_set_errno(22); return NULL; }
    if (g->std == 1 && !g->f) g->f = stdin;
    return g;
}
// stdout / stderr: into the log, a line at a time
static void std_write(GFile *g, const char *s, size_t n) {
    (void)g;
    if (n) rt_log("%.*s", (int)n, s);
}
API(stdio, __acrt_iob_func) { RET(A0 < 3 ? G(&g_std[A0]) : 0); }
// a Microsoft fopen mode ("rb", "wt", "a+, ccs=UTF-8", "rN"...) as a host one
static void host_mode(const char *m, char *out, int *text) {
    int k = 0; *text = 1;
    for (; *m && *m != ','; m++) {
        if (strchr("rwa+", *m)) out[k++] = *m;
        else if (*m == 'b') { *text = 0; }
        else if (*m == 'x' && k < 6) out[k++] = 'x';
    }
    out[k++] = 0;
}
static uint64_t open_file(const char *win, const char *mode) {
    char hm[8]; int text; host_mode(mode, hm, &text);
    char *h = rt_host_path(win);
    if (!h) { ucrt_set_errno(2); return 0; }
    FILE *f = fopen(h, hm); free(h);
    if (!f) { ucrt_set_errno(ucrt_errno_from_host(errno)); return 0; }
    GFile *g = calloc(1, sizeof *g); g->magic = GFILE_MAGIC; g->f = f; g->fd = fileno(f); g->text = text;
    return G(g);
}
API(stdio, fopen) { RET(open_file(PTR(A0), PTR(A1))); }
API(stdio, _fsopen) { RET(open_file(PTR(A0), PTR(A1))); }
API(stdio, fopen_s) {   // fopen_s(*file, name, mode)
    uint64_t f = open_file(PTR(A1), PTR(A2)); if (A0) wr64(A0, f);
    RET(f ? 0 : 2);
}
static uint64_t open_wfile(uint64_t name, uint64_t mode) {
    char *n = w16_to_utf8(PTR(name)), *m = w16_to_utf8(PTR(mode));
    uint64_t f = open_file(n, m); free(n); free(m); return f;
}
API(stdio, _wfopen) { RET(open_wfile(A0, A1)); }
API(stdio, _wfsopen) { RET(open_wfile(A0, A1)); }
API(stdio, _wfopen_s) { uint64_t f = open_wfile(A1, A2); if (A0) wr64(A0, f); RET(f ? 0 : 2); }
API(stdio, _fdopen) {
    char hm[8]; int text; host_mode(PTR(A1), hm, &text);
    FILE *f = fdopen((int)A0, hm);
    if (!f) { ucrt_set_errno(ucrt_errno_from_host(errno)); RET(0); return; }
    GFile *g = calloc(1, sizeof *g); g->magic = GFILE_MAGIC; g->f = f; g->fd = (int)A0; g->text = text;
    RET(G(g));
}
API(stdio, fclose) {
    GFile *g = gf(A0); if (!g) { RET((uint64_t)-1); return; }
    if (g->std) { RET(0); return; }
    int r = fclose(g->f); g->magic = 0; free(g); RET((uint64_t)(int64_t)(r ? -1 : 0));
}
API(stdio, fread) {   // fread(buffer, size, count, file)
    GFile *g = gf(A3); if (!g || !g->f) { RET(0); return; }
    RET(fread(PTR(A0), A1, A2, g->f));
}
API(stdio, fwrite) {
    GFile *g = gf(A3); if (!g) { RET(0); return; }
    if (g->std > 1) { std_write(g, PTR(A0), A1 * A2); RET(A2); return; }
    RET(fwrite(PTR(A0), A1, A2, g->f));
}
API(stdio, fseek) {   // fseek(file, long offset (32 bits), origin)
    GFile *g = gf(A0); if (!g || !g->f) { RET((uint64_t)-1); return; }
    RET((uint64_t)(int64_t)fseeko(g->f, (off_t)(int32_t)A1, (int)A2));
}
API(stdio, _fseeki64) {
    GFile *g = gf(A0); if (!g || !g->f) { RET((uint64_t)-1); return; }
    RET((uint64_t)(int64_t)fseeko(g->f, (off_t)A1, (int)A2));
}
API(stdio, ftell) {
    GFile *g = gf(A0); if (!g || !g->f) { RET((uint64_t)-1); return; }
    off_t p = ftello(g->f); RET((uint32_t)(p > INT32_MAX ? -1 : (int32_t)p));
}
API(stdio, _ftelli64) { GFile *g = gf(A0); RET(g && g->f ? (uint64_t)ftello(g->f) : (uint64_t)-1); }
// fgets in text mode turns the CR of a CR LF line ending into nothing, as Windows' text streams do
API(stdio, fgets) {
    GFile *g = gf(A2); if (!g || !g->f || (int)A1 <= 0) { RET(0); return; }
    char *s = fgets(PTR(A0), (int)A1, g->f);
    if (s && g->text) { size_t n = strlen(s); if (n >= 2 && s[n - 2] == '\r' && s[n - 1] == '\n') { s[n - 2] = '\n'; s[n - 1] = 0; } }
    RET(G(s));
}
API(stdio, fgetc) { GFile *g = gf(A0); RET((uint32_t)(g && g->f ? fgetc(g->f) : -1)); }
API(stdio, getc) { GFile *g = gf(A0); RET((uint32_t)(g && g->f ? getc(g->f) : -1)); }
API(stdio, ungetc) { GFile *g = gf(A1); RET((uint32_t)(g && g->f ? ungetc((int)A0, g->f) : -1)); }
API(stdio, fputc) {
    GFile *g = gf(A1); if (!g) { RET((uint32_t)-1); return; }
    char ch = (char)A0;
    if (g->std > 1) std_write(g, &ch, 1); else fputc(ch, g->f);
    RET((uint8_t)ch);
}
API(stdio, fputs) {
    GFile *g = gf(A1); if (!g) { RET((uint32_t)-1); return; }
    const char *s = PTR(A0);
    if (g->std > 1) std_write(g, s, strlen(s)); else if (fputs(s, g->f) < 0) { RET((uint32_t)-1); return; }
    RET(0);
}
API(stdio, puts) { const char *s = PTR(A0); rt_log("%s\n", s); RET(0); }
API(stdio, fflush) {
    if (!A0) { fflush(NULL); RET(0); return; }
    GFile *g = gf(A0); RET(g && g->f && !g->std ? (uint64_t)(int64_t)fflush(g->f) : 0);
}
API(stdio, feof) { GFile *g = gf(A0); RET(g && g->f ? (feof(g->f) ? 0x10 : 0) : 0); }
API(stdio, ferror) { GFile *g = gf(A0); RET(g && g->f ? (ferror(g->f) ? 0x20 : 0) : 0); }
API(stdio, clearerr) { GFile *g = gf(A0); if (g && g->f) clearerr(g->f); }
API(stdio, rewind) { GFile *g = gf(A0); if (g && g->f) rewind(g->f); }
// setvbuf(file, buffer, mode, size): Microsoft's modes are _IOFBF 0, _IOLBF 0x40, _IONBF 4
API(stdio, setvbuf) {
    GFile *g = gf(A0); if (!g || !g->f || g->std) { RET(0); return; }
    int m = (int)A2 == 4 ? _IONBF : (int)A2 == 0x40 ? _IOLBF : _IOFBF;
    RET((uint64_t)(int64_t)setvbuf(g->f, NULL, m, A3 ? A3 : BUFSIZ));
}
API(stdio, _fileno) { GFile *g = gf(A0); RET((uint32_t)(g ? g->fd : -1)); }
// __stdio_common_vfprintf(options, file, format, locale, va)
static int64_t vfprintf_to(uint64_t file, int wide, uint64_t opts, const void *fmt, uint64_t va) {
    GFile *g = gf(file); if (!g) return -1;
    size_t n; void *s = ucrt_format(wide, opts, fmt, va, &n);
    char *u = wide ? w16_to_utf8(s) : s;
    size_t un = wide ? strlen(u) : n;
    if (g->std > 1) std_write(g, u, un); else if (g->f) fwrite(u, 1, un, g->f);
    if (wide) free(u);
    free(s);
    return (int64_t)n;
}
API(stdio, __stdio_common_vfprintf) { RET((uint64_t)vfprintf_to(A1, 0, A0, PTR(A2), AN(4))); }
API(stdio, __stdio_common_vfprintf_s) { RET((uint64_t)vfprintf_to(A1, 0, A0, PTR(A2), AN(4))); }
API(stdio, __stdio_common_vfwprintf) { RET((uint64_t)vfprintf_to(A1, 1, A0, PTR(A2), AN(4))); }

// ---------------- scanf ----------------
// Over UTF-8 bytes or UTF-16 units. options bit 0 (_CRT_INTERNAL_SCANF_SECURECRT): %s, %c and %[ take a buffer size
// (an unsigned int in units) after the pointer.
typedef struct { int wide; const uint8_t *n8; const uint16_t *n16; size_t i, len; } In;
static int in_peek(In *s) {
    if (s->i >= s->len) return -1;
    return s->wide ? s->n16[s->i] : s->n8[s->i];
}
static int is_ws(int ch) { return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f'; }
static int64_t do_scanf(int wide, uint64_t opts, const void *input, size_t inlen, const void *fmtp, uint64_t va) {
    In in = { wide, input, input, 0, inlen };
    const uint8_t *f8 = fmtp; const uint16_t *f16 = fmtp;
    #define FC(k) (wide ? (int)f16[k] : (int)f8[k])
    #define NEXT() (va += 8, rd64(va - 8))
    size_t i = 0; int64_t assigned = 0; int any = 0;
    while (FC(i)) {
        int fc = FC(i);
        if (is_ws(fc)) { while (is_ws(in_peek(&in))) in.i++; i++; continue; }
        if (fc != '%' || FC(i + 1) == '%') {
            if (fc == '%') i++;
            if (in_peek(&in) != fc) break;
            in.i++; i++; continue;
        }
        i++;
        int suppress = 0, width = -1, size = 4, wtarget = wide;
        if (FC(i) == '*') { suppress = 1; i++; }
        while (FC(i) >= '0' && FC(i) <= '9') { width = (width < 0 ? 0 : width) * 10 + FC(i) - '0'; i++; }
        for (;;) {
            int k = FC(i);
            if (k == 'h') { if (FC(i + 1) == 'h') { size = 1; i += 2; } else { size = 2; wtarget = 0; i++; } }
            else if (k == 'l') { if (FC(i + 1) == 'l') { size = 8; i += 2; } else { size = 9; wtarget = 1; i++; } }   // 9: long / double
            else if (k == 'w') { wtarget = 1; i++; }
            else if (k == 'L' || k == 'j' || k == 'z' || k == 't') { size = 8; i++; }
            else if (k == 'I') {
                if (FC(i + 1) == '6' && FC(i + 2) == '4') { size = 8; i += 3; }
                else if (FC(i + 1) == '3' && FC(i + 2) == '2') { size = 4; i += 3; }
                else { size = 8; i++; }
            } else break;
        }
        int cv = FC(i++);
        if (!cv) break;
        if (cv == 'n') { if (!suppress) { uint64_t p = NEXT(); if (size == 8) wr64(p, in.i); else wr32(p, (uint32_t)in.i); } continue; }
        if (cv != 'c' && cv != '[') while (is_ws(in_peek(&in))) in.i++;
        if (in_peek(&in) < 0) { if (!any) assigned = -1; break; }
        if (cv == 'S' || cv == 'C') wtarget = !wide;
        switch (cv) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': case 'p': {
            char buf[80]; int k = 0, lim = width > 0 && width < 79 ? width : 79;
            while (k < lim) { int ch = in_peek(&in); if (ch < 0 || ch > 127 || is_ws(ch)) break; buf[k++] = (char)ch; in.i++; }
            buf[k] = 0;
            int base = cv == 'i' ? 0 : cv == 'o' ? 8 : (cv == 'x' || cv == 'X' || cv == 'p') ? 16 : 10;
            char *end; unsigned long long v = (cv == 'd' || cv == 'i') ? (unsigned long long)strtoll(buf, &end, base) : strtoull(buf, &end, base);
            in.i -= (size_t)(k - (end - buf));   // give back what the number didn't use
            if (end == buf) goto done;
            any = 1;
            if (!suppress) {
                uint64_t p = NEXT();
                int sz = cv == 'p' ? 8 : size == 9 ? 4 : size;
                if (sz == 1) wr8(p, (uint8_t)v); else if (sz == 2) wr16(p, (uint16_t)v); else if (sz == 8) wr64(p, v); else wr32(p, (uint32_t)v);
                assigned++;
            }
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            char buf[128]; int k = 0, lim = width > 0 && width < 127 ? width : 127;
            while (k < lim) { int ch = in_peek(&in); if (ch < 0 || ch > 127 || is_ws(ch)) break; buf[k++] = (char)ch; in.i++; }
            buf[k] = 0;
            char *end; double v = strtod(buf, &end);
            in.i -= (size_t)(k - (end - buf));
            if (end == buf) goto done;
            any = 1;
            if (!suppress) {
                uint64_t p = NEXT();
                if (size == 9 || size == 8) memcpy(PTR(p), &v, 8); else { float f = (float)v; memcpy(PTR(p), &f, 4); }
                assigned++;
            }
            break;
        }
        case 's': case 'S': case 'c': case 'C': case '[': {
            uint8_t set[65536 / 8]; int neg = 0;
            if (cv == '[') {
                memset(set, 0, sizeof set);
                if (FC(i) == '^') { neg = 1; i++; }
                if (FC(i) == ']') { set[']' / 8] |= 1 << (']' % 8); i++; }
                while (FC(i) && FC(i) != ']') {
                    int a = FC(i);
                    if (FC(i + 1) == '-' && FC(i + 2) && FC(i + 2) != ']') { int b = FC(i + 2); for (int x = a; x <= b; x++) set[x / 8] |= 1 << (x % 8); i += 3; }
                    else { set[a / 8] |= 1 << (a % 8); i++; }
                }
                if (FC(i) == ']') i++;
            }
            uint64_t p = suppress ? 0 : NEXT();
            uint64_t cap = (!suppress && (opts & 1)) ? (uint32_t)NEXT() : (uint64_t)-1;
            int lim = width > 0 ? width : (cv == 'c' || cv == 'C') ? 1 : 0x7FFFFFFF;
            size_t k = 0;
            while ((int)k < lim) {
                int ch = in_peek(&in);
                if (ch < 0) break;
                if ((cv == 's' || cv == 'S') && is_ws(ch)) break;
                if (cv == '[' && (((set[ch / 8] >> (ch % 8)) & 1) == neg)) break;
                if (p) {
                    if (k + ((cv == 'c' || cv == 'C') ? 0 : 1) >= cap) { if (wtarget) wr16(p, 0); else wr8(p, 0); goto done; }
                    if (wtarget) wr16(p + 2 * k, (uint16_t)ch); else wr8(p + k, (uint8_t)(ch < 256 ? ch : '?'));
                }
                k++; in.i++;
            }
            if (!k) goto done;
            any = 1;
            if (p) { if (cv != 'c' && cv != 'C') { if (wtarget) wr16(p + 2 * k, 0); else wr8(p + k, 0); } assigned++; }
            break;
        }
        default: goto done;
        }
    }
done:
    #undef FC
    #undef NEXT
    return assigned;
}
// __stdio_common_vsscanf(options, buffer, bufcount, format, locale, va)
API(stdio, __stdio_common_vsscanf) {
    size_t n = A2 == TRUNCATE ? strlen(PTR(A1)) : strnlen(PTR(A1), A2);
    RET((uint64_t)do_scanf(0, A0, PTR(A1), n, PTR(A3), AN(5)));
}
API(stdio, __stdio_common_vswscanf) {
    const uint16_t *s = PTR(A1); size_t n = 0; while ((A2 == TRUNCATE || n < A2) && s[n]) n++;
    RET((uint64_t)do_scanf(1, A0, s, n, PTR(A3), AN(5)));
}

// ---------------- low-level I/O (file descriptors) ----------------
// _open_osfhandle(handle, flags): a descriptor for a kernel32 file handle (a duplicate of its host descriptor)
API(stdio, _open_osfhandle) {
    uint64_t h = A0; int fd = -1;
    switch (h >> 32) { case 0x53544430: fd = 0; break; case 0x53544431: fd = 1; break; case 0x53544432: fd = 2; break;
    default: { HObj *o = h_get(h); if (o && o->type == HT_FILE) fd = o->fd; } }
    if (fd < 0) { ucrt_set_errno(9); RET((uint32_t)-1); return; }
    RET((uint32_t)(fd <= 2 ? fd : dup(fd)));
}
API(stdio, _get_osfhandle) { RET(A0 <= 2 ? (0x5354443000000000ull + ((uint64_t)A0 << 32)) : (uint64_t)-1); }
API(stdio, _close) { RET((uint32_t)((int)A0 > 2 ? close((int)A0) : 0)); }
API(stdio, _lseek) { off_t r = lseek((int)A0, (off_t)(int32_t)A1, (int)A2); RET((uint32_t)(r > INT32_MAX ? -1 : (int32_t)r)); }
API(stdio, _lseeki64) { RET((uint64_t)lseek((int)A0, (off_t)A1, (int)A2)); }
API(stdio, _read) { ssize_t r = read((int)A0, PTR(A1), (uint32_t)A2); if (r < 0) ucrt_set_errno(ucrt_errno_from_host(errno)); RET((uint32_t)(int32_t)r); }
API(stdio, _write) {
    if ((int)A0 == 1 || (int)A0 == 2) { std_write(NULL, PTR(A1), (uint32_t)A2); RET((uint32_t)A2); return; }
    ssize_t r = write((int)A0, PTR(A1), (uint32_t)A2); if (r < 0) ucrt_set_errno(ucrt_errno_from_host(errno)); RET((uint32_t)(int32_t)r);
}
API(stdio, _dup) { RET((uint32_t)dup((int)A0)); }
API(stdio, _dup2) { RET((uint32_t)(dup2((int)A0, (int)A1) < 0 ? -1 : 0)); }
API(stdio, _setmode) { RET(0x4000); }   // the previous mode: _O_TEXT
API(stdio, _set_fmode) { RET(0); }
API(stdio, _get_fmode) { if (A0) wr32(A0, 0x4000); RET(0); }
static int g_commode;
API(stdio, __p__commode) { RET(G(&g_commode)); }
static int g_fmode = 0x4000;
API(stdio, __p__fmode) { RET(G(&g_fmode)); }
// _getcwd(buffer, maxlen): the guest's current directory, as GetCurrentDirectoryA reports it
API(stdio, _getcwd) {
    char tmp[1024];
    uint64_t sr = c->rcx, sd = c->rdx, sa = c->rax;
    c->rcx = sizeof tmp; c->rdx = G(tmp); I_kernel32_dll_GetCurrentDirectoryA(c);
    uint32_t n = (uint32_t)c->rax; c->rcx = sr; c->rdx = sd; c->rax = sa;
    if (!n || n >= sizeof tmp) { ucrt_set_errno(34); RET(0); return; }
    if (!A0) { RET(G(strdup(tmp))); return; }
    if (n + 1 > (uint32_t)A1) { ucrt_set_errno(34); RET(0); return; }
    memcpy(PTR(A0), tmp, n + 1); RET(A0);
}

// ---------------- filesystem ----------------
static char *hp(uint64_t win) { char *h = rt_host_path(PTR(win)); if (!h) ucrt_set_errno(2); return h; }
#define FS_CALL(expr) do { char *h = hp(A0); if (!h) { RET((uint32_t)-1); return; } int r_ = (expr); \
    if (r_) ucrt_set_errno(ucrt_errno_from_host(errno)); free(h); RET((uint32_t)(r_ ? -1 : 0)); } while (0)
API(filesystem, _mkdir) { FS_CALL(mkdir(h, 0755)); }
API(filesystem, _rmdir) { FS_CALL(rmdir(h)); }
API(filesystem, remove) { FS_CALL(unlink(h)); }
API(filesystem, _unlink) { FS_CALL(unlink(h)); }
API(filesystem, _chmod) { FS_CALL(access(h, F_OK)); }   // read-only flags aren't kept on the Mac
API(filesystem, rename) {
    char *a = hp(A0), *b = hp(A1); int r = a && b ? rename(a, b) : -1;
    if (r && a && b) ucrt_set_errno(ucrt_errno_from_host(errno));
    free(a); free(b); RET((uint32_t)(r ? -1 : 0));
}
API(filesystem, _access) {   // _access(path, mode): 0 exists, 2 write, 4 read, 6 both
    char *h = hp(A0); if (!h) { RET((uint32_t)-1); return; }
    int m = (int)A1, r = access(h, (m & 2 ? W_OK : 0) | (m & 4 ? R_OK : 0) | F_OK);
    if (r) ucrt_set_errno(ucrt_errno_from_host(errno));
    free(h); RET((uint32_t)(r ? -1 : 0));
}
// Microsoft's st_mode: _S_IFDIR 0x4000, _S_IFREG 0x8000, and the owner's rwx copied to group and others
static uint16_t ms_mode(const struct stat *st) {
    uint16_t m = S_ISDIR(st->st_mode) ? 0x4000 | 0x49 : 0x8000;
    m |= 0x124;   // readable
    if (st->st_mode & S_IWUSR) m |= 0x92;
    return m;
}
// _stat64i32(path, struct _stat64i32 *): dev 0, ino 4 (u16), mode 6, nlink 8, uid 10, gid 12, rdev 16, size 20 (i32),
// atime 24, mtime 32, ctime 40 (64-bit times)
API(filesystem, _stat64i32) {
    char *h = hp(A0); struct stat st;
    if (!h || stat(h, &st)) { if (h) ucrt_set_errno(ucrt_errno_from_host(errno)); free(h); RET((uint32_t)-1); return; }
    free(h);
    uint64_t b = A1; memset(PTR(b), 0, 48);
    wr16(b + 6, ms_mode(&st)); wr16(b + 8, (uint16_t)st.st_nlink);
    wr32(b + 20, (uint32_t)(st.st_size > INT32_MAX ? INT32_MAX : st.st_size));
    wr64(b + 24, (uint64_t)st.st_atimespec.tv_sec); wr64(b + 32, (uint64_t)st.st_mtimespec.tv_sec); wr64(b + 40, (uint64_t)st.st_ctimespec.tv_sec);
    RET(0);
}
// _stat64(path, struct _stat64 *): the same with a 64-bit size at 24 and the times at 32, 40, 48
API(filesystem, _stat64) {
    char *h = hp(A0); struct stat st;
    if (!h || stat(h, &st)) { if (h) ucrt_set_errno(ucrt_errno_from_host(errno)); free(h); RET((uint32_t)-1); return; }
    free(h);
    uint64_t b = A1; memset(PTR(b), 0, 56);
    wr16(b + 6, ms_mode(&st)); wr16(b + 8, (uint16_t)st.st_nlink); wr64(b + 24, (uint64_t)st.st_size);
    wr64(b + 32, (uint64_t)st.st_atimespec.tv_sec); wr64(b + 40, (uint64_t)st.st_mtimespec.tv_sec); wr64(b + 48, (uint64_t)st.st_ctimespec.tv_sec);
    RET(0);
}
// _splitpath(path, drive, dir, fname, ext): each output optional
API(filesystem, _splitpath) {
    const char *p = PTR(A0); char *drive = PTR(A1), *dir = PTR(A2), *fname = PTR(A3), *ext = PTR(AN(4));
    if (drive) *drive = 0;
    if (p[0] && p[1] == ':') { if (drive) { drive[0] = p[0]; drive[1] = ':'; drive[2] = 0; } p += 2; }
    const char *slash = NULL, *dot = NULL;
    for (const char *q = p; *q; q++) { if (*q == '\\' || *q == '/') { slash = q; dot = NULL; } else if (*q == '.') dot = q; }
    const char *base = slash ? slash + 1 : p;
    if (dir) { size_t n = (size_t)(base - p); memcpy(dir, p, n); dir[n] = 0; }
    const char *e = dot ? dot : base + strlen(base);
    if (fname) { size_t n = (size_t)(e - base); memcpy(fname, base, n); fname[n] = 0; }
    if (ext) strcpy(ext, dot ? dot : "");
}
// _findfirst64i32(spec, struct _finddata64i32_t *): attrib 0, time_create 8, time_access 16, time_write 24,
// size 32 (u32), name 36 (260 chars). The handle is a host pointer to the search.
typedef struct { DIR *d; char *dir, *pat; } Find;
static int find_fill(Find *f, uint64_t data) {
    struct dirent *e;
    while ((e = readdir(f->d))) {
        if (fnmatch(f->pat, e->d_name, FNM_CASEFOLD) && !(strcmp(f->pat, "*.*") == 0)) continue;
        char full[2048]; snprintf(full, sizeof full, "%s/%s", f->dir, e->d_name);
        struct stat st; if (stat(full, &st)) continue;
        memset(PTR(data), 0, 296);
        wr32(data, S_ISDIR(st.st_mode) ? 0x10 : 0x20);
        wr64(data + 8, (uint64_t)st.st_birthtimespec.tv_sec); wr64(data + 16, (uint64_t)st.st_atimespec.tv_sec);
        wr64(data + 24, (uint64_t)st.st_mtimespec.tv_sec);
        wr32(data + 32, (uint32_t)(st.st_size > UINT32_MAX ? UINT32_MAX : st.st_size));
        snprintf(PTR(data + 36), 260, "%s", e->d_name);
        return 1;
    }
    return 0;
}
API(filesystem, _findfirst64i32) {
    const char *spec = PTR(A0); const char *sl = strrchr(spec, '\\'), *sl2 = strrchr(spec, '/');
    if (sl2 > sl) sl = sl2;
    char *wdir = sl ? strndup(spec, (size_t)(sl - spec)) : strdup(".");
    char *h = rt_host_path(*wdir ? wdir : "\\"); free(wdir);
    DIR *d = h ? opendir(h) : NULL;
    if (!d) { free(h); ucrt_set_errno(2); RET((uint64_t)-1); return; }
    Find *f = calloc(1, sizeof *f); f->d = d; f->dir = h; f->pat = strdup(sl ? sl + 1 : spec);
    if (!find_fill(f, A1)) { closedir(d); free(f->dir); free(f->pat); free(f); ucrt_set_errno(2); RET((uint64_t)-1); return; }
    RET(G(f));
}
API(filesystem, _findnext64i32) {
    Find *f = PTR(A0); if (!f || A0 == (uint64_t)-1) { RET((uint32_t)-1); return; }
    if (!find_fill(f, A1)) { ucrt_set_errno(2); RET((uint32_t)-1); return; }
    RET(0);
}
API(filesystem, _findclose) {
    Find *f = PTR(A0); if (!f || A0 == (uint64_t)-1) { RET((uint32_t)-1); return; }
    closedir(f->d); free(f->dir); free(f->pat); free(f); RET(0);
}
// The UCRT exports _fdopen from the math API set too (api-ms-win-crt-math), and some games import it from there
API(math, _fdopen) { I_api_ms_win_crt_stdio_l1_1_0_dll__fdopen(c); }
