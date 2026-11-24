// Import binding: every IAT slot gets the guest-callable address of its shim, so `call [slot]` through a register
// (mov esi, [__imp_X] ; call esi -- MSVC x86 does that for repeated calls) reaches the same native code as the
// direct calls the translator emits. GetProcAddress resolves names through the same tables.
#include "rt32.h"
#include <ctype.h>
#include <strings.h>

void rt_bind_imports(void) {
    for (int i = 0; i < ngimports; i++)
        wr32(gimports[i].slot, rt_host_fn(gimports[i].fn, gimports[i].name));
}

// extra exports that the game only reaches through GetProcAddress (registered by the API modules)
typedef struct { const char *dll, *name; gfn fn; } Extra;
static Extra extras[512]; static int nextras;
void rt_register_export(const char *dll, const char *name, gfn fn) {
    if (nextras < 512) extras[nextras++] = (Extra){dll, name, fn};
}

static int dll_match(const char *full, const char *dll) {
    // full: "KERNEL32.dll!Name"; dll: "kernel32" or "kernel32.dll"
    size_t n = strcspn(full, "!");
    size_t m = strlen(dll);
    if (m > 4 && !strcasecmp(dll + m - 4, ".dll")) m -= 4;
    size_t fn = n; if (fn > 4 && !strncasecmp(full + fn - 4, ".dll", 4)) fn -= 4;
    return fn == m && !strncasecmp(full, dll, m);
}

gfn rt_import_by_name(const char *dll, const char *name) {
    for (int i = 0; i < ngimports; i++) {
        const char *bang = strchr(gimports[i].name, '!');
        if (bang && !strcmp(bang + 1, name) && (!dll || dll_match(gimports[i].name, dll))) return gimports[i].fn;
    }
    for (int i = 0; i < nextras; i++)
        if (!strcmp(extras[i].name, name) && (!dll || !strncasecmp(extras[i].dll, dll, strlen(extras[i].dll)))) return extras[i].fn;
    return NULL;
}

// ---- UTF-16 helpers ----
size_t w_len(const uint16_t *s) { size_t n = 0; if (s) while (s[n]) n++; return n; }
void w_to_utf8(const uint16_t *s, char *out, size_t n) {
    size_t o = 0;
    for (; s && *s && o + 4 < n; s++) {
        uint32_t ch = *s;
        if (ch >= 0xD800 && ch < 0xDC00 && s[1] >= 0xDC00 && s[1] < 0xE000) { ch = 0x10000 + ((ch - 0xD800) << 10) + (s[1] - 0xDC00); s++; }
        if (ch < 0x80) out[o++] = (char)ch;
        else if (ch < 0x800) { out[o++] = (char)(0xC0 | ch >> 6); out[o++] = (char)(0x80 | (ch & 63)); }
        else if (ch < 0x10000) { out[o++] = (char)(0xE0 | ch >> 12); out[o++] = (char)(0x80 | ((ch >> 6) & 63)); out[o++] = (char)(0x80 | (ch & 63)); }
        else { out[o++] = (char)(0xF0 | ch >> 18); out[o++] = (char)(0x80 | ((ch >> 12) & 63)); out[o++] = (char)(0x80 | ((ch >> 6) & 63)); out[o++] = (char)(0x80 | (ch & 63)); }
    }
    if (n) out[o] = 0;
}
void utf8_to_w(const char *s, uint16_t *out, size_t n) {
    size_t o = 0;
    const uint8_t *p = (const uint8_t *)s;
    while (p && *p && o + 2 < n) {
        uint32_t ch = *p++;
        if (ch >= 0xF0 && p[0] && p[1] && p[2]) { ch = ((ch & 7) << 18) | ((p[0] & 63) << 12) | ((p[1] & 63) << 6) | (p[2] & 63); p += 3; }
        else if (ch >= 0xE0 && p[0] && p[1]) { ch = ((ch & 15) << 12) | ((p[0] & 63) << 6) | (p[1] & 63); p += 2; }
        else if (ch >= 0xC0 && p[0]) { ch = ((ch & 31) << 6) | (p[0] & 63); p += 1; }
        if (ch >= 0x10000) { ch -= 0x10000; out[o++] = (uint16_t)(0xD800 + (ch >> 10)); out[o++] = (uint16_t)(0xDC00 + (ch & 0x3FF)); }
        else out[o++] = (uint16_t)ch;
    }
    if (n) out[o] = 0;
}

RtGame32 rt_game = {"Game", "game.exe", "C:\\Games\\Game", "C:\\Users\\Player\\Documents", "orig.exe", 0};

// ---- paths ----
// Windows paths are in the game's ANSI code page; macOS file names must be UTF-8. Valid UTF-8 (ASCII included) is
// kept; otherwise bytes map as Shift-JIS's full-width space (0x81 0x40, which Japanese-made games put in folder names)
// and Latin-1 for the rest, the same way every time (reads find what writes made).
static int valid_utf8(const unsigned char *p) {
    while (*p) {
        int n = *p < 0x80 ? 0 : (*p >> 5) == 6 ? 1 : (*p >> 4) == 14 ? 2 : (*p >> 3) == 30 ? 3 : -1;
        if (n < 0) return 0;
        p++;
        for (int i = 0; i < n; i++, p++) if ((*p & 0xC0) != 0x80) return 0;
    }
    return 1;
}
static void ansi_to_utf8(const char *in, char *out, size_t n) {
    const unsigned char *p = (const unsigned char *)in;
    if (valid_utf8(p)) { snprintf(out, n, "%s", in); return; }
    size_t o = 0;
    for (; *p && o + 4 < n; p++) {
        if (*p < 0x80) out[o++] = (char)*p;
        else if (p[0] == 0x81 && p[1] == 0x40) { out[o++] = (char)0xE3; out[o++] = (char)0x80; out[o++] = (char)0x80; p++; }   // U+3000
        else { out[o++] = (char)(0xC0 | (*p >> 6)); out[o++] = (char)(0x80 | (*p & 0x3F)); }
    }
    out[o] = 0;
}
// The game opens files relative to its folder (nativePC\...), and its saves through SHGetFolderPath; drive
// letters map to the game folder (C:\ -> /) only for absolute paths the game built from GetCurrentDirectory.
const char *rt_host_path(const char *win, char *out, size_t n) {
    char tmp[1024]; size_t k = 0;
    const char *s = win;
    if (isalpha((unsigned char)s[0]) && s[1] == ':') {
        size_t gl = strlen(rt_game.win_dir), dl = strlen(rt_game.docs_dir);
        if (!strncasecmp(s, rt_game.win_dir, gl)) { snprintf(tmp, sizeof tmp, "%s%s", rt_game_dir, s + gl); s = NULL; }
        else if (!strncasecmp(s, rt_game.docs_dir, dl)) { snprintf(tmp, sizeof tmp, "%s%s", rt_data_dir, s + dl); s = NULL; }
        else s += 2;
    }
    if (s) { for (; *s && k + 1 < sizeof tmp; s++) tmp[k++] = *s; tmp[k] = 0; }
    for (char *p = tmp; *p; p++) if (*p == '\\') *p = '/';
    ansi_to_utf8(tmp, out, n);
    return out;
}
