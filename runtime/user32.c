// user32/gdi32: the parts the engine and its MFC startup query before any window exists.
#include "rt.h"
#include <CoreGraphics/CoreGraphics.h>

#define PSEUDO_GDI 0x4744490000000000ull   // fake DC/brush/cursor handles

int rt_primary_rect(int32_t r[4]);   // display.c: current (possibly emulated) primary display mode
static void screen_px(uint32_t *w, uint32_t *h) { int32_t r[4]; rt_primary_rect(r); *w = (uint32_t)(r[2] - r[0]); *h = (uint32_t)(r[3] - r[1]); }
void I_user32_dll_GetSystemMetrics(CPU *c) {
    uint32_t w, h; screen_px(&w, &h);
    switch ((int)A0) {
    case 0: case 78: RET(w); break;          // SM_CXSCREEN, SM_CXVIRTUALSCREEN
    case 1: case 79: RET(h); break;          // SM_CYSCREEN, SM_CYVIRTUALSCREEN
    case 76: case 77: RET(0); break;         // virtual screen origin
    case 80: RET(1); break;                  // SM_CMONITORS
    case 5: case 6: RET(1); break;           // borders
    case 4: RET(23); break;                  // caption
    case 11: case 12: RET(32); break;        // icon
    case 13: case 14: RET(32); break;        // cursor
    case 32: case 33: RET(4); break;         // frame
    case 43: RET(5); break;                  // mouse buttons
    case 19: RET(1); break;                  // mouse present
    default: RET(0); break;
    }
}
// A window's DC carries its hwnd (bit 32 set), so SwapBuffers / wglMakeCurrent can find the window (opengl.m)
#define DC_WINDOW 0x100000000ull
void I_user32_dll_GetDC(CPU *c) { RET(PSEUDO_GDI | (A0 ? DC_WINDOW | (uint32_t)A0 : 1)); }
void I_user32_dll_GetWindowDC(CPU *c) { RET(PSEUDO_GDI | (A0 ? DC_WINDOW | (uint32_t)A0 : 1)); }
uint64_t rt_dc_window(uint64_t dc) { return (dc & ~0xFFFFFFFFull) == (PSEUDO_GDI | DC_WINDOW) ? (uint32_t)dc : 0; }
void I_user32_dll_ReleaseDC(CPU *c) { RET(1); }
void I_gdi32_dll_GetDeviceCaps(CPU *c) {
    uint32_t w, h; screen_px(&w, &h);
    switch ((int)A1) {
    case 8: RET(w); break; case 10: RET(h); break;          // HORZRES, VERTRES
    case 12: RET(32); break; case 14: RET(1); break;        // BITSPIXEL, PLANES
    case 88: case 90: RET(96); break;                       // LOGPIXELSX/Y
    case 116: RET(60); break;                               // VREFRESH
    case 4: RET(w * 254 / 960); break; case 6: RET(h * 254 / 960); break;   // HORZSIZE/VERTSIZE (mm)
    default: RET(0); break;
    }
}
void I_user32_dll_GetSysColor(CPU *c) { RET(0x00F0F0F0); }
void I_user32_dll_GetSysColorBrush(CPU *c) { RET(PSEUDO_GDI | 0x100 | (A0 & 0xFF)); }
void I_user32_dll_LoadCursorA(CPU *c) { RET(PSEUDO_GDI | 0x10000 | (A1 & 0xFFFF)); }
void I_user32_dll_LoadCursorW(CPU *c) { RET(PSEUDO_GDI | 0x10000 | (A1 & 0xFFFF)); }
void I_user32_dll_LoadIconA(CPU *c) { RET(PSEUDO_GDI | 0x20000 | (A1 & 0xFFFF)); }
void I_user32_dll_LoadIconW(CPU *c) { RET(PSEUDO_GDI | 0x20000 | (A1 & 0xFFFF)); }
static uint32_t next_msg = 0xC000;
void I_user32_dll_RegisterWindowMessageA(CPU *c) { RET(__atomic_fetch_add(&next_msg, 1, __ATOMIC_SEQ_CST)); }
void I_user32_dll_RegisterWindowMessageW(CPU *c) { RET(__atomic_fetch_add(&next_msg, 1, __ATOMIC_SEQ_CST)); }
void I_gdi32_dll_CreateSolidBrush(CPU *c) { RET(PSEUDO_GDI | 0x400 | (A0 & 0xFF)); }
void I_gdi32_dll_CreateFontA(CPU *c) { RET(PSEUDO_GDI | 0x500); }
void I_gdi32_dll_SetTextColor(CPU *c) { RET(0); }
void I_gdi32_dll_SetBkColor(CPU *c) { RET(0xFFFFFF); }
// EnumDisplayDevicesA(device, index, DISPLAY_DEVICEA*, flags): one adapter with one monitor.
// DISPLAY_DEVICEA: cb +0, DeviceName[32] +4, DeviceString[128] +36, StateFlags +164, DeviceID[128] +168, DeviceKey[128] +296
void I_user32_dll_EnumDisplayDevicesA(CPU *c) {
    uint64_t d = A2;
    if ((uint32_t)A1 != 0 || !d) { RET(0); return; }
    uint32_t cb = rd32(d); if (cb < 168) { RET(0); return; }
    memset(PTR(d + 4), 0, cb - 4);
    const char *name = A0 ? "\\\\.\\DISPLAY1\\Monitor0" : "\\\\.\\DISPLAY1";
    const char *desc = A0 ? "Built-in Display" : "Apple GPU";
    strncpy(PTR(d + 4), name, 31); strncpy(PTR(d + 36), desc, 127);
    wr32(d + 164, A0 ? 0x3 : 0x5);   // monitor: ACTIVE | ATTACHED; adapter: ATTACHED_TO_DESKTOP | PRIMARY_DEVICE
    RET(1);
}
void I_gdi32_dll_GetStockObject(CPU *c) { RET(PSEUDO_GDI | 0x300 | (A0 & 0xFF)); }
static void dib_free(uint64_t h);
void I_gdi32_dll_DeleteDC(CPU *c) { RET(1); }
void I_gdi32_dll_CreateCompatibleDC(CPU *c) { RET(PSEUDO_GDI | 2); }
void I_gdi32_dll_SelectObject(CPU *c) { RET(PSEUDO_GDI | 0x300); }
void I_user32_dll_GetKeyboardLayout(CPU *c) { RET(0x04090409); }
void I_user32_dll_GetDoubleClickTime(CPU *c) { RET(500); }

// ---------------- clipboard: text, on the Mac pasteboard ----------------
// CF_TEXT (1) is UTF-8 (the ANSI code page this runtime reports is 65001), CF_UNICODETEXT (13) UTF-16. A handle from
// GetClipboardData belongs to the clipboard (the next call frees it), as on Windows.
#include "cocoa.h"
void *rt_heap_alloc(size_t n, int zero);   // kernel32.c
void rt_heap_free(void *p);
void I_user32_dll_OpenClipboard(CPU *c) { RET(1); }
void I_user32_dll_CloseClipboard(CPU *c) { RET(1); }
void I_user32_dll_EmptyClipboard(CPU *c) { cocoa_clipboard_clear(); RET(1); }
// SetClipboardData(format, hMem): hMem is GlobalAlloc memory (GlobalLock returns the same address)
void I_user32_dll_SetClipboardData(CPU *c) {
    uint32_t fmt = (uint32_t)A0; uint64_t mem = A1;
    if (!mem) { RET(0); return; }
    if (fmt == 1) cocoa_clipboard_set_text(PTR(mem));
    else if (fmt == 13) { char *u = w16_to_utf8(PTR(mem)); cocoa_clipboard_set_text(u); free(u); }
    else { set_last_error(1168); RET(0); return; }   // only text formats (ERROR_NOT_FOUND)
    RET(mem);
}
void I_user32_dll_GetClipboardData(CPU *c) {
    static void *last;
    uint32_t fmt = (uint32_t)A0;
    if (fmt != 1 && fmt != 13) { RET(0); return; }
    char *u = cocoa_clipboard_text();
    if (!u) { RET(0); return; }
    if (last) { rt_heap_free(last); last = NULL; }
    if (fmt == 1) { size_t n = strlen(u) + 1; last = rt_heap_alloc(n, 0); if (last) memcpy(last, u, n); }
    else { uint16_t *w = utf8_to_w16(u); size_t n = (w16len(w) + 1) * 2; last = rt_heap_alloc(n, 0); if (last) memcpy(last, w, n); free(w); }
    free(u);
    RET(G(last));
}
void I_user32_dll_IsClipboardFormatAvailable(CPU *c) {
    uint32_t fmt = (uint32_t)A0; char *u = (fmt == 1 || fmt == 13) ? cocoa_clipboard_text() : NULL;
    RET(u != NULL); free(u);
}

// ---------------- dialog boxes: none ----------------
// Dialog templates are Win32 resources this runtime doesn't render; a dialog fails as it would without its template
// (-1, ERROR_RESOURCE_TYPE_NOT_FOUND), so the game takes its no-dialog path.
void I_user32_dll_DialogBoxParamA(CPU *c) {
    static int n; if (n++ < 3) rt_log("[user32] DialogBoxParam: dialog resources are not supported; failing\n");
    set_last_error(1813); RET((uint64_t)-1);
}
void I_user32_dll_DialogBoxParamW(CPU *c) { I_user32_dll_DialogBoxParamA(c); }
void I_user32_dll_EndDialog(CPU *c) { RET(1); }
void I_user32_dll_GetDlgItemTextA(CPU *c) { if (A2 && (uint32_t)A3) wr8(A2, 0); set_last_error(1421); RET(0); }   // ERROR_CONTROL_ID_NOT_FOUND
void I_user32_dll_SetDlgItemTextA(CPU *c) { set_last_error(1421); RET(0); }

// ---------------- GDI: objects, DIB sections, pixels ----------------
// There is no GDI surface to draw on: drawing calls succeed without effect. DIB sections are real memory (games fill
// them and read them back), kept in a small table so GetDIBits finds them.
void I_gdi32_dll_CreatePen(CPU *c) { RET(PSEUDO_GDI | 0x600); }
void I_gdi32_dll_CreateCompatibleBitmap(CPU *c) { RET(PSEUDO_GDI | 0x700); }
void I_gdi32_dll_SetStretchBltMode(CPU *c) { RET(1); }   // the previous mode: BLACKONWHITE
void I_gdi32_dll_StretchBlt(CPU *c) { RET(1); }
void I_gdi32_dll_GetPixel(CPU *c) { RET(0); }
void I_gdi32_dll_SetPixel(CPU *c) { RET((uint32_t)A3); }   // SetPixel(hdc, x, y, color) returns the color set
// GetTextCharsetInfo(hdc, FONTSIGNATURE*, flags): ANSI_CHARSET, an empty signature
void I_gdi32_dll_GetTextCharsetInfo(CPU *c) { if (A1) memset(PTR(A1), 0, 24); RET(0); }
// EnumFontFamiliesA(hdc, family, proc, lparam): no fonts to enumerate; the callback is not called
void I_gdi32_dll_EnumFontFamiliesA(CPU *c) { RET(1); }
#include <pthread.h>
typedef struct { uint64_t handle; void *bits; int32_t w, h; uint16_t bpp; uint32_t stride; } Dib;
static Dib dibs[64];
static pthread_mutex_t dib_mu = PTHREAD_MUTEX_INITIALIZER;
static void dib_free(uint64_t h) {   // DeleteObject of a DIB section frees its memory
    if ((h & ~0xFFull) != (PSEUDO_GDI | 0x800)) return;
    pthread_mutex_lock(&dib_mu);
    Dib *d = &dibs[h & 0x3F];
    if (d->handle == h) { free(d->bits); memset(d, 0, sizeof *d); }
    pthread_mutex_unlock(&dib_mu);
}
// CreateDIBSection(hdc, BITMAPINFO*, usage, void **bits, section, offset). BITMAPINFOHEADER: biWidth +4,
// biHeight +8 (negative: top-down), biBitCount +14
void I_gdi32_dll_CreateDIBSection(CPU *c) {
    uint64_t bmi = A1, out = A3;
    int32_t w = (int32_t)rd32(bmi + 4), h = (int32_t)rd32(bmi + 8); uint16_t bpp = rd16(bmi + 14);
    if (w <= 0 || !h || !bpp || bpp > 32) { set_last_error(87); RET(0); return; }
    uint32_t stride = ((uint32_t)w * bpp + 31) / 32 * 4; uint64_t size = (uint64_t)stride * (uint32_t)(h < 0 ? -h : h);
    pthread_mutex_lock(&dib_mu);
    int i = 0; while (i < 64 && dibs[i].handle) i++;
    if (i == 64) { pthread_mutex_unlock(&dib_mu); set_last_error(8); RET(0); return; }
    void *bits = calloc(1, size ? size : 1);
    dibs[i] = (Dib){ PSEUDO_GDI | 0x800 | (uint64_t)i, bits, w, h, bpp, stride };
    pthread_mutex_unlock(&dib_mu);
    if (out) wr64(out, G(bits));
    RET(dibs[i].handle);
}
// GetDIBits(hdc, bitmap, start, lines, bits, BITMAPINFO*, usage): a DIB section's rows, or its header when bits is
// NULL; other bitmaps read as black
void I_gdi32_dll_GetDIBits(CPU *c) {
    uint64_t hbm = A1, bits = AN(4), bmi = AN(5); uint32_t start = (uint32_t)A2, lines = (uint32_t)A3;
    pthread_mutex_lock(&dib_mu);
    Dib *d = NULL; for (int i = 0; i < 64; i++) if (dibs[i].handle && dibs[i].handle == hbm) d = &dibs[i];
    if (!d) {
        pthread_mutex_unlock(&dib_mu);
        if (bits && bmi) { int32_t w = (int32_t)rd32(bmi + 4); uint16_t bpp = rd16(bmi + 14);
            memset(PTR(bits), 0, (size_t)(((uint32_t)(w > 0 ? w : 0) * bpp + 31) / 32 * 4) * lines); }
        RET(lines); return;
    }
    if (!bits) {   // fill in the header
        wr32(bmi, 40); wr32(bmi + 4, (uint32_t)d->w); wr32(bmi + 8, (uint32_t)d->h); wr16(bmi + 12, 1); wr16(bmi + 14, d->bpp);
        wr32(bmi + 16, 0); wr32(bmi + 20, d->stride * (uint32_t)(d->h < 0 ? -d->h : d->h));
        pthread_mutex_unlock(&dib_mu); RET(1); return;
    }
    uint32_t rows = (uint32_t)(d->h < 0 ? -d->h : d->h);
    if (start >= rows) { pthread_mutex_unlock(&dib_mu); RET(0); return; }
    if (lines > rows - start) lines = rows - start;
    memcpy(PTR(bits), (uint8_t *)d->bits + (size_t)start * d->stride, (size_t)lines * d->stride);
    pthread_mutex_unlock(&dib_mu);
    RET(lines);
}

// RegisterClipboardFormatA(name): a format number from 0xC000 up, the same one for the same name (case-insensitive)
void I_user32_dll_RegisterClipboardFormatA(CPU *c) {
    static char names[64][64]; static int n; static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    const char *name = A0 ? (const char *)PTR(A0) : "";
    if (!*name) { set_last_error(87); RET(0); return; }
    pthread_mutex_lock(&mu);
    int i = 0; while (i < n && strcasecmp(names[i], name)) i++;
    if (i == n && n < 64) snprintf(names[n++], 64, "%s", name);
    pthread_mutex_unlock(&mu);
    RET(i < 64 ? 0xC000 + i : 0);
}
// Fonts: one pretend 16-pixel proportional font. Nothing is drawn with GDI text, but games size things by it.
void I_gdi32_dll_CreateFontIndirectA(CPU *c) { RET(A0 ? PSEUDO_GDI | 0x500 : 0); }
// GetTextMetricsA(hdc, TEXTMETRICA*)
void I_gdi32_dll_GetTextMetricsA(CPU *c) {
    uint64_t tm = A1; if (!tm) { RET(0); return; }
    memset(PTR(tm), 0, 56);
    wr32(tm + 0, 16); wr32(tm + 4, 13); wr32(tm + 8, 3);          // tmHeight, tmAscent, tmDescent
    wr32(tm + 20, 7); wr32(tm + 24, 14); wr32(tm + 28, 400);      // tmAveCharWidth, tmMaxCharWidth, tmWeight (normal)
    wr32(tm + 36, 96); wr32(tm + 40, 96);                         // tmDigitizedAspectX/Y
    wr8(tm + 44, 32); wr8(tm + 45, 255); wr8(tm + 46, '?'); wr8(tm + 47, ' ');   // first, last, default, break char
    wr8(tm + 51, 0x06);                                           // TMPF_VECTOR | TMPF_TRUETYPE (proportional)
    RET(1);
}
// GetObjectA(h, size, buf): a DIB section's BITMAP (32 bytes) or DIBSECTION (104: + BITMAPINFOHEADER at +32), or a
// font's LOGFONTA (60 bytes); with no buffer, the size it would write
void I_gdi32_dll_GetObjectA(CPU *c) {
    uint64_t h = A0, buf = A2; int32_t size = (int32_t)A1;
    if ((h & ~0xFFull) == (PSEUDO_GDI | 0x800)) {
        pthread_mutex_lock(&dib_mu);
        Dib d = dibs[h & 0x3F];
        pthread_mutex_unlock(&dib_mu);
        if (d.handle != h) { RET(0); return; }
        int32_t n = size >= 104 ? 104 : 32;
        if (!buf) { RET(104); return; }
        if (size < 32) { RET(0); return; }
        uint8_t b[104] = { 0 };
        int32_t ah = d.h < 0 ? -d.h : d.h;
        memcpy(b + 4, &d.w, 4); memcpy(b + 8, &ah, 4); memcpy(b + 12, &d.stride, 4);
        uint16_t one = 1; memcpy(b + 16, &one, 2); memcpy(b + 18, &d.bpp, 2);
        uint64_t bits = G(d.bits); memcpy(b + 24, &bits, 8);
        if (n == 104) {   // DIBSECTION.dsBmih
            uint32_t hs = 40, img = d.stride * (uint32_t)ah;
            memcpy(b + 32, &hs, 4); memcpy(b + 36, &d.w, 4); memcpy(b + 40, &d.h, 4);
            memcpy(b + 44, &one, 2); memcpy(b + 46, &d.bpp, 2); memcpy(b + 52, &img, 4);
        }
        memcpy(PTR(buf), b, (size_t)n);
        RET(n); return;
    }
    if ((h & ~0xFFull) == (PSEUDO_GDI | 0x500)) {
        if (!buf) { RET(60); return; }
        if (size < 60) { RET(0); return; }
        memset(PTR(buf), 0, 60);
        wr32(buf, (uint32_t)-16); wr32(buf + 16, 400);   // lfHeight, lfWeight
        memcpy(PTR(buf + 28), "Arial", 6);               // lfFaceName
        RET(60); return;
    }
    RET(0);
}

// ---------------- bitmaps and custom cursors ----------------
// UE4 builds its hardware cursors from PNGs: CreateBitmap(32-bit BGRA colour + 1-bit mask) -> CreateIconIndirect.
#include "cocoa.h"
#include <pthread.h>
typedef struct { uint32_t w, h, bpp; uint8_t *bits; } Bmp;
#define MAXGDI 256
#define H_BMP (PSEUDO_GDI | 0x1000000)
#define H_CUR (PSEUDO_GDI | 0x2000000)
static Bmp *bmps[MAXGDI]; static void *curs[MAXGDI];
static pthread_mutex_t gdi_mu = PTHREAD_MUTEX_INITIALIZER;
static int slot_of(uint64_t h, uint64_t kind) { return (h & ~0xFFFFFFull) == kind && (h & 0xFFFFFF) < MAXGDI ? (int)(h & 0xFFFFFF) : -1; }
// CreateBitmap(width, height, planes, bitsPerPixel, bits): rows are WORD-aligned, top row first
void I_gdi32_dll_CreateBitmap(CPU *c) {
    uint32_t w = (uint32_t)A0, h = (uint32_t)A1, planes = (uint32_t)A2, bpp = (uint32_t)A3; uint64_t bits = AN(4);
    if (!w || !h || w > 4096 || h > 4096 || planes != 1 || !bpp || bpp > 32) { RET(0); return; }
    size_t stride = ((size_t)w * bpp + 15) / 16 * 2;
    Bmp *b = calloc(1, sizeof *b); b->w = w; b->h = h; b->bpp = bpp; b->bits = calloc(stride, h);
    if (bits) memcpy(b->bits, PTR(bits), stride * h);
    pthread_mutex_lock(&gdi_mu);
    int i = 0; while (i < MAXGDI && bmps[i]) i++;
    if (i < MAXGDI) bmps[i] = b;
    pthread_mutex_unlock(&gdi_mu);
    if (i == MAXGDI) { free(b->bits); free(b); RET(0); return; }
    RET(H_BMP | (uint64_t)i);
}
// Regions: rectangles only. UE4 hit-tests the cursor against its window with CreateRectRgn + PtInRegion
// (FWindowsWindow::IsPointInWindow); without them no point is ever inside the window, so menus ignore the mouse.
#define H_RGN (PSEUDO_GDI | 0x3000000)
static int32_t (*rgns)[4]; static uint8_t rgn_used[MAXGDI];
static uint64_t new_rgn(int32_t l, int32_t t, int32_t r, int32_t b) {
    pthread_mutex_lock(&gdi_mu);
    if (!rgns) rgns = calloc(MAXGDI, sizeof *rgns);
    int i = 0; while (i < MAXGDI && rgn_used[i]) i++;
    if (i < MAXGDI) { rgn_used[i] = 1; rgns[i][0] = l; rgns[i][1] = t; rgns[i][2] = r; rgns[i][3] = b; }
    pthread_mutex_unlock(&gdi_mu);
    return i < MAXGDI ? H_RGN | (uint64_t)i : 0;
}
void I_gdi32_dll_CreateRectRgn(CPU *c) { RET(new_rgn((int32_t)A0, (int32_t)A1, (int32_t)A2, (int32_t)A3)); }
void I_gdi32_dll_CreateRoundRectRgn(CPU *c) { RET(new_rgn((int32_t)A0, (int32_t)A1, (int32_t)A2, (int32_t)A3)); }   // corners ignored
// PtInRegion(rgn, x, y): the rectangle includes its left/top edge, not its right/bottom
void I_gdi32_dll_PtInRegion(CPU *c) {
    int i = slot_of(A0, H_RGN); int32_t x = (int32_t)A1, y = (int32_t)A2, r[4] = { 0 }; int ok = 0;
    pthread_mutex_lock(&gdi_mu); if (i >= 0 && rgn_used[i]) { memcpy(r, rgns[i], sizeof r); ok = 1; } pthread_mutex_unlock(&gdi_mu);
    RET(ok && x >= r[0] && x < r[2] && y >= r[1] && y < r[3]);
}
void I_gdi32_dll_DeleteObject(CPU *c) {
    dib_free(A0);   // a DIB section (CreateDIBSection)
    int i = slot_of(A0, H_BMP);
    if (i >= 0) { pthread_mutex_lock(&gdi_mu); Bmp *b = bmps[i]; bmps[i] = NULL; pthread_mutex_unlock(&gdi_mu); if (b) { free(b->bits); free(b); } }
    i = slot_of(A0, H_RGN);
    if (i >= 0) { pthread_mutex_lock(&gdi_mu); rgn_used[i] = 0; pthread_mutex_unlock(&gdi_mu); }
    RET(1);
}
// CreateIconIndirect(ICONINFO*): { BOOL fIcon; DWORD xHotspot, yHotspot; HBITMAP hbmMask @16, hbmColor @24 }
void I_user32_dll_CreateIconIndirect(CPU *c) {
    uint64_t ii = A0; if (!ii) { RET(0); return; }
    uint32_t hx = rd32(ii + 4), hy = rd32(ii + 8);
    int bi = slot_of(rd64(ii + 24), H_BMP);
    pthread_mutex_lock(&gdi_mu); Bmp *b = bi >= 0 ? bmps[bi] : NULL; pthread_mutex_unlock(&gdi_mu);
    if (!b || b->bpp != 32) { rt_log("[user32] CreateIconIndirect: only 32-bit colour cursors are supported\n"); RET(0); return; }
    void *cur = cocoa_cursor_new(b->bits, (int)b->w, (int)b->h, (int)hx, (int)hy);
    if (!cur) { RET(0); return; }
    pthread_mutex_lock(&gdi_mu);
    int i = 0; while (i < MAXGDI && curs[i]) i++;
    if (i < MAXGDI) curs[i] = cur;
    pthread_mutex_unlock(&gdi_mu);
    if (i == MAXGDI) { cocoa_cursor_free(cur); RET(0); return; }
    RET(H_CUR | (uint64_t)i);
}
static void destroy_cursor(CPU *c) {
    int i = slot_of(A0, H_CUR);
    if (i >= 0) { pthread_mutex_lock(&gdi_mu); void *cur = curs[i]; curs[i] = NULL; pthread_mutex_unlock(&gdi_mu); cocoa_cursor_free(cur); }
    RET(1);
}
void I_user32_dll_DestroyCursor(CPU *c) { destroy_cursor(c); }
void I_user32_dll_DestroyIcon(CPU *c) { destroy_cursor(c); }
// the AppKit cursor behind a cursor handle: a custom one, or NULL (system arrow) for LoadCursor's
void *rt_cursor_native(uint64_t h) {
    int i = slot_of(h, H_CUR); if (i < 0) return NULL;
    pthread_mutex_lock(&gdi_mu); void *cur = curs[i]; pthread_mutex_unlock(&gdi_mu);
    return cur;
}
// .cur/.ani files are not supported: UE4 then falls back to its PNG cursors (CreateIconIndirect above)
void I_user32_dll_LoadCursorFromFileW(CPU *c) { set_last_error(2); RET(0); }
void I_user32_dll_LoadCursorFromFileA(CPU *c) { set_last_error(2); RET(0); }
