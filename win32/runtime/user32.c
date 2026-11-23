// user32 for 32-bit guests. Stage 1: windows exist as records (class, WndProc, rect, props) and messages flow through
// a per-process queue, so the game's window setup and message pump run; the Cocoa window and real input come
// with the Metal presenter (d3d9 layer), which attaches to the HWND the game passes to CreateDevice.
#include "rt32.h"
#include <strings.h>

typedef struct { char name[64]; uint32_t wndproc, style, icon, cursor; } WClass;
void *rt_cocoa_create_window(uint32_t hwnd, const char *title, int w, int h);
void rt_cocoa_set_size(uint32_t hwnd, int w, int h);
void rt_cocoa_screen_size(int *w, int *h);
extern uint8_t rt_keys[256];
extern int rt_mouse_x, rt_mouse_y;
typedef struct { int used; void *layer; uint32_t wndproc, style, exstyle; int x, y, w, h; int visible; char title[128];
                 struct { char k[32]; uint32_t v; } props[16]; uint32_t userdata; } Wnd;
static WClass classes[64]; static int nclasses;
static Wnd wnds[64];
#define HWND_OF(i) (0x00010000u + 0x10u * (uint32_t)(i))
static Wnd *wget(uint32_t h) { uint32_t i = (h - 0x10000u) / 0x10; return (h >= 0x10000u && i < 64 && wnds[i].used) ? &wnds[i] : NULL; }
void *rt_window_layer(uint32_t h) { Wnd *w = wget(h); return w ? w->layer : NULL; }
void rt_window_size(uint32_t h, int *cw, int *ch) { Wnd *w = wget(h); *cw = w ? w->w : 0; *ch = w ? w->h : 0; }
int rt_screen_w = 1920, rt_screen_h = 1080;

typedef struct { uint32_t hwnd, msg, wp, lp; } Msg;
static Msg queue[256]; static int qh, qt;
static pthread_mutex_t q_mu = PTHREAD_MUTEX_INITIALIZER;
void rt_post_message(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    pthread_mutex_lock(&q_mu);
    if ((qt + 1) % 256 != qh) { queue[qt] = (Msg){hwnd, msg, wp, lp}; qt = (qt + 1) % 256; }
    pthread_mutex_unlock(&q_mu);
}
static int trace_msg = -1;
static uint32_t send(CPU *c, uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    Wnd *w = wget(hwnd);
    if (trace_msg < 0) trace_msg = getenv("RT_TRACE_MSG") != NULL;
    if (trace_msg) rt_log("[user32] message 0x%04x wp=0x%x lp=0x%x -> hwnd 0x%x%s", msg, wp, lp, hwnd, w && w->wndproc ? "" : " (no window)");
    if (!w || !w->wndproc) return 0;
    uint32_t a[4] = {hwnd, msg, wp, lp};
    return guest_call(c, w->wndproc, 4, a);
}

static uint32_t register_class(CPU *c, uint32_t wc, int wide) {
    if (nclasses >= 64) return 0;
    WClass *k = &classes[nclasses];
    k->style = rd32(wc + 4); k->wndproc = rd32(wc + 8);
    uint32_t nm = rd32(wc + 40);
    if (nm < 0x10000) snprintf(k->name, sizeof k->name, "#%u", nm);
    else if (wide) w_to_utf8(G2H(nm), k->name, sizeof k->name);
    else snprintf(k->name, sizeof k->name, "%s", (char *)G2H(nm));
    if (rt_verbose) rt_log("[user32] RegisterClass %s wndproc=0x%x", k->name, k->wndproc);
    return 0xC000u + (uint32_t)nclasses++;
}
SHIM(user32_RegisterClassExA, 1) { return register_class(c, ARG(0), 0); }
SHIM(user32_RegisterClassExW, 1) { return register_class(c, ARG(0), 1); }

static uint32_t create_window(CPU *c, int wide) {
    uint32_t exst = ARG(0), cls = ARG(1), title = ARG(2), style = ARG(3);
    char cname[64] = "", t[128] = "";
    if (cls < 0x10000) snprintf(cname, sizeof cname, "#%u", cls);
    else if (wide) w_to_utf8(G2H(cls), cname, sizeof cname); else snprintf(cname, sizeof cname, "%s", (char *)G2H(cls));
    if (title) { if (wide) w_to_utf8(G2H(title), t, sizeof t); else snprintf(t, sizeof t, "%s", (char *)G2H(title)); }
    WClass *k = NULL;
    for (int i = 0; i < nclasses; i++) if (!strcasecmp(classes[i].name, cname) || (cls >= 0xC000u && cls < 0xC040u && (uint32_t)i == cls - 0xC000u)) k = &classes[i];
    int i = 1; while (i < 64 && wnds[i].used) i++;
    if (i == 64) return 0;
    Wnd *w = &wnds[i]; memset(w, 0, sizeof *w);
    w->used = 1; w->exstyle = exst; w->style = style; w->wndproc = k ? k->wndproc : 0;
    w->x = (int32_t)ARG(4); w->y = (int32_t)ARG(5); w->w = (int32_t)ARG(6); w->h = (int32_t)ARG(7);
    if (w->w <= 0 || (uint32_t)w->w == 0x80000000u) w->w = 1280;
    if (w->h <= 0 || (uint32_t)w->h == 0x80000000u) w->h = 720;
    snprintf(w->title, sizeof w->title, "%s", t);
    uint32_t h = HWND_OF(i);
    rt_log("[user32] CreateWindow \"%s\" class %s %dx%d -> 0x%x", t, cname, w->w, w->h, h);
    if (!(style & 0x40000000u)) {   // top-level (not WS_CHILD)
        extern uint64_t rt_last_surface_hwnd;
        w->layer = rt_cocoa_create_window(h, t, w->w, w->h);
        rt_last_surface_hwnd = h;
    }
    // WM_NCCREATE / WM_CREATE with a CREATESTRUCT
    uint32_t cs = gcalloc(1, 48);
    wr32(cs + 0, ARG(11)); wr32(cs + 4, ARG(9)); wr32(cs + 8, ARG(10)); wr32(cs + 12, ARG(8));
    wr32(cs + 16, (uint32_t)w->h); wr32(cs + 20, (uint32_t)w->w); wr32(cs + 24, (uint32_t)w->y); wr32(cs + 28, (uint32_t)w->x);
    wr32(cs + 32, style); wr32(cs + 36, title); wr32(cs + 40, cls); wr32(cs + 44, exst);
    send(c, h, 0x0081, 0, cs);
    send(c, h, 0x0001, 0, cs);
    gfree(cs);
    return h;
}
SHIM(user32_CreateWindowExA, 12) { return create_window(c, 0); }
SHIM(user32_CreateWindowExW, 12) { return create_window(c, 1); }
SHIM(user32_DestroyWindow, 1) {
    rt_log("[user32] DestroyWindow(0x%x) from 0x%x", ARG(0), rd32(c->esp)); Wnd *w = wget(ARG(0)); if (w) { send(c, ARG(0), 0x0002, 0, 0); w->used = 0; } return 1; }
SHIM(user32_ShowWindow, 2) { Wnd *w = wget(ARG(0)); int was = w && w->visible; if (w) w->visible = ARG(1) != 0; return (uint32_t)was; }
SHIM(user32_UpdateWindow, 1) { return 1; }
SHIM(user32_DefWindowProcA, 4) { return ARG(1) == 0x0081 ? 1 : 0; }
SHIM(user32_DefWindowProcW, 4) { return ARG(1) == 0x0081 ? 1 : 0; }
SHIM(user32_SetWindowLongA, 3) {
    Wnd *w = wget(ARG(0)); if (!w) return 0;
    int32_t i = (int32_t)ARG(1); uint32_t v = ARG(2), old = 0;
    if (i == -4) { old = w->wndproc; w->wndproc = v; }
    else if (i == -16) { old = w->style; w->style = v; }
    else if (i == -20) { old = w->exstyle; w->exstyle = v; }
    else if (i == -21) { old = w->userdata; w->userdata = v; }
    return old;
}
SHIM(user32_SetPropA, 3) {
    Wnd *w = wget(ARG(0)); if (!w) return 0;
    char k[32]; if (ARG(1) < 0x10000) snprintf(k, sizeof k, "#%u", ARG(1)); else snprintf(k, sizeof k, "%s", STR(1));
    for (int i = 0; i < 16; i++) if (!strcmp(w->props[i].k, k) || !w->props[i].k[0]) { snprintf(w->props[i].k, 32, "%s", k); w->props[i].v = ARG(2); return 1; }
    return 0;
}
SHIM(user32_GetPropA, 2) {
    Wnd *w = wget(ARG(0)); if (!w) return 0;
    char k[32]; if (ARG(1) < 0x10000) snprintf(k, sizeof k, "#%u", ARG(1)); else snprintf(k, sizeof k, "%s", STR(1));
    for (int i = 0; i < 16; i++) if (!strcmp(w->props[i].k, k)) return w->props[i].v;
    return 0;
}
SHIM(user32_RemovePropA, 2) {
    Wnd *w = wget(ARG(0)); if (!w) return 0;
    char k[32]; if (ARG(1) < 0x10000) snprintf(k, sizeof k, "#%u", ARG(1)); else snprintf(k, sizeof k, "%s", STR(1));
    for (int i = 0; i < 16; i++) if (!strcmp(w->props[i].k, k)) { uint32_t v = w->props[i].v; w->props[i].k[0] = 0; return v; }
    return 0;
}
static void wr_rect(uint32_t r, int l, int t, int rr, int b) { wr32(r, (uint32_t)l); wr32(r + 4, (uint32_t)t); wr32(r + 8, (uint32_t)rr); wr32(r + 12, (uint32_t)b); }
SHIM(user32_GetWindowRect, 2) { Wnd *w = wget(ARG(0)); if (!w) return 0; wr_rect(ARG(1), w->x, w->y, w->x + w->w, w->y + w->h); return 1; }
SHIM(user32_GetClientRect, 2) { Wnd *w = wget(ARG(0)); if (!w) return 0; wr_rect(ARG(1), 0, 0, w->w, w->h); return 1; }
SHIM(user32_AdjustWindowRect, 3) { return 1; }
SHIM(user32_SetWindowPos, 7) {
    Wnd *w = wget(ARG(0)); if (!w) return 0;
    uint32_t fl = ARG(6);
    if (!(fl & 2)) { w->x = (int32_t)ARG(2); w->y = (int32_t)ARG(3); }
    if (!(fl & 1)) { w->w = (int32_t)ARG(4); w->h = (int32_t)ARG(5); if (w->layer) rt_cocoa_set_size(ARG(0), w->w, w->h); }
    return 1;
}
SHIM(user32_GetSystemMetrics, 1) {
    static int once; if (!once++) rt_cocoa_screen_size(&rt_screen_w, &rt_screen_h);
    switch (ARG(0)) { case 0: case 16: case 78: return (uint32_t)rt_screen_w; case 1: case 17: case 79: return (uint32_t)rt_screen_h; default: return 0; }
}
SHIM(user32_SystemParametersInfoA, 4) {
    if (ARG(0) == 0x30 && ARG(2)) { wr_rect(ARG(2), 0, 0, rt_screen_w, rt_screen_h); return 1; }   // SPI_GETWORKAREA
    return 1;
}
SHIM(user32_PeekMessageA, 5) {
    uint32_t m = ARG(0), rm = ARG(4) & 1;
    pthread_mutex_lock(&q_mu);
    if (qh == qt) { pthread_mutex_unlock(&q_mu); return 0; }
    Msg x = queue[qh]; if (rm) qh = (qh + 1) % 256;
    pthread_mutex_unlock(&q_mu);
    wr32(m, x.hwnd); wr32(m + 4, x.msg); wr32(m + 8, x.wp); wr32(m + 12, x.lp); wr32(m + 16, 0); wr32(m + 20, 0); wr32(m + 24, 0);
    return 1;
}
SHIM(user32_TranslateMessage, 1) { return 0; }
SHIM(user32_DispatchMessageW, 1) { uint32_t m = ARG(0); return send(c, rd32(m), rd32(m + 4), rd32(m + 8), rd32(m + 12)); }
SHIM(user32_SendMessageA, 4) { if (trace_msg > 0) rt_log("[user32] SendMessageA(0x%x) from 0x%x", ARG(1), rd32(c->esp)); return send(c, ARG(0), ARG(1), ARG(2), ARG(3)); }
SHIM(user32_SendMessageW, 4) { if (trace_msg > 0) rt_log("[user32] SendMessageW(0x%x) from 0x%x", ARG(1), rd32(c->esp)); return send(c, ARG(0), ARG(1), ARG(2), ARG(3)); }
SHIM(user32_PostQuitMessage, 1) {
    rt_log("[user32] PostQuitMessage(%d) from 0x%x", (int)ARG(0), rd32(c->esp));
    rt_post_message(0, 0x0012, ARG(0), 0); return 0;
}
SHIM(user32_GetForegroundWindow, 0) { for (int i = 1; i < 64; i++) if (wnds[i].used) return HWND_OF(i); return 0; }
SHIM(user32_FindWindowW, 2) { return 0; }
SHIM(user32_IsIconic, 1) { return 0; }
SHIM(user32_GetWindowThreadProcessId, 2) { if (ARG(1)) wr32(ARG(1), 0x10); return 0x100; }
SHIM(user32_LoadIconA, 2) { return 0x20001; }
SHIM(user32_LoadIconW, 2) { return 0x20001; }
SHIM(user32_LoadCursorA, 2) { return 0x20002; }
SHIM(user32_LoadAcceleratorsA, 2) { return 0x20003; }
SHIM(user32_SetCursor, 1) {   // returns the previous cursor; NULL hides it
    void rt_cocoa_set_cursor_null(int null);
    static uint32_t cur = 0x10001;
    uint32_t prev = cur; cur = ARG(0);
    static int logged; if (logged < 2 && (cur == 0) != (prev == 0)) { logged++; rt_log("[user32] SetCursor(%s)", cur ? "cursor" : "NULL: hidden"); }
    rt_cocoa_set_cursor_null(cur == 0);
    return prev;
}
int rt_cocoa_show_cursor(int show);
SHIM(user32_ShowCursor, 1) { return (uint32_t)rt_cocoa_show_cursor(ARG(0) != 0); }
SHIM(user32_ClipCursor, 1) { return 1; }
SHIM(user32_GetCursorPos, 1) { wr32(ARG(0), (uint32_t)rt_mouse_x); wr32(ARG(0) + 4, (uint32_t)rt_mouse_y); return 1; }
SHIM(user32_ScreenToClient, 2) { return 1; }
SHIM(user32_ClientToScreen, 2) { return 1; }
SHIM(user32_GetAsyncKeyState, 1) { return rt_keys[ARG(0) & 0xFF] ? 0x8000u : 0; }
SHIM(user32_RegisterHotKey, 4) { return 1; }
SHIM(user32_UnregisterHotKey, 2) { return 1; }
SHIM(user32_GetSystemMenu, 2) { return 0x30001; }
SHIM(user32_DeleteMenu, 3) { return 1; }
SHIM(user32_EnableMenuItem, 3) { return 0; }
SHIM(user32_BeginPaint, 2) { memset(G2H(ARG(1)), 0, 64); return 0x40001; }
SHIM(user32_EndPaint, 2) { return 1; }
SHIM(user32_MessageBoxA, 4) { rt_log("[user32] MessageBox \"%s\": %s", STR(2) ? STR(2) : "", STR(1) ? STR(1) : ""); return 1; }
SHIM(user32_EmptyClipboard, 0) { return 1; }
SHIM(user32_SetClipboardData, 2) { return ARG(1); }
SHIM(user32_CloseClipboard, 0) { return 1; }
