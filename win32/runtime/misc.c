#include <string.h>
// The small DLLs: winmm, advapi32, shell32, ole32/oleaut32, gdi32, imm32, iphlpapi, ws2_32, XInput, DirectInput,
// Steam (offline), and the not-yet-implemented media and graphics entry points (they fail cleanly and log).
#include "rt32.h"
#include <time.h>
#include <sys/stat.h>
#include <mach/mach_time.h>

// ---- winmm ----
SHIM(winmm_timeGetTime, 0) {
    static mach_timebase_info_data_t tb; if (!tb.denom) mach_timebase_info(&tb);
    return (uint32_t)(mach_absolute_time() * tb.numer / tb.denom / 1000000ull);
}
SHIM(winmm_timeBeginPeriod, 1) { return 0; }
SHIM(winmm_timeEndPeriod, 1) { return 0; }

// ---- advapi32: no registry ----
SHIM(advapi32_RegOpenKeyExA, 5) { return 2; }   // ERROR_FILE_NOT_FOUND
SHIM(advapi32_RegQueryValueExA, 6) { return 2; }
SHIM(advapi32_RegCloseKey, 1) { return 0; }

// ---- shell32 ----
SHIM(shell32_SHGetFolderPathA, 5) {
    // CSIDL_PERSONAL (5), CSIDL_APPDATA (0x1A), CSIDL_LOCAL_APPDATA (0x1C)...: all under the app's data folder,
    // which rt_host_path maps back (rt_game.docs_dir -> rt_data_dir)
    const char *p = rt_game.docs_dir;
    snprintf(G2H(ARG(4)), 260, "%s", p);
    mkdir(rt_data_dir, 0755);
    return 0;
}
SHIM(shell32_DragAcceptFiles, 2) { return 0; }

// ---- ole32 / oleaut32 ----
SHIM(ole32_CoInitialize, 1) { return 0; }
SHIM(ole32_CoUninitialize, 0) { return 0; }
SHIM(ole32_CoCreateInstance, 5) {   // no COM servers: REGDB_E_CLASSNOTREG
    const uint8_t *g = gp(ARG(0));
    if (g) rt_log("[ole32] CoCreateInstance {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x} from 0x%x -> not registered",
                  *(uint32_t *)g, *(uint16_t *)(g + 4), *(uint16_t *)(g + 6), g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15], rd32(c->esp));
    if (ARG(4)) wr32(ARG(4), 0);
    return 0x80040154u;
}
SHIM(ole32_CoSetProxyBlanket, 8) { return 0; }
SHIM(ole32_CoTaskMemAlloc, 1) { return gmalloc(ARG(0)); }
SHIM(ole32_CoTaskMemFree, 1) { gfree(ARG(0)); return 0; }
SHIM(oleaut32_ord2, 1) {   // SysAllocString: length-prefixed UTF-16
    size_t n = w_len(WSTR(0));
    uint32_t p = gmalloc((uint32_t)(n * 2 + 6));
    wr32(p, (uint32_t)(n * 2)); memcpy(G2H(p + 4), WSTR(0), n * 2); wr16(p + 4 + (uint32_t)n * 2, 0);
    return p + 4;
}
SHIM(oleaut32_ord6, 1) { if (ARG(0)) gfree(ARG(0) - 4); return 0; }   // SysFreeString

// ---- gdi32 / imm32 ----
SHIM(gdi32_GetStockObject, 1) { return 0x50000u + ARG(0); }
SHIM(imm32_ImmGetContext, 1) { return 0; }
SHIM(imm32_ImmReleaseContext, 2) { return 1; }
SHIM(imm32_ImmGetCompositionStringA, 4) { return 0; }
SHIM(imm32_ImmGetDefaultIMEWnd, 1) { return 0; }

// ---- networking: the game only checks for an adapter ----
SHIM(ws2_32_ord115, 2) { if (ARG(1)) { memset(G2H(ARG(1)), 0, 400); wr16(ARG(1), 0x0202); wr16(ARG(1) + 2, 0x0202); } return 0; }   // WSAStartup
SHIM(ws2_32_ord116, 0) { return 0; }                                                                                              // WSACleanup
SHIM(iphlpapi_GetAdaptersAddresses, 5) { if (ARG(4)) wr32(ARG(4), 0); return 232; }   // ERROR_NO_DATA
SHIM(iphlpapi_GetIfEntry, 1) { return 50; }   // ERROR_NOT_SUPPORTED

// ---- XInput 1.4 (ordinals): no controller yet (GameController bridge comes with the input layer) ----
// XInput on the GameController framework (framework/runtime/gamepad.m, shared with the 64-bit runtime)
int gamepad_state(int user, uint8_t out[16], int guide);
int gamepad_connected(int user);
int gamepad_rumble(int user, uint16_t left, uint16_t right);
SHIM(xinput1_4_ord2, 2) {   // XInputGetState(user, XINPUT_STATE *)
    uint8_t st[16];
    if (!gamepad_state((int)ARG(0), st, 0)) return 1167;    // ERROR_DEVICE_NOT_CONNECTED
    if (ARG(1)) memcpy(G2H(ARG(1)), st, 16);
    return 0;
}
SHIM(xinput1_4_ord3, 2) {   // XInputSetState(user, XINPUT_VIBRATION * {left, right})
    uint32_t v = ARG(1);
    return gamepad_rumble((int)ARG(0), v ? rd16(v) : 0, v ? rd16(v + 2) : 0) ? 0 : 1167;
}
SHIM(xinput1_4_ord4, 3) {   // XInputGetCapabilities(user, flags, XINPUT_CAPABILITIES *): a full standard gamepad
    if (!gamepad_connected((int)ARG(0))) return 1167;
    uint32_t p = ARG(2);
    if (p) {
        memset(G2H(p), 0, 20);
        wr8(p, 1); wr8(p + 1, 1); wr16(p + 2, 0x0001);
        wr16(p + 4, 0xF3FF); wr8(p + 6, 0xFF); wr8(p + 7, 0xFF);
        for (int i = 0; i < 4; i++) wr16(p + 8 + 2 * i, 0xFFC0);
        wr16(p + 16, 0xFFFF); wr16(p + 18, 0xFFFF);
    }
    return 0;
}
SHIM(xinput1_4_ord5, 1) { return 0; }      // XInputEnable
// gamepad.m's hooks: the game window gets WM_DEVICECHANGE on connects/disconnects
uint64_t rt_last_surface_hwnd;
void win_from_cocoa(uint64_t h, uint32_t msg, uint64_t wp, uint64_t lp) {
    void rt_post_message(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp);
    rt_post_message((uint32_t)h, msg, (uint32_t)wp, (uint32_t)lp);
}

// ---- not yet implemented: fail the way a missing component does on Windows, and say so once ----
#define NOTYET(sym, n, ret, what) SHIM(sym, n) { static int once; if (!once++) rt_log("[todo] %s: %s", #sym, what); return ret; }
NOTYET(wmvcore_WMCreateWriter, 2, 0x80004005u, "WMCreateWriter")
NOTYET(wmvcore_WMCreateProfileManager, 1, 0x80004005u, "WMCreateProfileManager")
NOTYET(avifil32_AVIFileInit, 0, 0, "AVIFileInit")
NOTYET(avifil32_AVIFileExit, 0, 0, "AVIFileExit")
NOTYET(gdiplus_GdiplusStartup, 3, 1, "GDI+ (screenshot encoding) -> GenericError")
NOTYET(gdiplus_GdiplusShutdown, 1, 0, "GdiplusShutdown")
// d3d9: d3d9_bridge.cpp (host d3d9 backends such as DXVK)

// ---- Steam: steam32.c
