// Game controllers and COM: XInput (imported by ordinal) on the GameController framework (gamepad.m);
// ole32's CoCreateInstance hands out the audio objects and reports "class not registered" for the rest.
#include "rt.h"

#define ERROR_DEVICE_NOT_CONNECTED 1167
#define ERROR_EMPTY 4306

int gamepad_state(int user, uint8_t out[16], int guide);
int gamepad_connected(int user);
int gamepad_rumble(int user, uint16_t left, uint16_t right);
void gamepad_battery(int user, uint8_t *type, uint8_t *level);

// ---------------- xinput1_4.dll ----------------
// XInputGetState(user, XINPUT_STATE*); #100 XInputGetStateEx also reports the Guide button
static void get_state(CPU *c, int guide) {
    uint8_t st[16];
    static int logged_call, logged_ok;
    if (!logged_call) { logged_call = 1; rt_log("[xinput] first XInputGetState(user %u)\n", (uint32_t)A0); }
    if (!gamepad_state((int)(uint32_t)A0, st, guide)) { RET(ERROR_DEVICE_NOT_CONNECTED); return; }
    if (!logged_ok) { logged_ok = 1; rt_log("[xinput] controller %u reported to the game\n", (uint32_t)A0); }
    if (A1) memcpy(PTR(A1), st, 16);
    RET(0);
}
// XInputSetState(user, XINPUT_VIBRATION* { wLeftMotorSpeed, wRightMotorSpeed })
static void set_state(CPU *c) {
    uint16_t l = A1 ? rd16(A1) : 0, r = A1 ? rd16(A1 + 2) : 0;
    RET(gamepad_rumble((int)(uint32_t)A0, l, r) ? 0 : ERROR_DEVICE_NOT_CONNECTED);
}
// XInputGetCapabilities(user, flags, XINPUT_CAPABILITIES*): Type +0, SubType +1, Flags +2, Gamepad +4 (12),
// Vibration +16 (4): a standard gamepad with every button and axis and both motors
static void get_caps(CPU *c) {
    if (!gamepad_connected((int)(uint32_t)A0)) { RET(ERROR_DEVICE_NOT_CONNECTED); return; }
    uint64_t p = A2;
    if (p) {
        memset(PTR(p), 0, 20);
        wr8(p, 1); wr8(p + 1, 1); wr16(p + 2, 0x0001);          // XINPUT_DEVTYPE_GAMEPAD, _DEVSUBTYPE_GAMEPAD, CAPS_FFB_SUPPORTED
        wr16(p + 4, 0xF3FF); wr8(p + 6, 0xFF); wr8(p + 7, 0xFF);
        for (int i = 0; i < 4; i++) wr16(p + 8 + 2 * i, 0xFFC0);
        wr16(p + 16, 0xFFFF); wr16(p + 18, 0xFFFF);
    }
    RET(0);
}
// XInputGetBatteryInformation(user, devType, XINPUT_BATTERY_INFORMATION* { BatteryType, BatteryLevel })
static void get_battery(CPU *c) {
    if (!gamepad_connected((int)(uint32_t)A0)) { RET(ERROR_DEVICE_NOT_CONNECTED); return; }
    uint8_t t, l; gamepad_battery((int)(uint32_t)A0, &t, &l);
    if (A2) { wr8(A2, t); wr8(A2 + 1, l); }
    RET(0);
}
// XInputGetKeystroke(user, reserved, XINPUT_KEYSTROKE*): no keystroke queue (the game polls states)
static void get_keystroke(CPU *c) {
    uint32_t u = (uint32_t)A0;
    int any = 0; for (int i = 0; i < 4; i++) any |= gamepad_connected(i);
    RET((u == 0xFF ? any : gamepad_connected((int)u)) ? ERROR_EMPTY : ERROR_DEVICE_NOT_CONNECTED);
}
void I_xinput1_4_dll__2(CPU *c) { get_state(c, 0); }
void I_xinput1_4_dll__3(CPU *c) { set_state(c); }
void I_xinput1_4_dll__4(CPU *c) { get_caps(c); }
void I_xinput1_4_dll__5(CPU *c) { }   // XInputEnable
void I_xinput1_4_dll__7(CPU *c) { get_battery(c); }
void I_xinput1_4_dll__8(CPU *c) { get_keystroke(c); }
void I_xinput1_4_dll__100(CPU *c) { get_state(c, 1); }   // XInputGetStateEx (hidden)
// by name, for GetProcAddress
void I_xinput1_4_dll_XInputGetState(CPU *c) { get_state(c, 0); }
void I_xinput1_4_dll_XInputSetState(CPU *c) { set_state(c); }
void I_xinput1_4_dll_XInputGetCapabilities(CPU *c) { get_caps(c); }
void I_xinput1_4_dll_XInputEnable(CPU *c) { }
void I_xinput1_4_dll_XInputGetBatteryInformation(CPU *c) { get_battery(c); }
void I_xinput1_4_dll_XInputGetKeystroke(CPU *c) { get_keystroke(c); }
// xinput1_3 (DirectX SDK, older games): same ordinals and functions
void I_xinput1_3_dll__2(CPU *c) { get_state(c, 0); }
void I_xinput1_3_dll__3(CPU *c) { set_state(c); }
void I_xinput1_3_dll__4(CPU *c) { get_caps(c); }
void I_xinput1_3_dll__5(CPU *c) { }   // XInputEnable
void I_xinput1_3_dll__7(CPU *c) { get_battery(c); }
void I_xinput1_3_dll__8(CPU *c) { get_keystroke(c); }
void I_xinput1_3_dll__100(CPU *c) { get_state(c, 1); }
void I_xinput1_3_dll_XInputGetState(CPU *c) { get_state(c, 0); }
void I_xinput1_3_dll_XInputSetState(CPU *c) { set_state(c); }
void I_xinput1_3_dll_XInputGetCapabilities(CPU *c) { get_caps(c); }
void I_xinput1_3_dll_XInputEnable(CPU *c) { }
void I_xinput1_3_dll_XInputGetBatteryInformation(CPU *c) { get_battery(c); }
void I_xinput1_3_dll_XInputGetKeystroke(CPU *c) { get_keystroke(c); }

// ---------------- ole32.dll ----------------
#define REGDB_E_CLASSNOTREG 0x80040154u
static void guid_str(uint64_t g, char *out, size_t n) {
    if (!g) { snprintf(out, n, "(null)"); return; }
    const uint8_t *b = PTR(g);
    snprintf(out, n, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", rd32(g), rd16(g + 4), rd16(g + 6),
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}
void I_ole32_dll_CoInitialize(CPU *c) { RET(0); }
void I_ole32_dll_CoInitializeEx(CPU *c) { RET(0); }
void I_ole32_dll_CoUninitialize(CPU *c) { }
void I_ole32_dll_CoInitializeSecurity(CPU *c) { RET(0); }
// CoCreateGuid(GUID *): a random (version 4) GUID
void I_ole32_dll_CoCreateGuid(CPU *c) {
    if (!A0) { RET(0x80070057u); return; }   // E_INVALIDARG
    uint8_t *g = PTR(A0); arc4random_buf(g, 16);
    g[7] = (uint8_t)((g[7] & 0x0F) | 0x40); g[8] = (uint8_t)((g[8] & 0x3F) | 0x80);   // Data3 high nibble 4, variant 10
    RET(0);
}
// CoCreateInstance(rclsid, outer, clsctx, riid, *ppv)
uint32_t xaudio2_cocreate(uint64_t clsid, uint64_t iid, uint64_t ppv);   // xaudio2.c
uint32_t wasapi_cocreate(uint64_t clsid, uint64_t iid, uint64_t ppv);    // wasapi.c
void I_ole32_dll_CoCreateInstance(CPU *c) {
    if (A0 && AN(4)) { uint32_t hr = xaudio2_cocreate(A0, A3, AN(4)); if (hr != REGDB_E_CLASSNOTREG) { RET(hr); return; } }
    if (A0 && AN(4)) { uint32_t hr = wasapi_cocreate(A0, A3, AN(4)); if (hr != REGDB_E_CLASSNOTREG) { RET(hr); return; } }
    char cls[48], iid[48];
    guid_str(A0, cls, sizeof cls); guid_str(A3, iid, sizeof iid);
    static char seen[32][48]; static int nseen; int dup = 0;
    for (int i = 0; i < nseen; i++) if (!strcmp(seen[i], cls)) dup = 1;
    if (!dup) { if (nseen < 32) strcpy(seen[nseen++], cls); rt_log("[ole32] CoCreateInstance(%s, %s): class not available\n", cls, iid); }
    if (AN(4)) wr64(AN(4), 0);
    RET(REGDB_E_CLASSNOTREG);
}
void I_ole32_dll_CoTaskMemAlloc(CPU *c) { RET(G(malloc(A0 ? A0 : 1))); }
void I_ole32_dll_CoTaskMemFree(CPU *c) { free(PTR(A0)); }
void I_ole32_dll_CoTaskMemRealloc(CPU *c) { RET(G(realloc(PTR(A0), A1 ? A1 : 1))); }
