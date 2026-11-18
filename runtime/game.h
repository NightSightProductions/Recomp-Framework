// Per-game settings. The runtime is game-agnostic; everything that names a particular game lives in one
// `const RtGame rt_game` that each game project defines (game.c).
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *name;          // display name, e.g. "My Game"
    const char *exe;           // the Windows executable, e.g. "MyGame.exe"
    const char *win_dir;       // where the game believes it is installed, e.g. "C:\\Games\\MyGame" (no trailing backslash)
    const char *data_name;     // per-user data folder: ~/Library/Application Support/<data_name>
    const char *log_name;      // ~/Library/Logs/<log_name>.log
    const char *env_prefix;    // prefix of the environment settings: <prefix>_GAME_DIR, <prefix>_DATA_DIR, ...
    const char *steam_folder;  // the game's folder in steamapps/common, for finding it
    uint32_t steam_app_id;     // Steam app ID (0: no Steam)
    const char *relaunch_prefix;   // CreateProcess/ShellExecute of an exe whose name starts with this relaunches us
    const char *const *extra_args; // arguments always appended to the game's command line (NULL-terminated, or NULL)
    const char *cloud_save_dir;    // save folder synced to Steam Cloud, under the data folder; "%llu" = Steam ID (or NULL)
    const char *cloud_prefix;      // name prefix of the synced files in the game's cloud space, e.g. "mygame-recomp/"
    const char *computer_name;     // what GetComputerName reports
    const char *pick_folder_msg;   // message of the folder picker when the game isn't found
    const char *image;             // optional: the executable image to load, from the app's Resources when it is
                                   // there (e.g. a DRM-free copy of the exe made at build time); else <game folder>/<exe>
    const char *gl_extensions;     // OpenGL games: extra names for GL_EXTENSIONS, space-separated (e.g. an extension
                                   // the engine checks before loading entry points that the core profile has anyway)
    // Opt-in Win32 behaviour (0 keeps the older behaviour that existing ports were built and tested against):
    int windows_env;               // GetEnvironmentVariable reports a Windows environment (LOCALAPPDATA, APPDATA, TEMP,
                                   // USERNAME, SystemRoot... in the virtual C:); 0: only DXVK_/MESA_/VKD3D_ host variables
    int win32_cursors;             // SetCursor changes the on-screen cursor (custom cursors from CreateIconIndirect,
                                   // SetCursor(NULL) hides it), and mouse moves send WM_SETCURSOR, as on Windows (UE4)
    // When the Steam layer runs offline (no Steam client, or <PREFIX>_STEAM_OFFLINE):
    int steam_offline_logged_off;  // ISteamUser::BLoggedOn reports false, as Steam in offline mode does; 0: true, so the
                                   // game tries its online sign-in and waits for the ticket requests to fail
    int offline_no_http;           // WinHttpCheckPlatform reports WinHTTP unavailable, so the game makes no web
                                   // requests (telemetry, online config). Needs the check to come after SteamAPI_Init,
                                   // unless offline is forced by <PREFIX>_STEAM_OFFLINE.
} RtGame;

extern const RtGame rt_game;

// getenv("<env_prefix>_<name>")
const char *rt_game_env(const char *name);
// The Steam layer runs offline: forced by <PREFIX>_STEAM_OFFLINE, or SteamAPI_Init found no Steam client
// (0 before SteamAPI_Init, unless forced).
int rt_steam_offline(void);
