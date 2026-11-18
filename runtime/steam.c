// steam_api64.dll. Each interface the game asks for is an object whose vtable slots are native functions,
// laid out as the game's SDK had them (SteamUser018, SteamFriends015, SteamUtils007, SteamApps007, ...).
//
// Online (default when the Steam for Mac client is running; <PREFIX>_STEAM_OFFLINE=1 forces offline): identity
// calls are forwarded through Valve's libsteam_api.dylib flat API: Steam ID, persona name, auth/encrypted
// app tickets (which online services need), language/DLC. Every callback / call-result object the game
// registers gets a native twin (an Itanium-ABI CCallbackBase) registered with the real library; Steam's own
// SteamAPI_RunCallbacks fires the twins, which convert the struct (macOS SDK structs are packed to 4,
// Windows ones to 8) and call the game's handler.
// Offline (no client or no library): SteamAPI_Init still succeeds, the user is "Player", and async calls
// complete with k_EResultNoConnection after a delay. BLoggedOn reports true, or false with
// rt_game.steam_offline_logged_off.
// Slots not implemented log once and return 0.
#include "rt.h"
#include <dlfcn.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <time.h>

#define NSLOTS 96
// ISteamRemoteStorage: every method answers 0 (cloud disabled, no files), so saves stay on local disk
enum { IF_USER, IF_FRIENDS, IF_UTILS, IF_APPS, IF_USERSTATS, IF_MATCHMAKING, IF_NETWORKING, IF_CONTROLLER, IF_CLIENT,
       IF_REMOTESTORAGE, NIF };
static const char *if_names[NIF] = { "ISteamUser", "ISteamFriends", "ISteamUtils", "ISteamApps", "ISteamUserStats",
                                     "ISteamMatchmaking", "ISteamNetworking", "ISteamController", "ISteamClient",
                                     "ISteamRemoteStorage" };
static uint64_t objs[NIF];
#include "game.h"
#define app_id (rt_game.steam_app_id)

typedef void (*slotfn)(CPU *c, int iface, int slot);
static void slot_default(CPU *c, int iface, int slot);
static slotfn impl[NIF][NSLOTS];

static void slot_default(CPU *c, int iface, int slot) {
    static uint8_t seen[NIF][NSLOTS];
    if (!seen[iface][slot]) { seen[iface][slot] = 1; rt_log("[steam] %s::slot %d (this=%llx) -> 0\n", if_names[iface], slot, (unsigned long long)A0); }
    RET(0);
}
static void dispatch(CPU *c, int iface, int slot) {
    slotfn f = impl[iface][slot];
    (f ? f : slot_default)(c, iface, slot);
}

// one native function per (interface, slot): see steam_slots.h (tools/gen_steam_slots.py NIF NSLOTS)
#include "steam_slots.h"

static uint64_t make_iface(int i) {
    if (objs[i]) return objs[i];
    uint64_t *vt = calloc(NSLOTS, 8);
    for (int s = 0; s < NSLOTS; s++) {
        char *n = malloc(48); snprintf(n, 48, "%s#%d", if_names[i], s);
        vt[s] = rt_host_fn(slot_fns[i][s], n);
    }
    uint64_t *obj = calloc(4, 8);
    obj[0] = G(vt);
    objs[i] = G(obj);
    return objs[i];
}

// ---------------- the real Steam client (libsteam_api.dylib) ----------------
static struct {
    int online;
    void *user, *friends, *utils, *apps, *mm, *net, *stats, *rs;   // host interface pointers
    int32_t pipe;
    bool (*InitSafe)(void);
    void (*Shutdown)(void);
    int32_t (*GetHSteamPipe)(void);
    bool (*BLoggedOn)(void *);
    uint64_t (*GetSteamID)(void *);
    uint32_t (*GetAuthSessionTicket)(void *, void *, int, uint32_t *, const void *);
    void (*CancelAuthTicket)(void *, uint32_t);
    uint64_t (*RequestEncryptedAppTicket)(void *, void *, int);
    bool (*GetEncryptedAppTicket)(void *, void *, int, uint32_t *);
    int (*GetPlayerSteamLevel)(void *);
    const char *(*GetPersonaName)(void *);
    uint32_t (*GetAppID)(void *);
    const char *(*GetCurrentGameLanguage)(void *);
    bool (*BIsDlcInstalled)(void *, uint32_t);
    bool (*BIsSubscribedApp)(void *, uint32_t);
    const char *(*GetIPCountry)(void *);
    bool (*IsAPICallCompleted)(void *, uint64_t, bool *);
    bool (*GetAPICallResult)(void *, uint64_t, void *, int, int, bool *);
    void (*RunCallbacks)(void);
    void (*RegisterCallback)(void *, int), (*UnregisterCallback)(void *);
    void (*RegisterCallResult)(void *, uint64_t), (*UnregisterCallResult)(void *, uint64_t);
} S;

static void flat_load(void *h);
static void *steam_lib(void) {
    char p[PATH_MAX]; uint32_t n = sizeof p;
    const char *env = rt_game_env("STEAM_API");
    if (env) { void *h = dlopen(env, RTLD_NOW | RTLD_LOCAL); if (h) return h; }
    if (!_NSGetExecutablePath(p, &n)) {   // inside the app bundle: Contents/Frameworks/libsteam_api.dylib
        char *s = strrchr(p, '/');
        if (s) { snprintf(s, sizeof p - (size_t)(s - p), "/../Frameworks/libsteam_api.dylib"); void *h = dlopen(p, RTLD_NOW | RTLD_LOCAL); if (h) return h; }
    }
    const char *home = getenv("HOME") ? getenv("HOME") : "";
    const char *known[] = {
        // the Steam client's own copy, which every Mac Steam install has
        "%s/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/Frameworks/Steam Helper.app/Contents/MacOS/libsteam_api.dylib",
        // copies bundled with Mac Steam games
        "%s/Library/Application Support/Steam/steamapps/common/Balatro/Balatro.app/Contents/Resources/libsteam_api.dylib",
        "%s/Library/Application Support/Steam/steamapps/common/Half-Life/libsteam_api.dylib",
    };
    for (size_t i = 0; i < sizeof known / sizeof *known; i++) {
        snprintf(p, sizeof p, known[i], home);
        void *h = dlopen(p, RTLD_NOW | RTLD_LOCAL);
        if (h) { rt_log("[steam] using %s\n", p); return h; }
    }
    return NULL;
}
static void *steam_accessor(void *h, const char *iface, int newest, int oldest) {
    char n[96];
    for (int v = newest; v >= oldest; v--) {
        snprintf(n, sizeof n, "SteamAPI_%s_v%03d", iface, v);
        void *f = dlsym(h, n);
        if (f) return f;
    }
    return NULL;
}
static int steam_connect(void) {
    if (rt_game_env("STEAM_OFFLINE")) return 0;
    void *h = steam_lib();
    if (!h) { rt_log("[steam] libsteam_api.dylib not found: offline (set <PREFIX>_STEAM_API to its path)\n"); return 0; }
#define SYM(field, name) S.field = dlsym(h, name); if (!S.field) { rt_log("[steam] %s missing in libsteam_api.dylib: offline\n", name); return 0; }
    SYM(InitSafe, "SteamAPI_InitSafe") SYM(Shutdown, "SteamAPI_Shutdown")
    SYM(GetHSteamPipe, "SteamAPI_GetHSteamPipe") SYM(RunCallbacks, "SteamAPI_RunCallbacks")
    SYM(RegisterCallback, "SteamAPI_RegisterCallback") SYM(UnregisterCallback, "SteamAPI_UnregisterCallback")
    SYM(RegisterCallResult, "SteamAPI_RegisterCallResult") SYM(UnregisterCallResult, "SteamAPI_UnregisterCallResult")
    SYM(GetAPICallResult, "SteamAPI_ISteamUtils_GetAPICallResult")
    SYM(BLoggedOn, "SteamAPI_ISteamUser_BLoggedOn") SYM(GetSteamID, "SteamAPI_ISteamUser_GetSteamID")
    SYM(GetAuthSessionTicket, "SteamAPI_ISteamUser_GetAuthSessionTicket") SYM(CancelAuthTicket, "SteamAPI_ISteamUser_CancelAuthTicket")
    SYM(RequestEncryptedAppTicket, "SteamAPI_ISteamUser_RequestEncryptedAppTicket") SYM(GetEncryptedAppTicket, "SteamAPI_ISteamUser_GetEncryptedAppTicket")
    SYM(GetPlayerSteamLevel, "SteamAPI_ISteamUser_GetPlayerSteamLevel") SYM(GetPersonaName, "SteamAPI_ISteamFriends_GetPersonaName")
    SYM(GetAppID, "SteamAPI_ISteamUtils_GetAppID") SYM(GetIPCountry, "SteamAPI_ISteamUtils_GetIPCountry")
    SYM(IsAPICallCompleted, "SteamAPI_ISteamUtils_IsAPICallCompleted")
    SYM(GetCurrentGameLanguage, "SteamAPI_ISteamApps_GetCurrentGameLanguage")
    SYM(BIsDlcInstalled, "SteamAPI_ISteamApps_BIsDlcInstalled") SYM(BIsSubscribedApp, "SteamAPI_ISteamApps_BIsSubscribedApp")
#undef SYM
    // interface accessors: the newest version first. Calls go through the flat API, whose functions keep their
    // signatures across these versions.
    void *(*user_v)(void) = steam_accessor(h, "SteamUser", 24, 23), *(*friends_v)(void) = steam_accessor(h, "SteamFriends", 18, 17);
    void *(*utils_v)(void) = steam_accessor(h, "SteamUtils", 11, 10), *(*apps_v)(void) = steam_accessor(h, "SteamApps", 9, 8);
    if (!user_v || !friends_v || !utils_v || !apps_v) { rt_log("[steam] libsteam_api.dylib is from an unsupported SDK version: offline\n"); return 0; }
    char id[16]; snprintf(id, sizeof id, "%u", app_id);
    setenv("SteamAppId", id, 1); setenv("SteamGameId", id, 1);
    if (!S.InitSafe()) { rt_log("[steam] Steam client not running (or not logged in): offline\n"); return 0; }
    S.user = user_v(); S.friends = friends_v(); S.utils = utils_v(); S.apps = apps_v();
    void *(*mm_v)(void) = dlsym(h, "SteamAPI_SteamMatchmaking_v009"), *(*net_v)(void) = dlsym(h, "SteamAPI_SteamNetworking_v006");
    S.mm = mm_v ? mm_v() : NULL; S.net = net_v ? net_v() : NULL;
    void *(*stats_v)(void) = steam_accessor(h, "SteamUserStats", 13, 12); S.stats = stats_v ? stats_v() : NULL;
    void *(*rs_v)(void) = dlsym(h, "SteamAPI_SteamRemoteStorage_v016"); S.rs = rs_v ? rs_v() : NULL;
    flat_load(h);
    S.pipe = S.GetHSteamPipe();
    return S.user && S.friends && S.utils && S.apps;
}

// ---------------- offline async results ----------------
typedef struct { uint64_t handle; int id, size; uint8_t data[64]; int done; uint64_t ready_ms; } CallResult;
#define OFFLINE_DELAY_MS 10000   // offline Steam takes seconds to fail; answering at once makes the game retry every frame
static CallResult results[256]; static int nresults;
static uint64_t next_call = 0x5354454100000001ull;
static pthread_mutex_t smu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t now_ms(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000; }
static uint64_t complete_call(int id, const void *data, int size) {
    pthread_mutex_lock(&smu);
    uint64_t h = next_call++;
    CallResult *r = &results[nresults++ % 256];
    r->handle = h; r->id = id; r->size = size; r->done = 0; memcpy(r->data, data, (size_t)size);
    r->ready_ms = now_ms() + OFFLINE_DELAY_MS;
    pthread_mutex_unlock(&smu);
    return h;
}

// ---------------- interface methods ----------------
void steam_register_pending(void);
static void ret_true(CPU *c, int i, int s) { RET(1); }
// ISteamUser018: 1 BLoggedOn, 2 GetSteamID, 13 GetAuthSessionTicket, 16 CancelAuthTicket,
// 20 RequestEncryptedAppTicket, 21 GetEncryptedAppTicket, 23 GetPlayerSteamLevel
static void u_BLoggedOn(CPU *c, int i, int s) { RET(S.online ? S.BLoggedOn(S.user) : !rt_game.steam_offline_logged_off); }
// CSteamID is returned through a hidden pointer (rdx) under the MSVC ABI
static void u_GetSteamID(CPU *c, int i, int s) { wr64(A1, S.online ? S.GetSteamID(S.user) : 0x0110000100000001ull); RET(A1); }
// GetAuthSessionTicket(ticket, cbMax, *pcbTicket) -> HAuthTicket
static void u_GetAuthSessionTicket(CPU *c, int i, int s) {
    if (!S.online) { if (A3) wr32(A3, 0); RET(0); return; }
    uint32_t n = 0, h = S.GetAuthSessionTicket(S.user, PTR(A1), (int)A2, &n, NULL);
    if (A3) wr32(A3, n);
    rt_log("[steam] GetAuthSessionTicket -> handle %u, %u bytes\n", h, n);
    RET(h);
}
static void u_CancelAuthTicket(CPU *c, int i, int s) { if (S.online) S.CancelAuthTicket(S.user, (uint32_t)A1); }
// RequestEncryptedAppTicket(data, size) -> SteamAPICall_t; result EncryptedAppTicketResponse_t (id 154)
static void u_RequestEncryptedAppTicket(CPU *c, int i, int s) {
    if (S.online) { uint64_t h = S.RequestEncryptedAppTicket(S.user, PTR(A1), (int)A2); rt_log("[steam] RequestEncryptedAppTicket -> call %llx\n", (unsigned long long)h); RET(h); return; }
    int32_t eresult = 3;   // k_EResultNoConnection
    static int n; if (n++ < 3) rt_log("[steam] RequestEncryptedAppTicket -> offline failure%s\n", n == 3 ? " (further requests not logged)" : "");
    RET(complete_call(154, &eresult, 4));
}
// GetEncryptedAppTicket(ticket, cbMax, *pcbTicket) -> bool
static void u_GetEncryptedAppTicket(CPU *c, int i, int s) {
    uint32_t n = 0; bool ok = S.online && S.GetEncryptedAppTicket(S.user, PTR(A1), (int)A2, &n);
    rt_log("[steam] GetEncryptedAppTicket -> %d, %u bytes\n", ok, n);
    if (A3) wr32(A3, n);
    RET(ok);
}
static void u_GetPlayerSteamLevel(CPU *c, int i, int s) { RET(S.online ? (uint32_t)S.GetPlayerSteamLevel(S.user) : 0); }
// ISteamFriends015: 0 GetPersonaName (the returned string lives in host memory, which the guest can read)
static void f_GetPersonaName(CPU *c, int i, int s) { static const char n[] = "Player"; RET(S.online ? G(S.GetPersonaName(S.friends)) : G(n)); }
// ISteamUtils007: 2 GetConnectedUniverse, 4 GetIPCountry, 9 GetAppID, 11 IsAPICallCompleted, 12 GetAPICallFailureReason, 13 GetAPICallResult
static void ut_GetConnectedUniverse(CPU *c, int i, int s) { RET(1); }   // k_EUniversePublic
static void ut_GetIPCountry(CPU *c, int i, int s) { static const char us[] = "US"; RET(S.online ? G(S.GetIPCountry(S.utils)) : G(us)); }
static void ut_GetAppID(CPU *c, int i, int s) { RET(app_id); }
// polled call results (IsAPICallCompleted(h, *failed) / GetAPICallResult(h, p, cub, iExpected, *failed))
static CallResult *offline_result(uint64_t h) {
    for (int k = 0; k < nresults && k < 256; k++) if (results[k].handle == h) return &results[k];
    return NULL;
}
static void ut_IsAPICallCompleted(CPU *c, int i, int s) {
    if (S.online) { bool failed = 0; bool done = S.IsAPICallCompleted(S.utils, A1, &failed); if (A2) wr8(A2, failed); RET(done); return; }
    pthread_mutex_lock(&smu); CallResult *r = offline_result(A1); int done = r && now_ms() >= r->ready_ms; pthread_mutex_unlock(&smu);
    if (A2) wr8(A2, 0);
    RET(done);
}
static void ut_GetAPICallFailureReason(CPU *c, int i, int s) { RET((uint32_t)-1); }   // k_ESteamAPICallFailureNone
static void ut_GetAPICallResult(CPU *c, int i, int s) {
    if (S.online) { bool failed = 0; bool ok = S.GetAPICallResult(S.utils, A1, PTR(A2), (int)A3, (int)AN(4), &failed); if (AN(5)) wr8(AN(5), failed); RET(ok); return; }
    pthread_mutex_lock(&smu); CallResult *r = offline_result(A1);
    int ok = r && now_ms() >= r->ready_ms;
    if (ok) { memcpy(PTR(A2), r->data, (size_t)((uint32_t)A3 < (uint32_t)r->size ? (uint32_t)A3 : (uint32_t)r->size)); r->done = 1; }
    pthread_mutex_unlock(&smu);
    if (AN(5)) wr8(AN(5), 0);
    RET(ok);
}
// ISteamApps007: 0 BIsSubscribed, 4 GetCurrentGameLanguage, 6 BIsSubscribedApp, 7 BIsDlcInstalled
static void a_GetCurrentGameLanguage(CPU *c, int i, int s) { static const char l[] = "english"; RET(S.online ? G(S.GetCurrentGameLanguage(S.apps)) : G(l)); }
static void a_BIsSubscribedApp(CPU *c, int i, int s) { RET(S.online ? S.BIsSubscribedApp(S.apps, (uint32_t)A1) : 1); }
static void a_BIsDlcInstalled(CPU *c, int i, int s) { RET(S.online ? S.BIsDlcInstalled(S.apps, (uint32_t)A1) : 1); }

// ---------------- matchmaking (SteamMatchMaking009), P2P (SteamNetworking005), rich presence ----------------
// Flat API entry points, looked up by name; a missing one leaves the slot answering 0.
// MSVC ABI reminders: `this` is rcx; a returned CSteamID goes through a hidden pointer in rdx (arguments
// then start at r8); CSteamID arguments are passed by value as a uint64.
#define FLAT(ret, name, ...) static ret (*f_##name)(void *, ##__VA_ARGS__);
#define FLATS \
    FLAT(uint64_t, RequestLobbyList) FLAT(void, AddRequestLobbyListStringFilter, const char *, const char *, int) \
    FLAT(void, AddRequestLobbyListNumericalFilter, const char *, int, int) FLAT(void, AddRequestLobbyListNearValueFilter, const char *, int) \
    FLAT(void, AddRequestLobbyListFilterSlotsAvailable, int) FLAT(void, AddRequestLobbyListDistanceFilter, int) \
    FLAT(void, AddRequestLobbyListResultCountFilter, int) FLAT(void, AddRequestLobbyListCompatibleMembersFilter, uint64_t) \
    FLAT(uint64_t, GetLobbyByIndex, int) FLAT(uint64_t, CreateLobby, int, int) FLAT(uint64_t, JoinLobby, uint64_t) \
    FLAT(void, LeaveLobby, uint64_t) FLAT(bool, InviteUserToLobby, uint64_t, uint64_t) FLAT(int, GetNumLobbyMembers, uint64_t) \
    FLAT(uint64_t, GetLobbyMemberByIndex, uint64_t, int) FLAT(const char *, GetLobbyData, uint64_t, const char *) \
    FLAT(bool, SetLobbyData, uint64_t, const char *, const char *) FLAT(int, GetLobbyDataCount, uint64_t) \
    FLAT(bool, GetLobbyDataByIndex, uint64_t, int, char *, int, char *, int) FLAT(bool, DeleteLobbyData, uint64_t, const char *) \
    FLAT(const char *, GetLobbyMemberData, uint64_t, uint64_t, const char *) FLAT(void, SetLobbyMemberData, uint64_t, const char *, const char *) \
    FLAT(bool, SendLobbyChatMsg, uint64_t, const void *, int) FLAT(int, GetLobbyChatEntry, uint64_t, int, uint64_t *, void *, int, int *) \
    FLAT(bool, RequestLobbyData, uint64_t) FLAT(void, SetLobbyGameServer, uint64_t, uint32_t, uint16_t, uint64_t) \
    FLAT(bool, GetLobbyGameServer, uint64_t, uint32_t *, uint16_t *, uint64_t *) FLAT(bool, SetLobbyMemberLimit, uint64_t, int) \
    FLAT(int, GetLobbyMemberLimit, uint64_t) FLAT(bool, SetLobbyType, uint64_t, int) FLAT(bool, SetLobbyJoinable, uint64_t, bool) \
    FLAT(uint64_t, GetLobbyOwner, uint64_t) FLAT(bool, SetLobbyOwner, uint64_t, uint64_t) FLAT(bool, SetLinkedLobby, uint64_t, uint64_t) \
    FLAT(bool, SendP2PPacket, uint64_t, const void *, uint32_t, int, int) FLAT(bool, IsP2PPacketAvailable, uint32_t *, int) \
    FLAT(bool, ReadP2PPacket, void *, uint32_t, uint32_t *, uint64_t *, int) FLAT(bool, AcceptP2PSessionWithUser, uint64_t) \
    FLAT(bool, CloseP2PSessionWithUser, uint64_t) FLAT(bool, CloseP2PChannelWithUser, uint64_t, int) \
    FLAT(bool, GetP2PSessionState, uint64_t, void *) FLAT(bool, AllowP2PPacketRelay, bool) \
    FLAT(bool, SetRichPresence, const char *, const char *) FLAT(void, ClearRichPresence) \
    FLAT(const char *, GetFriendPersonaName, uint64_t) FLAT(int, GetFriendCount, int) FLAT(uint64_t, GetFriendByIndex, int, int) \
    FLAT(int, GetFriendPersonaState, uint64_t) FLAT(int, GetFriendRelationship, uint64_t) FLAT(bool, ActivateGameOverlayInviteDialog, uint64_t) \
    FLAT(int, GetSmallFriendAvatar, uint64_t) FLAT(int, GetMediumFriendAvatar, uint64_t) FLAT(int, GetLargeFriendAvatar, uint64_t) \
    FLAT(bool, GetImageSize, int, uint32_t *, uint32_t *) FLAT(bool, GetImageRGBA, int, uint8_t *, int) \
    FLAT(const char *, GetFriendRichPresence, uint64_t, const char *) FLAT(bool, IsOverlayEnabled) \
    FLAT(bool, RequestCurrentStats) FLAT(bool, GetStatInt32, const char *, int32_t *) FLAT(bool, GetStatFloat, const char *, float *) \
    FLAT(bool, SetStatInt32, const char *, int32_t) FLAT(bool, SetStatFloat, const char *, float) \
    FLAT(bool, GetAchievement, const char *, bool *) FLAT(bool, SetAchievement, const char *) FLAT(bool, ClearAchievement, const char *) \
    FLAT(bool, GetAchievementAndUnlockTime, const char *, bool *, uint32_t *) FLAT(bool, StoreStats) \
    FLAT(const char *, GetAchievementDisplayAttribute, const char *, const char *) \
    FLAT(bool, IndicateAchievementProgress, const char *, uint32_t, uint32_t) FLAT(uint32_t, GetNumAchievements) \
    FLAT(const char *, GetAchievementName, uint32_t) \
    FLAT(bool, FileWrite, const char *, const void *, int32_t) FLAT(int32_t, FileRead, const char *, void *, int32_t) \
    FLAT(bool, FileDelete, const char *) FLAT(int32_t, GetFileSize, const char *) FLAT(int64_t, GetFileTimestamp, const char *) \
    FLAT(int32_t, GetFileCount) FLAT(const char *, GetFileNameAndSize, int, int32_t *) \
    FLAT(bool, BeginFileWriteBatch) FLAT(bool, EndFileWriteBatch)
FLATS
#undef FLAT
static void flat_load(void *h) {
    static const char *const ifs[] = { "ISteamMatchmaking", "ISteamNetworking", "ISteamFriends", "ISteamUtils", "ISteamUserStats", "ISteamRemoteStorage" };
    char n[128];
#define FLAT(ret, name, ...) \
    for (size_t k = 0; k < 6 && !f_##name; k++) { snprintf(n, sizeof n, "SteamAPI_%s_%s", ifs[k], #name); f_##name = dlsym(h, n); }
    FLATS
#undef FLAT
}
#define NEED(fn) if (!S.online || !f_##fn) { RET(0); return; }
#define STR(a) ((const char *)PTR(a))
// SteamMatchMaking009
static void mm_RequestLobbyList(CPU *c, int i, int s) { NEED(RequestLobbyList) uint64_t h = f_RequestLobbyList(S.mm); rt_log("[steam] RequestLobbyList -> call %llx\n", (unsigned long long)h); RET(h); }
static void mm_StrFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListStringFilter) f_AddRequestLobbyListStringFilter(S.mm, STR(A1), STR(A2), (int)A3); }
static void mm_NumFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListNumericalFilter) f_AddRequestLobbyListNumericalFilter(S.mm, STR(A1), (int)A2, (int)A3); }
static void mm_NearFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListNearValueFilter) f_AddRequestLobbyListNearValueFilter(S.mm, STR(A1), (int)A2); }
static void mm_SlotsFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListFilterSlotsAvailable) f_AddRequestLobbyListFilterSlotsAvailable(S.mm, (int)A1); }
static void mm_DistFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListDistanceFilter) f_AddRequestLobbyListDistanceFilter(S.mm, (int)A1); }
static void mm_CountFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListResultCountFilter) f_AddRequestLobbyListResultCountFilter(S.mm, (int)A1); }
static void mm_CompatFilter(CPU *c, int i, int s) { NEED(AddRequestLobbyListCompatibleMembersFilter) f_AddRequestLobbyListCompatibleMembersFilter(S.mm, A1); }
static void mm_GetLobbyByIndex(CPU *c, int i, int s) { uint64_t id = S.online && f_GetLobbyByIndex ? f_GetLobbyByIndex(S.mm, (int)A2) : 0; wr64(A1, id); RET(A1); }
static void mm_CreateLobby(CPU *c, int i, int s) { NEED(CreateLobby) uint64_t h = f_CreateLobby(S.mm, (int)A1, (int)A2); rt_log("[steam] CreateLobby(type %d, max %d) -> call %llx\n", (int)A1, (int)A2, (unsigned long long)h); RET(h); }
static void mm_JoinLobby(CPU *c, int i, int s) { NEED(JoinLobby) uint64_t h = f_JoinLobby(S.mm, A1); rt_log("[steam] JoinLobby(%llu) -> call %llx\n", (unsigned long long)A1, (unsigned long long)h); RET(h); }
static void mm_LeaveLobby(CPU *c, int i, int s) { NEED(LeaveLobby) f_LeaveLobby(S.mm, A1); }
static void mm_Invite(CPU *c, int i, int s) { NEED(InviteUserToLobby) RET(f_InviteUserToLobby(S.mm, A1, A2)); }
static void mm_NumMembers(CPU *c, int i, int s) { NEED(GetNumLobbyMembers) RET((uint32_t)f_GetNumLobbyMembers(S.mm, A1)); }
static void mm_MemberByIndex(CPU *c, int i, int s) { uint64_t id = S.online && f_GetLobbyMemberByIndex ? f_GetLobbyMemberByIndex(S.mm, A2, (int)A3) : 0; wr64(A1, id); RET(A1); }
static void mm_GetData(CPU *c, int i, int s) { static const char empty[1]; RET(S.online && f_GetLobbyData ? G(f_GetLobbyData(S.mm, A1, STR(A2))) : G(empty)); }
static void mm_SetData(CPU *c, int i, int s) { NEED(SetLobbyData) RET(f_SetLobbyData(S.mm, A1, STR(A2), STR(A3))); }
static void mm_DataCount(CPU *c, int i, int s) { NEED(GetLobbyDataCount) RET((uint32_t)f_GetLobbyDataCount(S.mm, A1)); }
static void mm_DataByIndex(CPU *c, int i, int s) { NEED(GetLobbyDataByIndex) RET(f_GetLobbyDataByIndex(S.mm, A1, (int)A2, PTR(A3), (int)AN(4), PTR(AN(5)), (int)AN(6))); }
static void mm_DeleteData(CPU *c, int i, int s) { NEED(DeleteLobbyData) RET(f_DeleteLobbyData(S.mm, A1, STR(A2))); }
static void mm_GetMemberData(CPU *c, int i, int s) { static const char empty[1]; RET(S.online && f_GetLobbyMemberData ? G(f_GetLobbyMemberData(S.mm, A1, A2, STR(A3))) : G(empty)); }
static void mm_SetMemberData(CPU *c, int i, int s) { NEED(SetLobbyMemberData) f_SetLobbyMemberData(S.mm, A1, STR(A2), STR(A3)); }
static void mm_SendChat(CPU *c, int i, int s) { NEED(SendLobbyChatMsg) RET(f_SendLobbyChatMsg(S.mm, A1, PTR(A2), (int)A3)); }
// GetLobbyChatEntry(lobby, chatID, CSteamID *user, data, cub, EChatEntryType *type)
static void mm_GetChat(CPU *c, int i, int s) {
    NEED(GetLobbyChatEntry)
    uint64_t user = 0; int type = 0;
    int n = f_GetLobbyChatEntry(S.mm, A1, (int)A2, &user, PTR(AN(4)), (int)AN(5), &type);
    if (A3) wr64(A3, user);
    if (AN(6)) wr32(AN(6), (uint32_t)type);
    RET((uint32_t)n);
}
static void mm_RequestData(CPU *c, int i, int s) { NEED(RequestLobbyData) RET(f_RequestLobbyData(S.mm, A1)); }
static void mm_SetGameServer(CPU *c, int i, int s) { NEED(SetLobbyGameServer) f_SetLobbyGameServer(S.mm, A1, (uint32_t)A2, (uint16_t)A3, AN(4)); }
static void mm_GetGameServer(CPU *c, int i, int s) {
    NEED(GetLobbyGameServer)
    uint32_t ip = 0; uint16_t port = 0; uint64_t srv = 0;
    bool ok = f_GetLobbyGameServer(S.mm, A1, &ip, &port, &srv);
    if (A2) wr32(A2, ip);
    if (A3) wr16(A3, port);
    if (AN(4)) wr64(AN(4), srv);
    RET(ok);
}
static void mm_SetLimit(CPU *c, int i, int s) { NEED(SetLobbyMemberLimit) RET(f_SetLobbyMemberLimit(S.mm, A1, (int)A2)); }
static void mm_GetLimit(CPU *c, int i, int s) { NEED(GetLobbyMemberLimit) RET((uint32_t)f_GetLobbyMemberLimit(S.mm, A1)); }
static void mm_SetType(CPU *c, int i, int s) { NEED(SetLobbyType) RET(f_SetLobbyType(S.mm, A1, (int)A2)); }
static void mm_SetJoinable(CPU *c, int i, int s) { NEED(SetLobbyJoinable) RET(f_SetLobbyJoinable(S.mm, A1, (uint8_t)A2 != 0)); }
static void mm_GetOwner(CPU *c, int i, int s) { uint64_t id = S.online && f_GetLobbyOwner ? f_GetLobbyOwner(S.mm, A2) : 0; wr64(A1, id); RET(A1); }
static void mm_SetOwner(CPU *c, int i, int s) { NEED(SetLobbyOwner) RET(f_SetLobbyOwner(S.mm, A1, A2)); }
static void mm_SetLinked(CPU *c, int i, int s) { NEED(SetLinkedLobby) RET(f_SetLinkedLobby(S.mm, A1, A2)); }
// SteamNetworking005 (P2P)
static void n_Send(CPU *c, int i, int s) { NEED(SendP2PPacket) RET(f_SendP2PPacket(S.net, A1, PTR(A2), (uint32_t)A3, (int)AN(4), (int)AN(5))); }
static void n_Available(CPU *c, int i, int s) {
    NEED(IsP2PPacketAvailable)
    uint32_t n = 0; bool ok = f_IsP2PPacketAvailable(S.net, &n, (int)A2);
    if (A1) wr32(A1, n);
    RET(ok);
}
static void n_Read(CPU *c, int i, int s) {
    NEED(ReadP2PPacket)
    uint32_t n = 0; uint64_t from = 0;
    bool ok = f_ReadP2PPacket(S.net, PTR(A1), (uint32_t)A2, &n, &from, (int)AN(5));
    if (A3) wr32(A3, n);
    if (AN(4)) wr64(AN(4), from);
    RET(ok);
}
static void n_Accept(CPU *c, int i, int s) { NEED(AcceptP2PSessionWithUser) RET(f_AcceptP2PSessionWithUser(S.net, A1)); }
static void n_Close(CPU *c, int i, int s) { NEED(CloseP2PSessionWithUser) RET(f_CloseP2PSessionWithUser(S.net, A1)); }
static void n_CloseChan(CPU *c, int i, int s) { NEED(CloseP2PChannelWithUser) RET(f_CloseP2PChannelWithUser(S.net, A1, (int)A2)); }
static void n_State(CPU *c, int i, int s) { NEED(GetP2PSessionState) RET(f_GetP2PSessionState(S.net, A1, PTR(A2))); }   // P2PSessionState_t: same layout
static void n_Relay(CPU *c, int i, int s) { NEED(AllowP2PPacketRelay) RET(f_AllowP2PPacketRelay(S.net, (uint8_t)A1 != 0)); }
// SteamFriends015
static void f_SetRP(CPU *c, int i, int s) { NEED(SetRichPresence) RET(f_SetRichPresence(S.friends, STR(A1), STR(A2))); }
static void f_ClearRP(CPU *c, int i, int s) { NEED(ClearRichPresence) f_ClearRichPresence(S.friends); }
static void f_GetRP(CPU *c, int i, int s) { static const char empty[1]; RET(S.online && f_GetFriendRichPresence ? G(f_GetFriendRichPresence(S.friends, A1, STR(A2))) : G(empty)); }
static void f_FriendName(CPU *c, int i, int s) { static const char unk[] = "[unknown]"; RET(S.online && f_GetFriendPersonaName ? G(f_GetFriendPersonaName(S.friends, A1)) : G(unk)); }
static void f_FriendCount(CPU *c, int i, int s) { NEED(GetFriendCount) RET((uint32_t)f_GetFriendCount(S.friends, (int)A1)); }
static void f_FriendByIndex(CPU *c, int i, int s) { uint64_t id = S.online && f_GetFriendByIndex ? f_GetFriendByIndex(S.friends, (int)A2, (int)A3) : 0; wr64(A1, id); RET(A1); }
static void f_FriendRel(CPU *c, int i, int s) { NEED(GetFriendRelationship) RET((uint32_t)f_GetFriendRelationship(S.friends, A1)); }
static void f_FriendState(CPU *c, int i, int s) { NEED(GetFriendPersonaState) RET((uint32_t)f_GetFriendPersonaState(S.friends, A1)); }
// ActivateGameOverlayInviteDialog(lobby): the Steam overlay's invite dialog when the overlay is up (when Steam
// launched the game); otherwise a native picker lists the online friends and the invites go out with ISteamMatchmaking::InviteUserToLobby (the friend gets them in Steam chat;
// accepting starts or joins the game through GameLobbyJoinRequested_t).
#include "cocoa.h"
typedef struct { uint64_t lobby; int n; uint64_t ids[]; } InvitePick;
static void invite_done(const int *picked, int np, void *ctx) {
    InvitePick *p = ctx;
    for (int k = 0; k < np; k++) {
        uint64_t id = p->ids[picked[k]];
        bool ok = f_InviteUserToLobby && f_InviteUserToLobby(S.mm, p->lobby, id);
        rt_log("[steam] invite %s to lobby %llx -> %s\n", f_GetFriendPersonaName ? f_GetFriendPersonaName(S.friends, id) : "?",
               (unsigned long long)p->lobby, ok ? "sent" : "failed");
    }
    free(p);
}
static void f_InviteDialog(CPU *c, int i, int s) {
    if (S.online && f_IsOverlayEnabled && f_IsOverlayEnabled(S.utils) && f_ActivateGameOverlayInviteDialog) {   // the real overlay
        rt_log("[steam] overlay invite dialog for lobby %llx\n", (unsigned long long)A1);
        f_ActivateGameOverlayInviteDialog(S.friends, A1);
        return;
    }
    if (!S.online || !f_GetFriendCount || !f_GetFriendByIndex || !f_GetFriendPersonaName || !f_GetFriendPersonaState) return;
    enum { FRIEND_IMMEDIATE = 4 };
    static const char *const states[] = { "Offline", "Online", "Busy", "Away", "Snooze", "Looking to trade", "Looking to play", "Invisible" };
    int total = f_GetFriendCount(S.friends, FRIEND_IMMEDIATE), n = 0;
    InvitePick *p = malloc(sizeof *p + sizeof(uint64_t) * (size_t)(total > 0 ? total : 1));
    const char **names = calloc((size_t)(total > 0 ? total : 1), sizeof *names), **det = calloc((size_t)(total > 0 ? total : 1), sizeof *det);
    p->lobby = A1;
    for (int k = 0; k < total; k++) {   // online friends, in Steam's order
        uint64_t id = f_GetFriendByIndex(S.friends, k, FRIEND_IMMEDIATE);
        int st = f_GetFriendPersonaState(S.friends, id);
        if (st <= 0 || st >= 7) continue;
        const char *game = f_GetFriendRichPresence ? f_GetFriendRichPresence(S.friends, id, "status") : NULL;
        p->ids[n] = id; names[n] = f_GetFriendPersonaName(S.friends, id);
        det[n] = game && *game ? game : states[st];
        n++;
    }
    p->n = n;
    rt_log("[steam] invite dialog for lobby %llx: %d of %d friends online\n", (unsigned long long)A1, n, total);
    cocoa_pick_friends(n, names, det, invite_done, p);   // copies the strings; answers later on the main thread
    free(names); free(det);
}
// ISteamUtils007 17 IsOverlayEnabled: the game only offers "Invite friend" when the overlay is on; the invite dialog
// above stands in for it
static void ut_IsOverlayEnabled(CPU *c, int i, int s) {
    static int logged;
    int real = S.online && f_IsOverlayEnabled && f_IsOverlayEnabled(S.utils);
    if (real != logged) { logged = real; rt_log("[steam] Steam overlay %s\n", real ? "active" : "not active (invites use the native picker)"); }
    RET(S.online ? 1 : 0);
}
static void f_SmallAvatar(CPU *c, int i, int s) { NEED(GetSmallFriendAvatar) RET((uint32_t)f_GetSmallFriendAvatar(S.friends, A1)); }
static void f_MediumAvatar(CPU *c, int i, int s) { NEED(GetMediumFriendAvatar) RET((uint32_t)f_GetMediumFriendAvatar(S.friends, A1)); }
static void f_LargeAvatar(CPU *c, int i, int s) { NEED(GetLargeFriendAvatar) RET((uint32_t)f_GetLargeFriendAvatar(S.friends, A1)); }
// SteamUserStats011: 0 RequestCurrentStats, 1/2 GetStat(name, int32* | float*), 3/4 SetStat(name, int32 | float),
// 6 GetAchievement, 7 SetAchievement, 8 ClearAchievement, 9 GetAchievementAndUnlockTime, 10 StoreStats.
// The overloads' slot order depends on MSVC, so both slots of a pair ask Steam which type the stat has.
static int stats_received_pending;   // a UserStatsReceived_t to post ourselves (SDK 1.61+, see us_Request)
static void us_Request(CPU *c, int i, int s) {
    // SDK 1.61 dropped RequestCurrentStats: the client syncs stats itself and still posts UserStatsReceived
    if (S.online && S.stats && !f_RequestCurrentStats) {   // answered in RunCallbacks (stats_received_pending)
        stats_received_pending = 1;
        rt_log("[steam] RequestCurrentStats: automatic in this SDK\n");
        RET(1); return;
    }
    NEED(RequestCurrentStats) bool ok = f_RequestCurrentStats(S.stats); rt_log("[steam] RequestCurrentStats -> %d\n", ok); RET(ok); }
static void us_GetStat(CPU *c, int i, int s) {
    NEED(GetStatInt32)
    int32_t v; float fv;
    if (f_GetStatInt32(S.stats, STR(A1), &v)) { wr32(A2, (uint32_t)v); RET(1); return; }
    if (f_GetStatFloat && f_GetStatFloat(S.stats, STR(A1), &fv)) { memcpy(&v, &fv, 4); wr32(A2, (uint32_t)v); RET(1); return; }
    RET(0);
}
static void us_SetStat(CPU *c, int i, int s) {
    NEED(SetStatInt32)
    int32_t cur;
    if (f_GetStatInt32(S.stats, STR(A1), &cur)) { RET(f_SetStatInt32(S.stats, STR(A1), (int32_t)A2)); return; }
    float fv; memcpy(&fv, &c->xmm[2].u[0], 4);   // float argument 3 arrives in xmm2
    RET(f_SetStatFloat && f_SetStatFloat(S.stats, STR(A1), fv));
}
static void us_GetAch(CPU *c, int i, int s) { NEED(GetAchievement) bool a = 0; bool ok = f_GetAchievement(S.stats, STR(A1), &a); if (A2) wr8(A2, a); RET(ok); }
static void us_SetAch(CPU *c, int i, int s) { NEED(SetAchievement) rt_log("[steam] SetAchievement(%s)\n", STR(A1)); RET(f_SetAchievement(S.stats, STR(A1))); }
static void us_ClearAch(CPU *c, int i, int s) { NEED(ClearAchievement) RET(f_ClearAchievement(S.stats, STR(A1))); }
static void us_GetAchTime(CPU *c, int i, int s) {
    NEED(GetAchievementAndUnlockTime)
    bool a = 0; uint32_t t = 0; bool ok = f_GetAchievementAndUnlockTime(S.stats, STR(A1), &a, &t);
    if (A2) wr8(A2, a);
    if (A3) wr32(A3, t);
    RET(ok);
}
static void us_Store(CPU *c, int i, int s) { NEED(StoreStats) RET(f_StoreStats(S.stats)); }
// 12 GetAchievementDisplayAttribute(name, key), 13 IndicateAchievementProgress(name, cur, max),
// 14 GetNumAchievements(), 15 GetAchievementName(index)
static void us_DispAttr(CPU *c, int i, int s) { static const char empty[1]; RET(S.online && f_GetAchievementDisplayAttribute ? G(f_GetAchievementDisplayAttribute(S.stats, STR(A1), STR(A2))) : G(empty)); }
static void us_Progress(CPU *c, int i, int s) { NEED(IndicateAchievementProgress) RET(f_IndicateAchievementProgress(S.stats, STR(A1), (uint32_t)A2, (uint32_t)A3)); }
static void us_NumAch(CPU *c, int i, int s) { NEED(GetNumAchievements) RET(f_GetNumAchievements(S.stats)); }
static void us_AchName(CPU *c, int i, int s) { static const char empty[1]; RET(S.online && f_GetAchievementName ? G(f_GetAchievementName(S.stats, (uint32_t)A1)) : G(empty)); }
// SteamUtils007: 5 GetImageSize(image, *w, *h), 6 GetImageRGBA(image, dest, size)
static void ut_ImageSize(CPU *c, int i, int s) {
    NEED(GetImageSize)
    uint32_t w = 0, h = 0; bool ok = f_GetImageSize(S.utils, (int)A1, &w, &h);
    if (A2) wr32(A2, w);
    if (A3) wr32(A3, h);
    RET(ok);
}
static void ut_ImageRGBA(CPU *c, int i, int s) { NEED(GetImageRGBA) RET(f_GetImageRGBA(S.utils, (int)A1, PTR(A2), (int)A3)); }

__attribute__((constructor)) static void steam_slots(void) {
    impl[IF_USER][1] = u_BLoggedOn;            impl[IF_USER][2] = u_GetSteamID;
    impl[IF_USER][13] = u_GetAuthSessionTicket; impl[IF_USER][16] = u_CancelAuthTicket;
    impl[IF_USER][20] = u_RequestEncryptedAppTicket; impl[IF_USER][21] = u_GetEncryptedAppTicket;
    impl[IF_USER][23] = u_GetPlayerSteamLevel;
    impl[IF_FRIENDS][0] = f_GetPersonaName;
    impl[IF_UTILS][2] = ut_GetConnectedUniverse; impl[IF_UTILS][4] = ut_GetIPCountry; impl[IF_UTILS][9] = ut_GetAppID;
    impl[IF_UTILS][11] = ut_IsAPICallCompleted; impl[IF_UTILS][12] = ut_GetAPICallFailureReason; impl[IF_UTILS][13] = ut_GetAPICallResult;
    impl[IF_APPS][0] = ret_true;               impl[IF_APPS][4] = a_GetCurrentGameLanguage;
    impl[IF_APPS][6] = a_BIsSubscribedApp;     impl[IF_APPS][7] = a_BIsDlcInstalled;
    static const slotfn mm[] = { [4] = mm_RequestLobbyList, mm_StrFilter, mm_NumFilter, mm_NearFilter, mm_SlotsFilter, mm_DistFilter,
        mm_CountFilter, mm_CompatFilter, mm_GetLobbyByIndex, mm_CreateLobby, mm_JoinLobby, mm_LeaveLobby, mm_Invite, mm_NumMembers,
        mm_MemberByIndex, mm_GetData, mm_SetData, mm_DataCount, mm_DataByIndex, mm_DeleteData, mm_GetMemberData, mm_SetMemberData,
        mm_SendChat, mm_GetChat, mm_RequestData, mm_SetGameServer, mm_GetGameServer, mm_SetLimit, mm_GetLimit, mm_SetType,
        mm_SetJoinable, mm_GetOwner, mm_SetOwner, mm_SetLinked };
    for (size_t k = 0; k < sizeof mm / sizeof *mm; k++) if (mm[k]) impl[IF_MATCHMAKING][k] = mm[k];
    static const slotfn net[] = { n_Send, n_Available, n_Read, n_Accept, n_Close, n_CloseChan, n_State, n_Relay };
    for (size_t k = 0; k < sizeof net / sizeof *net; k++) impl[IF_NETWORKING][k] = net[k];
    impl[IF_FRIENDS][3] = f_FriendCount; impl[IF_FRIENDS][4] = f_FriendByIndex; impl[IF_FRIENDS][5] = f_FriendRel;
    impl[IF_FRIENDS][6] = f_FriendState; impl[IF_FRIENDS][7] = f_FriendName; impl[IF_FRIENDS][33] = f_InviteDialog;
    impl[IF_FRIENDS][34] = f_SmallAvatar; impl[IF_FRIENDS][35] = f_MediumAvatar; impl[IF_FRIENDS][36] = f_LargeAvatar;
    impl[IF_FRIENDS][43] = f_SetRP; impl[IF_FRIENDS][44] = f_ClearRP; impl[IF_FRIENDS][45] = f_GetRP;
    impl[IF_UTILS][5] = ut_ImageSize; impl[IF_UTILS][6] = ut_ImageRGBA; impl[IF_UTILS][17] = ut_IsOverlayEnabled;
    impl[IF_USERSTATS][0] = us_Request; impl[IF_USERSTATS][1] = us_GetStat; impl[IF_USERSTATS][2] = us_GetStat;
    impl[IF_USERSTATS][3] = us_SetStat; impl[IF_USERSTATS][4] = us_SetStat; impl[IF_USERSTATS][6] = us_GetAch;
    impl[IF_USERSTATS][7] = us_SetAch; impl[IF_USERSTATS][8] = us_ClearAch; impl[IF_USERSTATS][9] = us_GetAchTime;
    impl[IF_USERSTATS][10] = us_Store; impl[IF_USERSTATS][12] = us_DispAttr; impl[IF_USERSTATS][13] = us_Progress;
    impl[IF_USERSTATS][14] = us_NumAch; impl[IF_USERSTATS][15] = us_AchName;
}

// ---------------- Steam Cloud for the Mac port ----------------
// Windows games often sync saves with Steam Auto-Cloud, which Valve configures for the Windows paths only, so
// Mac Steam never syncs them. The save folder (rt_game.cloud_save_dir) is synced here through the Steam
// client's cloud API instead, as "<cloud_prefix><path>" in the game's cloud space: newer cloud copies are
// downloaded when the game starts, changed files are uploaded every 15 s and when it quits, and files deleted
// locally (a deleted save slot) are deleted in the cloud. A record of what was synced (manifest) lives outside
// the save folder. <PREFIX>_CLOUD=0 turns it off.
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#define CLOUD_PREFIX (rt_game.cloud_prefix)
static char cloud_root[PATH_MAX], cloud_manifest[PATH_MAX];
static pthread_mutex_t cloud_mu = PTHREAD_MUTEX_INITIALIZER;
typedef struct { char *rel; int64_t mtime; int seen; } CEntry;
static CEntry *man; static int nman, cap_man, cloud_on;
static CEntry *man_find(const char *rel) { for (int i = 0; i < nman; i++) if (!strcmp(man[i].rel, rel)) return &man[i]; return NULL; }
static void man_set(const char *rel, int64_t t) {
    CEntry *e = man_find(rel);
    if (!e) { if (nman == cap_man) { cap_man = cap_man ? cap_man * 2 : 64; man = realloc(man, sizeof *man * (size_t)cap_man); } e = &man[nman++]; e->rel = strdup(rel); }
    e->mtime = t;
}
static void man_load(void) {
    FILE *f = fopen(cloud_manifest, "r"); if (!f) return;
    char line[PATH_MAX + 32]; long long t;
    while (fgets(line, sizeof line, f)) { char *tab = strchr(line, '\t'); if (!tab) continue; line[strcspn(line, "\n")] = 0; t = atoll(line); man_set(tab + 1, t); }
    fclose(f);
}
static void man_save(void) {
    char tmp[PATH_MAX + 8]; snprintf(tmp, sizeof tmp, "%s.tmp", cloud_manifest);
    FILE *f = fopen(tmp, "w"); if (!f) return;
    for (int i = 0; i < nman; i++) fprintf(f, "%lld\t%s\n", (long long)man[i].mtime, man[i].rel);
    fclose(f); rename(tmp, cloud_manifest);
}
static int cloud_skip(const char *rel) {   // macOS litter and the local backups of the save importer
    return strstr(rel, ".DS_Store") || strstr(rel, "steam_autocloud.vdf") || strstr(rel, "PROFILE.windows") || strstr(rel, "PROFILE.offline");
}
static void mkdirs(const char *path) {   // parent folders of a file
    char d[PATH_MAX]; snprintf(d, sizeof d, "%s", path);
    for (char *p = d + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(d, 0755); *p = '/'; }
}
static void cloud_down(void) {
    int n = f_GetFileCount(S.rs), got = 0;
    for (int i = 0; i < n; i++) {
        int32_t sz = 0; const char *name = f_GetFileNameAndSize(S.rs, i, &sz);
        if (!name || strncmp(name, CLOUD_PREFIX, strlen(CLOUD_PREFIX))) continue;
        const char *rel = name + strlen(CLOUD_PREFIX);
        char local[PATH_MAX]; snprintf(local, sizeof local, "%s/%s", cloud_root, rel);
        int64_t ts = f_GetFileTimestamp(S.rs, name);
        struct stat st; int have = stat(local, &st) == 0;
        if (have && (int64_t)st.st_mtime >= ts) {   // the local copy is as new: in sync if the same size
            if (st.st_size == sz && !man_find(rel)) man_set(rel, (int64_t)st.st_mtime);
            continue;
        }
        void *buf = malloc((size_t)(sz > 0 ? sz : 1));
        int32_t r = f_FileRead(S.rs, name, buf, sz);
        if (r != sz) rt_log("[cloud] reading %s failed (%d of %d bytes)\n", rel, r, sz);
        if (r == sz) {
            mkdirs(local);
            char tmp[PATH_MAX + 8]; snprintf(tmp, sizeof tmp, "%s.cloud", local);
            FILE *f = fopen(tmp, "wb");
            if (f) { fwrite(buf, 1, (size_t)sz, f); fclose(f); rename(tmp, local);
                     struct timeval tv[2] = { { (time_t)ts, 0 }, { (time_t)ts, 0 } }; utimes(local, tv);
                     man_set(rel, ts); got++; }
        }
        free(buf);
    }
    man_save();
    rt_log("[cloud] %d cloud files, %d downloaded into %s\n", n, got, cloud_root);
}
static int up_count, up_changed, up_more;
static void cloud_walk(const char *dir, const char *rel, int final) {
    DIR *d = opendir(dir); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[PATH_MAX], r[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        snprintf(r, sizeof r, "%s%s%s", rel, *rel ? "/" : "", e->d_name);
        if (cloud_skip(r)) continue;
        struct stat st; if (stat(path, &st)) continue;
        if (S_ISDIR(st.st_mode)) { cloud_walk(path, r, final); continue; }
        CEntry *m = man_find(r);
        if (m) m->seen = 1;
        if (m && m->mtime == (int64_t)st.st_mtime) continue;
        if (!final && time(NULL) - st.st_mtime < 3) continue;   // still being written: next pass
        if (up_count >= 40) { up_more = 1; continue; }           // Steam limits writes: the rest next pass
        FILE *f = fopen(path, "rb"); if (!f) continue;
        void *buf = malloc((size_t)st.st_size + 1); size_t len = fread(buf, 1, (size_t)st.st_size, f); fclose(f);
        char name[PATH_MAX + 16]; snprintf(name, sizeof name, "%s%s", CLOUD_PREFIX, r);
        if (f_FileWrite(S.rs, name, buf, (int32_t)len)) {
            // give the local file the cloud copy's time, so the next start sees them as the same version
            int64_t ts = f_GetFileTimestamp ? f_GetFileTimestamp(S.rs, name) : 0, mt = (int64_t)st.st_mtime;
            if (ts > 0) { struct timeval tv[2] = { { (time_t)ts, 0 }, { (time_t)ts, 0 } }; if (!utimes(path, tv)) mt = ts; }
            man_set(r, mt); man_find(r)->seen = 1; up_count++; up_changed = 1;
        }
        else rt_log("[cloud] upload of %s failed\n", r);
        free(buf);
    }
    closedir(d);
}
static void cloud_up(int final) {
    pthread_mutex_lock(&cloud_mu);
    if (!cloud_on || !S.online) { pthread_mutex_unlock(&cloud_mu); return; }
    for (int i = 0; i < nman; i++) man[i].seen = 0;
    up_count = 0; up_changed = 0; up_more = 0;
    if (f_BeginFileWriteBatch) f_BeginFileWriteBatch(S.rs);
    cloud_walk(cloud_root, "", final);
    if (f_EndFileWriteBatch) f_EndFileWriteBatch(S.rs);
    for (int i = 0; i < nman; i++) if (!man[i].seen) {   // deleted here: delete in the cloud too
        char name[PATH_MAX + 16]; snprintf(name, sizeof name, "%s%s", CLOUD_PREFIX, man[i].rel);
        f_FileDelete(S.rs, name); rt_log("[cloud] deleted %s\n", man[i].rel);
        free(man[i].rel); man[i--] = man[--nman]; up_changed = 1;
    }
    if (up_changed) man_save();
    if (up_count) rt_log("[cloud] uploaded %d file(s)%s\n", up_count, up_more ? ", more next pass" : "");
    pthread_mutex_unlock(&cloud_mu);
}
static void *cloud_thread(void *p) { for (;;) { sleep(15); cloud_up(0); } return NULL; }
static void cloud_start(void) {
    const char *off = rt_game_env("CLOUD");
    if ((off && !strcmp(off, "0")) || !rt_game.cloud_save_dir || !rt_game.cloud_prefix || !S.rs || !f_FileWrite || !f_GetFileCount) return;
    const char *home = getenv("HOME") ? getenv("HOME") : "";
    unsigned long long id = (unsigned long long)S.GetSteamID(S.user);
    char sub[PATH_MAX]; snprintf(sub, sizeof sub, rt_game.cloud_save_dir, id);
    snprintf(cloud_root, sizeof cloud_root, "%s/Library/Application Support/%s/%s", home, rt_game.data_name, sub);
    snprintf(cloud_manifest, sizeof cloud_manifest, "%s/Library/Application Support/%s/cloud-%llu.txt", home, rt_game.data_name, id);
    mkdirs(cloud_manifest); char rootdir[PATH_MAX + 2]; snprintf(rootdir, sizeof rootdir, "%s/", cloud_root); mkdirs(rootdir);
    pthread_mutex_lock(&cloud_mu);
    man_load(); cloud_on = 1;
    cloud_down();
    pthread_mutex_unlock(&cloud_mu);
    cloud_up(1);   // the first sync uploads what the cloud doesn't have yet
    pthread_t t; pthread_create(&t, NULL, cloud_thread, NULL); pthread_detach(t);
}

static int steam_init_done;
int rt_steam_offline(void) { return app_id && (rt_game_env("STEAM_OFFLINE") || (steam_init_done && !S.online)); }
void I_steam_api64_dll_SteamAPI_Init(CPU *c) {
    if (!app_id) { rt_log("[steam] SteamAPI_Init -> false (no Steam app ID in game.c: the game runs as if Steam were not installed)\n"); RET(0); return; }
    S.online = steam_connect();
    steam_init_done = 1;
    if (S.online) steam_register_pending();
    if (S.online) cloud_start();
    if (S.online) rt_log("[steam] SteamAPI_Init: online as \"%s\" (Steam ID %llu, logged on %d)\n", S.GetPersonaName(S.friends),
                         (unsigned long long)S.GetSteamID(S.user), S.BLoggedOn(S.user));
    else rt_log("[steam] SteamAPI_Init (offline)\n");
    RET(1);
}
void I_steam_api64_dll_SteamAPI_Shutdown(CPU *c) { if (S.online) { cloud_up(1); pthread_mutex_lock(&cloud_mu); cloud_on = 0; pthread_mutex_unlock(&cloud_mu); S.Shutdown(); S.online = 0; } }

// ---------------- callbacks and call results ----------------
// CCallbackBase (guest): vtable +0, m_nCallbackFlags +8, m_iCallback +12. Both Run overloads of the SDK's
// CCallback / CCallResult deliver to the handler, so slot 0 is called with (param, bIOFailure, handle).
typedef struct { uint64_t obj, handle; } Reg;     // offline call result registrations
static Reg regs[256]; static int nregs;

// Native twin of a guest CCallbackBase: the Itanium layout libsteam_api expects (vptr, uint8
// m_nCallbackFlags +8, int m_iCallback +12) followed by our bookkeeping.
typedef struct Twin {
    const void *const *vt; uint8_t flags; int id;
    uint64_t obj, handle;       // the guest object; the call handle for a call result (0: callback)
    int win_size, mac_size;     // the struct size each side expects
    int registered, fired;
    struct Twin *next;
} Twin;
static Twin *twins;
static __thread CPU *cb_cpu;    // the guest thread inside SteamAPI_RunCallbacks

static void deliver(CPU *c, uint64_t obj, void *data, int failed, uint64_t handle) {
    uint64_t a[4] = { obj, G(data), (uint64_t)failed, handle };
    guest_call(c, rd64(rd64(obj)), 4, a);   // MSVC vtable slot 0: Run(void *, bool, SteamAPICall_t)
}
// macOS SDK structs are packed to 4, Windows ones to 8: a uint64 after a smaller field sits 4 bytes later on
// Windows, and the struct is padded to 8. Each callback with such a field is described by its field sizes
// ("8,4,1": uint64, uint32, uint8; "1*128": a char[128]) and converted field by field.
static const struct { int id; const char *fields; } layouts[] = {
    { 152, "4,8,1" },          // MicroTxnAuthorizationResponse_t
    { 304, "8,4" },            // PersonaStateChange_t
    { 333, "8,8" },            // GameLobbyJoinRequested_t
    { 337, "8,1*256" },        // GameRichPresenceJoinRequested_t
    { 503, "8,8,8" },          // LobbyInvite_t
    { 504, "8,4,1,4" },        // LobbyEnter_t
    { 505, "8,8,1" },          // LobbyDataUpdate_t
    { 506, "8,8,8,4" },        // LobbyChatUpdate_t
    { 507, "8,8,1,4" },        // LobbyChatMsg_t
    { 509, "8,8,4,2" },        // LobbyGameCreated_t
    { 510, "4" },              // LobbyMatchList_t
    { 512, "8,8,1" },          // LobbyKicked_t
    { 513, "4,8" },            // LobbyCreated_t
    { 1101, "8,4,8" },         // UserStatsReceived_t
    { 1102, "8,4" },           // UserStatsStored_t
    { 1103, "8,1,1*128,4,4" }, // UserAchievementStored_t
    { 1203, "8,1" },           // P2PSessionConnectFail_t
};
// walks the fields for one packing: fills the offsets, returns the struct size; *nf = number of fields
static int layout_offsets(const char *f, int win, int *off, int *sz, int *cnt, int *nf) {
    int pos = 0, align = 1, n = 0;
    while (*f && n < 16) {
        char *e; int size = (int)strtol(f, &e, 10), count = 1; f = e;
        if (*f == '*') { count = (int)strtol(f + 1, &e, 10); f = e; }
        if (*f == ',') f++;
        int a = win ? size : (size < 4 ? size : 4);
        if (a > align) align = a;
        pos = (pos + a - 1) / a * a;
        off[n] = pos; sz[n] = size; cnt[n] = count; n++;
        pos += size * count;
    }
    *nf = n;
    return (pos + align - 1) / align * align;
}
static const char *layout_of(int id) {
    for (size_t i = 0; i < sizeof layouts / sizeof *layouts; i++) if (layouts[i].id == id) return layouts[i].fields;
    return NULL;
}
static int to_windows(int id, const uint8_t *in, int n, uint8_t *out, int cap) {
    memset(out, 0, (size_t)cap);
    const char *f = layout_of(id);
    if (f) {
        int mo[16], wo[16], sz[16], cnt[16], nf;
        int msize = layout_offsets(f, 0, mo, sz, cnt, &nf), wsize = layout_offsets(f, 1, wo, sz, cnt, &nf);
        if (n >= msize && cap >= wsize) {
            for (int k = 0; k < nf; k++) memcpy(out + wo[k], in + mo[k], (size_t)(sz[k] * cnt[k]));
            return wsize;
        }
    }
    memcpy(out, in, (size_t)(n < cap ? n : cap));
    return n;
}
static int mac_size_of(int id, int win) {
    const char *f = layout_of(id);
    int o[16], z[16], c[16], nf;
    return f ? layout_offsets(f, 0, o, z, c, &nf) : win;
}
static void twin_fire(Twin *t, void *param, bool io) {
    CPU *c = cb_cpu;
    if (!c || t->fired) return;
    static uint8_t win[4096];
    int n = to_windows(t->id, param, t->mac_size, win, sizeof win); (void)n;
    if (t->handle) {   // call results fire once; Steam has already dropped the registration
        t->fired = 1; t->registered = 0;
        rt_log("[steam] call result %d for %llx delivered%s\n", t->id, (unsigned long long)t->handle, io ? " (I/O failure)" : "");
    } else {
        static int logged; if (logged++ < 40) rt_log("[steam] callback %d delivered\n", t->id);
    }
    deliver(c, t->obj, win, io, t->handle);
}
static void twin_run1(Twin *t, void *param) { twin_fire(t, param, 0); }
static void twin_run3(Twin *t, void *param, bool io, uint64_t h) { twin_fire(t, param, io); }
static int twin_size(Twin *t) { return t->mac_size; }
static const void *const twin_vt[3] = { (void *)twin_run1, (void *)twin_run3, (void *)twin_size };

static Twin *twin_new(CPU *c, uint64_t obj, int id, uint64_t handle) {
    Twin *t = calloc(1, sizeof *t);
    t->vt = twin_vt; t->obj = obj; t->id = id; t->handle = handle;
    // the guest object's GetCallbackSizeBytes (MSVC slot 2) gives the Windows struct size
    t->win_size = (int)guest_call(c, rd64(rd64(obj) + 16), 1, &obj);
    t->mac_size = mac_size_of(id, t->win_size);
    t->next = twins; twins = t;
    return t;
}
static void twin_register(Twin *t) {
    if (!S.online || t->registered || t->fired) return;
    if (t->handle) S.RegisterCallResult(t, t->handle); else S.RegisterCallback(t, t->id);
    t->registered = 1;
}
static void twin_unregister(Twin *t) {
    if (t->registered && S.online) { if (t->handle) S.UnregisterCallResult(t, t->handle); else S.UnregisterCallback(t); }
    t->registered = 0; t->fired = 1;   // freed later, outside any Steam dispatch
}
static void twins_reap(void) {   // only outside SteamAPI_RunCallbacks
    for (Twin **pp = &twins; *pp;) {
        Twin *t = *pp;
        if (t->fired && !t->registered) { *pp = t->next; free(t); } else pp = &t->next;
    }
}

// SteamAPI_RegisterCallback(CCallbackBase *cb, int iCallback): may come before SteamAPI_Init (global
// objects); those twins are registered with Steam when it connects
void I_steam_api64_dll_SteamAPI_RegisterCallback(CPU *c) {
    pthread_mutex_lock(&smu);
    wr8(A0 + 8, rd8(A0 + 8) | 1); wr32(A0 + 12, (uint32_t)A1);   // k_ECallbackFlagsRegistered, m_iCallback
    Twin *t = twin_new(c, A0, (int)A1, 0);
    twin_register(t);
    pthread_mutex_unlock(&smu);
    rt_log("[steam] RegisterCallback(id %d, %d bytes)\n", (int)A1, t->win_size);
}
void I_steam_api64_dll_SteamAPI_UnregisterCallback(CPU *c) {
    pthread_mutex_lock(&smu);
    for (Twin *t = twins; t; t = t->next) if (t->obj == A0 && !t->handle && !t->fired) twin_unregister(t);
    wr8(A0 + 8, rd8(A0 + 8) & ~1);
    pthread_mutex_unlock(&smu);
}
// SteamAPI_RegisterCallResult(CCallbackBase *cb, SteamAPICall_t h)
void I_steam_api64_dll_SteamAPI_RegisterCallResult(CPU *c) {
    pthread_mutex_lock(&smu);
    if (S.online) {
        Twin *t = twin_new(c, A0, (int)rd32(A0 + 12), A1);
        twin_register(t);
        rt_log("[steam] RegisterCallResult(id %d, handle %llx)\n", t->id, (unsigned long long)A1);
    } else if (nregs < 256) regs[nregs++] = (Reg){ A0, A1 };
    pthread_mutex_unlock(&smu);
}
void I_steam_api64_dll_SteamAPI_UnregisterCallResult(CPU *c) {
    pthread_mutex_lock(&smu);
    for (Twin *t = twins; t; t = t->next) if (t->obj == A0 && t->handle == A1 && !t->fired) twin_unregister(t);
    for (int i = 0; i < nregs; i++) if (regs[i].obj == A0 && regs[i].handle == A1) { regs[i] = regs[--nregs]; break; }
    pthread_mutex_unlock(&smu);
}
// UserStatsReceived_t { uint64 m_nGameID; EResult m_eResult; CSteamID m_steamIDUser } for the game's registered
// callbacks. Newer clients sync stats by themselves and post this at startup, before the game is listening.
static void post_stats_received(void) {
    stats_received_pending = 0;
    const char *f = layout_of(1101);
    int off[16], sz[16], cnt[16], nf;
    if (!f) return;
    int size = layout_offsets(f, 0, off, sz, cnt, &nf);
    uint8_t mac[64] = {0};
    if (nf < 3 || size > (int)sizeof mac) return;
    uint64_t game = app_id, user = S.GetSteamID(S.user);
    int32_t ok = 1;   // k_EResultOK
    memcpy(mac + off[0], &game, 8); memcpy(mac + off[1], &ok, 4); memcpy(mac + off[2], &user, 8);
    pthread_mutex_lock(&smu);
    Twin *list[16]; int n = 0;
    for (Twin *t = twins; t && n < 16; t = t->next) if (t->id == 1101 && !t->handle && t->registered) list[n++] = t;
    pthread_mutex_unlock(&smu);
    for (int i = 0; i < n; i++) twin_fire(list[i], mac, 0);
}
void steam_register_pending(void) {   // callbacks the game registered before SteamAPI_Init
    pthread_mutex_lock(&smu);
    for (Twin *t = twins; t; t = t->next) twin_register(t);
    pthread_mutex_unlock(&smu);
}
void I_steam_api64_dll_SteamAPI_RunCallbacks(CPU *c) {
    if (S.online) {
        // handlers may register/unregister (smu is not held while Steam dispatches)
        CPU *prev = cb_cpu; cb_cpu = c;
        S.RunCallbacks();
        if (stats_received_pending) post_stats_received();
        cb_cpu = prev;
        if (!prev) { pthread_mutex_lock(&smu); twins_reap(); pthread_mutex_unlock(&smu); }
        return;
    }
    for (;;) {
        Reg r = { 0, 0 }; CallResult *res = NULL;
        pthread_mutex_lock(&smu);
        for (int i = 0; i < nregs && !res; i++)
            for (int k = 0; k < nresults && k < 256; k++)
                if (!results[k].done && results[k].handle == regs[i].handle && now_ms() >= results[k].ready_ms) { res = &results[k]; r = regs[i]; regs[i] = regs[--nregs]; res->done = 1; break; }
        pthread_mutex_unlock(&smu);
        if (!res) return;
        static int n; if (n++ < 3) rt_log("[steam] call result %d for handle %llx delivered (offline failure)\n", res->id, (unsigned long long)res->handle);
        deliver(c, r.obj, res->data, 0, r.handle);
    }
}
void I_steam_api64_dll_SteamUser(CPU *c) { RET(make_iface(IF_USER)); }
void I_steam_api64_dll_SteamFriends(CPU *c) { RET(make_iface(IF_FRIENDS)); }
void I_steam_api64_dll_SteamUtils(CPU *c) { RET(make_iface(IF_UTILS)); }
void I_steam_api64_dll_SteamApps(CPU *c) { RET(make_iface(IF_APPS)); }
void I_steam_api64_dll_SteamUserStats(CPU *c) { RET(make_iface(IF_USERSTATS)); }
void I_steam_api64_dll_SteamMatchmaking(CPU *c) { RET(make_iface(IF_MATCHMAKING)); }
void I_steam_api64_dll_SteamNetworking(CPU *c) { RET(make_iface(IF_NETWORKING)); }
void I_steam_api64_dll_SteamController(CPU *c) { RET(make_iface(IF_CONTROLLER)); }
void I_steam_api64_dll_SteamClient(CPU *c) { RET(make_iface(IF_CLIENT)); }
void I_steam_api64_dll_SteamRemoteStorage(CPU *c) { RET(make_iface(IF_REMOTESTORAGE)); }
