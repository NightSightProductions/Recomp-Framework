// win32 runtime: shared declarations for the Windows API shims.
//
// Import shims are `void I_<dll>_<name>(CPU *c)`. The translated caller has pushed the return address, so the
// first stack argument is at esp+4; after the shim returns the caller pops the return address itself. stdcall
// shims (almost all of the Windows API) also pop their arguments: SHIM(sym, n) adds 4*n to esp; CRT functions are
// cdecl (CSHIM, the caller cleans up).
#pragma once
#include "cpu32.h"
#include "tables32.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>

#define ARG(i)  rds32(c->esp + 4 + 4 * (i))
#define ARGF(i) rdsf(c->esp + 4 + 4 * (i))
#define ARGD(i) rdsd(c->esp + 4 + 4 * (i))          // a double occupying stack slots i, i+1
#define ARG64(i) rds64(c->esp + 4 + 4 * (i))
// Natives (translator --native: guest functions replaced by host code; RT_NATIVE_OFF=all|addr,... runs the translated
// code instead). A native reads its arguments with ARG(i) (this = c->ecx for thiscall), sets c->eax, and pops its
// stack arguments itself if the guest function is callee-cleanup (stdcall/thiscall `ret n`): NATIVE_POP(n slots).
// CALL_ORIG runs the translated original with the same registers and arguments, leaving esp as it was.
int rt_native_enabled(uint32_t a);
#define NATIVE_POP(n) (c->esp += 4u * (n))
#define CALL_ORIG(addr) do { void F_##addr##__orig(CPU *); uint32_t sp_ = c->esp; F_##addr##__orig(c); c->esp = sp_; } while (0)
static inline void *gp(uint32_t a) { return a ? G2H(a) : NULL; }      // guest pointer -> host (NULL stays NULL)
static inline uint32_t hg(const void *p) { return p ? H2G(p) : 0; }   // host pointer into the window -> guest
#define PTR(i)  gp(ARG(i))
#define STR(i)  ((const char *)gp(ARG(i)))
#define WSTR(i) ((const uint16_t *)gp(ARG(i)))

#define SHIM(sym, n) static uint32_t sym##_body(CPU *c); \
    void I_##sym(CPU *c) { uint32_t r_ = sym##_body(c); c->eax = r_; c->esp += 4u * (n); } \
    static uint32_t sym##_body(CPU *c)
#define CSHIM(sym) SHIM(sym, 0)
// shims that set registers themselves (64-bit results in edx:eax, x87 results in st0)
#define RAWSHIM(sym) void I_##sym(CPU *c)

// ---- runtime services (rt32.c) ----
extern int rt_verbose;
void rt_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void rt_fatal(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));
uint32_t guest_call(CPU *c, uint32_t addr, int nargs, const uint32_t *args);   // any convention: esp restored
uint32_t rt_host_fn(gfn f, const char *name);   // native function -> guest-callable address (stdcall/cdecl as f does)
uint32_t rt_host_fn_ctx(void (*f)(CPU *, uintptr_t), uintptr_t ctx, const char *name);   // same, with a context value
gfn rt_import_by_name(const char *dll, const char *name);   // shim for GetProcAddress
CPU *rt_cpu(void);                              // the calling thread's CPU

// guest address space
uint32_t gvm_alloc(uint32_t addr, uint32_t size, int commit, uint32_t prot);   // VirtualAlloc-like; 0 on failure
int gvm_free(uint32_t addr);
int gvm_protect(uint32_t addr, uint32_t size, uint32_t prot);
int gvm_query(uint32_t addr, uint32_t *base, uint32_t *size, uint32_t *state, uint32_t *prot);
uint32_t gmalloc(uint32_t n);
uint32_t gcalloc(uint32_t n, uint32_t sz);
uint32_t grealloc(uint32_t p, uint32_t n);
void gfree(uint32_t p);
uint32_t gmsize(uint32_t p);
uint32_t gstrdup(const char *s);

// debugging: RT_WATCH=<guest address> logs bulk writes by runtime shims (file reads, memcpy...) that cover it
extern uint32_t rt_watch_addr;
void rt_watch_bulk(uint32_t dst, uint32_t n, const char *who);
#define WATCH_BULK(dst, n, who) do { if (__builtin_expect(rt_watch_addr != 0, 0)) rt_watch_bulk((dst), (n), (who)); } while (0)

// per-thread state
typedef struct RtThread {
    CPU *cpu;
    uint32_t teb, tid;
    uint32_t last_error;
    pthread_t pt;
    uint32_t handle;
} RtThread;
RtThread *rt_thread(void);
#define LAST_ERROR (rt_thread()->last_error)
uint32_t rt_teb_alloc(RtThread *t, uint32_t stack_lo, uint32_t stack_hi);
extern uint32_t rt_peb, rt_process_heap;

// per-game settings: the game project fills rt_game before rt_init (see src/game.c)
typedef struct {
    const char *name;        // display name (window titles, logs)
    const char *exe;         // the Windows executable's file name ("game.exe")
    const char *win_dir;     // where the game believes it is installed (default C:\Games\Game)
    const char *docs_dir;    // the folder SHGetFolderPath returns (default C:\Users\Player\Documents)
    const char *image;       // the executable image to load, e.g. a DRM-free copy made at build time ("orig.exe"):
                             // found in the app's Resources, next to the binary, or one folder up (dev builds)
    uint32_t steam_app_id;   // Steam app ID (0: not a Steam game); steam32.c signs in through the Steam for Mac client
} RtGame32;
extern RtGame32 rt_game;

// paths: Windows path in the game -> host path (backslashes, drive letters, the save folder)
const char *rt_host_path(const char *win, char *out, size_t n);
extern char rt_game_dir[1024], rt_data_dir[1024], rt_exe_dir[1024];
// set before rt_init: called once with the whole guest window while it is still mapped read/write and before anything
// is protected (a GPU API can wrap it then, e.g. Metal's newBufferWithBytesNoCopy, which refuses PROT_NONE pages)
extern void (*rt_guest_window_hook)(void *base, uint64_t size);

// UTF-16 helpers
size_t w_len(const uint16_t *s);
void w_to_utf8(const uint16_t *s, char *out, size_t n);
void utf8_to_w(const char *s, uint16_t *out, size_t n);
