# Recomp-Framework

A static recompilation framework for running games natively on Apple Silicon Macs. It has two targets:

- **Windows x86-64**: the 64-bit Windows release of a game (PE executables and DLLs), with Vulkan or OpenGL graphics.
- **32-bit Intel Mac** (`mac32/`): Mac games built for 32-bit Intel Macs (2006–2019), which stopped running when
  macOS dropped 32-bit support in Catalina (i386 Mach-O, OpenGL).

A game's executable is translated ahead of time into C, compiled for arm64, and linked with a native runtime that
implements the platform the game was written for on top of current macOS. The result is an ordinary `.app`: no emulator, no Rosetta and no
Wine at run time. The user's own copy of the game supplies the data.

Recomp-Framework is NightSightProductions' own tool. It began with JPTG Recomp, the port of a 32-bit Intel Mac game,
which became the `mac32` target, and grew a Windows x86-64 target while porting DOOM (2016). It is MIT licensed: we believe in open
source.

## Pipeline (Windows x86-64)

```
Game.exe ──recomp64.py──▶ gen/code_*.c ──clang──▶ libgame.a ─┐
                          gen/tables.c                        ├──▶ boot ──make_app.py──▶ Game.app
game.c + runtime/ ──────────────────clang──▶ runtime objects ─┘
```

1. **Translate.** `tools/recomp64.py` reads the PE and writes one C function per guest function, plus tables of
   functions, imports and modules.
2. **Compile and link.** The generated C, the runtime and the game's `game.c` are linked into one arm64 binary. The
   guest image's address range is reserved inside the binary itself.
3. **Package.** `tools/make_app.py` builds a signed app bundle with the game's own icon and the bundled Vulkan driver.
   At launch the app finds the user's game folder by itself.

## Repository layout

| Path | Contents |
|---|---|
| `tools/recomp64.py` | The translator |
| `tools/pe.py` | PE reader: sections, imports, relocations, exception directory (`.pdata`) |
| `tools/gen_vk.py` | Generates the Vulkan entry points from the Vulkan headers |
| `tools/gen_gl.py` | Generates the OpenGL entry points from the macOS SDK's `OpenGL/gl3.h` |
| `tools/gen_steam_slots.py` | Generates the per-slot stubs of the Steam interfaces (`runtime/steam_slots.h`) |
| `tools/make_app.py`, `tools/app_icon.py` | App bundle packaging |
| `tools/nsr.py` | **NightSight Recomp (NSR)**: one Steam Play compatibility tool for every recomp (needs [NotProton](https://github.com/NotProtonNot/NotProton)). Each game's own Steam entry starts its app, with the Steam overlay and NotProton plugins; see [Steam Play](#steam-play-nightsight-recomp-nsr) |
| `runtime/` | The native runtime: execution core and the Windows platform layer |
| `runtime/game.h` | The per-game settings interface |
| `tests/` | Differential instruction fuzzer (`insn_fuzz.py`, MMX: `mmx_fuzz.py`), offline Vulkan shader harness |
| `patches/mesa/` | Patches applied to the KosmicKrisp Vulkan driver |
| `template/` | Skeleton of a game project |
| `recomp.mk` | Build rules included by game projects |
| `mac32/` | The 32-bit Intel Mac target: its translator, runtime, template and build rules (see below) |

## Translator

**Input:** a Windows x86-64 executable or DLL.

**Output:** C, where each guest function becomes `void F_<address>(CPU *c)`.

- **Instructions.** Instructions are decoded with Capstone and translated individually into C operating on the
  guest CPU state. Within a function, guest registers are cached in C locals; flags are written per instruction and the
  compiler removes the ones nothing reads. Packed SSE operations map to clang vector extensions, which compile to NEON. Supported: the general-purpose
  ISA, MMX, SSE through SSE4.1 (with SSSE3 and POPCNT), and a subset of x87. Not supported: SSE4.2 string instructions
  and AVX. The runtime's CPUID reports exactly what the translator supports, so games choose matching code paths.
- **Function discovery.** Function starts are collected from:
  - the exception directory (`.pdata`), the entry point and exports;
  - direct call and tail-jump targets;
  - `lea`-referenced code;
  - code pointers in the relocation table;
  - leaf functions, scanned iteratively until no new starts appear.
- **Control flow.** Branches within a function become labels and `goto`s. Jump tables are recovered from their
  bounds checks, including two-level tables. Calls map onto native C calls; the guest return address is still pushed
  on the guest stack.
- **Indirect branches.** These resolve at run time through a guest-address → function table: a direct-mapped fast
  path, then a sorted fallback. Unresolved targets are reported with a backtrace.

| Option | |
|---|---|
| `--native FILE` | Replace guest functions with native implementations (`address name` per line). The translation is kept, and `RT_NATIVE_OFF` switches back to it. |
| `--patches FILE` | Replace single guest instructions with C (`address code`, registers as `C.<reg>`) |
| `--probes FILE` | Insert C before guest instructions, for in-game diagnostics |
| `--module NAME` | Translate a DLL as a loadable module |
| `--rebase HEX` | Translate a DLL at another base address (for DLLs with colliding preferred bases) |
| `--no-abi-trim` | Reload all registers after calls (for hand-written assembly that doesn't follow the Win64 ABI) |
| `--only ADDR,...` | Translate selected functions only |

## Runtime

**Execution core** (`cpu.h`, `rt.c`, `teb.c`, `fiber.c`):
- **Memory.** Guest memory is identity-mapped: the executable is loaded at its preferred base (`0x140000000`) and
  translated DLLs rebased into `0x160000000`–`0x164000000` (`--rebase`; their usual base, `0x180000000`, is where
  arm64 macOS maps its shared cache), so guest pointers are host pointers.
- **Threads.** Each guest thread runs on a host thread with its own CPU state. `lock`-prefixed operations map to
  atomic builtins, and fibers are supported.
- **Memory ordering.** x86's TSO ordering is preserved by emitting guest loads and stores as acquire/release
  (`LDAPR`/`STLR`); stack accesses are exempt. Modules that only synchronize through OS objects can be built with
  `-DRT_TSO=0`. `-DRT_RELAX_FP` also exempts float and vector (SSE) accesses, which is safe when the game
  synchronizes through integer flags and locks; their acquire/release still orders the data around them.
  `-DRT_ORDER_RELAXED` drops all ordering. It's unsafe, and only there to measure what ordering costs.
- **Profile-guided optimization.** `make app PGO=gen` builds an instrumented app, `make pgo-merge` merges the
  profiles recorded while playing, and `make app PGO=use` builds with them.

**Windows platform layer.** About 1,400 functions:

| Area | Implemented on |
|---|---|
| Files, memory, heaps, threads, synchronization, time (kernel32) | POSIX and Darwin |
| Windows, messages, input, display modes (user32) | Cocoa |
| XInput | GameController, with rumble through CoreHaptics |
| DirectInput 8 (keyboard, mouse) | AppKit events |
| Sockets (Winsock) | BSD sockets |
| WinHTTP | NSURLSession |
| bcrypt | CommonCrypto |
| Audio (WASAPI, XAudio2) | CoreAudio |
| Vulkan | KosmicKrisp, Mesa's Vulkan driver for Metal, with Windows-only extensions translated (`VK_KHR_win32_surface` → Metal surface) |
| OpenGL (WGL) | macOS's OpenGL 4.1 core profile (`opengl.m`); the window's framebuffer is emulated over IOSurfaces and presented through Metal, query names are shared across contexts, legacy texture formats become swizzled R/RG |
| Steam API | The real `libsteam_api.dylib` (callbacks, matchmaking, P2P, stats and achievements), plus save sync to Steam Cloud |

On the graphics side, `spvfix.c` rewrites SPIR-V patterns that desktop drivers tolerate but Metal does not. The
bundled driver has two patches (`patches/mesa`):
- **0001:** vertex shaders keep IEEE float semantics.
- **0002:** when Steam's overlay is loaded, frames are presented through a Metal 3 command buffer, which is where
  the overlay hooks in. KosmicKrisp otherwise presents the Metal 4 way, which the overlay never sees.

Translated game DLLs (video codecs, scripting engines…) are registered as modules and loaded through `LoadLibrary`.

## Porting a game

1. Copy `template/` and point `FW` in its Makefile at this repository (or add the framework as a git submodule).
2. Fill in `game.c`. Every game-specific name the runtime needs is in the `RtGame` struct:

   | Field | Meaning |
   |---|---|
   | `name`, `exe` | Display name; the Windows executable's file name |
   | `win_dir` | Where the game believes it is installed (`C:\Games\MyGame`) |
   | `data_name`, `log_name` | `~/Library/Application Support/<data_name>` and `~/Library/Logs/<log_name>.log` |
   | `env_prefix` | Prefix of the runtime's environment settings (`<PREFIX>_GAME_DIR`, `<PREFIX>_DATA_DIR`, `<PREFIX>_STEAM_OFFLINE`, …) |
   | `steam_folder`, `steam_app_id` | Used to find the game in Steam libraries, and for the Steam bridge |
   | `relaunch_prefix` | Executables the game starts that should relaunch the app instead |
   | `extra_args` | Arguments always passed to the game |
   | `cloud_save_dir`, `cloud_prefix` | Optional Steam Cloud sync of a save folder |
   | `image` | Optional executable image in the app's `Resources`, loaded instead of the game folder's exe (e.g. a DRM-free copy made at build time; `make_app.py --resource`) |
   | `gl_extensions` | OpenGL games: extra names for `GL_EXTENSIONS` the engine checks for |

3. Link the game's executable as `orig.exe`, then run `make kosmickrisp` (once), `make gen` and `make app`.
4. Run `make fuzz`. It checks the translator against the original instructions, run under Rosetta as the
   reference, for most instruction forms the executable uses. It skips `rep` string instructions, AVX and x87.
5. Add DLLs that contain code with `MODULE_RULES` (see `recomp.mk`).
6. Implement missing Windows functions as the game needs them. Calls to unimplemented imports are logged.
7. Optionally register the app with NSR, so it starts from the game's own Steam entry (see below).

Requirements:
- An Apple Silicon Mac with macOS 26 or newer.
- Xcode Command Line Tools.
- Python 3 with `capstone==5.0.6` and `lief==0.16.6`.
- To build the Vulkan driver: Homebrew `llvm`, `libclc` and `spirv-llvm-translator`, plus the Vulkan SDK.

## Steam Play: NightSight Recomp (NSR)

Steam for Mac has Steam Play compatibility tools switched off; [NotProton](https://github.com/NotProtonNot/NotProton)
switches them on. `tools/nsr.py` registers one tool, **NightSight Recomp (NSR)**, for any number of recomps. Choose it
for a game (Properties > Compatibility > Force the use of a specific Steam Play compatibility tool) and Play on the
game's own library entry starts the native app on the Windows release Steam installed, with playtime, presence and
the Steam overlay.

```
python3 tools/nsr.py install
python3 tools/nsr.py add --appid 379720 --app /Applications/DOOM.app --pass-paths --exe 'doomx64*.exe' --force-exe DOOMx64vk.exe
python3 tools/nsr.py list
```

- `--pass-paths` starts the app as `app <exe> <game folder>`, which Recomp-Framework apps take (with `rt_game.image`,
  the bundled image replaces the exe Steam passes); without it the app only gets the game's own arguments.
- `--exe` is the exe Steam starts as the game (anything else it runs first, such as redistributable installers,
  finishes at once); `--force-exe` always passes one exe from the game folder.
- NotProton plugins in `~/Library/Application Support/notproton/plugins/*.conf` that are switched on for the game are
  applied as NotProton's own launcher does: `inject` loads the plugin's dylib after Steam's overlay, `env` lines and
  `NOTPROTON_ENV_<NAME>` options set variables, and `depends`, `requires` and `tools` (the tool's name is `nsr`) are
  honoured.
- A game's environment (plugin switches such as `NOTPROTON_<ID>=1`, runtime settings) is set with
  `nsr.py set-env --appid <id> NAME=value ...` and kept in games.conf. Leave the game's Steam launch options empty:
  Steam for Mac starts a launch with options as `env VAR=value <tool>`, which fails ("OS Error 260") for any
  compatibility tool other than NotProton's own.
- Each launch is logged to `~/Library/Logs/nsr.log`. Games live in `compatibilitytools.d/nsr/games.conf`, one line
  each.

## 32-bit Intel Mac games (`mac32/`)

A separate translator and runtime for i386 Mach-O executables. Games link against the Mac frameworks of their era
(Carbon/Cocoa, CoreFoundation, OpenGL, FMOD…), so the runtime implements those instead of Windows.

| Path | Contents |
|---|---|
| `mac32/tools/recomp32.py` | The translator: i386 Mach-O → C (`recomp32.py BINARY LO HI OUTDIR [--hle FILE]`) |
| `mac32/tools/macho.py` | Mach-O reader: segments, sections, function symbols, import stubs and pointers |
| `mac32/tools/eh32.py` | Reads `__eh_frame` and `__gcc_except_tab`, so translated code can throw and catch C++ exceptions |
| `mac32/tools/glgen.py` | Generates the OpenGL entry points from a signature table |
| `mac32/runtime/` | The 32-bit runtime and the Cocoa/OpenGL host |
| `mac32/template/`, `mac32/mac32.mk` | Starting point and build rules for a game project |

- **Execution.** Guest memory is a 4 GiB reservation, with guest address `a` at `M + a`. Guest pointers are 32-bit
  and the original data layouts are kept. Each guest thread has its own CPU state; x87 and SSE are both translated.
- **Symbols.** Mach-O binaries of this era usually keep their symbol table, which gives exact function boundaries
  and names. Imports resolve to native shims by symbol name (`I_<symbol>`).
- **Runtime:**

  | Area | |
  |---|---|
  | C library, threads, and the C++ runtime of GCC 4.2's libstdc++ (RTTI and `dynamic_cast`, iostreams, copy-on-write strings, exceptions) | `libc2.c`, `shims.c`, `sys.c`, `cxx.c`, `cxxstr.c`, `eh.c` |
  | CoreFoundation, CoreGraphics display modes and preferences, Carbon events, IOKit queries | `cf.c` |
  | Objective-C 1.0 message dispatch for the little Cocoa a game's wrapper code uses | `objc.c` |
  | Bink movies, decoded by FFmpeg with `make FFMPEG=1` (black frames otherwise) | `bink.c` |
  | OpenGL (legacy profile on CGL) with the engine's viewport mapped onto Retina drawables | `gl.c` + generated entry points |
  | FMOD Ex on CoreAudio, Ogg Vorbis through stb_vorbis | `fmod.c`, `vorbis.c` |
  | Steamworks of the period, offline (stats and achievements stored locally) | `steam.c` |
  | Game controllers through the GameController framework, in XInput's layout | `pad.m` |
  | The app host: window, OpenGL view, input, fullscreen, screenshots, scripted input, MetalFX upscaling, a statistics overlay, frame pacing | `host.m` |

- **Porting.** The host drives the game through a few hooks the game project implements (`mac32/runtime/game32.h`):
  start, frame, window size, quit, and input. They usually call the engine's own C entry points: the ones the
  original app's Cocoa code called. Engine functions that talked to the old OS are replaced natively through
  `--hle` (`address name` per line, implemented as `H_<name>`). A project can name the one executable it was made
  for (`exe_sha256` in `rt32_game`); the host then refuses other builds with a clear message.
- **Opt-in behaviour.** Off by default, so existing ports keep working as they did: `-DRT_TSO=1` (x86 store ordering
  for lock-free guest code), and in `rt32_game` `.gl_fast_buffers` (mapped buffers alias the driver's memory, dirty-page
  uploads, orphaning), `.gl_invariant_position`, `.metalfx` and `.cf_release` (real `CFRelease`).
- **Diagnostics.**
  - `RT32_SHOT`, `RT32_EXIT_AFTER`, `RT32_INPUT`: screenshots, timed exits and scripted input for automated runs.
  - `RT32_STRICT`: abort on unimplemented imports.
  - `RT32_WATCH`, `RT32_MEMWATCH`, and `-DMEMCHECK` builds: watch guest functions and guest memory writes.
  - `RT32_TRACE_GL`, `RT32_TRACE_FMOD`, `RT32_TRACE_FILES`: subsystem traces.
  - `RT32_HUD=1`: overlay with frame rate, frame time, GPU time and memory (F12 toggles it while `RT32_HUD` is set).
    With `.metalfx = 1` in `rt32_game`, F9 switches MetalFX upscaling on and off (`RT32_NO_METALFX=1` disables it).
  - `[frame]`, `[hitch+]`, `[slowcall]`, `[shader]` log lines: where frame time goes, with GPU time from a timer
    query. `RT32_PACE=display` paces frames from the display (variable refresh), `RT32_WARM=1` draws once with
    each shader program when it is validated.

## Diagnostics (Windows x86-64)

| Setting | |
|---|---|
| `RT_NATIVE_OFF=all` or a list of addresses | Use the translated originals instead of native replacements |
| `--probes` / `rt_watch_set`, `rt_watch` | In-game logging at chosen instructions; `mprotect` watchpoints that identify writers to a buffer |
| `RT_WATCHDOG=seconds` | Periodic dump of what each guest thread is executing |
| `RT_VK_DUMP=dir` | Shaders, pipelines and per-frame snapshots (F9), including indirect-draw arguments read back from the GPU; F10 hides pipelines one at a time |
| `RT_VK_REPLACE=dir` | Replace shaders by hash with custom SPIR-V |
| `RT_FPS`, `RT_SCREENSHOT=n` with `RT_SCREENSHOT_FILE` | Frame-rate log; capture of frame *n* |
| `RT_GPU_CAPTURE=seconds[:path]` | Metal GPU capture (`.gputrace`, opens in Xcode) of one frame presented that many seconds after launch |
| `RT_HTTP_TRACE`, `RT_QUERY_STATS`, `RT_YIELD_STATS`, `RT_VK_FORMATS`, `RT_LIST_MODES` | Subsystem traces |
| `RT_GL_CHECK=1`, `RT_GL_SHADERS=dir`, `RT_GL_SCREENSHOT=n` with `RT_GL_SCREENSHOT_FILE` | OpenGL games: `glGetError` after every call (logged once per function and error), shader dumps, capture of frame *n* |
| `RT_NET_TRACE=1`, `RT_AUDIO_TRACE=1` | Socket setup and first receives; XAudio2 voices, routing and output level |
| `tests/vs_probe.c` | Runs a captured vertex shader on the driver offline and reads back its outputs |

## Limitations

- Windows: x86-64 executables only (no 32-bit Windows), no AVX and no SSE4.2 string instructions.
- 32-bit Mac: i386 executables with OpenGL; Carbon-only games need more platform coverage.
- Code generated or modified at run time (JIT, packers, self-modifying code), DRM and kernel-level anti-cheat are out
  of scope for static recompilation.
- Windows API coverage reflects the games ported so far, and grows with each port.

## Support and Feedback

  * [GitHub Issue Tracker](https://github.com/NightSightProductions/Recomp-Framework/issues)
  * [Discord](https://discord.gg/GKacpbpyQb)

## License

MIT, see [LICENSE](LICENSE). Bundled third-party components:
- the Vulkan headers (Khronos, Apache-2.0 or MIT);
- stb_vorbis (Sean Barrett, public domain or MIT).

KosmicKrisp is built from Mesa (MIT).
