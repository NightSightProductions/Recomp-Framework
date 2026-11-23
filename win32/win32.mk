# Recomp-Framework win32: build rules for 32-bit Windows games (PE32 i386 -> C -> arm64).
# A game project's Makefile sets these and includes this file:
#
#   FW        = path/to/Recomp-Framework
#   GAME_EXE  = orig.exe                  # the game's executable, DRM removed (32-bit PE)
#   APP_NAME  = MyGame
#   GAME_SRC  = src/game.c                # main(): settings, rt_init, rt_run; plus game-specific natives
#   NATIVE    = native.txt                # optional: guest functions replaced by native ones (addr name)
#   PATCHES   = patches.txt               # optional: guest instructions replaced by C (addr code)
#   include $(FW)/win32/win32.mk
#
# Targets: gen (translate), boot (link), runtime (compile check without the game), clean.

CC        ?= clang
PYTHON    ?= python3
ARCH      ?= -arch arm64
MACOS_MIN ?= 14.0
GEN_DIR   ?= gen
BUILD     ?= build
APP_NAME  ?= Game
GAME_SRC  ?= game.c
NATIVE    ?=
PATCHES   ?=
W32       = $(FW)/win32

WARN       = -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-label -Wno-parentheses-equality
W32_INC    = -I$(W32)/runtime
CFLAGS    ?= -O1 -g $(ARCH) -mmacosx-version-min=$(MACOS_MIN) $(WARN) $(W32_INC)
GEN_CFLAGS ?= -O2 -g $(ARCH) -mmacosx-version-min=$(MACOS_MIN) $(WARN) -Wno-tautological-constant-out-of-range-compare $(W32_INC)

TRANSLATE = $(PYTHON) $(W32)/tools/recomp_w32.py
TRANSLATE_OPTS = $(if $(NATIVE),--native $(NATIVE)) $(if $(PATCHES),--patches $(PATCHES))

gen:
	$(TRANSLATE) $(GAME_EXE) $(GEN_DIR) $(TRANSLATE_OPTS)

GEN_SRC = $(sort $(wildcard $(GEN_DIR)/code_*.c)) $(GEN_DIR)/tables.c
GEN_OBJ = $(patsubst %.c,$(BUILD)/%.o,$(GEN_SRC))
W32_HDR = $(wildcard $(W32)/runtime/*.h)
$(BUILD)/$(GEN_DIR)/%.o: $(GEN_DIR)/%.c $(W32)/runtime/cpu32.h $(W32)/runtime/tables32.h
	@mkdir -p $(dir $@)
	$(CC) $(GEN_CFLAGS) -c $< -o $@
$(BUILD)/libgame.a: $(GEN_OBJ)
	rm -f $@; ar rcs $@ $^

W32_RT_C ?= rt32.c native32.c imports.c kernel32.c crt.c user32.c misc.c com32.c dinput8.c steam32.c wmvcore.c xaudio2_9.c
W32_RT_M ?= cocoa32.m mtl_render.m
# the Direct3D 9 backend: dxvk (default) runs the game's D3D9 calls on DXVK + KosmicKrisp through the d3d9 bridge, for
# prototyping; none for a game with its own native renderer (no bridge, no DXVK or Vulkan in the build or the app)
D3D9_BACKEND ?= dxvk
ifeq ($(D3D9_BACKEND),dxvk)
W32_RT_CPP ?= d3d9_bridge.cpp
D3D9_LIB    = $(DXVK_LIB)
else
W32_RT_CPP ?=
D3D9_LIB    =
CFLAGS     += -DRT_NO_D3D9_BRIDGE
endif
include $(W32)/dxvk.mk
include $(W32)/ffmpeg.mk
include $(W32)/sm3msl.mk
include $(FW)/kosmickrisp.mk
RT_OBJ   = $(patsubst %.c,$(BUILD)/w32/%.o,$(W32_RT_C)) $(patsubst %.m,$(BUILD)/w32/%.o,$(W32_RT_M)) \
           $(patsubst %.cpp,$(BUILD)/w32/%.o,$(W32_RT_CPP))
# controllers: the shared GameController/XInput module of the 64-bit runtime (framework/runtime/gamepad.m)
RT_OBJ  += $(BUILD)/w32/gamepad.o
$(BUILD)/w32/gamepad.o: $(FW)/runtime/gamepad.m
	@mkdir -p $(dir $@)
	$(CC) -O1 -g $(ARCH) -mmacosx-version-min=$(MACOS_MIN) -fobjc-arc -I$(FW)/runtime -c $< -o $@
GAME_OBJ = $(patsubst %.c,$(BUILD)/game/%.o,$(GAME_SRC))
$(BUILD)/w32/%.o: $(W32)/runtime/%.c $(W32_HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
# the WMV reader compiles against the FFmpeg it links (ffmpeg.mk)
$(BUILD)/w32/wmvcore.o: $(W32)/runtime/wmvcore.c $(W32_HDR) $(FFMPEG_OUT)/lib/libavcodec.a
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(FFMPEG_INC) -c $< -o $@
$(BUILD)/w32/%.o: $(W32)/runtime/%.m $(W32_HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fobjc-arc -c $< -o $@
# the d3d9 bridge uses DXVK's native Windows headers (C++; their BOOL clashes with Objective-C's, so AppKit code
# stays in .m files)
$(BUILD)/w32/%.o: $(W32)/runtime/%.cpp $(W32_HDR)
	@mkdir -p $(dir $@)
	clang++ -std=c++17 -O1 -g $(ARCH) -mmacosx-version-min=$(MACOS_MIN) $(WARN) $(W32_INC) $(DXVK_INC) -c $< -o $@
$(BUILD)/game/%.o: %.c $(W32_HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

FRAMEWORKS ?= -framework CoreFoundation -framework AppKit -framework QuartzCore -framework Metal -framework MetalKit \
              -framework AudioToolbox -framework CoreAudio -framework GameController -framework CoreHaptics
$(BUILD)/$(APP_NAME): $(BUILD)/libgame.a $(RT_OBJ) $(GAME_OBJ) $(SM3MSL_RT)
	$(CC) $(ARCH) $(RT_OBJ) $(GAME_OBJ) $(BUILD)/libgame.a $(SM3MSL_RT) $(FFMPEG_LIBS) $(FRAMEWORKS) -lc++ -o $@
boot: $(BUILD)/$(APP_NAME) $(D3D9_LIB)
runtime: $(RT_OBJ) $(GAME_OBJ)

# ---- macOS app (framework/tools/make_app.py): binary, the game image, the d3d9 backend, KosmicKrisp, icon ----
#   APP_FILE / APP_DISPLAY   the .app's file name / the name in the menu bar and Dock (default APP_NAME)
#   APP_IMAGE                the executable image to bundle as Resources/$(APP_IMAGE_NAME) (rt_game.image)
#   APP_ICON                 an image for the icon when the exe's own is too small (optional)
APP_FILE       ?= $(APP_NAME)
APP_DISPLAY    ?= $(APP_FILE)
BUNDLE_ID      ?= com.example.game-recomp
APP_CATEGORY   ?= public.app-category.games
APP_IMAGE      ?= $(GAME_EXE)
APP_IMAGE_NAME ?= orig.exe
APP_ICON       ?=
APP_FLAGS      ?=
#   APP_RESOURCES            more files for Contents/Resources (FILE[=NAME] ...), e.g. a native renderer's metallib
APP_RESOURCES  ?=
app: $(BUILD)/$(APP_NAME) $(D3D9_LIB) $(firstword $(subst =, ,$(APP_RESOURCES)))
	@test "$(D3D9_BACKEND)" != dxvk || test -d $(KK_STAGE) || { echo "error: no $(KK_STAGE): run 'make kosmickrisp' first (the Vulkan driver DXVK runs on)" >&2; exit 1; }
	$(PYTHON) $(FW)/tools/make_app.py $(BUILD)/$(APP_NAME) $(GAME_EXE) "$(BUILD)/$(APP_FILE).app" --name "$(APP_NAME)" \
	    --display-name "$(APP_DISPLAY)" --bundle-id $(BUNDLE_ID) --category $(APP_CATEGORY) \
	    --resource "$(APP_IMAGE)=$(APP_IMAGE_NAME)" $(foreach r,$(APP_RESOURCES),--resource "$(r)") \
	    $(if $(D3D9_LIB),--lib $(D3D9_LIB),--no-vulkan) $(if $(APP_ICON),--icon "$(APP_ICON)") $(APP_FLAGS)

clean:
	rm -rf $(BUILD)

.PHONY: gen boot runtime app clean
