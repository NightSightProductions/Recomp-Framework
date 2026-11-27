# Recomp-Framework build rules. A game project's Makefile sets a few variables and includes this file:
#
#   FW        = path/to/Recomp-Framework
#   GAME_EXE  = orig.exe                  # the game's Windows executable (a symlink to the user's copy)
#   APP_NAME  = MyGame                    # the app's executable name; APP_FILE / APP_DISPLAY (default APP_NAME):
#                                         # the .app's file name and the name shown in the menu bar and Dock
#   BUNDLE_ID = com.example.mygame-recomp
#   GAME_SRC  = game.c                    # game.c (the RtGame settings) plus any game-specific runtime code
#   NATIVE    = native.txt                # optional: guest functions replaced by native ones (addr name)
#   PATCHES   = patches.txt               # optional: guest instructions replaced by C (addr code)
#   include $(FW)/recomp.mk
#
# Targets: gen (translate the exe), boot (link the runtime + translated game), runtime (compile check of the
# runtime alone), app (the .app bundle),
# kosmickrisp (build the Vulkan driver from Mesa), fuzz (differential instruction test), clean.
# Extra translated DLLs: see MODULE_RULES at the end.

CC        ?= clang
PYTHON    ?= python3
ARCH      ?= -arch arm64
MACOS_MIN ?= 26.0
GEN_DIR   ?= gen
BUILD     ?= build
APP_NAME  ?= Game
APP_FILE  ?= $(APP_NAME)
APP_DISPLAY ?= $(APP_NAME)
BUNDLE_ID ?= com.example.game-recomp
APP_CATEGORY ?= public.app-category.games
APP_FLAGS ?=
GAME_SRC  ?= game.c
NATIVE    ?=
PATCHES   ?=
EXTRA_LIBS ?=
EXTRA_LIBS_FORCE ?=

FW_INC     = -I$(FW)/runtime -I$(FW)/third_party/vulkan/include
WARN       = -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-label
CFLAGS    ?= -O1 -g $(ARCH) -mmacosx-version-min=$(MACOS_MIN) $(WARN) $(FW_INC)
# translated code: -O2 so clang's loop vectorizer turns per-lane XMM loops back into NEON.
# Conditional jumps come out as `if ((sf==of))` (the condition table keeps each condition parenthesized for use
# inside other expressions); clang flags every one with -Wparentheses-equality, about 20,000 lines per build.
GEN_WARN   = $(WARN) -Wno-parentheses-equality
GEN_CFLAGS ?= -O2 -g $(ARCH) -mmacosx-version-min=$(MACOS_MIN) $(GEN_WARN) -I$(FW)/runtime

# ---- profile-guided optimization ----
#   make app PGO=gen BUILD=build-pgo   instrumented build; play it (each run writes $(PGO_DIR)/*.profraw on exit)
#   make pgo-merge                     merge the runs into $(PGO_DATA)
#   make app PGO=use                   optimized build using the profile
PGO      ?=
PGO_DIR  ?= $(CURDIR)/pgo
PGO_DATA ?= $(PGO_DIR)/game.profdata
PGO_LDFLAGS =
ifeq ($(PGO),gen)
GEN_CFLAGS  += -fprofile-instr-generate
CFLAGS      += -fprofile-instr-generate
PGO_LDFLAGS  = -fprofile-instr-generate
endif
ifeq ($(PGO),use)
GEN_CFLAGS += -fprofile-instr-use=$(PGO_DATA) -Wno-profile-instr-out-of-date -Wno-profile-instr-unprofiled
CFLAGS     += -fprofile-instr-use=$(PGO_DATA) -Wno-profile-instr-out-of-date -Wno-profile-instr-unprofiled
endif
pgo-merge:
	xcrun llvm-profdata merge -o "$(PGO_DATA)" "$(PGO_DIR)"/*.profraw

TRANSLATE = $(PYTHON) $(FW)/tools/recomp64.py
TRANSLATE_OPTS = $(if $(NATIVE),--native $(NATIVE)) $(if $(PATCHES),--patches $(PATCHES))

# ---- translation of the game executable ----
gen:
	$(TRANSLATE) $(GAME_EXE) $(GEN_DIR) $(TRANSLATE_OPTS)

GEN_SRC = $(sort $(wildcard $(GEN_DIR)/code_*.c)) $(GEN_DIR)/tables.c
GEN_OBJ = $(patsubst %.c,$(BUILD)/%.o,$(GEN_SRC))
$(BUILD)/$(GEN_DIR)/%.o: $(GEN_DIR)/%.c $(FW)/runtime/cpu.h $(FW)/runtime/tables.h
	@mkdir -p $(dir $@)
	$(CC) $(GEN_CFLAGS) -c $< -o $@
$(BUILD)/libgame.a: $(GEN_OBJ)
	rm -f $@; ar rcs $@ $^

# ---- runtime ----
FW_RT_C = rt.c teb.c kernel32.c handles.c files.c vulkan.c display.c window.c bcrypt.c input.c xaudio2.c pdh.c \
          system.c dinput.c sockets.c wasapi.c fiber.c user32.c steam.c native.c spvfix.c setjmp.c xreverb.c \
          ucrt.c ucrt_stdio.c vcruntime.c msvcp.c cxxeh.c schannel.c
FW_RT_M = cocoa.m winhttp.m gamepad.m gpucapture.m opengl.m
RT_OBJ  = $(patsubst %.c,$(BUILD)/fw/%.o,$(FW_RT_C)) $(patsubst %.m,$(BUILD)/fw/%.o,$(FW_RT_M))
GAME_OBJ = $(patsubst %.c,$(BUILD)/game/%.o,$(GAME_SRC))
FW_HDR  = $(wildcard $(FW)/runtime/*.h)

$(BUILD)/fw/%.o: $(FW)/runtime/%.c $(FW_HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/fw/%.o: $(FW)/runtime/%.m $(FW_HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fobjc-arc -c $< -o $@
$(BUILD)/game/%.o: %.c $(FW_HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# The guest image range is reserved inside the executable as zero-fill segments (rt.c): the exe at its
# preferred base 0x140000000, translated DLLs at 0x160000000 (rebased: 0x180000000 is the arm64 shared cache's range).
LDFLAGS ?= $(ARCH) -Wl,-export_dynamic -Wl,-segaddr,__GUEST,0x140000000 -Wl,-segaddr,__GUESTDLL,0x160000000 \
           -framework CoreGraphics -framework CoreFoundation -framework AppKit -framework QuartzCore \
           -framework AudioToolbox -framework CoreAudio -framework GameController -framework CoreHaptics -framework Metal \
           -framework OpenGL -framework IOSurface -framework Security

$(BUILD)/boot: $(BUILD)/libgame.a $(EXTRA_LIBS) $(EXTRA_LIBS_FORCE) $(RT_OBJ) $(GAME_OBJ) $(BUILD)/fw/boot.o $(FW)/runtime/boot-Info.plist
	$(CC) $(LDFLAGS) $(PGO_LDFLAGS) -Wl,-sectcreate,__TEXT,__info_plist,$(FW)/runtime/boot-Info.plist $(BUILD)/fw/boot.o $(RT_OBJ) $(GAME_OBJ) \
	    $(BUILD)/libgame.a $(EXTRA_LIBS) $(foreach l,$(EXTRA_LIBS_FORCE),-Wl,-force_load,$(l)) -o $@
boot: $(BUILD)/boot
# the runtime alone (no translated game): a quick compile check
runtime: $(RT_OBJ) $(GAME_OBJ) $(BUILD)/fw/boot.o

# ---- macOS app ----
app: $(BUILD)/boot
	$(PYTHON) $(FW)/tools/make_app.py $(BUILD)/boot $(GAME_EXE) "$(BUILD)/$(APP_FILE).app" --name "$(APP_NAME)" \
	    --display-name "$(APP_DISPLAY)" \
	    --bundle-id $(BUNDLE_ID) --category $(APP_CATEGORY) $(APP_FLAGS)

# ---- Vulkan thunks (generated from the Vulkan headers) ----
$(FW)/runtime/vk_thunks.h: $(FW)/tools/gen_vk.py $(FW)/third_party/vulkan/include/vulkan/vulkan_core.h
	$(PYTHON) $(FW)/tools/gen_vk.py $(FW)/third_party/vulkan/include/vulkan/vulkan_core.h $@
$(BUILD)/fw/vulkan.o: $(FW)/runtime/vk_thunks.h

# ---- OpenGL thunks (generated from the macOS SDK's OpenGL/gl3.h) ----
GL3_H = $(shell xcrun --show-sdk-path)/System/Library/Frameworks/OpenGL.framework/Headers/gl3.h
$(FW)/runtime/gl_thunks.h: $(FW)/tools/gen_gl.py
	$(PYTHON) $(FW)/tools/gen_gl.py "$(GL3_H)" $@
$(BUILD)/fw/opengl.o: $(FW)/runtime/gl_thunks.h

# ---- instruction fuzzer: every instruction form the exe uses, translated vs. original x86 (under Rosetta) ----
fuzz:
	$(PYTHON) $(FW)/tests/insn_fuzz.py $(GAME_EXE) --trials 96

include $(FW)/kosmickrisp.mk

clean:
	rm -rf $(BUILD)

.PHONY: gen boot runtime app fuzz kosmickrisp clean pgo-merge

# ---- extra translated DLLs (game DLLs that contain code) ----
# $(call MODULE_RULES,name,dll,dir,extra translator options,extra cflags) defines `gen-<name>` and
# $(BUILD)/lib<name>.a; add the library to EXTRA_LIBS_FORCE. DLLs are translated rebased (--rebase <hex>) into
# the DLL range at 0x160000000-0x164000000: their usual preferred base, 0x180000000, is where arm64 macOS maps
# its shared cache. Example:
#   $(eval $(call MODULE_RULES,bink2w64,orig_bink.dll,gen_bink,--rebase 162000000 --no-abi-trim,-DRT_TSO=0))
#   EXTRA_LIBS_FORCE += $(BUILD)/libbink2w64.a
define MODULE_RULES
gen-$(1):
	$$(TRANSLATE) $(2) $(3) --module $(1) $(4)
$(1)_SRC = $$(sort $$(wildcard $(3)/code_*.c)) $(3)/tables.c
$(1)_OBJ = $$(patsubst %.c,$$(BUILD)/%.o,$$($(1)_SRC))
$$(BUILD)/$(3)/%.o: $(3)/%.c $$(FW)/runtime/cpu.h $$(FW)/runtime/tables.h
	@mkdir -p $$(dir $$@)
	$$(CC) $$(GEN_CFLAGS) $(5) -c $$< -o $$@
$$(BUILD)/lib$(1).a: $$($(1)_OBJ)
	rm -f $$@; ar rcs $$@ $$^
.PHONY: gen-$(1)
endef
