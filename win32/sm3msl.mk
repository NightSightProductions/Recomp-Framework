# sm3msl (tools/sm3msl): offline D3D9 SM1-3 bytecode -> Metal converter for native Metal renderers. Built from the
# dxbc-spirv (sm3 frontend, SPIR-V backend) and SPIRV-Cross (MSL backend) submodules; nothing of it runs in the game.
# Included by win32.mk.
#   make sm3msl                          build $(SM3MSL)
#   make shaders SHADER_SRC=dir          convert dir/{vs,ps}_*.bin into $(SHADER_OUT): .metal, sm3_shaders.inc and
#                                        shaders.metallib (one function per shader, named like the .bin)
SM3_DXBC_SRC  = $(W32)/../third_party/dxbc-spirv
SM3_SPVC_SRC  = $(W32)/../third_party/spirv-cross
SM3_DXBC_OUT  = $(BUILD)/dxbc-spirv
SM3_SPVC_OUT  = $(BUILD)/spirv-cross
SM3MSL        = $(BUILD)/sm3msl
SHADER_OUT   ?= $(BUILD)/shaders
SM3_SPVC_LIBS = $(SM3_SPVC_OUT)/libspirv-cross-msl.a $(SM3_SPVC_OUT)/libspirv-cross-glsl.a $(SM3_SPVC_OUT)/libspirv-cross-core.a

$(SM3_DXBC_OUT)/libdxbc_spv.a:
	@test -f $(SM3_DXBC_SRC)/meson.build || git -C $(W32)/.. submodule update --init --recursive third_party/dxbc-spirv
	@test -d $(SM3_DXBC_OUT) || meson setup $(SM3_DXBC_OUT) $(SM3_DXBC_SRC) --buildtype=release
	ninja -C $(SM3_DXBC_OUT) libdxbc_spv.a
$(SM3_SPVC_LIBS) &:
	@test -f $(SM3_SPVC_SRC)/CMakeLists.txt || git -C $(W32)/.. submodule update --init third_party/spirv-cross
	cmake -S $(SM3_SPVC_SRC) -B $(SM3_SPVC_OUT) -G Ninja -DCMAKE_BUILD_TYPE=Release -DSPIRV_CROSS_ENABLE_TESTS=OFF >/dev/null
	ninja -C $(SM3_SPVC_OUT) spirv-cross-msl spirv-cross-glsl spirv-cross-core
$(SM3MSL): $(W32)/tools/sm3msl/sm3msl.cpp $(W32)/runtime/sm3msl.h $(SM3_DXBC_OUT)/libdxbc_spv.a $(SM3_SPVC_LIBS)
	clang++ -std=c++17 -O2 -I$(SM3_DXBC_SRC) -I$(SM3_DXBC_SRC)/submodules/spirv_headers/include -I$(SM3_SPVC_SRC) \
	    -I$(W32)/runtime $< $(SM3_DXBC_OUT)/libdxbc_spv.a $(SM3_SPVC_LIBS) -o $@
sm3msl: $(SM3MSL)
# the converter as a library for the runtime (shaders first seen while the game runs are converted then, and cached)
SM3MSL_RT = $(BUILD)/sm3msl_lib.o $(SM3_DXBC_OUT)/libdxbc_spv.a $(SM3_SPVC_LIBS)
$(BUILD)/sm3msl_lib.o: $(W32)/tools/sm3msl/sm3msl.cpp $(W32)/runtime/sm3msl.h $(SM3_DXBC_OUT)/libdxbc_spv.a $(SM3_SPVC_LIBS)
	clang++ -std=c++17 -O2 -DSM3MSL_LIB -I$(SM3_DXBC_SRC) -I$(SM3_DXBC_SRC)/submodules/spirv_headers/include -I$(SM3_SPVC_SRC) \
	    -I$(W32)/runtime -c $< -o $@

shaders: $(SM3MSL)
	@test -n "$(SHADER_SRC)" || { echo "set SHADER_SRC to a directory of dumped shaders (RT_DUMP_SHADERS=1)"; exit 1; }
	@mkdir -p $(SHADER_OUT)/air
	@find $(SHADER_OUT) -maxdepth 2 \( -name '[vp]s_*.metal' -o -name '[vp]s_*.air' \) -delete
	$(SM3MSL) $(SHADER_OUT) "$(SHADER_SRC)"/*.bin
	@ls $(SHADER_OUT)/*.metal | xargs -P $$(sysctl -n hw.ncpu) -I{} sh -c 'xcrun -sdk macosx metal -c "{}" -o $(SHADER_OUT)/air/$$(basename "{}" .metal).air'
	xcrun -sdk macosx metallib $(SHADER_OUT)/air/*.air -o $(SHADER_OUT)/shaders.metallib
	@echo "$$(ls $(SHADER_OUT)/air | wc -l | tr -d ' ') shaders -> $(SHADER_OUT)/shaders.metallib"

.PHONY: sm3msl shaders
