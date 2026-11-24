// Native Metal renderer backend for recomps that replace a Direct3D 9-era engine renderer with Metal. Game code (the
// natives replacing the engine's render functions) decodes the engine's own data and drives this C API; values are
// Metal's (MTLPixelFormat, MTLBlendFactor, MTLCompareFunction, MTLVertexFormat ...), never D3D's.
//
// Memory: the whole guest window is one MTLBuffer (mtlr_init must run before rt_init). Vertex, index and constant
// data are bound by guest address: no copies, no staging. Shaders: the sm3msl metallib + table (sm3msl.h).
//
// Shadow mode (RT_METAL_SHADOW=1): the engine still renders through its original path and Metal renders the same
// frames into a second window, for comparing while the native renderer is incomplete.
#pragma once
#include <stdint.h>
#include "sm3msl.h"

typedef uint32_t MtlTex;            // texture handle (0 = none)

void mtlr_init(void);               // before rt_init: sets rt_guest_window_hook
int mtlr_active(void);              // device and guest buffer ready
int mtlr_shadow(void);              // RT_METAL_SHADOW
void mtlr_load_shaders(const char *metallib, const Sm3ShaderInfo *table, int n);
const Sm3ShaderInfo *mtlr_shader_info(uint32_t hash);
uint32_t mtlr_shader_add(const uint32_t *tokens, uint32_t ntokens);   // convert at run time if the build did not (cached); -> hash

// ---- output ----
void mtlr_set_window(uint32_t hwnd, int w, int h);   // the game window (shadow mode opens its own)
MtlTex mtlr_backbuffer(void);                          // valid between frames; resolves to the drawable at present
void mtlr_present(int sync_interval);
void mtlr_set_gamma(const uint16_t ramp[768]);   // D3D-style ramp (256 red, green, blue): applied at present

// ---- textures ----
enum { MTLR_TEX_2D, MTLR_TEX_CUBE, MTLR_TEX_3D };
enum { MTLR_USE_SAMPLE = 1, MTLR_USE_TARGET = 2 };
enum { MTLR_SWZ_RGBA, MTLR_SWZ_RGB1, MTLR_SWZ_RRR1, MTLR_SWZ_RRRG, MTLR_SWZ_000R };   // L8, A8L8, A8 ...
typedef struct {
    uint8_t type, levels, samples, usage, swizzle;
    uint32_t format;                // MTLPixelFormat
    uint32_t width, height, depth;
} MtlTexDesc;
MtlTex mtlr_tex_create(const MtlTexDesc *d);
void mtlr_tex_destroy(MtlTex t);
const MtlTexDesc *mtlr_tex_desc(MtlTex t);
// rows of a mip level (face for cubes, slice range for volumes) from host memory; pitch = bytes per row (per block
// row for compressed formats), slice = bytes per slice for volumes
void mtlr_tex_upload(MtlTex t, int face, int level, const void *data, uint32_t pitch, uint32_t slice);
void mtlr_tex_upload_rect(MtlTex t, int face, int level, int x, int y, int w, int h, const void *data, uint32_t pitch);
int mtlr_tex_texel_bytes(MtlTex t, int *block);   // bytes per texel (per block for compressed formats), block size
uint32_t mtlr_tex_level_size(MtlTex t, int level, uint32_t *pitch, uint32_t *rows);   // bytes, tightly packed

// ---- state (applies to the next draws) ----
typedef struct { MtlTex tex; uint8_t face, level, srgb; } MtlTarget;
void mtlr_set_targets(const MtlTarget color[4], MtlTarget depth);
void mtlr_set_viewport(float x, float y, float w, float h, float zmin, float zmax);
void mtlr_set_scissor(int x, int y, int w, int h);
typedef struct {
    uint8_t enable, src, dst, op, src_a, dst_a, op_a;   // MTLBlendFactor / MTLBlendOperation
    uint8_t mask;                                       // MTLColorWriteMask (R 8, G 4, B 2, A 1)
} MtlBlend;
void mtlr_set_blend(const MtlBlend rt[4], const float factor[4]);
typedef struct { uint8_t fail, zfail, pass, func; } MtlStencilFace;   // MTLStencilOperation, MTLCompareFunction
typedef struct {
    uint8_t depth_test, depth_write, depth_func, stencil;
    MtlStencilFace front, back;
    uint8_t read_mask, write_mask, ref;
} MtlDepthStencil;
void mtlr_set_depth_stencil(const MtlDepthStencil *d);
typedef struct { uint8_t cull, fill, ccw_front; float depth_bias, slope_bias; } MtlRaster;   // MTLCullMode, MTLTriangleFillMode
void mtlr_set_raster(const MtlRaster *r);
typedef struct {
    uint8_t min, mag, mip, aniso;   // MTLSamplerMinMagFilter (0 nearest 1 linear), MTLSamplerMipFilter, max anisotropy
    uint8_t u, v, w;                // MTLSamplerAddressMode
    uint8_t border;                 // MTLSamplerBorderColor
    uint8_t srgb;                   // sample through an sRGB view
    float lod_bias, max_level;      // max_level: the most detailed level used (D3D MAXMIPLEVEL)
} MtlSampler;
void mtlr_set_texture(int stage, int slot, MtlTex t, const MtlSampler *s);   // stage SM3_STAGE_*
typedef struct { uint8_t stream, offset, format, usage, index; } MtlVertexElement;   // format: MTLVertexFormat
uint32_t mtlr_vertex_layout(const MtlVertexElement *e, int n);   // interned id
void mtlr_set_shaders(uint32_t vs_hash, uint32_t ps_hash, uint32_t layout);
void mtlr_set_consts(int stage, int first, const float *v, int count);   // float4 registers
void mtlr_set_alpha_test(int func, int ref);                              // MTLCompareFunction (Always = off), 0..255
void mtlr_set_stream(int i, uint32_t guest_addr, uint32_t stride, uint32_t instance_rate);   // rate 0 = per vertex
void mtlr_set_indices(uint32_t guest_addr, int bytes_per_index);

// ---- work ----
// prim: MTLPrimitiveType (0 point, 1 line, 2 line strip, 3 triangle, 4 triangle strip); D3D fans must be converted
void mtlr_draw(int prim, uint32_t first_vertex, uint32_t vertex_count, uint32_t instances);
void mtlr_draw_indexed(int prim, uint32_t first_index, uint32_t index_count, int32_t base_vertex, uint32_t instances);
enum { MTLR_CLEAR_COLOR = 1, MTLR_CLEAR_DEPTH = 2, MTLR_CLEAR_STENCIL = 4 };
void mtlr_clear(int flags, const float color[4], float depth, uint8_t stencil);   // the current targets, scissored to the viewport
void mtlr_copy(MtlTex src, const int src_rect[4], MtlTex dst, const int dst_rect[4], int linear);   // rects x0,y0,x1,y1
void mtlr_wait_idle(void);
uint64_t mtlr_fence(void);        // submit the work so far; a fence completing when the GPU has done it
int mtlr_fence_done(uint64_t fence);           // the GPU has finished everything submitted

// ---- Metal enum values for C callers (checked against the Metal headers in mtl_render.m) ----
enum {   // MTLPixelFormat
    MTLR_PF_A8 = 1, MTLR_PF_R8 = 10, MTLR_PF_R16 = 20, MTLR_PF_R16F = 25, MTLR_PF_RG8 = 30, MTLR_PF_B5G6R5 = 40,
    MTLR_PF_A1BGR5 = 41, MTLR_PF_ABGR4 = 42, MTLR_PF_BGR5A1 = 43, MTLR_PF_R32F = 55, MTLR_PF_RG16 = 60, MTLR_PF_RG16F = 65,
    MTLR_PF_RGBA8 = 70, MTLR_PF_BGRA8 = 80, MTLR_PF_RGB10A2 = 90, MTLR_PF_RG32F = 105, MTLR_PF_RGBA16 = 110,
    MTLR_PF_RGBA16F = 115, MTLR_PF_RGBA32F = 125, MTLR_PF_BC1 = 130, MTLR_PF_BC2 = 132, MTLR_PF_BC3 = 134, MTLR_PF_BC4 = 140,
    MTLR_PF_BC5 = 142, MTLR_PF_D16 = 250, MTLR_PF_D32F = 252, MTLR_PF_D32F_S8 = 260,
};
enum {   // MTLVertexFormat
    MTLR_VF_UCHAR4 = 3, MTLR_VF_UCHAR4N = 9, MTLR_VF_USHORT2 = 13, MTLR_VF_USHORT4 = 15, MTLR_VF_SHORT2 = 16, MTLR_VF_SHORT4 = 18,
    MTLR_VF_USHORT2N = 19, MTLR_VF_USHORT4N = 21, MTLR_VF_SHORT2N = 22, MTLR_VF_SHORT4N = 24, MTLR_VF_HALF2 = 25, MTLR_VF_HALF4 = 27,
    MTLR_VF_FLOAT = 28, MTLR_VF_FLOAT2 = 29, MTLR_VF_FLOAT3 = 30, MTLR_VF_FLOAT4 = 31, MTLR_VF_INT1010102N = 40,
    MTLR_VF_UINT1010102N = 41, MTLR_VF_UCHAR4N_BGRA = 42,
};
// MTLBlendFactor 0 zero 1 one 2 src color 3 1-src color 4 src alpha 5 1-src alpha 6 dst color 7 1-dst color
//   8 dst alpha 9 1-dst alpha 10 src alpha saturated 11 blend color 12 1-blend color
// MTLBlendOperation 0 add 1 sub 2 rev sub 3 min 4 max; MTLCompareFunction 0 never .. 7 always (D3DCMP - 1)
// MTLStencilOperation 0 keep 1 zero 2 replace 3 incr clamp 4 decr clamp 5 invert 6 incr wrap 7 decr wrap (D3DSTENCILOP - 1)
// MTLCullMode 0 none 1 front 2 back; MTLTriangleFillMode 0 fill 1 lines
// MTLSamplerAddressMode 0 clamp 1 mirror clamp 2 repeat 3 mirror repeat 4 clamp to zero 5 border
// MTLSamplerMinMagFilter 0 nearest 1 linear; MTLSamplerMipFilter 0 none 1 nearest 2 linear
// MTLSamplerBorderColor 0 transparent black 1 opaque black 2 opaque white
void mtlr_debug_dump(const char *dir);  // RT_METAL_DUMP: write render targets as images
void mtlr_tex_download(MtlTex t, int face, int level, void *dst, uint32_t pitch);   // waits for the GPU
// cost since the last call: pipeline creation (ms, count) and the wait for a drawable (ms)
void mtlr_frame_stats(double *pso_ms, int *pso_n, double *drawable_ms);
// build the pipelines recorded by earlier runs (<data dir>/pipelines_v2.bin) in the background; after mtlr_load_shaders
void mtlr_prewarm(void);
// speculative pipelines: when the game loads a shader pair (+ its vertex layout), build it in the background against
// the target/blend setup of that rank by use so far (0: the most used); queue rank 0 for everything first, then rank 1..
// mtlr_speculate_config seeds a setup (weight: prior use count)
void mtlr_speculate(uint32_t vs, uint32_t ps, uint32_t layout, int rank);
void mtlr_speculate_config(const uint32_t color[4], uint32_t depth, int alpha_test, const MtlBlend blend[4], uint32_t weight);
int mtlr_speculated(void);   // background builds started so far
// look-ahead: between begin and end the state setters and draws only start the pipelines those draws will need
// (nothing is encoded; the state is restored at end); replay the frame once like that, then for real. end returns
// how many builds it started.
void mtlr_lookahead_begin(void);
int mtlr_lookahead_end(void);
double mtlr_gpu_ms(void);   // GPU time of the command buffers completed since the last call (ms)
// buffer hazards (D3D9 lock semantics): mtlr_seq_now is the command buffer the current draws go into; mtlr_wait_seq
// returns once the GPU finished it (a lock without DISCARD / NOOVERWRITE of a buffer the GPU may still read)
uint64_t mtlr_seq_now(void);
void mtlr_wait_seq(uint64_t seq);
// shaders as Metal source batches (mtlr_load_shaders given a folder of batch_*.metal): wait until all are compiled
void mtlr_wait_shaders(void);
int mtlr_init_shaders_only(void);   // the Metal device only: load and compile shaders without a game (returns 0 without Metal)
// threads without an autorelease pool (a game's own threads) that encode: drain it after each frame's work
void mtlr_drain_pool(void);
