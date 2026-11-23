// Binding model and per-shader table of the Metal shaders that tools/sm3msl generates from SM1-3 bytecode, shared by
// the converter and native Metal renderers. Buffer layouts follow dxbc-spirv's legacy built-ins (ir/ir.h, Legacy*Layout).
#pragma once
#include <stdint.h>

#define SM3_STAGE_VERTEX 0
#define SM3_STAGE_PIXEL 1
#define SM3_BUFFER_BASE 16        // Metal buffer index of constant buffer 0; vertex streams use buffer(0..15)
#define SM3_MAX_IO 16
#define SM3_FC_ALPHA_TEST 0        // pixel: function constant (bool) enabling the alpha test (false: no discard)
#define SM3_ATTR_SCALE_BUFFER 30  // vertex: float[16] scale per input attribute (integer formats bound normalized)

enum {                            // constant buffers: buffer(SM3_BUFFER_BASE + k)
    SM3_CBV_FLOAT,                // float4 c[256] (vertex) / c[224] (pixel)
    SM3_CBV_INT,                  // int4 i[16]
    SM3_CBV_BOOL,                 // uint b (bit per register)
    SM3_CBV_ALPHA_TEST,           // Sm3AlphaTest
    SM3_CBV_FOG,
    SM3_CBV_CLIP_PLANES,          // Sm3ClipPlanes
    SM3_CBV_POINT_ARGS,           // Sm3PointArgs
    SM3_CBV_SAMPLER_STATE,        // Sm3SamplerState[16]
    SM3_CBV_TEXTURE_STAGE,
    SM3_CBV_COUNT
};

typedef struct {
    uint32_t compare_op;          // MTLCompareFunction order (never 0 .. always 7): D3DCMP_* - 1; 7 disables the test
    uint32_t precision_bits;      // extra bits of alpha precision beyond 8 (0 for 8-bit targets)
    uint32_t alpha_ref;           // 0..255
} Sm3AlphaTest;
typedef struct { uint32_t count; float plane[6][4]; } Sm3ClipPlanes;
typedef struct { uint32_t is_point_sprite; float size, size_min, size_max; } Sm3PointArgs;
typedef struct {
    uint32_t texture_type;        // only read for dynamically typed samplers
    uint32_t use_dref;            // depth-compare (shadow map) sampling
    uint32_t use_proj;            // projected sampling (texldp / D3DTTFF_PROJECTED)
    uint32_t is_null;             // no texture bound: sampling returns (0,0,0,1)
    uint32_t use_gather;          // fetch4
    uint32_t dref_clamp;          // clamp the compare value to 0..1
    float dref_scale;
} Sm3SamplerState;

enum { SM3_TEX_NONE = 0, SM3_TEX_2D = 2, SM3_TEX_CUBE = 3, SM3_TEX_VOLUME = 4 };   // D3DSAMPLER_TEXTURE_TYPE >> 27

typedef struct { uint8_t reg, usage, index; } Sm3Io;   // usage: D3DDECLUSAGE_* (0 position .. 13 sample)
typedef struct {
    uint32_t hash;                // FNV-1a 32 of the bytecode, version token to end token inclusive
    uint8_t stage, major;
    const char *function;         // Metal function name
    uint32_t cbv_mask;            // constant buffers the shader reads (1 << SM3_CBV_*)
    uint8_t sampler_type[16];     // SM3_TEX_* per sampler register
    uint8_t ninputs; Sm3Io inputs[SM3_MAX_IO];    // vertex: attribute(reg) <- (usage, index)
    uint8_t noutputs; Sm3Io outputs[SM3_MAX_IO];
} Sm3ShaderInfo;

static inline uint32_t sm3_hash(const uint32_t *tokens, uint32_t ntokens) {
    uint32_t h = 2166136261u;
    const uint8_t *b = (const uint8_t *)tokens;
    for (uint32_t i = 0; i < ntokens * 4; i++) h = (h ^ b[i]) * 16777619u;
    return h;
}
// tokens up to and including the end token (0x0000FFFF); SM2+ (SM1 has no instruction lengths in its tokens)
static inline uint32_t sm3_length(const uint32_t *t) {
    uint32_t n = 1;
    while (n < (1u << 20) && t[n] != 0x0000FFFFu) n += 1 + ((t[n] & 0xFFFF) == 0xFFFE ? (t[n] >> 16) : ((t[n] >> 24) & 0xF));
    return n + 1;
}

// runtime conversion (tools/sm3msl built as a library, sm3msl.mk SM3MSL_RT): tokens up to the end token -> MSL (malloc'd,
// entry point info->function, malloc'd) and the table row; NULL on failure (err filled)
#ifdef __cplusplus
extern "C"
#endif
char *sm3msl_convert(const uint32_t *tokens, uint32_t ntokens, Sm3ShaderInfo *info, char *err, size_t errlen);
