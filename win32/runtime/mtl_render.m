// Native Metal renderer backend (mtl_render.h). One render thread drives state and draws; textures can be created
// and uploaded from any thread.
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include "rt32.h"
#include "mtl_render.h"

id<MTLDevice> rt_metal_device(void);
void *rt_window_layer(uint32_t hwnd);
void *rt_cocoa_create_window(uint32_t hwnd, const char *title, int w, int h);

#define FRAMES 2                       // frames in flight
#define RING (24u << 20)               // per-frame upload ring (constants)
#define NTEX 65536

static id<MTLDevice> dev;
static id<MTLCommandQueue> queue;
static id<MTLBuffer> guest;            // the whole guest window
static int active, shadow_on = -1;
static id<MTLLibrary> lib, builtin;
static const Sm3ShaderInfo *shaders; static int nshaders;
static NSMutableDictionary<NSString *, id<MTLFunction>> *functions;

// ---------------- init ----------------
static void wrap_guest(void *base, uint64_t size) {
    dev = rt_metal_device();
    if (!dev) return;
    guest = [dev newBufferWithBytesNoCopy:base length:size options:MTLResourceStorageModeShared | MTLResourceHazardTrackingModeUntracked deallocator:nil];
    if (!guest) { rt_log("[mtl] couldn't wrap the guest window as a Metal buffer"); return; }
    queue = [dev newCommandQueueWithMaxCommandBufferCount:16];
    active = 1;
    rt_log("[mtl] %s, guest window wrapped (%llu MiB max buffer)", dev.name.UTF8String, (unsigned long long)(dev.maxBufferLength >> 20));
}
void mtlr_init(void) { rt_guest_window_hook = wrap_guest; }
int mtlr_active(void) { return active; }
int mtlr_shadow(void) {
    if (shadow_on < 0) {
        const char *e = getenv("RT_METAL_SHADOW"); shadow_on = e && *e && *e != '0';
#ifdef RT_NO_D3D9_BRIDGE
        if (shadow_on) rt_log("[mtl] RT_METAL_SHADOW needs the d3d9 bridge (D3D9_BACKEND=dxvk): ignored");
        shadow_on = 0;
#endif
    }
    return shadow_on;
}

static const char *builtin_src =
    "#include <metal_stdlib>\nusing namespace metal;\n"
    "struct CV { float4 p [[position]]; };\n"
    "vertex CV clear_vs(uint v [[vertex_id]], constant float &z [[buffer(0)]]) {"
    "  float2 q = float2((v << 1) & 2, v & 2); CV o; o.p = float4(q * float2(2, -2) + float2(-1, 1), z, 1); return o; }\n"
    "struct CF { float4 c0 [[color(0)]]; float4 c1 [[color(1)]]; float4 c2 [[color(2)]]; float4 c3 [[color(3)]]; };\n"
    "fragment CF clear_ps(CV i [[stage_in]], constant float4 &c [[buffer(0)]]) { CF o; o.c0 = o.c1 = o.c2 = o.c3 = c; return o; }\n"
    "struct BV { float4 p [[position]]; float2 t; };\n"
    "vertex BV blit_vs(uint v [[vertex_id]], constant float4 &r [[buffer(0)]]) {"
    "  float2 q = float2((v << 1) & 2, v & 2); BV o; o.p = float4(q * float2(2, -2) + float2(-1, 1), 0, 1);"
    "  o.t = mix(r.xy, r.zw, q); return o; }\n"
    "fragment float4 red_ps() { return float4(1, 0, 0, 1); }\n"
    "fragment float4 gamma_ps(BV i [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]], constant float4 *lut [[buffer(0)]]) {"
    "  float4 c = t.sample(s, i.t); float3 x = saturate(c.rgb) * 255.0; float3 f = fract(x); uint3 k = uint3(x);"
    "  uint3 k1 = min(k + 1, uint3(255));"
    "  return float4(mix(lut[k.r].r, lut[k1.r].r, f.r), mix(lut[k.g].g, lut[k1.g].g, f.g), mix(lut[k.b].b, lut[k1.b].b, f.b), c.a); }\n"
    "fragment float4 blit_ps(BV i [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]]) { return t.sample(s, i.t); }\n";

void mtlr_load_shaders(const char *path, const Sm3ShaderInfo *table, int n) {
    if (!active) return;
    NSError *err = nil;
    lib = [dev newLibraryWithURL:[NSURL fileURLWithPath:@(path)] error:&err];
    if (!lib) rt_fatal("[mtl] can't load %s: %s", path, err.localizedDescription.UTF8String);
    builtin = [dev newLibraryWithSource:@(builtin_src) options:nil error:&err];
    if (!builtin) rt_fatal("[mtl] builtin shaders: %s", err.localizedDescription.UTF8String);
    Sm3ShaderInfo *t = malloc(sizeof *t * (size_t)n); memcpy(t, table, sizeof *t * (size_t)n);
    qsort_b(t, (size_t)n, sizeof *t, ^int(const void *a, const void *b) {
        uint32_t x = ((const Sm3ShaderInfo *)a)->hash, y = ((const Sm3ShaderInfo *)b)->hash; return x < y ? -1 : x > y; });
    shaders = t; nshaders = n;
    functions = [NSMutableDictionary new];
    rt_log("[mtl] %d shaders from %s", n, path);
}
// shaders converted while the game runs (not in the build's metallib): open-addressed by hash
#define NDYN 16384
static Sm3ShaderInfo *dyn; static uint32_t ndyn;
static pthread_mutex_t shader_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t shader_cv = PTHREAD_COND_INITIALIZER;   // a run-time compile finished
static NSMutableDictionary<NSString *, NSNumber *> *pending;   // run-time compiles in flight
static NSMutableDictionary<NSString *, id<MTLLibrary>> *dyn_libs;   // the library of each run-time compiled shader
static NSMutableDictionary<NSString *, id<MTLFunction>> *no_alpha;  // pixel functions specialized without alpha test
const Sm3ShaderInfo *mtlr_shader_info(uint32_t hash) {
    int lo = 0, hi = nshaders - 1;     // sorted by hash at load
    while (lo <= hi) { int m = (lo + hi) / 2; if (shaders[m].hash == hash) return &shaders[m]; if (shaders[m].hash < hash) lo = m + 1; else hi = m - 1; }
    if (!dyn) return NULL;
    for (uint32_t i = hash & (NDYN - 1), n = 0; n < NDYN; i = (i + 1) & (NDYN - 1), n++) {
        if (!dyn[i].function) return NULL;
        if (dyn[i].hash == hash) return &dyn[i];
    }
    return NULL;
}
static id<MTLFunction> function(const Sm3ShaderInfo *s) {
    NSString *k = @(s->function);
    pthread_mutex_lock(&shader_mu);
    id<MTLFunction> f = functions[k];
    if (!f) { f = [lib newFunctionWithName:k]; if (f) functions[k] = f; }
    while (!f && functions[k] == nil && pending[k]) { pthread_cond_wait(&shader_cv, &shader_mu); f = functions[k]; }   // compiling
    pthread_mutex_unlock(&shader_mu);
    if (!f) { static int n; if (n++ < 20) rt_log("[mtl] no function %s", s->function); }
    return f;
}
// a pixel function without its alpha test (function constant SM3_FC_ALPHA_TEST = false: no discard_fragment)
static id<MTLFunction> function_no_alpha(const Sm3ShaderInfo *s) {
    id<MTLFunction> base = function(s);
    if (!base || ![base.functionConstantsDictionary objectForKey:@"rn_alpha_test_fc"]) return base;   // not guarded: as is
    NSString *k = @(s->function);
    pthread_mutex_lock(&shader_mu);
    if (!no_alpha) no_alpha = [NSMutableDictionary new];
    id<MTLFunction> f = no_alpha[k];
    id<MTLLibrary> l = dyn_libs[k] ?: lib;
    pthread_mutex_unlock(&shader_mu);
    if (f) return f;
    MTLFunctionConstantValues *cv = [MTLFunctionConstantValues new];
    bool off = false;
    [cv setConstantValue:&off type:MTLDataTypeBool atIndex:SM3_FC_ALPHA_TEST];
    NSError *e = nil;
    f = [l newFunctionWithName:k constantValues:cv error:&e];
    if (!f) { rt_log("[mtl] %s without alpha test: %s", s->function, e.localizedDescription.UTF8String); return base; }
    pthread_mutex_lock(&shader_mu); no_alpha[k] = f; pthread_mutex_unlock(&shader_mu);
    return f;
}
// a shader the build didn't convert: SM3 -> MSL (sm3msl), compiled in the background, kept in <data dir>/shader_cache;
// its bytecode also goes to <data dir>/shaders, so the next `make shaders` builds it into the metallib
uint32_t mtlr_shader_add(const uint32_t *tokens, uint32_t ntokens) {
    uint32_t hash = sm3_hash(tokens, ntokens);
    if (!active || mtlr_shader_info(hash)) return hash;
    char dir[1100], path[1200];
    snprintf(dir, sizeof dir, "%s/shader_cache_v2", rt_data_dir); mkdir(dir, 0755);
    int vs = (tokens[0] >> 16) == 0xFFFE;
    snprintf(path, sizeof path, "%s/%s_%08x", dir, vs ? "vs" : "ps", hash);
    Sm3ShaderInfo info; char *msl = NULL;
    NSString *mp = [NSString stringWithFormat:@"%s.metal", path], *ip = [NSString stringWithFormat:@"%s.info", path];
    NSData *id_ = [NSData dataWithContentsOfFile:ip];
    NSString *cached = id_.length == sizeof info ? [NSString stringWithContentsOfFile:mp encoding:NSUTF8StringEncoding error:nil] : nil;
    char name[32]; snprintf(name, sizeof name, "%s_%08x", vs ? "vs" : "ps", hash);
    {   // the bytecode, for the next `make shaders`
        char bp[1200]; snprintf(bp, sizeof bp, "%s/shaders", rt_data_dir); mkdir(bp, 0755);
        snprintf(bp, sizeof bp, "%s/shaders/%s.bin", rt_data_dir, name);
        if (access(bp, R_OK)) [[NSData dataWithBytes:tokens length:ntokens * 4] writeToFile:@(bp) atomically:YES];
    }
    if (cached) { memcpy(&info, id_.bytes, sizeof info); info.function = strdup(name); msl = strdup(cached.UTF8String); }
    else {
        char err[256] = "";
        msl = sm3msl_convert(tokens, ntokens, &info, err, sizeof err);
        if (!msl) { rt_log("[mtl] shader %s: conversion failed: %s", name, err); return hash; }
        [@(msl) writeToFile:mp atomically:YES encoding:NSUTF8StringEncoding error:nil];
        Sm3ShaderInfo disk = info; disk.function = NULL;
        [[NSData dataWithBytes:&disk length:sizeof disk] writeToFile:ip atomically:YES];
    }
    NSString *nm = @(name), *src = @(msl);
    free(msl);
    pthread_mutex_lock(&shader_mu);
    if (!dyn) dyn = calloc(NDYN, sizeof *dyn);
    if (!pending) pending = [NSMutableDictionary new];
    int added = 0;
    if (ndyn < NDYN / 2) {
        uint32_t i = hash & (NDYN - 1);
        while (dyn[i].function && dyn[i].hash != hash) i = (i + 1) & (NDYN - 1);
        if (!dyn[i].function) { pending[nm] = @1; dyn[i] = info; dyn[i].function = strdup(name); ndyn++; added = 1; }
    }
    pthread_mutex_unlock(&shader_mu);
    if (added)
        [dev newLibraryWithSource:src options:[MTLCompileOptions new] completionHandler:^(id<MTLLibrary> l, NSError *e) {
            id<MTLFunction> f = [l newFunctionWithName:nm];
            if (!f) rt_log("[mtl] shader %s: Metal compile failed: %s", nm.UTF8String, e.localizedDescription.UTF8String);
            pthread_mutex_lock(&shader_mu);
            if (f) { functions[nm] = f; if (!dyn_libs) dyn_libs = [NSMutableDictionary new]; dyn_libs[nm] = l; }
            [pending removeObjectForKey:nm];
            pthread_cond_broadcast(&shader_cv);
            pthread_mutex_unlock(&shader_mu);
        }];
    static int logged; if (logged++ < 3 || logged % 100 == 0) rt_log("[mtl] %u shaders converted at run time (%s)", ndyn, cached ? "cached" : "new");
    return hash;
}

// ---------------- textures ----------------
typedef struct {
    id<MTLTexture> tex, sample, srgb, target_srgb;   // sample: swizzled view; srgb: sRGB sampling view
    MtlTexDesc d;
    int is_depth;
} Tex;
static Tex *texs; static uint32_t ntex = 1;      // handles are not reused
static pthread_mutex_t tex_mu = PTHREAD_MUTEX_INITIALIZER;

static int is_depth_format(MTLPixelFormat f) {
    return f == MTLPixelFormatDepth32Float || f == MTLPixelFormatDepth16Unorm || f == MTLPixelFormatDepth32Float_Stencil8 || f == MTLPixelFormatStencil8;
}
static MTLPixelFormat srgb_of(MTLPixelFormat f) {
    switch (f) {
    case MTLPixelFormatBGRA8Unorm: return MTLPixelFormatBGRA8Unorm_sRGB;
    case MTLPixelFormatRGBA8Unorm: return MTLPixelFormatRGBA8Unorm_sRGB;
    case MTLPixelFormatBC1_RGBA: return MTLPixelFormatBC1_RGBA_sRGB;
    case MTLPixelFormatBC2_RGBA: return MTLPixelFormatBC2_RGBA_sRGB;
    case MTLPixelFormatBC3_RGBA: return MTLPixelFormatBC3_RGBA_sRGB;
    default: return f;
    }
}
static Tex *tget(MtlTex h) { return h && h < ntex ? &texs[h] : NULL; }

MtlTex mtlr_tex_create(const MtlTexDesc *d) {
    if (!active) return 0;
    MTLTextureDescriptor *td = [MTLTextureDescriptor new];
    td.textureType = d->type == MTLR_TEX_CUBE ? MTLTextureTypeCube : d->type == MTLR_TEX_3D ? MTLTextureType3D :
                     d->samples > 1 ? MTLTextureType2DMultisample : MTLTextureType2D;
    td.pixelFormat = (MTLPixelFormat)d->format;
    td.width = d->width; td.height = d->height; td.depth = d->type == MTLR_TEX_3D ? d->depth : 1;
    td.mipmapLevelCount = d->levels ? d->levels : 1;
    td.sampleCount = d->samples > 1 ? d->samples : 1;
    td.usage = MTLTextureUsageShaderRead | MTLTextureUsagePixelFormatView | ((d->usage & MTLR_USE_TARGET) ? MTLTextureUsageRenderTarget : 0);
    td.storageMode = (d->usage & MTLR_USE_TARGET) || d->samples > 1 ? MTLStorageModePrivate : MTLStorageModeShared;
    id<MTLTexture> t = [dev newTextureWithDescriptor:td];
    if (!t) { rt_log("[mtl] texture %ux%u format %u failed", d->width, d->height, d->format); return 0; }
    pthread_mutex_lock(&tex_mu);
    if (!texs) texs = calloc(NTEX, sizeof *texs);
    uint32_t h = ntex++;
    if (h >= NTEX) rt_fatal("[mtl] too many textures");
    Tex *x = &texs[h];
    x->tex = t; x->d = *d; x->is_depth = is_depth_format(td.pixelFormat);
    static const MTLTextureSwizzle S[][4] = {
        {MTLTextureSwizzleRed, MTLTextureSwizzleGreen, MTLTextureSwizzleBlue, MTLTextureSwizzleAlpha},
        {MTLTextureSwizzleRed, MTLTextureSwizzleGreen, MTLTextureSwizzleBlue, MTLTextureSwizzleOne},
        {MTLTextureSwizzleRed, MTLTextureSwizzleRed, MTLTextureSwizzleRed, MTLTextureSwizzleOne},
        {MTLTextureSwizzleRed, MTLTextureSwizzleRed, MTLTextureSwizzleRed, MTLTextureSwizzleGreen},
        {MTLTextureSwizzleZero, MTLTextureSwizzleZero, MTLTextureSwizzleZero, MTLTextureSwizzleRed},
    };
    if (d->swizzle && d->swizzle < 5) {
        const MTLTextureSwizzle *s = S[d->swizzle];
        x->sample = [t newTextureViewWithPixelFormat:td.pixelFormat textureType:td.textureType levels:NSMakeRange(0, td.mipmapLevelCount)
                                              slices:NSMakeRange(0, d->type == MTLR_TEX_CUBE ? 6 : 1) swizzle:MTLTextureSwizzleChannelsMake(s[0], s[1], s[2], s[3])];
    } else x->sample = t;
    pthread_mutex_unlock(&tex_mu);
    return h;
}
void mtlr_tex_destroy(MtlTex h) {
    pthread_mutex_lock(&tex_mu);
    Tex *x = tget(h);
    if (x) { x->tex = nil; x->sample = nil; x->srgb = nil; x->target_srgb = nil; }
    pthread_mutex_unlock(&tex_mu);
}
const MtlTexDesc *mtlr_tex_desc(MtlTex h) { Tex *x = tget(h); return x ? &x->d : NULL; }

static int block_bytes(MTLPixelFormat f, int *bw) {
    *bw = 1;
    switch (f) {
    case MTLPixelFormatBC1_RGBA: case MTLPixelFormatBC1_RGBA_sRGB: case MTLPixelFormatBC4_RUnorm: *bw = 4; return 8;
    case MTLPixelFormatBC2_RGBA: case MTLPixelFormatBC3_RGBA: case MTLPixelFormatBC2_RGBA_sRGB: case MTLPixelFormatBC3_RGBA_sRGB:
    case MTLPixelFormatBC5_RGUnorm: *bw = 4; return 16;
    case MTLPixelFormatR8Unorm: case MTLPixelFormatA8Unorm: case MTLPixelFormatStencil8: return 1;
    case MTLPixelFormatRG8Unorm: case MTLPixelFormatR16Unorm: case MTLPixelFormatR16Float: case MTLPixelFormatB5G6R5Unorm:
    case MTLPixelFormatA1BGR5Unorm: case MTLPixelFormatBGR5A1Unorm: case MTLPixelFormatABGR4Unorm: case MTLPixelFormatDepth16Unorm: return 2;
    case MTLPixelFormatRGBA16Float: case MTLPixelFormatRGBA16Unorm: case MTLPixelFormatRG32Float: return 8;
    case MTLPixelFormatRGBA32Float: return 16;
    case MTLPixelFormatDepth32Float_Stencil8: return 8;
    default: return 4;
    }
}
uint32_t mtlr_tex_level_size(MtlTex h, int level, uint32_t *pitch, uint32_t *rows) {
    Tex *x = tget(h); if (!x) return 0;
    int bw; int bb = block_bytes((MTLPixelFormat)x->d.format, &bw);
    uint32_t w = x->d.width >> level, hh = x->d.height >> level, dd = x->d.type == MTLR_TEX_3D ? x->d.depth >> level : 1;
    if (!w) w = 1; if (!hh) hh = 1; if (!dd) dd = 1;
    uint32_t bx = (w + bw - 1) / bw, by = (hh + bw - 1) / bw;
    if (pitch) *pitch = bx * bb;
    if (rows) *rows = by;
    return bx * bb * by * dd;
}
// uploads are copied to a staging buffer now and become blits in the render command stream at the next pass
// (flush_uploads): the GPU applies them after the earlier work that reads the texture, as D3D orders an unlock,
// instead of writing a texture an in-flight frame may be sampling
typedef struct { __unsafe_unretained id<MTLTexture> tex; void *buf; int face, level; MTLRegion r; uint32_t pitch, slice; } Upload;
static NSMutableArray *up_tex, *up_buf;   // keep the textures and staging buffers alive until encoded
static Upload *ups; static int nups, cups;
static pthread_mutex_t up_mu = PTHREAD_MUTEX_INITIALIZER;
static void queue_upload(Tex *x, int face, int level, MTLRegion r, const void *data, uint32_t pitch, uint32_t slice, NSUInteger bytes) {
    id<MTLBuffer> b = [dev newBufferWithBytes:data length:bytes options:MTLResourceStorageModeShared];
    pthread_mutex_lock(&up_mu);
    if (!up_tex) { up_tex = [NSMutableArray new]; up_buf = [NSMutableArray new]; }
    if (nups == cups) { cups = cups ? cups * 2 : 256; ups = realloc(ups, sizeof *ups * (size_t)cups); }
    [up_tex addObject:x->tex]; [up_buf addObject:b];
    ups[nups++] = (Upload){x->tex, (__bridge void *)b, face, level, r, pitch, slice};
    pthread_mutex_unlock(&up_mu);
}
static void flush_uploads(id<MTLCommandBuffer> cb) {
    if (!__atomic_load_n(&nups, __ATOMIC_ACQUIRE)) return;
    pthread_mutex_lock(&up_mu);
    if (nups) {
        id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
        for (int i = 0; i < nups; i++) {
            Upload *u = &ups[i];
            [e copyFromBuffer:(__bridge id<MTLBuffer>)u->buf sourceOffset:0 sourceBytesPerRow:u->pitch sourceBytesPerImage:u->slice
                   sourceSize:u->r.size toTexture:u->tex destinationSlice:u->face destinationLevel:u->level destinationOrigin:u->r.origin];
        }
        [e endEncoding];
        NSArray *keep_t = up_tex, *keep_b = up_buf;
        [cb addCompletedHandler:^(id<MTLCommandBuffer> c) { (void)keep_t; (void)keep_b; }];
        up_tex = [NSMutableArray new]; up_buf = [NSMutableArray new];
        nups = 0;
    }
    pthread_mutex_unlock(&up_mu);
}
void mtlr_tex_upload(MtlTex h, int face, int level, const void *data, uint32_t pitch, uint32_t slice) {
    Tex *x = tget(h); if (!x || !x->tex) return;
    uint32_t w = x->d.width >> level, hh = x->d.height >> level, dd = x->d.type == MTLR_TEX_3D ? x->d.depth >> level : 1;
    if (!w) w = 1; if (!hh) hh = 1; if (!dd) dd = 1;
    uint32_t rows; mtlr_tex_level_size(h, level, NULL, &rows);
    uint32_t img = x->d.type == MTLR_TEX_3D ? slice : pitch * rows;
    queue_upload(x, x->d.type == MTLR_TEX_3D ? 0 : face, level, MTLRegionMake3D(0, 0, 0, w, hh, dd), data, pitch, img, (NSUInteger)img * dd);
}
// a sub-rectangle of a level (x, y, w, h in texels; block aligned for compressed formats); data at its first row
void mtlr_tex_upload_rect(MtlTex h, int face, int level, int x, int y, int w, int hh, const void *data, uint32_t pitch) {
    Tex *t = tget(h); if (!t || !t->tex || w <= 0 || hh <= 0) return;
    int lw = (int)(t->d.width >> level), lh = (int)(t->d.height >> level); if (lw < 1) lw = 1; if (lh < 1) lh = 1;
    if (x + w > lw) w = lw - x; if (y + hh > lh) hh = lh - y;
    if (w <= 0 || hh <= 0) return;
    int bw; block_bytes(t->tex.pixelFormat, &bw);
    NSUInteger rows = (NSUInteger)(hh + bw - 1) / (NSUInteger)bw;
    queue_upload(t, face, level, MTLRegionMake2D(x, y, w, hh), data, pitch, (uint32_t)(pitch * rows), pitch * rows);
}
int mtlr_tex_texel_bytes(MtlTex h, int *block) { Tex *t = tget(h); if (!t) { *block = 1; return 4; } return block_bytes(t->tex.pixelFormat, block); }
static id<MTLTexture> sample_view(Tex *x, int srgb) {
    if (srgb && srgb_of(x->tex.pixelFormat) != x->tex.pixelFormat) {
        if (!x->srgb) x->srgb = [x->sample newTextureViewWithPixelFormat:srgb_of(x->tex.pixelFormat)];
        return x->srgb;
    }
    return x->sample;
}

// ---------------- frames ----------------
static int dbg[8];   // draws prepared, no encoder, no pipeline, passes, clears (load), clears (quad), presents
static uint32_t win_hwnd; static CAMetalLayer *layer;
static MtlTex backbuf;
static id<MTLCommandBuffer> cmd;
static id<MTLRenderCommandEncoder> enc;
static dispatch_semaphore_t inflight;
static id<MTLBuffer> rings[FRAMES]; static uint32_t ring_frame, ring_pos;
static id<MTLCommandBuffer> last_committed;

void mtlr_set_window(uint32_t hwnd, int w, int h) {
    if (!active) return;
    if (!inflight) inflight = dispatch_semaphore_create(FRAMES);
    if (mtlr_shadow()) {
        if (!layer) layer = (__bridge_transfer CAMetalLayer *)rt_cocoa_create_window(0xFFFF0001u, "Metal (shadow)", w, h);
    } else {
        win_hwnd = hwnd;
        layer = (__bridge CAMetalLayer *)rt_window_layer(hwnd);
    }
    rt_log("[mtl] output %dx%d on window %08x: layer %p%s", w, h, hwnd, (__bridge void *)layer, mtlr_shadow() ? " (shadow)" : "");
    if (!layer) rt_log("[mtl] no Metal layer for window %08x: nothing will be shown", hwnd);
    layer.device = dev; layer.pixelFormat = MTLPixelFormatBGRA8Unorm; layer.framebufferOnly = NO;
    layer.drawableSize = CGSizeMake(w, h);
    MtlTexDesc d = {MTLR_TEX_2D, 1, 1, MTLR_USE_TARGET | MTLR_USE_SAMPLE, 0, MTLPixelFormatBGRA8Unorm, (uint32_t)w, (uint32_t)h, 1};
    if (backbuf) mtlr_tex_destroy(backbuf);
    backbuf = mtlr_tex_create(&d);
    for (int i = 0; i < FRAMES; i++) if (!rings[i]) rings[i] = [dev newBufferWithLength:RING options:MTLResourceStorageModeShared | MTLResourceCPUCacheModeWriteCombined];
}
MtlTex mtlr_backbuffer(void) { return backbuf; }

static void end_encoder(void) { if (enc) { [enc endEncoding]; enc = nil; } }
static void ensure_cmd(void) {
    if (cmd) return;
    dispatch_semaphore_wait(inflight, DISPATCH_TIME_FOREVER);
    cmd = [queue commandBuffer];
    flush_uploads(cmd);
    dispatch_semaphore_t s = inflight;
    [cmd addCompletedHandler:^(id<MTLCommandBuffer> b) { dispatch_semaphore_signal(s); }];
    ring_frame = (ring_frame + 1) % FRAMES; ring_pos = 0;
}
static uint32_t ring_put(const void *p, uint32_t n) {
    ring_pos = (ring_pos + 255) & ~255u;
    if (ring_pos + n > RING) rt_fatal("[mtl] upload ring overflow");
    memcpy((uint8_t *)rings[ring_frame].contents + ring_pos, p, n);
    uint32_t o = ring_pos; ring_pos += n; return o;
}

static id<MTLRenderPipelineState> blit_pso;
static id<MTLSamplerState> blit_linear, blit_point;
static void blit_to(id<MTLTexture> dst, id<MTLTexture> src, const float rect[4], int linear, MTLLoadAction load);

// gamma ramp (D3D9 SetGammaRamp: the game's brightness setting): applied when the frame goes to the window
static float gamma_lut[256][4]; static int gamma_on;
static id<MTLRenderPipelineState> gamma_pso;
void mtlr_set_gamma(const uint16_t ramp[768]) {
    int identity = 1;
    for (int i = 0; i < 256; i++) {
        for (int ch = 0; ch < 3; ch++) {
            gamma_lut[i][ch] = ramp[ch * 256 + i] / 65535.0f;
            if (abs((int)ramp[ch * 256 + i] - i * 257) > 256) identity = 0;
        }
        gamma_lut[i][3] = 1;
    }
    gamma_on = !identity;
}
static void gamma_to(id<MTLTexture> dst, id<MTLTexture> src) {
    if (!gamma_pso) {
        MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
        d.vertexFunction = [builtin newFunctionWithName:@"blit_vs"]; d.fragmentFunction = [builtin newFunctionWithName:@"gamma_ps"];
        d.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        gamma_pso = [dev newRenderPipelineStateWithDescriptor:d error:nil];
    }
    float r[4] = {0, 0, 1, 1};
    static id<MTLSamplerState> lin;
    if (!lin) { MTLSamplerDescriptor *sd = [MTLSamplerDescriptor new]; sd.minFilter = sd.magFilter = MTLSamplerMinMagFilterLinear; lin = [dev newSamplerStateWithDescriptor:sd]; }
    MTLRenderPassDescriptor *p = [MTLRenderPassDescriptor renderPassDescriptor];
    p.colorAttachments[0].texture = dst; p.colorAttachments[0].loadAction = MTLLoadActionDontCare; p.colorAttachments[0].storeAction = MTLStoreActionStore;
    id<MTLRenderCommandEncoder> e = [cmd renderCommandEncoderWithDescriptor:p];
    [e setRenderPipelineState:gamma_pso];
    [e setVertexBytes:r length:16 atIndex:0];
    [e setFragmentTexture:src atIndex:0]; [e setFragmentSamplerState:lin atIndex:0];
    [e setFragmentBytes:gamma_lut length:sizeof gamma_lut atIndex:0];
    [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    [e endEncoding];
}
static void commit_cmd(void);
void mtlr_present(int interval) {
    if (!active || !backbuf) return;
    ensure_cmd();
    end_encoder();
    flush_uploads(cmd);
    {   // the drawable stays the game's resolution (window resizes and fullscreen scale it in the compositor)
        Tex *bt = tget(backbuf);
        CGSize want = CGSizeMake(bt->d.width, bt->d.height);
        if (!CGSizeEqualToSize(layer.drawableSize, want)) layer.drawableSize = want;
    }
    {   // sync interval 0 (D3DPRESENT_INTERVAL_IMMEDIATE / vsync off): present as soon as rendered
        BOOL sync = interval != 0;
        if (layer.displaySyncEnabled != sync) layer.displaySyncEnabled = sync;
    }
    id<CAMetalDrawable> dr = [layer nextDrawable];
    if (!dr) { static int n; if (n++ < 5) rt_log("[mtl] present: no drawable (layer %p)", (__bridge void *)layer); }
    if (dr) {
        Tex *b = tget(backbuf);
        if (gamma_on) gamma_to(dr.texture, b->tex);
        else if (dr.texture.width == b->tex.width && dr.texture.height == b->tex.height) {
            id<MTLBlitCommandEncoder> e = [cmd blitCommandEncoder];
            [e copyFromTexture:b->tex toTexture:dr.texture]; [e endEncoding];
        } else {
            float r[4] = {0, 0, 1, 1}; blit_to(dr.texture, b->tex, r, 1, MTLLoadActionDontCare);
        }
        [cmd presentDrawable:dr];
    }
    commit_cmd();
    if (++dbg[6] % 120 == 0) rt_log("[mtl] last 120 frames: draws %d, no encoder %d, no pipeline %d, passes %d, clears %d+%d",
                                     dbg[0], dbg[1], dbg[2], dbg[3], dbg[4], dbg[5]);
    if (dbg[6] % 120 == 0) memset(dbg, 0, sizeof dbg);
}
// fences: a GPU sync point the CPU can poll (D3D event queries). Command buffers are numbered as committed.
static uint64_t committed_seq, completed_seq;
static void commit_cmd(void) {
    if (!cmd) return;
    end_encoder();
    uint64_t seq = ++committed_seq;
    [cmd addCompletedHandler:^(id<MTLCommandBuffer> b) {
        uint64_t c = __atomic_load_n(&completed_seq, __ATOMIC_ACQUIRE);
        while (c < seq && !__atomic_compare_exchange_n(&completed_seq, &c, seq, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {}
    }];
    [cmd commit];
    last_committed = cmd; cmd = nil;
}
uint64_t mtlr_fence(void) { if (!active) return 0; commit_cmd(); return committed_seq; }
int mtlr_fence_done(uint64_t f) { return __atomic_load_n(&completed_seq, __ATOMIC_ACQUIRE) >= f; }
void mtlr_wait_idle(void) {
    commit_cmd();
    if (last_committed) [last_committed waitUntilCompleted];
}

// ---------------- state ----------------
typedef struct { uint32_t addr, stride, rate; } Stream;
static struct {
    MtlTarget color[4], depth;
    int targets_dirty;
    MTLViewport vp; MTLScissorRect sc; int vp_dirty, sc_dirty;
    MtlBlend blend[4]; float blend_factor[4];
    MtlDepthStencil ds; MtlRaster rs;
    MtlTex tex[2][16]; MtlSampler samp[2][16];
    uint32_t vs, ps, layout;
    float consts[2][256 * 4]; int consts_dirty[2];
    int alpha_func, alpha_ref;
    Stream streams[16];
    uint32_t index_addr; int index_bytes;
} st;

void mtlr_set_targets(const MtlTarget color[4], MtlTarget depth) {
    if (memcmp(st.color, color, sizeof st.color) || memcmp(&st.depth, &depth, sizeof depth)) {
        memcpy(st.color, color, sizeof st.color); st.depth = depth; st.targets_dirty = 1;
    }
}
void mtlr_set_viewport(float x, float y, float w, float h, float zmin, float zmax) {
    // D3D9 puts pixel centers on integer coordinates: shift by half a pixel
    st.vp = (MTLViewport){x + 0.5, y + 0.5, w, h, zmin, zmax}; st.vp_dirty = 1;
}
void mtlr_set_scissor(int x, int y, int w, int h) { st.sc = (MTLScissorRect){(NSUInteger)x, (NSUInteger)y, (NSUInteger)w, (NSUInteger)h}; st.sc_dirty = 1; }
void mtlr_set_blend(const MtlBlend rt[4], const float f[4]) { memcpy(st.blend, rt, sizeof st.blend); memcpy(st.blend_factor, f, sizeof st.blend_factor); }
void mtlr_set_depth_stencil(const MtlDepthStencil *d) { st.ds = *d; }
void mtlr_set_raster(const MtlRaster *r) { st.rs = *r; }
void mtlr_set_texture(int stage, int slot, MtlTex t, const MtlSampler *s) { st.tex[stage][slot] = t; if (s) st.samp[stage][slot] = *s; }
void mtlr_set_consts(int stage, int first, const float *v, int count) {
    if (first < 0 || first + count > 256) return;
    memcpy(&st.consts[stage][first * 4], v, (size_t)count * 16); st.consts_dirty[stage] = 1;
}
void mtlr_set_alpha_test(int func, int ref) { st.alpha_func = func; st.alpha_ref = ref; }
void mtlr_set_stream(int i, uint32_t a, uint32_t stride, uint32_t rate) { st.streams[i] = (Stream){a, stride, rate}; }
void mtlr_set_indices(uint32_t a, int bytes) { st.index_addr = a; st.index_bytes = bytes; }
void mtlr_set_shaders(uint32_t vs, uint32_t ps, uint32_t layout) { st.vs = vs; st.ps = ps; st.layout = layout; }

// vertex layouts
#define NLAYOUT 1024
static struct { int n; MtlVertexElement e[32]; } layouts[NLAYOUT]; static int nlayouts = 1;
uint32_t mtlr_vertex_layout(const MtlVertexElement *e, int n) {
    if (n > 32) n = 32;
    for (int i = 1; i < nlayouts; i++) if (layouts[i].n == n && !memcmp(layouts[i].e, e, sizeof *e * (size_t)n)) return (uint32_t)i;
    if (nlayouts >= NLAYOUT) rt_fatal("[mtl] too many vertex layouts");
    layouts[nlayouts].n = n; memcpy(layouts[nlayouts].e, e, sizeof *e * (size_t)n);
    return (uint32_t)nlayouts++;
}

// ---------------- caches ----------------
typedef struct { uint64_t h; const void *key; uint32_t klen; void *val; } Ent;
typedef struct { Ent *e; uint32_t cap, n; } Map;
static uint64_t fnv(const void *p, size_t n) { const uint8_t *b = p; uint64_t h = 1469598103934665603ull; for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 1099511628211ull; return h; }
static void *map_get(Map *m, const void *k, uint32_t n, uint64_t h) {
    if (!m->cap) return NULL;
    for (uint32_t i = (uint32_t)h & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
        Ent *e = &m->e[i];
        if (!e->key) return NULL;
        if (e->h == h && e->klen == n && !memcmp(e->key, k, n)) return e->val;
    }
}
static void map_put(Map *m, const void *k, uint32_t n, uint64_t h, void *v) {
    if ((m->n + 1) * 2 > m->cap) {
        Map o = *m; m->cap = o.cap ? o.cap * 2 : 256; m->e = calloc(m->cap, sizeof *m->e); m->n = 0;
        for (uint32_t i = 0; i < o.cap; i++) if (o.e[i].key) map_put(m, o.e[i].key, o.e[i].klen, o.e[i].h, o.e[i].val);
        free(o.e);
    }
    uint32_t i = (uint32_t)h & (m->cap - 1);
    while (m->e[i].key) i = (i + 1) & (m->cap - 1);
    void *kc = malloc(n); memcpy(kc, k, n);
    m->e[i] = (Ent){h, kc, n, v}; m->n++;
}
static Map pso_map, dss_map, samp_map;

typedef struct {
    uint32_t vs, ps, layout;
    uint32_t color[4], depth; uint8_t samples, srgb_mask, alpha_test, pad;
    MtlBlend blend[4];
    uint32_t strides[16]; uint8_t rates[16];
} PsoKey;

static MTLVertexFormat zero_attr_format(void) { return MTLVertexFormatFloat4; }
// integer vertex formats are bound normalized and scaled back in the shader (sm3msl: rn_attr_scale)
static MTLVertexFormat bound_format(uint8_t f, float *scale) {
    *scale = 1;
    switch (f) {
    case MTLVertexFormatUChar4: *scale = 255; return MTLVertexFormatUChar4Normalized;
    case MTLVertexFormatShort2: *scale = 32767; return MTLVertexFormatShort2Normalized;
    case MTLVertexFormatShort4: *scale = 32767; return MTLVertexFormatShort4Normalized;
    case MTLVertexFormatUShort2: *scale = 65535; return MTLVertexFormatUShort2Normalized;
    case MTLVertexFormatUShort4: *scale = 65535; return MTLVertexFormatUShort4Normalized;
    }
    return (MTLVertexFormat)f;
}
static id<MTLBuffer> zero_buf;

static id<MTLRenderPipelineState> pipeline(const PsoKey *k) {
    uint64_t h = fnv(k, sizeof *k);
    id<MTLRenderPipelineState> p = (__bridge id<MTLRenderPipelineState>)map_get(&pso_map, k, sizeof *k, h);
    if (p) return p;
    const Sm3ShaderInfo *vs = mtlr_shader_info(k->vs), *ps = mtlr_shader_info(k->ps);
    if (!vs || !ps) return nil;
    MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
    d.vertexFunction = function(vs); d.fragmentFunction = k->alpha_test ? function(ps) : function_no_alpha(ps);
    if (!d.vertexFunction || !d.fragmentFunction) return nil;
    {   // debug: RT_METAL_RED=1 (all) or =<vertex shader hash>[,...]: solid red pixel shader (shading vs geometry)
        const char *e = getenv("RT_METAL_RED");
        if (e && (!strcmp(e, "1") || strstr(e, vs->function + 3))) d.fragmentFunction = [builtin newFunctionWithName:@"red_ps"];
    }
    MTLVertexDescriptor *vd = [MTLVertexDescriptor new];
    int used_streams = 0, need_zero = 0;
    for (int i = 0; i < vs->ninputs; i++) {
        const Sm3Io *in = &vs->inputs[i];
        const MtlVertexElement *el = NULL;
        for (int j = 0; j < layouts[k->layout].n; j++) {
            const MtlVertexElement *e = &layouts[k->layout].e[j];
            if (e->usage == in->usage && e->index == in->index) { el = e; break; }
        }
        MTLVertexAttributeDescriptor *a = vd.attributes[in->reg];
        if (el && k->strides[el->stream]) {
            float sc; a.format = bound_format(el->format, &sc); a.offset = el->offset; a.bufferIndex = el->stream;
            used_streams |= 1 << el->stream;
        } else {
            a.format = zero_attr_format(); a.offset = 0; a.bufferIndex = 15; need_zero = 1;
            static int nlog; if (nlog < 40) { nlog++;
                char els[512] = ""; size_t o = 0;
                for (int j = 0; j < layouts[k->layout].n && o < 480; j++) { const MtlVertexElement *e = &layouts[k->layout].e[j];
                    o += (size_t)snprintf(els + o, sizeof els - o, " s%u+%u:%u.%u%s", e->stream, e->offset, e->usage, e->index, k->strides[e->stream] ? "" : "(no stream)"); }
                rt_log("[mtl] %s input v%u (usage %u.%u) has no vertex element; layout %u:%s", vs->function, in->reg, in->usage, in->index, k->layout, els); }
        }
    }
    for (int s = 0; s < 15; s++) if (used_streams & (1 << s)) {
        vd.layouts[s].stride = k->strides[s];
        vd.layouts[s].stepFunction = k->rates[s] ? MTLVertexStepFunctionPerInstance : MTLVertexStepFunctionPerVertex;
        vd.layouts[s].stepRate = k->rates[s] ? k->rates[s] : 1;
    }
    if (need_zero) { vd.layouts[15].stride = 16; vd.layouts[15].stepFunction = MTLVertexStepFunctionConstant; vd.layouts[15].stepRate = 0; }
    d.vertexDescriptor = vd;
    for (int i = 0; i < 4; i++) {
        MTLRenderPipelineColorAttachmentDescriptor *c = d.colorAttachments[i];
        c.pixelFormat = (MTLPixelFormat)k->color[i];
        if (!k->color[i]) continue;
        const MtlBlend *b = &k->blend[i];
        c.blendingEnabled = b->enable;
        c.sourceRGBBlendFactor = b->src; c.destinationRGBBlendFactor = b->dst; c.rgbBlendOperation = b->op;
        c.sourceAlphaBlendFactor = b->src_a; c.destinationAlphaBlendFactor = b->dst_a; c.alphaBlendOperation = b->op_a;
        c.writeMask = b->mask;
    }
    d.depthAttachmentPixelFormat = (MTLPixelFormat)k->depth;
    if (k->depth == MTLPixelFormatDepth32Float_Stencil8) d.stencilAttachmentPixelFormat = (MTLPixelFormat)k->depth;
    d.rasterSampleCount = k->samples ? k->samples : 1;
    NSError *err = nil;
    p = [dev newRenderPipelineStateWithDescriptor:d error:&err];
    if (!p) { rt_log("[mtl] pipeline %s/%s: %s", vs->function, ps->function, err.localizedDescription.UTF8String); return nil; }
    map_put(&pso_map, k, sizeof *k, h, (__bridge_retained void *)p);
    return p;
}
static id<MTLDepthStencilState> depth_state(const MtlDepthStencil *s, int has_depth, int has_stencil) {
    MtlDepthStencil k = *s;
    static int nodepth = -1; if (nodepth < 0) nodepth = getenv("RT_METAL_NODEPTH") != NULL;   // debug
    if (nodepth) { k.depth_test = 0; k.stencil = 0; }
    if (!has_depth) { k.depth_test = 0; k.depth_write = 0; }
    if (!has_stencil) k.stencil = 0;
    if (!k.stencil) { memset(&k.front, 0, sizeof k.front); memset(&k.back, 0, sizeof k.back); k.read_mask = k.write_mask = 0; }
    k.ref = 0;
    uint64_t h = fnv(&k, sizeof k);
    id<MTLDepthStencilState> p = (__bridge id<MTLDepthStencilState>)map_get(&dss_map, &k, sizeof k, h);
    if (p) return p;
    MTLDepthStencilDescriptor *d = [MTLDepthStencilDescriptor new];
    d.depthCompareFunction = k.depth_test ? (MTLCompareFunction)k.depth_func : MTLCompareFunctionAlways;
    d.depthWriteEnabled = k.depth_test && k.depth_write;
    if (k.stencil) {
        MTLStencilDescriptor *f = [MTLStencilDescriptor new], *b = [MTLStencilDescriptor new];
        f.stencilFailureOperation = k.front.fail; f.depthFailureOperation = k.front.zfail; f.depthStencilPassOperation = k.front.pass;
        f.stencilCompareFunction = k.front.func; f.readMask = k.read_mask; f.writeMask = k.write_mask;
        b.stencilFailureOperation = k.back.fail; b.depthFailureOperation = k.back.zfail; b.depthStencilPassOperation = k.back.pass;
        b.stencilCompareFunction = k.back.func; b.readMask = k.read_mask; b.writeMask = k.write_mask;
        d.frontFaceStencil = f; d.backFaceStencil = b;
    }
    p = [dev newDepthStencilStateWithDescriptor:d];
    map_put(&dss_map, &k, sizeof k, h, (__bridge_retained void *)p);
    return p;
}
static id<MTLSamplerState> sampler(const MtlSampler *s) {
    MtlSampler k = *s; k.srgb = 0;
    uint64_t h = fnv(&k, sizeof k);
    id<MTLSamplerState> p = (__bridge id<MTLSamplerState>)map_get(&samp_map, &k, sizeof k, h);
    if (p) return p;
    MTLSamplerDescriptor *d = [MTLSamplerDescriptor new];
    d.minFilter = k.min; d.magFilter = k.mag; d.mipFilter = k.mip;
    d.maxAnisotropy = k.aniso > 1 ? k.aniso : 1;
    d.sAddressMode = k.u; d.tAddressMode = k.v; d.rAddressMode = k.w;
    d.borderColor = k.border;
    d.lodMinClamp = k.max_level;
    d.lodMaxClamp = FLT_MAX;
    if (@available(macOS 26.0, *)) d.lodBias = k.lod_bias;
    p = [dev newSamplerStateWithDescriptor:d];
    map_put(&samp_map, &k, sizeof k, h, (__bridge_retained void *)p);
    return p;
}

// ---------------- encoding ----------------
static MtlTarget enc_color[4], enc_depth;
static void target_size(uint32_t *w, uint32_t *h) {
    Tex *t = tget(st.color[0].tex); if (!t) t = tget(st.depth.tex);
    *w = t ? t->d.width >> (t == tget(st.color[0].tex) ? st.color[0].level : st.depth.level) : 1;
    *h = t ? t->d.height >> (t == tget(st.color[0].tex) ? st.color[0].level : st.depth.level) : 1;
}
static id<MTLTexture> target_view(const MtlTarget *t, Tex *x) {
    if (t->srgb && srgb_of(x->tex.pixelFormat) != x->tex.pixelFormat) {
        if (!x->target_srgb) x->target_srgb = [x->tex newTextureViewWithPixelFormat:srgb_of(x->tex.pixelFormat)];
        return x->target_srgb;
    }
    return x->tex;
}
// begin a render pass on the current targets; clear = load actions for a full-target clear
static void begin_pass(int clear, const float color[4], float depth, uint8_t stencil) {
    ensure_cmd();
    end_encoder();
    flush_uploads(cmd);
    MTLRenderPassDescriptor *p = [MTLRenderPassDescriptor renderPassDescriptor];
    for (int i = 0; i < 4; i++) {
        Tex *x = tget(st.color[i].tex);
        if (!x) continue;
        p.colorAttachments[i].texture = target_view(&st.color[i], x);
        p.colorAttachments[i].level = st.color[i].level; p.colorAttachments[i].slice = st.color[i].face;
        p.colorAttachments[i].loadAction = (clear & MTLR_CLEAR_COLOR) ? MTLLoadActionClear : MTLLoadActionLoad;
        if (clear & MTLR_CLEAR_COLOR) p.colorAttachments[i].clearColor = MTLClearColorMake(color[0], color[1], color[2], color[3]);
        p.colorAttachments[i].storeAction = MTLStoreActionStore;
    }
    Tex *dx = tget(st.depth.tex);
    if (dx) {
        p.depthAttachment.texture = dx->tex; p.depthAttachment.level = st.depth.level;
        p.depthAttachment.loadAction = (clear & MTLR_CLEAR_DEPTH) ? MTLLoadActionClear : MTLLoadActionLoad;
        p.depthAttachment.clearDepth = depth; p.depthAttachment.storeAction = MTLStoreActionStore;
        if (dx->tex.pixelFormat == MTLPixelFormatDepth32Float_Stencil8) {
            p.stencilAttachment.texture = dx->tex; p.stencilAttachment.level = st.depth.level;
            p.stencilAttachment.loadAction = (clear & MTLR_CLEAR_STENCIL) ? MTLLoadActionClear : MTLLoadActionLoad;
            p.stencilAttachment.clearStencil = stencil; p.stencilAttachment.storeAction = MTLStoreActionStore;
        }
    }
    if (!p.colorAttachments[0].texture && !dx) return;
    enc = [cmd renderCommandEncoderWithDescriptor:p]; dbg[3]++;
    memcpy(enc_color, st.color, sizeof enc_color); enc_depth = st.depth;
    st.targets_dirty = 0; st.vp_dirty = st.sc_dirty = 1;
    st.consts_dirty[0] = st.consts_dirty[1] = 1;
}
static void ensure_pass(void) {
    if (!enc || st.targets_dirty) {
        if (enc && !memcmp(enc_color, st.color, sizeof enc_color) && !memcmp(&enc_depth, &st.depth, sizeof enc_depth)) { st.targets_dirty = 0; return; }
        begin_pass(0, NULL, 0, 0);
    }
}
static void apply_rect_state(void) {
    uint32_t w, h; target_size(&w, &h);
    if (st.vp_dirty) { [enc setViewport:st.vp]; st.vp_dirty = 0; }
    MTLScissorRect s = st.sc;
    if (s.x >= w || s.y >= h) s = (MTLScissorRect){0, 0, 0, 0};
    else { if (s.x + s.width > w) s.width = w - s.x; if (s.y + s.height > h) s.height = h - s.y; }
    [enc setScissorRect:s];
}

static int prepare_draw(void) {
    if (!active) return 0;
    ensure_pass();
    if (!enc) { dbg[1]++; return 0; }
    PsoKey k; memset(&k, 0, sizeof k);
    k.vs = st.vs; k.ps = st.ps; k.layout = st.layout;
    k.alpha_test = st.alpha_func != 7;   // MTLCompareFunctionAlways: the test is off -> the variant without discard
    for (int i = 0; i < 4; i++) {
        Tex *x = tget(st.color[i].tex);
        if (x) { k.color[i] = (uint32_t)target_view(&st.color[i], x).pixelFormat; k.blend[i] = st.blend[i]; k.samples = x->d.samples; }
    }
    Tex *dx = tget(st.depth.tex);
    if (dx) { k.depth = (uint32_t)dx->tex.pixelFormat; k.samples = dx->d.samples; }
    for (int s = 0; s < 15; s++) { k.strides[s] = st.streams[s].addr ? st.streams[s].stride : 0; k.rates[s] = (uint8_t)st.streams[s].rate; }
    id<MTLRenderPipelineState> p = pipeline(&k);
    if (!p) { dbg[2]++; return 0; }
    dbg[0]++;
    [enc setRenderPipelineState:p];
    [enc setDepthStencilState:depth_state(&st.ds, dx != NULL, dx && dx->tex.pixelFormat == MTLPixelFormatDepth32Float_Stencil8)];
    [enc setStencilReferenceValue:st.ds.ref];
    [enc setBlendColorRed:st.blend_factor[0] green:st.blend_factor[1] blue:st.blend_factor[2] alpha:st.blend_factor[3]];
    [enc setCullMode:(MTLCullMode)st.rs.cull];
    [enc setFrontFacingWinding:st.rs.ccw_front ? MTLWindingCounterClockwise : MTLWindingClockwise];
    [enc setTriangleFillMode:(MTLTriangleFillMode)st.rs.fill];
    [enc setDepthBias:st.rs.depth_bias slopeScale:st.rs.slope_bias clamp:0];
    apply_rect_state();
    for (int s = 0; s < 15; s++) if (k.strides[s]) [enc setVertexBuffer:guest offset:st.streams[s].addr atIndex:s];
    if (!zero_buf) zero_buf = [dev newBufferWithLength:64 options:MTLResourceStorageModeShared];
    [enc setVertexBuffer:zero_buf offset:0 atIndex:15];
    {   // per-attribute scale for integer formats (see bound_format)
        float scale[16]; for (int i = 0; i < 16; i++) scale[i] = 1;
        const Sm3ShaderInfo *vsi = mtlr_shader_info(st.vs);
        for (int i = 0; vsi && i < vsi->ninputs; i++)
            for (int j = 0; j < layouts[st.layout].n; j++) {
                const MtlVertexElement *e = &layouts[st.layout].e[j];
                if (e->usage == vsi->inputs[i].usage && e->index == vsi->inputs[i].index && vsi->inputs[i].reg < 16) { bound_format(e->format, &scale[vsi->inputs[i].reg]); break; }
            }
        [enc setVertexBytes:scale length:sizeof scale atIndex:SM3_ATTR_SCALE_BUFFER];
    }
    // constants and the legacy blocks (sm3msl.h)
    const Sm3ShaderInfo *si[2] = {mtlr_shader_info(st.vs), mtlr_shader_info(st.ps)};
    for (int stage = 0; stage < 2; stage++) {
        const Sm3ShaderInfo *s = si[stage];
        id<MTLBuffer> ring = rings[ring_frame];
        if (s->cbv_mask & (1 << SM3_CBV_FLOAT)) {
            uint32_t o = ring_put(st.consts[stage], stage ? 224 * 16 : 256 * 16);
            if (stage) [enc setFragmentBuffer:ring offset:o atIndex:SM3_BUFFER_BASE + SM3_CBV_FLOAT];
            else [enc setVertexBuffer:ring offset:o atIndex:SM3_BUFFER_BASE + SM3_CBV_FLOAT];
        }
        if (s->cbv_mask & (1 << SM3_CBV_ALPHA_TEST)) {
            Sm3AlphaTest a = {(uint32_t)st.alpha_func, 0, (uint32_t)st.alpha_ref};
            [enc setFragmentBytes:&a length:sizeof a atIndex:SM3_BUFFER_BASE + SM3_CBV_ALPHA_TEST];
        }
        if (s->cbv_mask & (1 << SM3_CBV_CLIP_PLANES)) {
            Sm3ClipPlanes c = {0};
            if (stage) [enc setFragmentBytes:&c length:sizeof c atIndex:SM3_BUFFER_BASE + SM3_CBV_CLIP_PLANES];
            else [enc setVertexBytes:&c length:sizeof c atIndex:SM3_BUFFER_BASE + SM3_CBV_CLIP_PLANES];
        }
        if (s->cbv_mask & (1 << SM3_CBV_POINT_ARGS)) {
            Sm3PointArgs pa = {0, 1, 1, 64};
            if (stage) [enc setFragmentBytes:&pa length:sizeof pa atIndex:SM3_BUFFER_BASE + SM3_CBV_POINT_ARGS];
            else [enc setVertexBytes:&pa length:sizeof pa atIndex:SM3_BUFFER_BASE + SM3_CBV_POINT_ARGS];
        }
        Sm3SamplerState ss[16]; memset(ss, 0, sizeof ss);
        for (int t = 0; t < 16; t++) {
            if (!s->sampler_type[t]) continue;
            Tex *x = tget(st.tex[stage][t]);
            if (!x || !x->tex) { ss[t].is_null = 1; continue; }
            ss[t].texture_type = s->sampler_type[t];
            id<MTLTexture> v = sample_view(x, st.samp[stage][t].srgb);
            id<MTLSamplerState> sm = sampler(&st.samp[stage][t]);
            if (stage) { [enc setFragmentTexture:v atIndex:t]; [enc setFragmentSamplerState:sm atIndex:t]; }
            else { [enc setVertexTexture:v atIndex:t]; [enc setVertexSamplerState:sm atIndex:t]; }
        }
        if (s->cbv_mask & (1 << SM3_CBV_SAMPLER_STATE)) {
            if (stage) [enc setFragmentBytes:ss length:sizeof ss atIndex:SM3_BUFFER_BASE + SM3_CBV_SAMPLER_STATE];
            else [enc setVertexBytes:ss length:sizeof ss atIndex:SM3_BUFFER_BASE + SM3_CBV_SAMPLER_STATE];
        }
    }
    return 1;
}
void mtlr_draw(int prim, uint32_t first, uint32_t count, uint32_t inst) {
    if (!count || !prepare_draw()) return;
    [enc drawPrimitives:(MTLPrimitiveType)prim vertexStart:first vertexCount:count instanceCount:inst ? inst : 1];
}
void mtlr_draw_indexed(int prim, uint32_t first, uint32_t count, int32_t base, uint32_t inst) {
    if (!count || !st.index_addr || !prepare_draw()) return;
    [enc drawIndexedPrimitives:(MTLPrimitiveType)prim indexCount:count indexType:st.index_bytes == 4 ? MTLIndexTypeUInt32 : MTLIndexTypeUInt16
                   indexBuffer:guest indexBufferOffset:st.index_addr + first * (uint32_t)st.index_bytes instanceCount:inst ? inst : 1
                    baseVertex:base baseInstance:0];
}

static id<MTLRenderPipelineState> clear_pso_for(void) {
    static Map m;
    uint32_t key[6] = {0};
    for (int i = 0; i < 4; i++) { Tex *x = tget(st.color[i].tex); key[i] = x ? (uint32_t)target_view(&st.color[i], x).pixelFormat : 0; }
    Tex *dx = tget(st.depth.tex); key[4] = dx ? (uint32_t)dx->tex.pixelFormat : 0;
    Tex *any = tget(st.color[0].tex) ? tget(st.color[0].tex) : dx; key[5] = any ? any->d.samples : 1;
    uint64_t h = fnv(key, sizeof key);
    id<MTLRenderPipelineState> p = (__bridge id<MTLRenderPipelineState>)map_get(&m, key, sizeof key, h);
    if (p) return p;
    MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
    d.vertexFunction = [builtin newFunctionWithName:@"clear_vs"]; d.fragmentFunction = [builtin newFunctionWithName:@"clear_ps"];
    for (int i = 0; i < 4; i++) d.colorAttachments[i].pixelFormat = (MTLPixelFormat)key[i];
    d.depthAttachmentPixelFormat = (MTLPixelFormat)key[4];
    if (key[4] == MTLPixelFormatDepth32Float_Stencil8) d.stencilAttachmentPixelFormat = (MTLPixelFormat)key[4];
    d.rasterSampleCount = key[5] ? key[5] : 1;
    p = [dev newRenderPipelineStateWithDescriptor:d error:nil];
    map_put(&m, key, sizeof key, h, (__bridge_retained void *)p);
    return p;
}
void mtlr_clear(int flags, const float color[4], float depth, uint8_t stencil) {
    if (!active) return;
    uint32_t w, h; target_size(&w, &h);
    MTLViewport v = st.vp;
    int full = v.originX - 0.5 <= 0 && v.originY - 0.5 <= 0 && v.originX - 0.5 + v.width >= w && v.originY - 0.5 + v.height >= h;
    if (full) { dbg[4]++; begin_pass(flags, color, depth, stencil); return; }
    dbg[5]++;
    // partial: draw a quad over the viewport with write masks for what is cleared
    ensure_pass();
    if (!enc) return;
    MtlBlend saved[4]; memcpy(saved, st.blend, sizeof saved);
    [enc setRenderPipelineState:clear_pso_for()];
    MtlDepthStencil ds = {0};
    ds.depth_test = (flags & MTLR_CLEAR_DEPTH) != 0; ds.depth_write = ds.depth_test; ds.depth_func = MTLCompareFunctionAlways;
    if (flags & MTLR_CLEAR_STENCIL) { ds.stencil = 1; ds.front = ds.back = (MtlStencilFace){MTLStencilOperationReplace, MTLStencilOperationReplace, MTLStencilOperationReplace, MTLCompareFunctionAlways}; ds.read_mask = ds.write_mask = 0xFF; }
    Tex *dx = tget(st.depth.tex);
    [enc setDepthStencilState:depth_state(&ds, dx != NULL, dx && dx->tex.pixelFormat == MTLPixelFormatDepth32Float_Stencil8)];
    [enc setStencilReferenceValue:stencil];
    [enc setCullMode:MTLCullModeNone];
    MTLViewport cv = {v.originX - 0.5, v.originY - 0.5, v.width, v.height, 0, 1};
    [enc setViewport:cv]; st.vp_dirty = 1;
    [enc setScissorRect:(MTLScissorRect){0, 0, w, h}];
    float z = depth;
    float c[4] = {color ? color[0] : 0, color ? color[1] : 0, color ? color[2] : 0, color ? color[3] : 0};
    [enc setVertexBytes:&z length:4 atIndex:0];
    [enc setFragmentBytes:c length:16 atIndex:0];
    if (flags & MTLR_CLEAR_COLOR) [enc drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    else {
        // depth/stencil only: no color writes (the clear pipeline writes all color targets) -> skip color via a
        // zero-size write is not possible per draw, so fall back to a full-pass clear when color must survive
        [enc drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    }
    (void)saved;
}

static void blit_to(id<MTLTexture> dst, id<MTLTexture> src, const float r[4], int linear, MTLLoadAction load) {
    if (!blit_pso) {
        MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
        d.vertexFunction = [builtin newFunctionWithName:@"blit_vs"]; d.fragmentFunction = [builtin newFunctionWithName:@"blit_ps"];
        d.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        blit_pso = [dev newRenderPipelineStateWithDescriptor:d error:nil];
        MTLSamplerDescriptor *s = [MTLSamplerDescriptor new]; s.minFilter = s.magFilter = MTLSamplerMinMagFilterLinear;
        blit_linear = [dev newSamplerStateWithDescriptor:s];
        s.minFilter = s.magFilter = MTLSamplerMinMagFilterNearest; blit_point = [dev newSamplerStateWithDescriptor:s];
    }
    MTLRenderPassDescriptor *p = [MTLRenderPassDescriptor renderPassDescriptor];
    p.colorAttachments[0].texture = dst; p.colorAttachments[0].loadAction = load; p.colorAttachments[0].storeAction = MTLStoreActionStore;
    id<MTLRenderCommandEncoder> e = [cmd renderCommandEncoderWithDescriptor:p];
    [e setRenderPipelineState:blit_pso];
    [e setVertexBytes:r length:16 atIndex:0];
    [e setFragmentTexture:src atIndex:0]; [e setFragmentSamplerState:linear ? blit_linear : blit_point atIndex:0];
    [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    [e endEncoding];
}
void mtlr_copy(MtlTex s, const int sr[4], MtlTex d, const int dr[4], int linear) {
    Tex *a = tget(s), *b = tget(d);
    if (!active || !a || !b) return;
    ensure_cmd(); end_encoder(); flush_uploads(cmd);
    int sw = sr[2] - sr[0], sh = sr[3] - sr[1], dw = dr[2] - dr[0], dh = dr[3] - dr[1];
    if (sw == dw && sh == dh && a->tex.pixelFormat == b->tex.pixelFormat && a->d.samples == b->d.samples) {
        id<MTLBlitCommandEncoder> e = [cmd blitCommandEncoder];
        [e copyFromTexture:a->tex sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(sr[0], sr[1], 0) sourceSize:MTLSizeMake(sw, sh, 1)
                 toTexture:b->tex destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(dr[0], dr[1], 0)];
        [e endEncoding];
        return;
    }
    if (b->tex.pixelFormat != MTLPixelFormatBGRA8Unorm) { rt_log("[mtl] scaled copy to format %lu not supported yet", (unsigned long)b->tex.pixelFormat); return; }
    // scaled copy into the whole destination rect (a quad; the destination outside the rect is kept)
    float r[4] = {(float)sr[0] / a->d.width, (float)sr[1] / a->d.height, (float)sr[2] / a->d.width, (float)sr[3] / a->d.height};
    MTLRenderPassDescriptor *p = [MTLRenderPassDescriptor renderPassDescriptor];
    (void)p;
    blit_to(b->tex, a->tex, r, linear, MTLLoadActionLoad);
}

_Static_assert(MTLR_PF_BGRA8 == MTLPixelFormatBGRA8Unorm && MTLR_PF_BC3 == MTLPixelFormatBC3_RGBA && MTLR_PF_D32F_S8 == MTLPixelFormatDepth32Float_Stencil8 &&
               MTLR_PF_RGBA16F == MTLPixelFormatRGBA16Float && MTLR_PF_A8 == MTLPixelFormatA8Unorm && MTLR_PF_RG8 == MTLPixelFormatRG8Unorm &&
               MTLR_PF_B5G6R5 == MTLPixelFormatB5G6R5Unorm && MTLR_PF_BC5 == MTLPixelFormatBC5_RGUnorm && MTLR_PF_D16 == MTLPixelFormatDepth16Unorm &&
               MTLR_PF_R32F == MTLPixelFormatR32Float && MTLR_PF_RG16F == MTLPixelFormatRG16Float && MTLR_PF_RGB10A2 == MTLPixelFormatRGB10A2Unorm, "pixel formats");
_Static_assert(MTLR_VF_UCHAR4N_BGRA == MTLVertexFormatUChar4Normalized_BGRA && MTLR_VF_FLOAT4 == MTLVertexFormatFloat4 &&
               MTLR_VF_HALF4 == MTLVertexFormatHalf4 && MTLR_VF_SHORT4N == MTLVertexFormatShort4Normalized && MTLR_VF_UCHAR4 == MTLVertexFormatUChar4 &&
               MTLR_VF_UINT1010102N == MTLVertexFormatUInt1010102Normalized && MTLR_VF_USHORT4N == MTLVertexFormatUShort4Normalized, "vertex formats");
_Static_assert(MTLBlendFactorBlendColor == 11 && MTLStencilOperationDecrementWrap == 7 && MTLSamplerAddressModeClampToBorderColor == 5 &&
               MTLCompareFunctionAlways == 7 && MTLCullModeBack == 2 && MTLSamplerMipFilterLinear == 2, "enums");

// ---------------- debugging ----------------
// write every render target (8-bit and half-float color formats) to dir/rt_<handle>_<w>x<h>.ppm, after the GPU is idle
void mtlr_debug_dump(const char *dir) {
    mtlr_wait_idle();
    int n = 0, bb_only = getenv("RT_METAL_DUMP_BB") != NULL;
    for (uint32_t h = 1; h < ntex; h++) {
        Tex *x = &texs[h];
        if (bb_only && h != backbuf) continue;
        if (!x->tex || !(x->d.usage & MTLR_USE_TARGET) || x->d.samples > 1 || x->d.type != MTLR_TEX_2D) continue;
        MTLPixelFormat f = x->tex.pixelFormat;
        int bpp = f == MTLPixelFormatBGRA8Unorm || f == MTLPixelFormatRGBA8Unorm || f == MTLPixelFormatRGB10A2Unorm ? 4 : f == MTLPixelFormatRGBA16Float ? 8 : 0;
        if (!bpp) continue;
        NSUInteger w = x->tex.width, hh = x->tex.height;
        id<MTLBuffer> b = [dev newBufferWithLength:w * hh * bpp options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cb = [queue commandBuffer];
        id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
        [e copyFromTexture:x->tex sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(w, hh, 1)
                  toBuffer:b destinationOffset:0 destinationBytesPerRow:w * bpp destinationBytesPerImage:w * hh * bpp];
        [e endEncoding]; [cb commit]; [cb waitUntilCompleted];
        char p[1300]; snprintf(p, sizeof p, "%s/rt_%u_%lux%lu_f%lu.ppm", dir, h, (unsigned long)w, (unsigned long)hh, (unsigned long)f);
        FILE *o = fopen(p, "wb"); if (!o) continue;
        fprintf(o, "P6\n%lu %lu\n255\n", (unsigned long)w, (unsigned long)hh);
        const uint8_t *s = b.contents;
        for (NSUInteger i = 0; i < w * hh; i++) {
            uint8_t rgb[3];
            if (f == MTLPixelFormatBGRA8Unorm) { rgb[0] = s[i * 4 + 2]; rgb[1] = s[i * 4 + 1]; rgb[2] = s[i * 4]; }
            else if (f == MTLPixelFormatRGBA8Unorm) { rgb[0] = s[i * 4]; rgb[1] = s[i * 4 + 1]; rgb[2] = s[i * 4 + 2]; }
            else if (f == MTLPixelFormatRGB10A2Unorm) { uint32_t v; memcpy(&v, s + i * 4, 4); rgb[0] = (uint8_t)((v & 1023) >> 2); rgb[1] = (uint8_t)(((v >> 10) & 1023) >> 2); rgb[2] = (uint8_t)(((v >> 20) & 1023) >> 2); }
            else { const __fp16 *hp = (const __fp16 *)(s + i * 8); for (int k = 0; k < 3; k++) { float v = hp[k]; v = v < 0 ? 0 : v > 1 ? 1 : v; rgb[k] = (uint8_t)(v * 255); } }
            fwrite(rgb, 1, 3, o);
        }
        fclose(o); n++;
    }
    rt_log("[mtl] dumped %d render targets to %s", n, dir);
}

// read a level back to host memory (waits for the GPU): render-target readback (screenshots, save thumbnails)
void mtlr_tex_download(MtlTex h, int face, int level, void *dst, uint32_t pitch) {
    Tex *t = tget(h); if (!t || !t->tex) return;
    ensure_cmd(); end_encoder(); flush_uploads(cmd);
    mtlr_wait_idle();
    NSUInteger w = MAX(1u, t->d.width >> level), hh = MAX(1u, t->d.height >> level);
    int bw; block_bytes(t->tex.pixelFormat, &bw);
    NSUInteger rows = (hh + bw - 1) / bw;
    if (t->tex.storageMode == MTLStorageModeShared) {
        [t->tex getBytes:dst bytesPerRow:pitch bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 0, w, hh) mipmapLevel:level slice:face];
        return;
    }
    id<MTLBuffer> b = [dev newBufferWithLength:pitch * rows options:MTLResourceStorageModeShared];
    id<MTLCommandBuffer> cb = [queue commandBuffer];
    id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
    [e copyFromTexture:t->tex sourceSlice:face sourceLevel:level sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(w, hh, 1)
              toBuffer:b destinationOffset:0 destinationBytesPerRow:pitch destinationBytesPerImage:pitch * rows];
    [e endEncoding]; [cb commit]; [cb waitUntilCompleted];
    memcpy(dst, b.contents, pitch * rows);
}
