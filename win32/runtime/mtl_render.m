// Native Metal renderer backend (mtl_render.h). One render thread drives state and draws; textures can be created
// and uploaded from any thread.
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include "rt32.h"
#include "mtl_render.h"

id<MTLDevice> rt_metal_device(void);
void *rt_window_layer(uint32_t hwnd);
void *rt_cocoa_create_window(uint32_t hwnd, const char *title, int w, int h);

#define FRAMES 3                       // frames in flight
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
// only the device, for tools that load shaders without running a game (an installer compiling them once)
int mtlr_init_shaders_only(void) {
    dev = rt_metal_device();
    if (!dev) return 0;
    active = 1;
    return 1;
}
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

static void load_source_batches(const char *dir);
static NSMutableDictionary<NSString *, id<MTLLibrary>> *src_lib;
static NSMutableDictionary<NSString *, NSString *> *src_qual;
static int src_pending;
void mtlr_load_shaders(const char *path, const Sm3ShaderInfo *table, int n) {
    if (!active) return;
    NSError *err = nil;
    BOOL isdir = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@(path) isDirectory:&isdir] && isdir) load_source_batches(path);
    else {
        lib = [dev newLibraryWithURL:[NSURL fileURLWithPath:@(path)] error:&err];
        if (!lib) rt_fatal("[mtl] can't load %s: %s", path, err.localizedDescription.UTF8String);
    }
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
static double now_ms_early(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }
// Shaders as Metal source (no offline Metal compiler at build time: tools/msl_batches.py): a folder of batch_*.metal,
// each holding many shaders in namespaces of their own (their functions are "bN::<name>"). They're compiled in the
// background at startup, all batches at once; a function waits only while batches are still compiling. macOS caches
// compiled source, so this costs about a minute once (an installer can do it: mtlr_wait_shaders) and nothing after.
// src_lib: plain function name -> its batch's library; src_qual: -> "bN::name"
static double src_t0;
static void load_source_batches(const char *dir) {
    NSArray *files = [[[NSFileManager defaultManager] contentsOfDirectoryAtPath:@(dir) error:nil] sortedArrayUsingSelector:@selector(compare:)];
    src_lib = [NSMutableDictionary new]; src_qual = [NSMutableDictionary new];
    src_t0 = now_ms_early();
    NSMutableArray<NSString *> *batches = [NSMutableArray new], *names = [NSMutableArray new];
    for (NSString *f in files) {
        if (![f hasPrefix:@"batch_"] || ![f hasSuffix:@".metal"]) continue;
        NSString *src = [NSString stringWithContentsOfFile:[@(dir) stringByAppendingPathComponent:f] encoding:NSUTF8StringEncoding error:nil];
        if (src) { [batches addObject:src]; [names addObject:f]; }
    }
    pthread_mutex_lock(&shader_mu); src_pending = (int)batches.count; pthread_mutex_unlock(&shader_mu);   // all counted first:
    rt_log("[mtl] compiling %d shader source batches from %s", src_pending, dir);                      // cached ones finish at once
    for (NSUInteger i = 0; i < batches.count; i++) {
        NSString *src = batches[i], *f = names[i];
        [dev newLibraryWithSource:src options:[MTLCompileOptions new] completionHandler:^(id<MTLLibrary> l, NSError *e) {
            pthread_mutex_lock(&shader_mu);
            if (l) for (NSString *q in l.functionNames) {
                NSRange r = [q rangeOfString:@"::" options:NSBackwardsSearch];
                NSString *plain = r.location == NSNotFound ? q : [q substringFromIndex:r.location + 2];
                src_lib[plain] = l; src_qual[plain] = q;
            } else rt_log("[mtl] %s: %s", f.UTF8String, e.localizedDescription.UTF8String);
            if (--src_pending == 0) rt_log("[mtl] shader sources compiled (%.1f s)", (now_ms_early() - src_t0) / 1000);
            pthread_cond_broadcast(&shader_cv);
            pthread_mutex_unlock(&shader_mu);
        }];
    }
}
void mtlr_wait_shaders(void) {
    pthread_mutex_lock(&shader_mu);
    while (src_pending > 0) pthread_cond_wait(&shader_cv, &shader_mu);
    pthread_mutex_unlock(&shader_mu);
}
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
    if (!f && lib) { f = [lib newFunctionWithName:k]; if (f) functions[k] = f; }
    while (!f && src_lib) {   // source batches: its batch may still be compiling
        if (src_lib[k]) { f = [src_lib[k] newFunctionWithName:src_qual[k]]; if (f) functions[k] = f; break; }
        if (src_pending <= 0) break;
        pthread_cond_wait(&shader_cv, &shader_mu);
    }
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
    id<MTLLibrary> l = dyn_libs[k] ?: src_lib[k] ?: lib;
    NSString *qn = src_qual[k] ?: k;
    pthread_mutex_unlock(&shader_mu);
    if (f) return f;
    MTLFunctionConstantValues *cv = [MTLFunctionConstantValues new];
    bool off = false;
    [cv setConstantValue:&off type:MTLDataTypeBool atIndex:SM3_FC_ALPHA_TEST];
    NSError *e = nil;
    f = [l newFunctionWithName:qn constantValues:cv error:&e];
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
static void pend_drop(MtlTex h);
void mtlr_tex_destroy(MtlTex h) {
    pend_drop(h);
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
static int npend_any(void);
static void pend_flush_uploads(void);
static void pend_flush(MtlTex t);
static void flush_uploads(id<MTLCommandBuffer> cb) {
    if (!__atomic_load_n(&nups, __ATOMIC_ACQUIRE)) return;
    if (npend_any()) pend_flush_uploads();   // a pending clear of an upload's texture comes first
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

// debug RT_METAL_PASSES=1: log the passes of one frame in 600 (attachments, draws, whether any draw used depth)
static int pass_log, pass_draws, pass_depth_used, pass_clear; static char pass_desc[256];
static id<MTLCounterSampleBuffer> pass_cs; static int pass_n; static char pass_descs[64][300];
static int getenv_cached_noclear_defer(void) { static int v = -1; if (v < 0) v = getenv("RT_METAL_NO_CLEAR_DEFER") != NULL; return v; }
static void depth_learn(void);
static void pass_dend(void);
static void end_encoder(void) {
    if (enc) {
        [enc endEncoding]; enc = nil;
        depth_learn();
        pass_dend();
        if (pass_log && pass_n > 0 && pass_n <= 64) snprintf(pass_descs[pass_n - 1], sizeof pass_descs[0], "%s draws %d depth-used %d clear %d", pass_desc, pass_draws, pass_depth_used, pass_clear);
    }
}
static pthread_t enc_thread;   // the thread encoding (ensure_cmd)
static void ensure_cmd(void) {
    if (cmd) return;
    enc_thread = pthread_self();
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
static uint32_t frame_no;   // frames presented (scratch depth)
static void commit_cmd(void);
// per-frame cost counters (mtlr_frame_stats)
static double fs_pso_ms, fs_drawable_ms; static int fs_pso_n;
static double now_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }
void mtlr_frame_stats(double *pso_ms, int *pso_n, double *drawable_ms) {
    *pso_ms = fs_pso_ms; *pso_n = fs_pso_n; *drawable_ms = fs_drawable_ms;
    fs_pso_ms = fs_drawable_ms = 0; fs_pso_n = 0;
}
void mtlr_present(int interval) {
    if (!active || !backbuf) return;
    pend_flush(backbuf);
    frame_no++;
    { static int f, on = -1, report; if (on < 0) on = getenv("RT_METAL_PASSES") != NULL; f++;
      if (on) {
        if (report) {   // the logged frame's command buffers are done by now: per pass GPU time from the timestamps
            report = 0;
            if (last_committed) [last_committed waitUntilCompleted];
            NSData *d = pass_cs ? [pass_cs resolveCounterRange:NSMakeRange(0, 4 * (NSUInteger)MIN(pass_n, 64))] : nil;
            const MTLCounterResultTimestamp *t = d ? d.bytes : NULL;
            uint64_t base = UINT64_MAX;
            for (int i = 0; i < pass_n && i < 64 && t; i++) for (int j = 0; j < 4; j++) if (t[4 * i + j].timestamp != MTLCounterErrorValue && t[4 * i + j].timestamp && t[4 * i + j].timestamp < base) base = t[4 * i + j].timestamp;
            for (int i = 0; i < pass_n && i < 64; i++) {
                double v0 = -1, v1 = -1, f0 = -1, f1 = -1;
                #define TS(k, out) if (t && t[4 * i + k].timestamp != MTLCounterErrorValue && t[4 * i + k].timestamp) out = (double)(t[4 * i + k].timestamp - base) / 1000.0
                TS(0, v0); TS(1, v1); TS(2, f0); TS(3, f1);
                #undef TS
                rt_log("[pass] %2d vtx %7.0f-%7.0f frag %7.0f-%7.0f us (%5.0f)  %s", i, v0, v1, f0, f1, f1 - f0, pass_descs[i]);
            }
            rt_log("[pass] ---- %d passes", pass_n);
        }
        if (pass_log) { end_encoder(); report = 1; }
        pass_log = f % 600 == 0; if (pass_log) pass_n = 0;
      } }
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
    double td = now_ms();
    id<CAMetalDrawable> dr = [layer nextDrawable];
    fs_drawable_ms += now_ms() - td;
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
    if (++dbg[6] % 120 == 0) rt_log("[mtl] last 120 frames: draws %d, no encoder %d, no pipeline %d, passes %d, clears %d+%d, loads skipped %d",
                                     dbg[0], dbg[1], dbg[2], dbg[3], dbg[4], dbg[5], dbg[7]);
    if (dbg[6] % 120 == 0) memset(dbg, 0, sizeof dbg);
}
// fences: a GPU sync point the CPU can poll (D3D event queries). Command buffers are numbered as committed.
static uint64_t committed_seq, completed_seq;
static pthread_mutex_t gpu_mu = PTHREAD_MUTEX_INITIALIZER; static double gpu_ms;   // GPU time of completed command buffers
double mtlr_gpu_ms(void) { pthread_mutex_lock(&gpu_mu); double g = gpu_ms; gpu_ms = 0; pthread_mutex_unlock(&gpu_mu); return g; }
static void commit_cmd(void) {
    if (!cmd) return;
    end_encoder();
    uint64_t seq = ++committed_seq;
    [cmd addCompletedHandler:^(id<MTLCommandBuffer> b) {
        double g = (b.GPUEndTime - b.GPUStartTime) * 1e3; if (g > 0) { pthread_mutex_lock(&gpu_mu); gpu_ms += g; pthread_mutex_unlock(&gpu_mu); }
        uint64_t c = __atomic_load_n(&completed_seq, __ATOMIC_ACQUIRE);
        while (c < seq && !__atomic_compare_exchange_n(&completed_seq, &c, seq, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {}
    }];
    [cmd commit];
    last_committed = cmd; cmd = nil;
}
uint64_t mtlr_fence(void) { if (!active) return 0; commit_cmd(); return committed_seq; }
// buffer hazards: the command buffer being encoded gets seq committed_seq + 1
uint64_t mtlr_seq_now(void) { return committed_seq + 1; }
void mtlr_wait_seq(uint64_t s) {
    if (!active || !s || mtlr_fence_done(s)) return;
    if (s > committed_seq) {
        if (cmd && pthread_equal(pthread_self(), enc_thread)) commit_cmd();   // ours: send it now
        // else the encoding thread commits it at its next present
    }
    double t0 = now_ms();
    while (!mtlr_fence_done(s)) {
        if (now_ms() - t0 > 200) { static int n; if (n++ < 5) rt_log("[mtl] buffer still in use by the GPU after 200 ms (seq %llu)", (unsigned long long)s); return; }
        usleep(20);
    }
}
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
    uint32_t strides[16]; uint8_t rates[16];   // strides: 1 = stream bound (the stride itself is dynamic, set per draw)
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

static MTLRenderPipelineDescriptor *pso_desc(const PsoKey *k) {
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
        vd.layouts[s].stride = MTLBufferLayoutStrideDynamic;   // setVertexBuffer:...attributeStride: per draw
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
    return d;
}

// Pipeline cache. Building a pipeline compiles its shaders for the GPU (10-120 ms each, cold), so every key is also
// recorded in <data dir>/pipelines_v2.bin and the next launch builds them all in the background (mtlr_prewarm) before
// the game asks for them. pso_map is shared with the compile completion handlers (pso_mu); pso_state marks keys
// built in the background: 1 queued, 3 compiling, 2 done.
typedef struct { PsoKey k; int32_t n; MtlVertexElement e[32]; } PsoRecord;
static pthread_mutex_t pso_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pso_cv = PTHREAD_COND_INITIALIZER;
static Map pso_state;
static FILE *pso_file;
static void map_set(Map *m, const void *k, uint32_t n, uint64_t h, void *v) {
    for (uint32_t i = m->cap ? (uint32_t)h & (m->cap - 1) : 0; m->cap && m->e[i].key; i = (i + 1) & (m->cap - 1))
        if (m->e[i].h == h && m->e[i].klen == n && !memcmp(m->e[i].key, k, n)) { m->e[i].val = v; return; }
    map_put(m, k, n, h, v);
}
static void pso_record(const PsoKey *k) {
    if (!pso_file) {
        char path[1100]; snprintf(path, sizeof path, "%s/pipelines_v2.bin", rt_data_dir);
        if (!(pso_file = fopen(path, "ab"))) return;
    }
    PsoRecord r; memset(&r, 0, sizeof r); r.k = *k; r.k.layout = 0;
    r.n = layouts[k->layout].n; memcpy(r.e, layouts[k->layout].e, sizeof *r.e * (size_t)r.n);
    fwrite(&r, sizeof r, 1, pso_file); fflush(pso_file);
}
// compile k in the background (no-op when it exists or is already being built); 1 when a compile was started
static int async_started, async_done; static double async_t0;
static int fg_inflight;   // (pso_mu) look-ahead builds running: the background queue waits for them
// Background builds run on one low-priority queue, a few at a time: the loading thread only queues them (building a
// descriptor can itself compile: the pixel function without alpha test), and the compiler's queue stays short, so a
// pipeline a draw needs right now isn't stuck behind thousands of speculative ones (a queued one it builds itself).
static dispatch_queue_t pso_queue; static dispatch_semaphore_t pso_slots;
static void pso_finish(const PsoKey *k, uint64_t h, id<MTLRenderPipelineState> p) {
    pthread_mutex_lock(&pso_mu);
    if (p && !map_get(&pso_map, k, sizeof *k, h)) map_put(&pso_map, k, sizeof *k, h, (__bridge_retained void *)p);
    map_set(&pso_state, k, sizeof *k, h, (void *)2);
    if (++async_done % 2000 == 0) rt_log("[mtl] background pipelines: %d of %d done, %.0f ms into the batch", async_done, async_started, now_ms() - async_t0);
    if (async_done == async_started) rt_log("[mtl] background pipelines done: %d so far, last batch %.0f ms", async_done, now_ms() - async_t0);
    pthread_cond_broadcast(&pso_cv);
    pthread_mutex_unlock(&pso_mu);
}
static int pso_async(const PsoKey *k) {
    uint64_t h = fnv(k, sizeof *k);
    pthread_mutex_lock(&pso_mu);
    int seen = map_get(&pso_map, k, sizeof *k, h) || map_get(&pso_state, k, sizeof *k, h);
    if (!seen) {
        map_set(&pso_state, k, sizeof *k, h, (void *)1);
        if (async_started == async_done) async_t0 = now_ms();
        async_started++;
    }
    pthread_mutex_unlock(&pso_mu);
    if (seen) return 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pso_queue = dispatch_queue_create("mtl.pipelines", dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_BACKGROUND, 0));
        pso_slots = dispatch_semaphore_create(2);   // light: leaves the compiler (and the CPU) to the game and look-ahead
    });
    PsoKey kc = *k;
    dispatch_async(pso_queue, ^{
        pthread_mutex_lock(&pso_mu);
        int have = map_get(&pso_map, &kc, sizeof kc, h) != NULL;   // a draw built it meanwhile
        pthread_mutex_unlock(&pso_mu);
        MTLRenderPipelineDescriptor *d = have ? nil : pso_desc(&kc);
        if (!d) { pso_finish(&kc, h, nil); return; }
        dispatch_semaphore_wait(pso_slots, DISPATCH_TIME_FOREVER);
        for (;;) {   // give the compiler to look-ahead builds (pipelines a frame needs now) first
            pthread_mutex_lock(&pso_mu); int busy = fg_inflight; pthread_mutex_unlock(&pso_mu);
            if (!busy) break;
            usleep(1000);
        }
        pthread_mutex_lock(&pso_mu);
        have = map_get(&pso_map, &kc, sizeof kc, h) != NULL;
        if (!have) map_set(&pso_state, &kc, sizeof kc, h, (void *)3);   // compiling: a draw needing it waits for it
        pthread_mutex_unlock(&pso_mu);
        if (have) { pso_finish(&kc, h, nil); dispatch_semaphore_signal(pso_slots); return; }
        [dev newRenderPipelineStateWithDescriptor:d completionHandler:^(id<MTLRenderPipelineState> p, NSError *e) {
            (void)e;
            pso_finish(&kc, h, p);
            dispatch_semaphore_signal(pso_slots);
        }];
    });
    return 1;
}
void mtlr_prewarm(void) {
    if (!active) return;
    char path[1100]; snprintf(path, sizeof path, "%s/pipelines_v2.bin", rt_data_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return;
    PsoRecord r; int n = 0, skipped = 0;
    while (fread(&r, sizeof r, 1, f) == 1) {
        if (r.n < 0 || r.n > 32 || !mtlr_shader_info(r.k.vs) || !mtlr_shader_info(r.k.ps)) { skipped++; continue; }
        PsoKey k = r.k; k.layout = r.n ? mtlr_vertex_layout(r.e, r.n) : 0;
        n += pso_async(&k);
    }
    fclose(f);
    rt_log("[mtl] building %d recorded pipelines in the background (%d skipped)", n, skipped);
}

// Speculation: the target/blend setups of the pipelines built so far, by use. A shader pair the game loads is built
// against the most used ones in the background (mtlr_speculate), long before its first draw.
typedef struct { uint32_t color[4], depth; uint8_t samples, srgb_mask, alpha_test, pad; MtlBlend blend[4]; } FragCfg;
#define NCFG 64
static struct { FragCfg c; uint32_t n; } cfgs[NCFG]; static int ncfg;   // pso_mu
static int cfg_same(const FragCfg *a, const FragCfg *b) {   // the depth format doesn't change the shader binaries
    FragCfg x = *a, y = *b; x.depth = y.depth = 0; return !memcmp(&x, &y, sizeof x);
}
static void cfg_count(const FragCfg *c, uint32_t w) {
    for (int i = 0; i < ncfg; i++) if (cfg_same(&cfgs[i].c, c)) { cfgs[i].n += w; return; }
    if (ncfg < NCFG) { cfgs[ncfg].c = *c; cfgs[ncfg].n = w; ncfg++; }
}
static void cfg_of(const PsoKey *k, FragCfg *c) {
    memset(c, 0, sizeof *c);
    memcpy(c->color, k->color, sizeof c->color); c->depth = k->depth; c->samples = k->samples; c->srgb_mask = k->srgb_mask;
    c->alpha_test = k->alpha_test; memcpy(c->blend, k->blend, sizeof c->blend);
}
void mtlr_speculate_config(const uint32_t color[4], uint32_t depth, int alpha_test, const MtlBlend blend[4], uint32_t weight) {
    FragCfg c; memset(&c, 0, sizeof c);
    memcpy(c.color, color, sizeof c.color); c.depth = depth; c.samples = 1; c.alpha_test = (uint8_t)alpha_test;
    for (int i = 0; i < 4; i++) if (color[i]) c.blend[i] = blend[i];
    pthread_mutex_lock(&pso_mu); cfg_count(&c, weight); pthread_mutex_unlock(&pso_mu);
}
static int spec_n;
static Map spec_pairs;   // debug (RT_RN_LEAD): shader pairs speculated
void mtlr_speculate(uint32_t vs, uint32_t ps, uint32_t layout, int rank) {
    if (!active || !mtlr_shader_info(vs) || !mtlr_shader_info(ps) || layout >= (uint32_t)nlayouts) return;
    { uint32_t pr[2] = {vs, ps}; pthread_mutex_lock(&pso_mu); map_set(&spec_pairs, pr, 8, fnv(pr, 8), (void *)(uintptr_t)(layout + 1)); pthread_mutex_unlock(&pso_mu); }
    FragCfg best[8]; int nb = 0;
    pthread_mutex_lock(&pso_mu);
    {   // the setup of that rank by use (0: the most used)
        uint8_t used[NCFG] = {0};
        int top = rank + 1;
        if (top > NCFG) top = NCFG;
        for (; nb < top; nb++) {
            int bi = -1;
            for (int i = 0; i < ncfg; i++) if (!used[i] && (bi < 0 || cfgs[i].n > cfgs[bi].n)) bi = i;
            if (bi < 0) break;
            used[bi] = 1; best[nb] = cfgs[bi].c;
        }
    }
    pthread_mutex_unlock(&pso_mu);
    for (int i = rank; i < nb; i++) {
        PsoKey k; memset(&k, 0, sizeof k);
        k.vs = vs; k.ps = ps; k.layout = layout;
        memcpy(k.color, best[i].color, sizeof k.color); k.depth = best[i].depth; k.samples = best[i].samples;
        k.srgb_mask = best[i].srgb_mask; k.alpha_test = best[i].alpha_test; memcpy(k.blend, best[i].blend, sizeof k.blend);
        for (int j = 0; j < layouts[layout].n; j++) k.strides[layouts[layout].e[j].stream] = 1;
        spec_n += pso_async(&k);
    }
}
int mtlr_speculated(void) { return spec_n; }

// Look-ahead: before a frame's packets are replayed for real, a dry pass (mtlr_lookahead_begin/end) computes every
// draw's pipeline key and starts the missing ones at once, in parallel, at high priority; the real pass then waits
// for them together. A room's first frame needing 20+ new pipelines costs one parallel round instead of a serial sum.
static int dry, dry_n;
static __typeof__(st) dry_saved;
static void pso_prefetch(const PsoKey *k) {
    uint64_t h = fnv(k, sizeof *k);
    pthread_mutex_lock(&pso_mu);
    void *state = map_get(&pso_state, k, sizeof *k, h);
    int skip = map_get(&pso_map, k, sizeof *k, h) || state == (void *)3;
    if (!skip) {
        map_set(&pso_state, k, sizeof *k, h, (void *)3);
        if (!state) { if (async_started == async_done) async_t0 = now_ms(); async_started++; }   // queued ones are counted
        fg_inflight++;
    }
    pthread_mutex_unlock(&pso_mu);
    if (skip) return;
    dry_n++;
    if (!state) pso_record(k);
    PsoKey kc = *k;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        MTLRenderPipelineDescriptor *d = pso_desc(&kc);
        void (^done)(id<MTLRenderPipelineState>) = ^(id<MTLRenderPipelineState> p) {
            pthread_mutex_lock(&pso_mu); fg_inflight--; pthread_mutex_unlock(&pso_mu);
            pso_finish(&kc, h, p);
        };
        if (!d) { done(nil); return; }
        [dev newRenderPipelineStateWithDescriptor:d completionHandler:^(id<MTLRenderPipelineState> p, NSError *e) { (void)e; done(p); }];
    });
}
void mtlr_lookahead_begin(void) { dry_saved = st; dry = 1; dry_n = 0; }
int mtlr_lookahead_end(void) { st = dry_saved; dry = 0; return dry_n; }

static id<MTLRenderPipelineState> pipeline(const PsoKey *k) {
    uint64_t h = fnv(k, sizeof *k);
    pthread_mutex_lock(&pso_mu);
    id<MTLRenderPipelineState> p = (__bridge id<MTLRenderPipelineState>)map_get(&pso_map, k, sizeof *k, h);
    void *state = p ? NULL : map_get(&pso_state, k, sizeof *k, h);
    double t0 = now_ms();
    if (!p) { FragCfg c; cfg_of(k, &c); cfg_count(&c, 1); }
    // being built in the background: wait for it, but not behind a long queue (then build it here as well)
    struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 1;   // a whole look-ahead batch can be compiling at once
    while (!p && state == (void *)3) {   // only when compiling; merely queued: build it here now
        if (pthread_cond_timedwait(&pso_cv, &pso_mu, &dl)) break;
        p = (__bridge id<MTLRenderPipelineState>)map_get(&pso_map, k, sizeof *k, h);
        state = map_get(&pso_state, k, sizeof *k, h);
    }
    pthread_mutex_unlock(&pso_mu);
    if (p) { if (state) { double w = now_ms() - t0; if (w > 0.05) { fs_pso_ms += w; fs_pso_n++; } } return p; }
    MTLRenderPipelineDescriptor *d = pso_desc(k);
    if (!d) return nil;
    NSError *err = nil;
    p = [dev newRenderPipelineStateWithDescriptor:d error:&err];
    if (!p) { rt_log("[mtl] pipeline %08x/%08x: %s", k->vs, k->ps, err.localizedDescription.UTF8String); return nil; }
    pthread_mutex_lock(&pso_mu);
    id<MTLRenderPipelineState> q = (__bridge id<MTLRenderPipelineState>)map_get(&pso_map, k, sizeof *k, h);
    if (q) p = q; else map_put(&pso_map, k, sizeof *k, h, (__bridge_retained void *)p);
    pthread_mutex_unlock(&pso_mu);
    if (!state) pso_record(k);
    fs_pso_ms += now_ms() - t0; fs_pso_n++;
    if (getenv("RT_RN_LEAD")) {
        uint32_t pr[2] = {k->vs, k->ps};
        pthread_mutex_lock(&pso_mu); uintptr_t sl = (uintptr_t)map_get(&spec_pairs, pr, 8, fnv(pr, 8)); pthread_mutex_unlock(&pso_mu);
        char st_[96] = ""; for (int s = 0; s < 16; s++) if (k->strides[s]) { size_t l = strlen(st_); snprintf(st_ + l, sizeof st_ - l, "%d%s ", s, k->rates[s] ? "i" : ""); }
        rt_log("[mtl] new pipeline %08x/%08x %.1f ms%s: pair %s (layout %u, spec layout %d) color %u,%u depth %u alpha %u srgb %u blend %u,%u,%u,%u,%u,%u,%u,%u streams %s",
               k->vs, k->ps, now_ms() - t0, state ? " (was being built)" : "", sl ? "speculated" : "not loaded", k->layout, (int)sl - 1,
               k->color[0], k->color[1], k->depth, k->alpha_test, k->srgb_mask, k->blend[0].enable, k->blend[0].src, k->blend[0].dst, k->blend[0].op,
               k->blend[0].src_a, k->blend[0].dst_a, k->blend[0].op_a, k->blend[0].mask, st_);
    }
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

// ---------------- deferred clears ----------------
// A clear is recorded and applied when its texture is next a render target: as that pass's clear load action (a
// full clear) or as a quad at the start of the pass (a viewport-sized one). On a tile GPU a pass loads and stores its
// whole attachments, so a pass of its own for a clear costs a full read and write of the target (a partial clear of
// a large shadow atlas: milliseconds); deferred, it costs nothing extra, and a depth clear whose result no pass ever
// attaches costs nothing at all. Before a texture is read (sampled, copied, presented, read back, uploaded to), its
// clears are applied in a small pass of their own (pend_flush).
typedef struct {
    MtlTex tex; int level, face, depth;   // depth: the depth/stencil texture (flags DEPTH and/or STENCIL)
    int flags, full;
    float color[4], z; uint8_t stencil;
    MTLViewport vp;                       // the cleared area (viewport, without the half-pixel offset)
} Pend;
#define NPEND 32
static Pend pend[NPEND]; static int npend;
static void pend_remove(int i) { memmove(&pend[i], &pend[i + 1], sizeof *pend * (size_t)(npend - i - 1)); npend--; }
static int pend_match(const Pend *q, MtlTex t, int level, int face, int depth) { return q->tex == t && q->level == level && q->face == face && q->depth == depth; }
static int pend_add(const Pend *n) {
    if (n->full) for (int i = npend - 1; i >= 0; i--)   // a full clear supersedes earlier ones it covers
        if (pend_match(&pend[i], n->tex, n->level, n->face, n->depth) && (pend[i].flags & ~n->flags) == 0) pend_remove(i);
    if (npend >= NPEND) return 0;
    pend[npend++] = *n;
    if (pass_log) { Tex *x = tget(n->tex); rt_log("[pass] pending clear tex %u %ux%u %s flags %d full %d rect %.0f,%.0f %.0fx%.0f value %g/%g", n->tex, x ? (unsigned)x->d.width : 0, x ? (unsigned)x->d.height : 0, n->depth ? "depth" : "color", n->flags, n->full, n->vp.originX, n->vp.originY, n->vp.width, n->vp.height, n->depth ? n->z : n->color[0], n->color[3]); }
    return 1;
}
// a clear quad inside the open encoder: writes only the attachments in cmask (color) / depth / stencil
static id<MTLRenderPipelineState> clear_quad_pso(const uint32_t cfmt[4], uint32_t dfmt, int samples, uint8_t cmask) {
    static Map m;
    uint32_t key[7] = {cfmt[0], cfmt[1], cfmt[2], cfmt[3], dfmt, (uint32_t)samples, cmask};
    uint64_t h = fnv(key, sizeof key);
    id<MTLRenderPipelineState> p = (__bridge id<MTLRenderPipelineState>)map_get(&m, key, sizeof key, h);
    if (p) return p;
    MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
    d.vertexFunction = [builtin newFunctionWithName:@"clear_vs"]; d.fragmentFunction = [builtin newFunctionWithName:@"clear_ps"];
    for (int i = 0; i < 4; i++) { d.colorAttachments[i].pixelFormat = (MTLPixelFormat)cfmt[i]; d.colorAttachments[i].writeMask = (cmask >> i) & 1 ? MTLColorWriteMaskAll : MTLColorWriteMaskNone; }
    d.depthAttachmentPixelFormat = (MTLPixelFormat)dfmt;
    if (dfmt == MTLPixelFormatDepth32Float_Stencil8) d.stencilAttachmentPixelFormat = (MTLPixelFormat)dfmt;
    d.rasterSampleCount = samples ? samples : 1;
    p = [dev newRenderPipelineStateWithDescriptor:d error:nil];
    map_put(&m, key, sizeof key, h, (__bridge_retained void *)p);
    return p;
}
static void clear_quad(id<MTLRenderCommandEncoder> e, const uint32_t cfmt[4], uint32_t dfmt, int samples, uint8_t cmask, const Pend *q, uint32_t w, uint32_t h) {
    [e setRenderPipelineState:clear_quad_pso(cfmt, dfmt, samples, cmask)];
    MtlDepthStencil ds = {0};
    ds.depth_test = q->depth && (q->flags & MTLR_CLEAR_DEPTH); ds.depth_write = ds.depth_test; ds.depth_func = MTLCompareFunctionAlways;
    if (q->depth && (q->flags & MTLR_CLEAR_STENCIL)) { ds.stencil = 1; ds.front = ds.back = (MtlStencilFace){MTLStencilOperationReplace, MTLStencilOperationReplace, MTLStencilOperationReplace, MTLCompareFunctionAlways}; ds.read_mask = ds.write_mask = 0xFF; }
    [e setDepthStencilState:depth_state(&ds, dfmt != 0, dfmt == MTLPixelFormatDepth32Float_Stencil8)];
    [e setStencilReferenceValue:q->stencil];
    [e setCullMode:MTLCullModeNone];
    [e setViewport:q->vp];
    [e setScissorRect:(MTLScissorRect){0, 0, w, h}];
    float z = q->z;
    [e setVertexBytes:&z length:4 atIndex:0];
    [e setFragmentBytes:q->color length:16 atIndex:0];
    [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
}
static void end_encoder(void);
static void ensure_cmd(void);
// apply a texture's pending clears now, in a pass of their own (before it is read)
static void pend_flush(MtlTex t) {
    if (!npend || !t) return;
    int any = 0; for (int i = 0; i < npend; i++) if (pend[i].tex == t) any = 1;
    if (!any) return;
    Tex *x = tget(t);
    if (!x || !x->tex) { for (int i = npend - 1; i >= 0; i--) if (pend[i].tex == t) pend_remove(i); return; }
    ensure_cmd(); end_encoder();
    for (int i = 0; i < npend; ) {   // one pass per (level, face) of t
        if (pend[i].tex != t) { i++; continue; }
        int level = pend[i].level, face = pend[i].face, depth = pend[i].depth;
        MTLRenderPassDescriptor *p = [MTLRenderPassDescriptor renderPassDescriptor];
        uint32_t cfmt[4] = {0}, dfmt = 0;
        if (depth) {
            p.depthAttachment.texture = x->tex; p.depthAttachment.level = level; p.depthAttachment.slice = face;
            p.depthAttachment.loadAction = MTLLoadActionLoad; p.depthAttachment.storeAction = MTLStoreActionStore;
            if (x->tex.pixelFormat == MTLPixelFormatDepth32Float_Stencil8) {
                p.stencilAttachment.texture = x->tex; p.stencilAttachment.level = level; p.stencilAttachment.slice = face;
                p.stencilAttachment.loadAction = MTLLoadActionLoad; p.stencilAttachment.storeAction = MTLStoreActionStore;
            }
            dfmt = (uint32_t)x->tex.pixelFormat;
        } else {
            p.colorAttachments[0].texture = x->tex; p.colorAttachments[0].level = level; p.colorAttachments[0].slice = face;
            p.colorAttachments[0].loadAction = MTLLoadActionLoad; p.colorAttachments[0].storeAction = MTLStoreActionStore;
            cfmt[0] = (uint32_t)x->tex.pixelFormat;
        }
        id<MTLRenderCommandEncoder> e = [cmd renderCommandEncoderWithDescriptor:p];
        uint32_t w = MAX(1u, (uint32_t)x->tex.width >> level), h = MAX(1u, (uint32_t)x->tex.height >> level);
        for (int j = i; j < npend; ) {
            if (pend_match(&pend[j], t, level, face, depth)) { clear_quad(e, cfmt, dfmt, x->d.samples, depth ? 0 : 1, &pend[j], w, h); pend_remove(j); }
            else j++;
        }
        [e endEncoding];
    }
    st.targets_dirty = 1;
}
static void pend_drop(MtlTex h) { for (int i = npend - 1; i >= 0; i--) if (pend[i].tex == h) pend_remove(i); }
static void pend_flush_mtl(id<MTLTexture> t) {   // by Metal texture (uploads)
    for (int i = 0; i < npend; i++) { Tex *x = tget(pend[i].tex); if (x && x->tex == t) { pend_flush(pend[i].tex); i = -1; } }
}
static int npend_any(void) { return npend; }
static void pend_flush_uploads(void) {
    pthread_mutex_lock(&up_mu);
    int n = nups; id<MTLTexture> ts[64]; int k = 0;
    for (int i = 0; i < n && k < 64; i++) ts[k++] = ups[i].tex;
    pthread_mutex_unlock(&up_mu);
    for (int i = 0; i < k; i++) pend_flush_mtl(ts[i]);
}
// ---------------- scratch depth ----------------
// A depth buffer that is only ever tested inside regions cleared in the same pass (a shadow atlas: each tile cleared,
// then its casters drawn) and never read as a texture doesn't need its old contents, nor to be written back: after 30
// frames seen to qualify it is neither loaded nor stored (hundreds of MB a frame for a large atlas). One draw
// outside the cleared regions, or any read of the texture, puts it back to normal for good.
typedef struct { MtlTex t; uint8_t bad, read; uint32_t clean, last; } ScratchD;
static ScratchD scr[64]; static int nscr;
static ScratchD *scr_get(MtlTex t, int make) {
    for (int i = 0; i < nscr; i++) if (scr[i].t == t) return &scr[i];
    if (!make || nscr >= 64) return NULL;
    scr[nscr] = (ScratchD){t, 0, 0, 0, 0xFFFFFFFFu};
    return &scr[nscr++];
}
static void scr_read(MtlTex t) { ScratchD *d = t ? scr_get(t, 0) : NULL; if (d && !d->read) { d->read = 1; rt_log("[mtl] depth %u is read (sampled/copied): not scratch", t); } }
static int pass_dtrack, pass_dfull, pass_dn, pass_dclean, pass_dused, pass_dscratch; static MtlTex pass_dtex;
static float pass_drect[16][4];   // x0 y0 x1 y1 of the depth regions cleared in this pass
static void pass_dclear_rect(const MTLViewport *v) {
    if (pass_dn < 16) { float *r = pass_drect[pass_dn++]; r[0] = (float)v->originX; r[1] = (float)v->originY; r[2] = (float)(v->originX + v->width); r[3] = (float)(v->originY + v->height); }
    else pass_dclean = 0;
}
static void pass_ddraw(float x0, float y0, float x1, float y1) {   // a depth-using draw over this area
    pass_dused = 1;
    if (pass_dfull) return;
    for (int i = 0; i < pass_dn; i++) {
        float *r = pass_drect[i];
        if (x0 >= r[0] - 1 && y0 >= r[1] - 1 && x1 <= r[2] + 1 && y1 <= r[3] + 1) return;
    }
    if (pass_dclean) { static int n; if (n++ < 6) { rt_log("[mtl] depth %u: draw %.0f,%.0f-%.0f,%.0f outside %d cleared regions%s", pass_dtex, x0, y0, x1, y1, pass_dn, pass_dn ? ":" : "");
        for (int i = 0; i < pass_dn && i < 6; i++) rt_log("[mtl]   cleared %.0f,%.0f-%.0f,%.0f", pass_drect[i][0], pass_drect[i][1], pass_drect[i][2], pass_drect[i][3]); } }
    pass_dclean = 0;
}
static void pass_dend(void) {
    if (!pass_dtrack || !pass_dused) { pass_dtrack = 0; return; }
    ScratchD *d = scr_get(pass_dtex, 1);
    if (d) {
        if (!pass_dclean) {
            if (!d->bad && pass_dscratch) rt_log("[mtl] depth %u was used outside its cleared regions: loaded and stored again", pass_dtex);
            d->bad = 1;
        } else if (d->last != frame_no) {
            d->last = frame_no;
            if (++d->clean == 30 && !d->bad && !d->read) { Tex *x = tget(pass_dtex); rt_log("[mtl] depth %u (%ux%u) is scratch: not loaded or stored", pass_dtex, x ? (unsigned)x->d.width : 0, x ? (unsigned)x->d.height : 0); }
        }
    }
    pass_dtrack = 0;
}
static int scr_ok(MtlTex t) {
    static int off = -1; if (off < 0) off = getenv("RT_METAL_NO_SCRATCH_DEPTH") != NULL;
    ScratchD *d = scr_get(t, 0);
    return !off && d && !d->bad && !d->read && d->clean >= 30;
}

// ---------------- full-screen first draws ----------------
// A pass whose first draw replaces every pixel of its color target (a post-effect quad: at most 6 vertices spanning
// clip space, full viewport and scissor, no blending, all channels written, no alpha test or depth) doesn't need the
// target's old contents: it isn't loaded (on a tile GPU, a full read of the target saved). RT_METAL_NO_FULLSCREEN_SKIP=1
// turns it off; RT_METAL_SKIP_CHECK=1 clears such targets to magenta instead, so a wrong guess shows on screen.
static uint32_t draw_first, draw_count; static int draw_indexed, pass_first_full;
static int full_cover(uint32_t w, uint32_t h) {
    static int off = -1; if (off < 0) off = getenv("RT_METAL_NO_FULLSCREEN_SKIP") != NULL;
    if (off || draw_indexed || draw_count < 3 || draw_count > 6 || st.alpha_func != 7) {
        if (getenv("RT_METAL_SKIP_DEBUG") && !draw_indexed && draw_count <= 6) { static int n; if (n++ < 6) rt_log("[skip] rejected: count %u alpha %d", draw_count, st.alpha_func); }
        return 0;
    }
    if (st.vp.originX - 0.5 > 0 || st.vp.originY - 0.5 > 0 || st.vp.width < w || st.vp.height < h) return 0;
    if (st.sc.x > 0 || st.sc.y > 0 || st.sc.x + st.sc.width < w || st.sc.y + st.sc.height < h) return 0;
    const MtlVertexElement *pe = NULL;
    for (int j = 0; j < layouts[st.layout].n; j++) { const MtlVertexElement *e = &layouts[st.layout].e[j]; if ((e->usage == 0 || e->usage == 9) && e->index == 0) { pe = e; break; } }
    if (getenv("RT_METAL_SKIP_DEBUG") && (!pe || pe->stream >= 15)) { static int n; if (n++ < 6) { char b[200] = ""; size_t o = 0; for (int j = 0; j < layouts[st.layout].n && o < 180; j++) o += (size_t)snprintf(b + o, sizeof b - o, " %u.%u f%u", layouts[st.layout].e[j].usage, layouts[st.layout].e[j].index, layouts[st.layout].e[j].format); rt_log("[skip] no position: layout%s", b); } }
    if (!pe || pe->stream >= 15 || (pe->format != MTLVertexFormatFloat2 && pe->format != MTLVertexFormatFloat3 && pe->format != MTLVertexFormatFloat4)) return 0;
    const Stream *sm = &st.streams[pe->stream];
    if (!sm->addr || !sm->stride || sm->rate) return 0;
    if (getenv("RT_METAL_SKIP_DEBUG")) { static int n; if (n++ < 12) {
        const float *f = (const float *)G2H(sm->addr + draw_first * sm->stride + pe->offset);
        rt_log("[skip] %ux%u vp %.1f,%.1f %.0fx%.0f fmt %u count %u v0 %g %g %g %g", w, h, st.vp.originX, st.vp.originY, st.vp.width, st.vp.height, pe->format, draw_count, f[0], f[1], pe->format >= MTLVertexFormatFloat3 ? f[2] : 0, pe->format == MTLVertexFormatFloat4 ? f[3] : 0); } }
    float x0 = 1e9f, y0 = 1e9f, x1 = -1e9f, y1 = -1e9f;
    for (uint32_t v = draw_first; v < draw_first + draw_count; v++) {
        const float *f = (const float *)G2H(sm->addr + v * sm->stride + pe->offset);
        if (pe->format == MTLVertexFormatFloat4 && f[3] != 0.0f && (f[3] < 0.999f || f[3] > 1.001f)) return 0;   // w 0 (the shader sets it) or 1
        x0 = MIN(x0, f[0]); x1 = MAX(x1, f[0]); y0 = MIN(y0, f[1]); y1 = MAX(y1, f[1]);
    }
    return x0 <= -0.999f && x1 >= 0.999f && y0 <= -0.999f && y1 >= 0.999f;   // clip space, the whole of it
}

// depth attachment decisions: per (color target 0, depth target, the pass's first draw's shaders), whether the pass
// needed depth last time (it is learned at the end of each pass)
static int enc_has_depth, pass_want_depth, pass_needed_depth; static uint32_t pass_first_vs, pass_first_ps;
static struct { uint32_t c, d, vs, ps; uint8_t used, want; } dwant[1024];
static uint32_t dwant_slot(uint32_t vs, uint32_t ps) {
    uint32_t k[4] = {st.color[0].tex, st.depth.tex, vs, ps};
    return (uint32_t)fnv(k, sizeof k) & 1023;
}
static int depth_wanted(uint32_t vs, uint32_t ps) {
    uint32_t i = dwant_slot(vs, ps);
    return dwant[i].used && dwant[i].c == st.color[0].tex && dwant[i].d == st.depth.tex && dwant[i].vs == vs && dwant[i].ps == ps && dwant[i].want;
}
static void depth_learn(void) {   // at the end of a pass (st still holds its targets unless they changed: use enc_*)
    if (!enc_depth.tex) return;
    uint32_t k[4] = {enc_color[0].tex, enc_depth.tex, pass_first_vs, pass_first_ps};
    uint32_t i = (uint32_t)fnv(k, sizeof k) & 1023;
    dwant[i].used = 1; dwant[i].c = enc_color[0].tex; dwant[i].d = enc_depth.tex; dwant[i].vs = pass_first_vs; dwant[i].ps = pass_first_ps;
    dwant[i].want = (uint8_t)pass_needed_depth;
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
        if (pass_first_full && !(clear & MTLR_CLEAR_COLOR) && !st.blend[i].enable && st.blend[i].mask == 15) {
            static int check = -1; if (check < 0) check = getenv("RT_METAL_SKIP_CHECK") != NULL;
            for (int j = npend - 1; j >= 0; j--) if (pend_match(&pend[j], st.color[i].tex, st.color[i].level, st.color[i].face, 0)) pend_remove(j);   // overwritten too
            if (check) { p.colorAttachments[i].loadAction = MTLLoadActionClear; p.colorAttachments[i].clearColor = MTLClearColorMake(1, 0, 1, 1); }
            else p.colorAttachments[i].loadAction = MTLLoadActionDontCare;
            dbg[7]++;
            continue;
        }
        for (int j = 0; j < npend; ) {   // pending clears of this attachment: superseded, or its load action (full)
            Pend *q = &pend[j];
            if (!pend_match(q, st.color[i].tex, st.color[i].level, st.color[i].face, 0)) { j++; continue; }
            if (clear & MTLR_CLEAR_COLOR) { pend_remove(j); continue; }
            if (q->full && p.colorAttachments[i].loadAction == MTLLoadActionLoad) {
                p.colorAttachments[i].loadAction = MTLLoadActionClear;
                p.colorAttachments[i].clearColor = MTLClearColorMake(q->color[0], q->color[1], q->color[2], q->color[3]);
                pend_remove(j); continue;
            }
            break;   // a partial one: drawn as a quad once the pass is open (with any after it)
        }
    }
    Tex *dx = tget(st.depth.tex);
    // depth only when the pass uses it (a full-screen pass that never tests or writes it would load and store the
    // whole depth buffer for nothing): it clears it, its first draw needs it, or it did last time (depth_wanted)
    int have_color = p.colorAttachments[0].texture || p.colorAttachments[1].texture;
    if (dx && have_color && !(clear & (MTLR_CLEAR_DEPTH | MTLR_CLEAR_STENCIL)) && !pass_want_depth) dx = NULL;
    enc_has_depth = dx != NULL;
    pass_needed_depth = (clear & (MTLR_CLEAR_DEPTH | MTLR_CLEAR_STENCIL)) != 0;
    if (dx) {
        p.depthAttachment.texture = dx->tex; p.depthAttachment.level = st.depth.level;
        p.depthAttachment.loadAction = (clear & MTLR_CLEAR_DEPTH) ? MTLLoadActionClear : MTLLoadActionLoad;
        p.depthAttachment.clearDepth = depth; p.depthAttachment.storeAction = MTLStoreActionStore;
        int has_st = dx->tex.pixelFormat == MTLPixelFormatDepth32Float_Stencil8;
        if (has_st) {
            p.stencilAttachment.texture = dx->tex; p.stencilAttachment.level = st.depth.level;
            p.stencilAttachment.loadAction = (clear & MTLR_CLEAR_STENCIL) ? MTLLoadActionClear : MTLLoadActionLoad;
            p.stencilAttachment.clearStencil = stencil; p.stencilAttachment.storeAction = MTLStoreActionStore;
        }
        pass_dtrack = 1; pass_dtex = st.depth.tex; pass_dn = 0; pass_dclean = 1; pass_dused = 0;
        pass_dfull = (clear & MTLR_CLEAR_DEPTH) != 0;
        for (int j = 0; j < npend; ) {   // pending depth/stencil clears, as for color
            Pend *q = &pend[j];
            if (!pend_match(q, st.depth.tex, st.depth.level, st.depth.face, 1)) { j++; continue; }
            int need = (q->flags & MTLR_CLEAR_DEPTH ? MTLR_CLEAR_DEPTH : 0) | (has_st && (q->flags & MTLR_CLEAR_STENCIL) ? MTLR_CLEAR_STENCIL : 0);
            if ((clear & need) == need) { pend_remove(j); continue; }
            if (q->full && !(clear & (MTLR_CLEAR_DEPTH | MTLR_CLEAR_STENCIL)) && p.depthAttachment.loadAction == MTLLoadActionLoad) {
                if (q->flags & MTLR_CLEAR_DEPTH) { p.depthAttachment.loadAction = MTLLoadActionClear; p.depthAttachment.clearDepth = q->z; pass_dfull = 1; }
                if (has_st && (q->flags & MTLR_CLEAR_STENCIL)) { p.stencilAttachment.loadAction = MTLLoadActionClear; p.stencilAttachment.clearStencil = q->stencil; }
                pend_remove(j); continue;
            }
            break;
        }
        // partial pending depth clears become quads at the start of this pass: regions the draws may use
        for (int j = 0; j < npend; j++) if (pend_match(&pend[j], st.depth.tex, st.depth.level, st.depth.face, 1) && (pend[j].flags & MTLR_CLEAR_DEPTH)) pass_dclear_rect(&pend[j].vp);
        pass_dscratch = scr_ok(st.depth.tex);
        if (pass_dscratch) {   // old contents never needed, new ones never read: keep it on chip
            if (p.depthAttachment.loadAction == MTLLoadActionLoad) p.depthAttachment.loadAction = MTLLoadActionDontCare;
            p.depthAttachment.storeAction = MTLStoreActionDontCare;
            if (p.stencilAttachment.texture) {
                if (p.stencilAttachment.loadAction == MTLLoadActionLoad) p.stencilAttachment.loadAction = MTLLoadActionDontCare;
                p.stencilAttachment.storeAction = MTLStoreActionDontCare;
            }
        }
    }
    if (!p.colorAttachments[0].texture && !dx) return;
    if (pass_log) {
        if (!pass_cs) {
            id<MTLCounterSet> ts = nil;
            for (id<MTLCounterSet> cs in dev.counterSets) if ([cs.name isEqualToString:MTLCommonCounterSetTimestamp]) ts = cs;
            if (ts && [dev supportsCounterSampling:MTLCounterSamplingPointAtStageBoundary]) {
                MTLCounterSampleBufferDescriptor *cd = [MTLCounterSampleBufferDescriptor new];
                cd.counterSet = ts; cd.storageMode = MTLStorageModeShared; cd.sampleCount = 64 * 4;
                pass_cs = [dev newCounterSampleBufferWithDescriptor:cd error:nil];
            }
        }
        if (pass_cs && pass_n < 64) {
            MTLRenderPassSampleBufferAttachmentDescriptor *a = p.sampleBufferAttachments[0];
            a.sampleBuffer = pass_cs;
            a.startOfVertexSampleIndex = 4 * pass_n; a.endOfVertexSampleIndex = 4 * pass_n + 1;
            a.startOfFragmentSampleIndex = 4 * pass_n + 2; a.endOfFragmentSampleIndex = 4 * pass_n + 3;
        }
        pass_n++;
    }
    enc = [cmd renderCommandEncoderWithDescriptor:p]; dbg[3]++;
    if (npend) {   // the remaining (partial) pending clears of this pass's attachments, in order, as quads
        uint32_t cfmt[4] = {0}, w = 1, h = 1;
        for (int i = 0; i < 4; i++) if (p.colorAttachments[i].texture) cfmt[i] = (uint32_t)p.colorAttachments[i].texture.pixelFormat;
        uint32_t dfmt = dx ? (uint32_t)dx->tex.pixelFormat : 0;
        target_size(&w, &h);
        int samples = 1; { Tex *a = tget(st.color[0].tex) ? tget(st.color[0].tex) : dx; if (a) samples = a->d.samples; }
        for (int j = 0; j < npend; ) {
            Pend *q = &pend[j]; int hit = 0; uint8_t cm = 0;
            for (int i = 0; i < 4; i++) if (p.colorAttachments[i].texture && pend_match(q, st.color[i].tex, st.color[i].level, st.color[i].face, 0)) { cm |= (uint8_t)(1 << i); hit = 1; }
            if (dx && pend_match(q, st.depth.tex, st.depth.level, st.depth.face, 1)) hit = 1;
            if (hit) { clear_quad(enc, cfmt, dfmt, samples, cm, q, w, h); pend_remove(j); }
            else j++;
        }
    }
    if (pass_log) {
        size_t o = 0; pass_desc[0] = 0;
        for (int i = 0; i < 4; i++) if (p.colorAttachments[i].texture) { id<MTLTexture> t = p.colorAttachments[i].texture;
            o += (size_t)snprintf(pass_desc + o, sizeof pass_desc - o, "c%d %lux%lu f%lu %s ", i, (unsigned long)t.width, (unsigned long)t.height, (unsigned long)t.pixelFormat, p.colorAttachments[i].loadAction == MTLLoadActionClear ? "clr" : "load"); }
        if (dx) snprintf(pass_desc + o, sizeof pass_desc - o, "d %lux%lu f%lu %s", (unsigned long)dx->tex.width, (unsigned long)dx->tex.height, (unsigned long)dx->tex.pixelFormat, p.depthAttachment.loadAction == MTLLoadActionClear ? "clr" : "load");
        pass_draws = 0; pass_depth_used = 0; pass_clear = clear;
    }
    memcpy(enc_color, st.color, sizeof enc_color); enc_depth = st.depth;
    st.targets_dirty = 0; st.vp_dirty = st.sc_dirty = 1;
    st.consts_dirty[0] = st.consts_dirty[1] = 1;
}
static void ensure_pass_for(int need_depth, uint32_t vs, uint32_t ps) {
    int depth_ok = !need_depth || enc_has_depth || !tget(st.depth.tex);
    if (!enc || st.targets_dirty || !depth_ok) {
        if (enc && depth_ok && !memcmp(enc_color, st.color, sizeof enc_color) && !memcmp(&enc_depth, &st.depth, sizeof enc_depth)) { st.targets_dirty = 0; return; }
        // a new pass (or the same targets again, now with depth: a draw needs it after all; then the pass being ended
        // is remembered as needing depth, so next time it starts with it and isn't split)
        if (enc && !depth_ok) pass_needed_depth = 1;
        pass_want_depth = need_depth || depth_wanted(vs, ps);
        pass_first_vs = vs; pass_first_ps = ps;
        begin_pass(0, NULL, 0, 0);
        pass_want_depth = 0;
    }
}
static void ensure_pass(void) { ensure_pass_for(1, 0, 0); }
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
    PsoKey k; memset(&k, 0, sizeof k);
    k.vs = st.vs; k.ps = st.ps; k.layout = st.layout;
    k.alpha_test = st.alpha_func != 7;   // MTLCompareFunctionAlways: the test is off -> the variant without discard
    for (int i = 0; i < 4; i++) {
        Tex *x = tget(st.color[i].tex);
        if (x) { k.color[i] = (uint32_t)target_view(&st.color[i], x).pixelFormat; k.blend[i] = st.blend[i]; k.samples = x->d.samples; }
    }
    Tex *dx = tget(st.depth.tex);
    int need_depth = st.ds.depth_test || st.ds.depth_write || st.ds.stencil;
    for (int j = 0; j < layouts[k.layout].n; j++) {   // only the streams the layout reads (as mtlr_speculate keys them)
        int s = layouts[k.layout].e[j].stream;
        if (s < 15) { k.strides[s] = st.streams[s].addr && st.streams[s].stride; k.rates[s] = (uint8_t)st.streams[s].rate; }
    }
    if (dry) {   // look-ahead pass: start what's missing, draw nothing (depth: as ensure_pass will likely decide)
        if (dx && (need_depth || !k.color[0] || depth_wanted(st.vs, st.ps))) { k.depth = (uint32_t)dx->tex.pixelFormat; k.samples = dx->d.samples; }
        pso_prefetch(&k); return 0;
    }
    if (npend) for (int sg = 0; sg < 2; sg++) for (int i = 0; i < 16; i++) if (st.tex[sg][i]) pend_flush(st.tex[sg][i]);   // read: clear it first
    if (nscr) for (int sg = 0; sg < 2; sg++) for (int i = 0; i < 16; i++) if (st.tex[sg][i]) scr_read(st.tex[sg][i]);
    { uint32_t w = 1, h = 1; target_size(&w, &h); pass_first_full = !need_depth && full_cover(w, h); }
    ensure_pass_for(need_depth, st.vs, st.ps);
    pass_first_full = 0;
    if (!enc) { dbg[1]++; return 0; }
    if (!enc_has_depth) dx = NULL;
    if (dx) { k.depth = (uint32_t)dx->tex.pixelFormat; k.samples = dx->d.samples; }
    if (need_depth) pass_needed_depth = 1;
    if (need_depth && dx && pass_dtrack) {
        float x0 = (float)(st.vp.originX - 0.5), y0 = (float)(st.vp.originY - 0.5), x1 = x0 + (float)st.vp.width, y1 = y0 + (float)st.vp.height;
        float sx0 = (float)st.sc.x, sy0 = (float)st.sc.y, sx1 = sx0 + (float)st.sc.width, sy1 = sy0 + (float)st.sc.height;
        if (sx1 > sx0 && sy1 > sy0) { x0 = MAX(x0, sx0); y0 = MAX(y0, sy0); x1 = MIN(x1, sx1); y1 = MIN(y1, sy1); }
        pass_ddraw(x0, y0, x1, y1);
    }
    id<MTLRenderPipelineState> p = pipeline(&k);
    if (!p) { dbg[2]++; return 0; }
    dbg[0]++;
    if (pass_log) { pass_draws++; if (st.ds.depth_test || st.ds.depth_write || st.ds.stencil) pass_depth_used = 1; }
    [enc setRenderPipelineState:p];
    [enc setDepthStencilState:depth_state(&st.ds, dx != NULL, dx && dx->tex.pixelFormat == MTLPixelFormatDepth32Float_Stencil8)];
    [enc setStencilReferenceValue:st.ds.ref];
    [enc setBlendColorRed:st.blend_factor[0] green:st.blend_factor[1] blue:st.blend_factor[2] alpha:st.blend_factor[3]];
    [enc setCullMode:(MTLCullMode)st.rs.cull];
    [enc setFrontFacingWinding:st.rs.ccw_front ? MTLWindingCounterClockwise : MTLWindingClockwise];
    [enc setTriangleFillMode:(MTLTriangleFillMode)st.rs.fill];
    [enc setDepthBias:st.rs.depth_bias slopeScale:st.rs.slope_bias clamp:0];
    apply_rect_state();
    for (int s = 0; s < 15; s++) if (k.strides[s]) [enc setVertexBuffer:guest offset:st.streams[s].addr attributeStride:st.streams[s].stride atIndex:s];
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
    draw_first = first; draw_count = count; draw_indexed = 0;
    if (!count || !prepare_draw()) return;
    [enc drawPrimitives:(MTLPrimitiveType)prim vertexStart:first vertexCount:count instanceCount:inst ? inst : 1];
}
void mtlr_draw_indexed(int prim, uint32_t first, uint32_t count, int32_t base, uint32_t inst) {
    draw_indexed = 1;
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
    if (!active || dry) return;
    uint32_t w, h; target_size(&w, &h);
    MTLViewport v = st.vp;
    int full = v.originX - 0.5 <= 0 && v.originY - 0.5 <= 0 && v.originX - 0.5 + v.width >= w && v.originY - 0.5 + v.height >= h;
    int open = enc && !st.targets_dirty && !memcmp(enc_color, st.color, sizeof enc_color) && !memcmp(&enc_depth, &st.depth, sizeof enc_depth);
    if (!open && !getenv_cached_noclear_defer()) {   // no pass on these targets: record it (deferred clears)
        Pend q; memset(&q, 0, sizeof q);
        q.full = full; q.z = depth; q.stencil = stencil;
        if (color) memcpy(q.color, color, sizeof q.color);
        q.vp = (MTLViewport){v.originX - 0.5, v.originY - 0.5, v.width, v.height, 0, 1};
        int ok = 1;
        if (flags & MTLR_CLEAR_COLOR) for (int i = 0; i < 4; i++) if (tget(st.color[i].tex)) {
            q.tex = st.color[i].tex; q.level = st.color[i].level; q.face = st.color[i].face; q.depth = 0; q.flags = MTLR_CLEAR_COLOR;
            ok &= pend_add(&q);
        }
        if ((flags & (MTLR_CLEAR_DEPTH | MTLR_CLEAR_STENCIL)) && tget(st.depth.tex)) {
            q.tex = st.depth.tex; q.level = st.depth.level; q.face = st.depth.face; q.depth = 1; q.flags = flags & (MTLR_CLEAR_DEPTH | MTLR_CLEAR_STENCIL);
            ok &= pend_add(&q);
        }
        if (ok) { dbg[4]++; return; }
        // out of room: apply everything pending for these targets and fall through to an immediate clear
        for (int i = 0; i < 4; i++) pend_flush(st.color[i].tex);
        pend_flush(st.depth.tex);
    }
    if (full) {
        dbg[4]++;
        pass_first_vs = pass_first_ps = 0; pass_want_depth = depth_wanted(0, 0);
        begin_pass(flags, color, depth, stencil);
        pass_want_depth = 0;
        return;
    }
    dbg[5]++;
    // partial: draw a quad over the viewport with write masks for what is cleared
    ensure_pass();   // with depth (the clear pipeline is made for the targets' depth format)
    if (!enc) return;
    if ((flags & MTLR_CLEAR_DEPTH) && pass_dtrack && pass_dtex == st.depth.tex) {   // a region its later draws may use
        MTLViewport r = {v.originX - 0.5, v.originY - 0.5, v.width, v.height, 0, 1};
        pass_dclear_rect(&r);
    }
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
    if (!active || !a || !b || dry) return;
    pend_flush(s); pend_flush(d); scr_read(s); scr_read(d);
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
    pend_flush(h); scr_read(h);
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
