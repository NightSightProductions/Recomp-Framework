// XAudio2 2.9 (xaudio2_9.dll) for 32-bit guests, on CoreAudio.
//
// An audio thread runs 10 ms processing passes at 48 kHz, paced by what the CoreAudio output unit consumes. Each
// pass: OnProcessingPassStart (engine callbacks), OnVoiceProcessingPassStart(bytes still needed) for every running
// source voice, then source voices consume their queued buffers (play region, loops, frequency ratio, linear
// resampling), apply volume / channel volumes / output matrix and add into their outputs; submix voices run in
// processing-stage order into theirs; the mastering voice's mix goes to the device (downmixed to stereo). Buffer
// and stream events are collected under the engine lock and delivered after it is released, on the audio thread's
// own guest CPU, as XAudio2 calls them on its thread.
// Formats: PCM 8/16/24/32-bit, IEEE float (WAVEFORMATEX / EXTENSIBLE); others (ADPCM, xWMA) play silence and log.
// Effects: effect objects (CreateAudioReverb & co.) are accepted and pass audio through.
// Every structure is #pragma pack(1) in xaudio2.h; with 32-bit pointers that is also the natural layout.
#include "com32.h"
#include <time.h>
#include <mach/mach_time.h>
#include <AudioToolbox/AudioToolbox.h>

#define S_OK 0
#define E_INVALIDARG 0x80070057u
#define E_NOINTERFACE 0x80004002u
#define XAUDIO2_E_INVALID_CALL 0x88960001u
#define XAUDIO2_END_OF_STREAM 0x40
#define XAUDIO2_LOOP_INFINITE 255
#define XAUDIO2_VOICE_NOSAMPLESPLAYED 0x100
#define RATE 48000
#define PASS 480                 // frames per 10 ms pass
#define MAXQ 64
#define MAXSEND 8
#define MAXCH 8

typedef struct { uint32_t flags, bytes, data, play_begin, play_len, loop_begin, loop_len, loop_count, ctx; uint64_t frames; int16_t *pcm; } Buf;
enum { V_SOURCE, V_SUBMIX, V_MASTER };
typedef struct Voice {
    ComObj base;
    int kind, dead;
    uint32_t flags, channels, rate, stage;
    // source format
    uint32_t tag, bits, block_align, is_float;
    uint32_t adpcm_spb; int16_t adpcm_coef[2][32]; int adpcm_ncoef;   // MS ADPCM: samples per block, coefficients
    float volume, ratio, max_ratio, chvol[MAXCH];
    uint32_t callback;                   // IXAudio2VoiceCallback* (guest)
    int started;
    Buf q[MAXQ]; int nq; int cur_started; double pos; uint32_t loops_left;
    uint64_t played;
    struct Voice *send[MAXSEND]; int nsend; int to_master;
    float mat[MAXSEND][MAXCH * MAXCH]; int mat_set[MAXSEND];
    float bus[PASS * MAXCH];             // submix/master input for this pass
    int warned;
} Voice;
typedef struct { ComObj base; } Engine;

static pthread_mutex_t xmu = PTHREAD_MUTEX_INITIALIZER;
static Voice *voices[512]; static int nvoices;
static Voice *master;
static uint32_t engine_cbs[16]; static int nengine_cbs;
static int engine_running = 1, audio_started;

// ---------------- format and buffers ----------------
static double sample_at(const Voice *v, const Buf *b, uint64_t frame, uint32_t ch) {
    if (b->pcm) return b->pcm[frame * v->channels + ch] / 32768.0;
    const uint8_t *p = (const uint8_t *)G2H(b->data) + frame * v->block_align + ch * (v->bits / 8);
    if (v->is_float) { float f; memcpy(&f, p, 4); return f; }
    switch (v->bits) {
    case 8: return ((int)p[0] - 128) / 128.0;
    case 16: { int16_t s; memcpy(&s, p, 2); return s / 32768.0; }
    case 24: { int32_t s = (int32_t)((uint32_t)p[0] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 24); return s / 2147483648.0; }
    case 32: { int32_t s; memcpy(&s, p, 4); return s / 2147483648.0; }
    }
    return 0;
}
static int pcm_ok(const Voice *v) { return (v->tag == 1 || v->tag == 2 || v->is_float) && v->block_align; }
static uint64_t play_end(const Buf *b) { return b->play_len ? (uint64_t)b->play_begin + b->play_len : b->frames; }
static uint64_t loop_end(const Buf *b) { return b->loop_len ? (uint64_t)b->loop_begin + b->loop_len : play_end(b); }

typedef struct { uint32_t cb; int kind; uint32_t arg; } Ev;   // kind: 2 StreamEnd, 3 BufferStart, 4 BufferEnd, 5 LoopEnd
static Ev evs[4096]; static int nev;
static void ev(Voice *v, int kind, uint32_t arg) { if (v->callback && nev < 4096) evs[nev++] = (Ev){v->callback, kind, arg}; }

// render `n` output frames of a source voice into `out` (its own channel count), consuming buffers
static void render_source(Voice *v, float *out, int n) {
    memset(out, 0, sizeof(float) * (size_t)n * v->channels);
    if (!v->started || !v->nq) return;
    if (!pcm_ok(v)) {
        if (!v->warned++) rt_log("[xaudio2] format tag 0x%x (%u bits) not supported yet: silence", v->tag, v->bits);
        // still consume buffers in real time so streams progress
    }
    double step = (double)v->rate * v->ratio / RATE;
    for (int i = 0; i < n && v->nq; i++) {
        Buf *b = &v->q[0];
        if (!v->cur_started) {
            v->cur_started = 1; v->pos = b->play_begin; v->loops_left = b->loop_count;
            ev(v, 3, b->ctx);
        }
        uint64_t f = (uint64_t)v->pos;
        if (pcm_ok(v) && f < b->frames) {
            double frac = v->pos - (double)f;
            for (uint32_t ch = 0; ch < v->channels; ch++) {
                double a = sample_at(v, b, f, ch), c2 = f + 1 < b->frames ? sample_at(v, b, f + 1, ch) : a;
                out[i * (int)v->channels + (int)ch] = (float)(a + (c2 - a) * frac) * v->volume * v->chvol[ch < MAXCH ? ch : 0];
            }
        }
        v->pos += step; v->played++;
        // loop / end of the play region
        if (b->loop_count && v->loops_left && v->pos >= (double)loop_end(b)) {
            v->pos -= (double)(loop_end(b) - b->loop_begin);
            if (v->loops_left != XAUDIO2_LOOP_INFINITE) v->loops_left--;
            ev(v, 5, b->ctx);
        } else if (v->pos >= (double)play_end(b)) {
            ev(v, 4, b->ctx);
            if (b->flags & XAUDIO2_END_OF_STREAM) ev(v, 2, 0);
            free(b->pcm);
            memmove(&v->q[0], &v->q[1], sizeof(Buf) * (size_t)(v->nq - 1));
            v->nq--; v->cur_started = 0;
        }
    }
}

// XAudio2's default matrices: identity for equal layouts, mono to the front pair, and standard downmixes
// (channel order FL FR C LFE BL BR SL SR; the LFE is dropped when downmixing)
static void default_matrix(uint32_t sc, uint32_t dc, float *m) {
    memset(m, 0, sizeof(float) * MAXCH * MAXCH);
#define G(o, i, g) m[(o) * sc + (i)] = (g)
    if (sc == dc) { for (uint32_t i = 0; i < sc; i++) G(i, i, 1.0f); return; }
    if (sc == 1) { G(0, 0, 1.0f); if (dc > 1) G(1, 0, 1.0f); return; }
    if (dc == 1) { for (uint32_t i = 0; i < sc; i++) if (i != 3 || sc < 4) G(0, i, 1.0f / sc); return; }
    if (dc == 2) {
        G(0, 0, 1.0f); G(1, 1, 1.0f);
        if (sc >= 3) { G(0, 2, 0.7071f); G(1, 2, 0.7071f); }                 // center
        if (sc >= 6) { G(0, 4, 0.7071f); G(1, 5, 0.7071f); }                 // back / side pair
        if (sc >= 8) { G(0, 6, 0.7071f); G(1, 7, 0.7071f); }
        if (sc == 4) { G(0, 2, 0.7071f); G(1, 3, 0.7071f); G(0, 2, 0); }      // quad: back pair to front
        if (sc == 4) { m[0 * sc + 2] = 0.7071f; m[1 * sc + 3] = 0.7071f; m[1 * sc + 2] = 0; }
        return;
    }
    for (uint32_t i = 0; i < sc && i < dc; i++) G(i, i, 1.0f);
#undef G
}
static void route(Voice *v, const float *in, int n) {
    int nout = v->nsend ? v->nsend : 1;
    for (int k = 0; k < nout; k++) {
        Voice *d = v->nsend ? v->send[k] : master;
        if (!d || d->dead) continue;
        float def[MAXCH * MAXCH]; const float *m = v->mat_set[k] ? v->mat[k] : (default_matrix(v->channels, d->channels, def), def);
        uint32_t sc = v->channels, dc = d->channels;
        for (int i = 0; i < n; i++) for (uint32_t o = 0; o < dc; o++) {
            float acc = 0;
            for (uint32_t s = 0; s < sc; s++) acc += in[i * (int)sc + (int)s] * m[o * sc + s];
            d->bus[i * (int)dc + (int)o] += acc;
        }
    }
}

// ---------------- device output ----------------
#define RING (RATE / 2)            // 0.5 s of stereo frames
static float ring[RING * 2];
static _Atomic uint64_t ring_w, ring_r;
static AudioComponentInstance unit;
static OSStatus out_cb(void *ref, AudioUnitRenderActionFlags *fl, const AudioTimeStamp *ts, UInt32 bus, UInt32 n, AudioBufferList *io) {
    float *o = io->mBuffers[0].mData;
    uint64_t r = ring_r, w = ring_w;
    for (UInt32 i = 0; i < n; i++) {
        if (r < w) { o[2 * i] = ring[(r % RING) * 2]; o[2 * i + 1] = ring[(r % RING) * 2 + 1]; r++; }
        else o[2 * i] = o[2 * i + 1] = 0;
    }
    ring_r = r;
    return noErr;
}
static int out_open(void) {
    AudioComponentDescription d = {kAudioUnitType_Output, kAudioUnitSubType_DefaultOutput, kAudioUnitManufacturer_Apple, 0, 0};
    AudioComponent comp = AudioComponentFindNext(NULL, &d);
    if (!comp || AudioComponentInstanceNew(comp, &unit)) return 0;
    AudioStreamBasicDescription f = {RATE, kAudioFormatLinearPCM, kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked, 8, 1, 8, 2, 32, 0};
    AudioUnitSetProperty(unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Input, 0, &f, sizeof f);
    AURenderCallbackStruct cb = {out_cb, NULL};
    AudioUnitSetProperty(unit, kAudioUnitProperty_SetRenderCallback, kAudioUnitScope_Input, 0, &cb, sizeof cb);
    return AudioUnitInitialize(unit) == noErr && AudioOutputUnitStart(unit) == noErr;
}

// ---------------- MS ADPCM ----------------
// Each block: per channel a predictor index, delta, sample1, sample2 (interleaved for stereo), then 4-bit codes,
// high nibble first. Output: sample2, sample1, then one sample per code.
static const int adpcm_adapt[16] = {230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230};
static int16_t *adpcm_decode(const Voice *v, const uint8_t *src, uint32_t bytes, uint64_t *frames_out) {
    uint32_t ch = v->channels, align = v->block_align, spb = v->adpcm_spb, nblocks = bytes / align;
    int16_t *out = malloc((size_t)nblocks * spb * ch * 2 + 16);
    uint64_t n = 0;
    for (uint32_t b = 0; b < nblocks; b++) {
        const uint8_t *p = src + (size_t)b * align;
        int pred[2] = {0, 0}, delta[2], s1[2], s2[2];
        for (uint32_t c = 0; c < ch; c++) pred[c] = p[c] < v->adpcm_ncoef ? p[c] : 0;
        p += ch;
        for (uint32_t c = 0; c < ch; c++) { delta[c] = (int16_t)(p[0] | p[1] << 8); p += 2; }
        for (uint32_t c = 0; c < ch; c++) { s1[c] = (int16_t)(p[0] | p[1] << 8); p += 2; }
        for (uint32_t c = 0; c < ch; c++) { s2[c] = (int16_t)(p[0] | p[1] << 8); p += 2; }
        int16_t *o = out + n * ch;
        for (uint32_t c = 0; c < ch; c++) o[c] = (int16_t)s2[c];
        for (uint32_t c = 0; c < ch; c++) o[ch + c] = (int16_t)s1[c];
        uint32_t k = 2 * ch, total = spb * ch;
        const uint8_t *end = src + (size_t)(b + 1) * align;
        for (; k < total && p < end; p++) {
            for (int half = 0; half < 2 && k < total; half++, k++) {
                uint32_t c = k % ch;
                int nib = half == 0 ? *p >> 4 : *p & 15, sn = nib >= 8 ? nib - 16 : nib;
                int pr = (s1[c] * v->adpcm_coef[0][pred[c]] + s2[c] * v->adpcm_coef[1][pred[c]]) / 256 + sn * delta[c];
                pr = pr > 32767 ? 32767 : pr < -32768 ? -32768 : pr;
                s2[c] = s1[c]; s1[c] = pr;
                o[k] = (int16_t)pr;
                delta[c] = adpcm_adapt[nib] * delta[c] / 256;
                if (delta[c] < 16) delta[c] = 16;
            }
        }
        n += spb;
    }
    *frames_out = n;
    return out;
}

// ---------------- the audio thread ----------------
RtThread *rt_thread_new(uint32_t stack_size);
void rt_thread_attach(RtThread *t);
static void callback(CPU *c, uint32_t obj, int slot, int nargs, uint32_t a1, uint32_t a2) {
    uint32_t args[3] = {obj, a1, a2};
    guest_call(c, rd32(rd32(obj) + 4u * (uint32_t)slot), nargs + 1, args);
}
static uint32_t bytes_needed(Voice *v) {   // what one pass will consume beyond the queued data
    if (!v->started || !pcm_ok(v)) return 0;
    double need = PASS * (double)v->rate * v->ratio / RATE + 2;
    for (int i = 0; i < v->nq && need > 0; i++) need -= (double)(play_end(&v->q[i]) - (i == 0 && v->cur_started ? (uint64_t)v->pos : v->q[i].play_begin));
    if (need <= 0) return 0;
    if (v->tag == 2 && v->adpcm_spb) return (uint32_t)((need + v->adpcm_spb - 1) / v->adpcm_spb) * v->block_align;   // whole ADPCM blocks
    return (uint32_t)need * v->block_align;
}
static void *audio_main(void *arg) {
    (void)arg;
    RtThread *t = rt_thread_new(0x100000);
    rt_thread_attach(t);
    CPU *c = t->cpu;
    int have_out = out_open();
    if (!have_out) rt_log("[xaudio2] no CoreAudio output: mixing silently");
    static float tmp[PASS * MAXCH];
    uint64_t t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW), passes = 0;
    for (;;) {
        // pace: keep ~3 passes queued for the device (or real time when there is no device)
        if (have_out) { while (ring_w - ring_r > 6 * PASS) usleep(2000); }
        else { uint64_t due = t0 + passes * 10000000ull, now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW); if (due > now) usleep((useconds_t)((due - now) / 1000)); }
        passes++;
        if (!engine_running) { if (have_out) { for (int i = 0; i < PASS; i++, ring_w++) ring[(ring_w % RING) * 2] = ring[(ring_w % RING) * 2 + 1] = 0; } continue; }
        // pass start: engine callbacks, then each source voice's OnVoiceProcessingPassStart(bytes required)
        pthread_mutex_lock(&xmu);
        uint32_t ecb[16]; int necb = nengine_cbs; memcpy(ecb, engine_cbs, sizeof ecb);
        uint32_t pcb[512], pneed[512]; int np = 0;
        for (int i = 0; i < nvoices; i++) { Voice *v = voices[i]; if (v->kind == V_SOURCE && !v->dead && v->callback && v->started) { pcb[np] = v->callback; pneed[np++] = bytes_needed(v); } }
        pthread_mutex_unlock(&xmu);
        for (int i = 0; i < necb; i++) callback(c, ecb[i], 0, 0, 0, 0);          // OnProcessingPassStart
        for (int i = 0; i < np; i++) callback(c, pcb[i], 0, 1, pneed[i], 0);     // OnVoiceProcessingPassStart
        // mix
        pthread_mutex_lock(&xmu);
        nev = 0;
        for (int i = 0; i < nvoices; i++) if (voices[i]->kind != V_SOURCE) memset(voices[i]->bus, 0, sizeof voices[i]->bus);
        for (int i = 0; i < nvoices; i++) {
            Voice *v = voices[i];
            if (v->kind != V_SOURCE || v->dead) continue;
            render_source(v, tmp, PASS);
            if (v->started) route(v, tmp, PASS);
        }
        // submixes by processing stage
        for (uint32_t stage = 0; stage < 64; stage++) for (int i = 0; i < nvoices; i++) {
            Voice *v = voices[i];
            if (v->kind != V_SUBMIX || v->dead || v->stage != stage) continue;
            for (int k = 0; k < PASS * (int)v->channels; k++) v->bus[k] *= v->volume;
            route(v, v->bus, PASS);
        }
        // master -> device
        if (master && have_out) {
            uint32_t mc = master->channels;
            for (int i = 0; i < PASS; i++, ring_w++) {
                float l = master->bus[i * (int)mc] * master->volume, r = mc > 1 ? master->bus[i * (int)mc + 1] * master->volume : l;
                if (mc > 2) { float cn = mc > 2 ? master->bus[i * (int)mc + 2] : 0; l += 0.707f * cn; r += 0.707f * cn; }
                ring[(ring_w % RING) * 2] = l > 1 ? 1 : l < -1 ? -1 : l;
                ring[(ring_w % RING) * 2 + 1] = r > 1 ? 1 : r < -1 ? -1 : r;
            }
        }
        Ev local[4096]; int nl = nev; memcpy(local, evs, sizeof(Ev) * (size_t)nev);
        pthread_mutex_unlock(&xmu);
        // events, then pass end
        for (int i = 0; i < nl; i++) {
            switch (local[i].kind) {
            case 2: callback(c, local[i].cb, 2, 0, 0, 0); break;                 // OnStreamEnd
            case 3: callback(c, local[i].cb, 3, 1, local[i].arg, 0); break;      // OnBufferStart(ctx)
            case 4: callback(c, local[i].cb, 4, 1, local[i].arg, 0); break;      // OnBufferEnd(ctx)
            case 5: callback(c, local[i].cb, 5, 1, local[i].arg, 0); break;      // OnLoopEnd(ctx)
            }
        }
        for (int i = 0; i < np; i++) callback(c, pcb[i], 1, 0, 0, 0);            // OnVoiceProcessingPassEnd
        for (int i = 0; i < necb; i++) callback(c, ecb[i], 1, 0, 0, 0);          // OnProcessingPassEnd
    }
    return NULL;
}
static void start_audio(void) {
    if (audio_started++) return;
    pthread_t th; pthread_attr_t a; pthread_attr_init(&a); pthread_attr_setstacksize(&a, 16u << 20);
    pthread_create(&th, &a, audio_main, NULL);
}

// ---------------- voices ----------------
#define V ((Voice *)s)
static void parse_sends(Voice *v, uint32_t sends) {
    v->nsend = 0; memset(v->mat_set, 0, sizeof v->mat_set);
    if (!sends) return;
    uint32_t n = rd32(sends), d = rd32(sends + 4);
    for (uint32_t i = 0; i < n && i < MAXSEND; i++) {
        Voice *dst = (Voice *)com_host(rd32(d + 8 * i + 4));
        if (dst) v->send[v->nsend++] = dst;
    }
}
static int send_index(Voice *v, uint32_t dest) {
    if (!v->nsend) return (!dest || com_host(dest) == &master->base) ? 0 : -1;
    for (int i = 0; i < v->nsend; i++) if (&v->send[i]->base == com_host(dest)) return i;
    return !dest ? 0 : -1;
}
static uint32_t v_GetVoiceDetails(CPU *c, ComObj *s, const ComMethod *m) {
    if (M(1)) { wr32(M(1), V->flags); wr32(M(1) + 4, V->flags); wr32(M(1) + 8, V->channels); wr32(M(1) + 12, V->rate); }
    return S_OK;
}
static uint32_t v_SetOutputVoices(CPU *c, ComObj *s, const ComMethod *m) { pthread_mutex_lock(&xmu); parse_sends(V, M(1)); pthread_mutex_unlock(&xmu); return S_OK; }
static uint32_t v_ok(CPU *c, ComObj *s, const ComMethod *m) { return S_OK; }
static uint32_t v_GetEffectState(CPU *c, ComObj *s, const ComMethod *m) { if (M(2)) wr32(M(2), 1); return S_OK; }
static uint32_t v_GetFilterParameters(CPU *c, ComObj *s, const ComMethod *m) {   // XAUDIO2_FILTER_PARAMETERS {type, freq, 1/Q}
    if (M(1)) { wr32(M(1), 0); wrf(M(1) + 4, 1.0f); wrf(M(1) + 8, 1.0f); }
    return S_OK;
}
static uint32_t v_GetOutputFilterParameters(CPU *c, ComObj *s, const ComMethod *m) {
    if (M(2)) { wr32(M(2), 0); wrf(M(2) + 4, 1.0f); wrf(M(2) + 8, 1.0f); }
    return S_OK;
}
static uint32_t v_SetVolume(CPU *c, ComObj *s, const ComMethod *m) { V->volume = MF(1); return S_OK; }
static uint32_t v_GetVolume(CPU *c, ComObj *s, const ComMethod *m) { if (M(1)) wrf(M(1), V->volume); return S_OK; }
static uint32_t v_SetChannelVolumes(CPU *c, ComObj *s, const ComMethod *m) {
    for (uint32_t i = 0; i < M(1) && i < MAXCH; i++) V->chvol[i] = rdf(M(2) + 4 * i);
    return S_OK;
}
static uint32_t v_GetChannelVolumes(CPU *c, ComObj *s, const ComMethod *m) {
    for (uint32_t i = 0; i < M(1) && i < MAXCH; i++) wrf(M(2) + 4 * i, V->chvol[i]);
    return S_OK;
}
// SetOutputMatrix(dest, SourceChannels, DestinationChannels, const float *matrix, OperationSet)
static uint32_t v_SetOutputMatrix(CPU *c, ComObj *s, const ComMethod *m) {
    uint32_t sc = M(2), dc = M(3);
    if (sc > MAXCH || dc > MAXCH || !M(4)) return E_INVALIDARG;
    pthread_mutex_lock(&xmu);
    int k = send_index(V, M(1));
    if (k >= 0) { for (uint32_t i = 0; i < sc * dc; i++) V->mat[k][i] = rdf(M(4) + 4 * i); V->mat_set[k] = 1; }
    pthread_mutex_unlock(&xmu);
    return k >= 0 ? S_OK : E_INVALIDARG;
}
static uint32_t v_GetOutputMatrix(CPU *c, ComObj *s, const ComMethod *m) {
    uint32_t sc = M(2), dc = M(3);
    int k = send_index(V, M(1));
    float def[MAXCH * MAXCH];
    const float *mt = k >= 0 && V->mat_set[k] ? V->mat[k] : (default_matrix(sc, dc, def), def);
    for (uint32_t i = 0; i < sc * dc && i < MAXCH * MAXCH; i++) wrf(M(4) + 4 * i, mt[i]);
    return S_OK;
}
static uint32_t v_DestroyVoice(CPU *c, ComObj *s, const ComMethod *m) {
    pthread_mutex_lock(&xmu);
    Voice *v = V;
    v->dead = 1;
    for (int i = 0; i < nvoices; i++) if (voices[i] == v) { voices[i] = voices[--nvoices]; break; }
    for (int i = 0; i < nvoices; i++) for (int k = 0; k < voices[i]->nsend; k++) if (voices[i]->send[k] == v) voices[i]->send[k] = master;
    if (master == v) master = NULL;
    pthread_mutex_unlock(&xmu);
    com_unwrap_free(&v->base);
    free(v);
    return S_OK;
}
// source voices
static uint32_t s_Start(CPU *c, ComObj *s, const ComMethod *m) { V->started = 1; return S_OK; }
static uint32_t s_Stop(CPU *c, ComObj *s, const ComMethod *m) { V->started = 0; return S_OK; }
// SubmitSourceBuffer(const XAUDIO2_BUFFER *, const XAUDIO2_BUFFER_WMA *)
static uint32_t s_SubmitSourceBuffer(CPU *c, ComObj *s, const ComMethod *m) {
    uint32_t b = M(1);
    if (!b) return E_INVALIDARG;
    pthread_mutex_lock(&xmu);
    Voice *v = V;
    if (v->nq >= MAXQ) { pthread_mutex_unlock(&xmu); return XAUDIO2_E_INVALID_CALL; }
    Buf *q = &v->q[v->nq++];
    q->flags = rd32(b); q->bytes = rd32(b + 4); q->data = rd32(b + 8); q->play_begin = rd32(b + 12); q->play_len = rd32(b + 16);
    q->loop_begin = rd32(b + 20); q->loop_len = rd32(b + 24); q->loop_count = rd32(b + 28); q->ctx = rd32(b + 32);
    q->frames = v->block_align ? q->bytes / v->block_align : 0;
    q->pcm = NULL;
    {   // RT_AUDIO_DUMP=file: append every PCM buffer submitted to multichannel voices (debugging)
        static FILE *dump; static int tried;
        if (!tried) { tried = 1; const char *d = getenv("RT_AUDIO_DUMP"); if (d) dump = fopen(d, "wb"); }
        if (dump && v->tag == 1 && v->channels >= 6) fwrite(G2H(q->data), 1, q->bytes, dump);
    }
    { static int n; if (getenv("RT_AUDIO_TRACE") && n++ < 12) rt_log("[xaudio2] submit #%d: flags 0x%x bytes %u data 0x%x play %u+%u loop %u+%u x%u ctx 0x%x (queued %d)", n, q->flags, q->bytes, q->data, q->play_begin, q->play_len, q->loop_begin, q->loop_len, q->loop_count, q->ctx, v->nq); }
    if (v->tag == 2 && v->adpcm_spb) q->pcm = adpcm_decode(v, G2H(q->data), q->bytes, &q->frames);
    if (!pcm_ok(v)) q->frames = (uint64_t)q->bytes * 8 / (v->bits ? v->bits : 4) / (v->channels ? v->channels : 1);   // approximate duration
    pthread_mutex_unlock(&xmu);
    return S_OK;
}
static uint32_t s_FlushSourceBuffers(CPU *c, ComObj *s, const ComMethod *m) {
    pthread_mutex_lock(&xmu);
    Voice *v = V;
    int keep = v->cur_started ? 1 : 0;   // the playing buffer finishes; the queued ones end now (OnBufferEnd each)
    for (int i = keep; i < v->nq; i++) { ev(v, 4, v->q[i].ctx); free(v->q[i].pcm); }
    v->nq = keep;
    pthread_mutex_unlock(&xmu);
    return S_OK;
}
static uint32_t s_ExitLoop(CPU *c, ComObj *s, const ComMethod *m) { V->loops_left = 0; return S_OK; }
// GetState(XAUDIO2_VOICE_STATE *, Flags): {pCurrentBufferContext, BuffersQueued, SamplesPlayed (u64)}
static uint32_t s_GetState(CPU *c, ComObj *s, const ComMethod *m) {
    if (!M(1)) return S_OK;
    pthread_mutex_lock(&xmu);
    Voice *v = V;
    wr32(M(1), v->nq ? v->q[0].ctx : 0); wr32(M(1) + 4, (uint32_t)v->nq);
    wr64(M(1) + 8, (M(2) & XAUDIO2_VOICE_NOSAMPLESPLAYED) ? 0 : v->played);
    pthread_mutex_unlock(&xmu);
    return S_OK;
}
static uint32_t s_SetFrequencyRatio(CPU *c, ComObj *s, const ComMethod *m) {
    float r = MF(1);
    if (r < 1.0f / 1024) r = 1.0f / 1024;
    if (r > V->max_ratio) r = V->max_ratio;
    V->ratio = r;
    return S_OK;
}
static uint32_t s_GetFrequencyRatio(CPU *c, ComObj *s, const ComMethod *m) { if (M(1)) wrf(M(1), V->ratio); return S_OK; }
static uint32_t s_SetSourceSampleRate(CPU *c, ComObj *s, const ComMethod *m) { V->rate = M(1); return S_OK; }
static uint32_t mv_GetChannelMask(CPU *c, ComObj *s, const ComMethod *m) { if (M(1)) wr32(M(1), V->channels >= 6 ? 0x3F : V->channels == 1 ? 4 : 3); return S_OK; }

#define VOICE_METHODS \
    {"GetVoiceDetails", 2, v_GetVoiceDetails, 0, 0, 0}, {"SetOutputVoices", 2, v_SetOutputVoices, 0, 0, 0}, \
    {"SetEffectChain", 2, v_ok, 0, 0, 0}, {"EnableEffect", 3, v_ok, 0, 0, 0}, {"DisableEffect", 3, v_ok, 0, 0, 0}, \
    {"GetEffectState", 3, v_GetEffectState, 0, 0, 0}, {"SetEffectParameters", 5, v_ok, 0, 0, 0}, \
    {"GetEffectParameters", 4, v_ok, 0, 0, 0}, {"SetFilterParameters", 3, v_ok, 0, 0, 0}, \
    {"GetFilterParameters", 2, v_GetFilterParameters, 0, 0, 0}, {"SetOutputFilterParameters", 4, v_ok, 0, 0, 0}, \
    {"GetOutputFilterParameters", 3, v_GetOutputFilterParameters, 0, 0, 0}, {"SetVolume", 3, v_SetVolume, 0, 0, 0}, \
    {"GetVolume", 2, v_GetVolume, 0, 0, 0}, {"SetChannelVolumes", 4, v_SetChannelVolumes, 0, 0, 0}, \
    {"GetChannelVolumes", 3, v_GetChannelVolumes, 0, 0, 0}, {"SetOutputMatrix", 6, v_SetOutputMatrix, 0, 0, 0}, \
    {"GetOutputMatrix", 5, v_GetOutputMatrix, 0, 0, 0}, {"DestroyVoice", 1, v_DestroyVoice, 0, 0, 0}
static const ComMethod source_m[] = { VOICE_METHODS,
    {"Start", 3, s_Start, 0, 0, 0}, {"Stop", 3, s_Stop, 0, 0, 0}, {"SubmitSourceBuffer", 3, s_SubmitSourceBuffer, 0, 0, 0},
    {"FlushSourceBuffers", 1, s_FlushSourceBuffers, 0, 0, 0}, {"Discontinuity", 1, v_ok, 0, 0, 0}, {"ExitLoop", 2, s_ExitLoop, 0, 0, 0},
    {"GetState", 3, s_GetState, 0, 0, 0}, {"SetFrequencyRatio", 3, s_SetFrequencyRatio, 0, 0, 0},
    {"GetFrequencyRatio", 2, s_GetFrequencyRatio, 0, 0, 0}, {"SetSourceSampleRate", 2, s_SetSourceSampleRate, 0, 0, 0} };
static const ComMethod submix_m[] = { VOICE_METHODS };
static const ComMethod master_m[] = { VOICE_METHODS, {"GetChannelMask", 2, mv_GetChannelMask, 0, 0, 0} };
static ComClass source_cls = {"IXAudio2SourceVoice", sizeof source_m / sizeof *source_m, source_m, 0, NULL};
static ComClass submix_cls = {"IXAudio2SubmixVoice", sizeof submix_m / sizeof *submix_m, submix_m, 0, NULL};
static ComClass master_cls = {"IXAudio2MasteringVoice", sizeof master_m / sizeof *master_m, master_m, 0, NULL};

static Voice *new_voice(int kind, uint32_t channels, uint32_t rate, uint32_t flags, const ComClass *cls, uint32_t out) {
    Voice *v = calloc(1, sizeof *v);
    v->kind = kind; v->channels = channels ? channels : 2; v->rate = rate ? rate : RATE; v->flags = flags;
    if (v->channels > MAXCH) v->channels = MAXCH;
    v->volume = 1; v->ratio = 1; v->max_ratio = 2;
    for (int i = 0; i < MAXCH; i++) v->chvol[i] = 1;
    wr32(out, com_wrap(&v->base, cls));
    pthread_mutex_lock(&xmu);
    if (nvoices < 512) voices[nvoices++] = v;
    pthread_mutex_unlock(&xmu);
    return v;
}

// ---------------- IXAudio2 ----------------
static uint32_t e_QueryInterface(CPU *c, ComObj *s, const ComMethod *m) { com_addref(s); if (M(2)) wr32(M(2), s->guest); return S_OK; }
static uint32_t e_RegisterForCallbacks(CPU *c, ComObj *s, const ComMethod *m) {
    pthread_mutex_lock(&xmu); if (nengine_cbs < 16 && M(1)) engine_cbs[nengine_cbs++] = M(1); pthread_mutex_unlock(&xmu); return S_OK;
}
static uint32_t e_UnregisterForCallbacks(CPU *c, ComObj *s, const ComMethod *m) {
    pthread_mutex_lock(&xmu);
    for (int i = 0; i < nengine_cbs; i++) if (engine_cbs[i] == M(1)) { engine_cbs[i] = engine_cbs[--nengine_cbs]; break; }
    pthread_mutex_unlock(&xmu);
    return S_OK;
}
// CreateSourceVoice(IXAudio2SourceVoice **, const WAVEFORMATEX *, Flags, float MaxFrequencyRatio, callback, sends, effects)
static uint32_t e_CreateSourceVoice(CPU *c, ComObj *s, const ComMethod *m) {
    uint32_t fmt = M(2);
    if (!M(1) || !fmt) return E_INVALIDARG;
    uint32_t tag = rd16(fmt), ch = rd16(fmt + 2), rate = rd32(fmt + 4), align = rd16(fmt + 12), bits = rd16(fmt + 14);
    int is_float = tag == 3;
    if (tag == 0xFFFE && rd16(fmt + 16) >= 22) { uint32_t sub = rd32(fmt + 24); tag = sub == 3 ? 3 : sub; is_float = sub == 3; }
    Voice *v = new_voice(V_SOURCE, ch, rate, M(3), &source_cls, M(1));
    v->tag = tag; v->bits = bits; v->block_align = align; v->is_float = is_float;
    if (tag == 2) {   // ADPCMWAVEFORMAT: wSamplesPerBlock, wNumCoef, coefficient pairs
        v->adpcm_spb = rd16(fmt + 18);
        v->adpcm_ncoef = rd16(fmt + 20) > 32 ? 32 : rd16(fmt + 20);
        for (int i = 0; i < v->adpcm_ncoef; i++) { v->adpcm_coef[0][i] = (int16_t)rd16(fmt + 22 + 4 * (uint32_t)i); v->adpcm_coef[1][i] = (int16_t)rd16(fmt + 24 + 4 * (uint32_t)i); }
    }
    float mr = MF(4); v->max_ratio = mr > 0 ? mr : 2;
    v->callback = M(5);
    parse_sends(v, M(6));
    if (rt_verbose) rt_log("[xaudio2] source voice: tag 0x%x %u ch %u Hz %u bits%s", tag, ch, rate, bits, M(5) ? " (callback)" : "");
    return S_OK;
}
// CreateSubmixVoice(IXAudio2SubmixVoice **, InputChannels, InputSampleRate, Flags, ProcessingStage, sends, effects)
static uint32_t e_CreateSubmixVoice(CPU *c, ComObj *s, const ComMethod *m) {
    if (!M(1)) return E_INVALIDARG;
    Voice *v = new_voice(V_SUBMIX, M(2), M(3), M(4), &submix_cls, M(1));
    v->stage = M(5);
    parse_sends(v, M(6));
    return S_OK;
}
// CreateMasteringVoice(IXAudio2MasteringVoice **, InputChannels, InputSampleRate, Flags, szDeviceId, effects, category)
static uint32_t e_CreateMasteringVoice(CPU *c, ComObj *s, const ComMethod *m) {
    if (!M(1)) return E_INVALIDARG;
    Voice *v = new_voice(V_MASTER, M(2) ? M(2) : 2, M(3) ? M(3) : RATE, M(4), &master_cls, M(1));
    master = v;
    start_audio();
    return S_OK;
}
static uint32_t e_StartEngine(CPU *c, ComObj *s, const ComMethod *m) { engine_running = 1; return S_OK; }
static uint32_t e_StopEngine(CPU *c, ComObj *s, const ComMethod *m) { engine_running = 0; return S_OK; }
static uint32_t e_GetPerformanceData(CPU *c, ComObj *s, const ComMethod *m) { if (M(1)) memset(G2H(M(1)), 0, 64); return S_OK; }
static const ComMethod engine_m[] = {
    {"QueryInterface", 3, e_QueryInterface, 0, 0, 0}, {"AddRef", 1, com_AddRef, 0, 0, 0}, {"Release", 1, com_Release, 0, 0, 0},
    {"RegisterForCallbacks", 2, e_RegisterForCallbacks, 0, 0, 0}, {"UnregisterForCallbacks", 2, e_UnregisterForCallbacks, 0, 0, 0},
    {"CreateSourceVoice", 8, e_CreateSourceVoice, 0, 0, 0}, {"CreateSubmixVoice", 8, e_CreateSubmixVoice, 0, 0, 0},
    {"CreateMasteringVoice", 8, e_CreateMasteringVoice, 0, 0, 0}, {"StartEngine", 1, e_StartEngine, 0, 0, 0},
    {"StopEngine", 1, e_StopEngine, 0, 0, 0}, {"CommitChanges", 2, v_ok, 0, 0, 0},
    {"GetPerformanceData", 2, e_GetPerformanceData, 0, 0, 0}, {"SetDebugConfiguration", 3, v_ok, 0, 0, 0},
};
static ComClass engine_cls = {"IXAudio2", sizeof engine_m / sizeof *engine_m, engine_m, 0, NULL};

// effect objects (CreateAudioReverb / CreateAudioVolumeMeter): pass-through, IUnknown only
static const ComMethod fx_m[] = { COM_IUNKNOWN };
static ComClass fx_cls = {"XAPO (pass-through)", 3, fx_m, 0, NULL};

// XAudio2Create(IXAudio2 **, Flags, XAUDIO2_PROCESSOR)
SHIM(xaudio2_9_ord1, 3) {
    if (!ARG(0)) return E_INVALIDARG;
    Engine *e = calloc(1, sizeof *e);
    wr32(ARG(0), com_wrap(&e->base, &engine_cls));
    if (rt_verbose) rt_log("[xaudio2] XAudio2Create -> 0x%x", rd32(ARG(0)));
    return S_OK;
}
// CreateAudioReverb / CreateAudioVolumeMeter (IUnknown **)
SHIM(xaudio2_9_ord2, 1) {
    if (!ARG(0)) return E_INVALIDARG;
    ComObj *o = calloc(1, sizeof *o);
    wr32(ARG(0), com_wrap(o, &fx_cls));
    return S_OK;
}
