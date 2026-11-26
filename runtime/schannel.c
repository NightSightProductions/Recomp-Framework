// SSPI's Schannel (secur32.dll / security.dll) on SecureTransport: TLS for games that run it over their own sockets.
// SSPI hands TLS records in and out as buffers (InitializeSecurityContext for the handshake, EncryptMessage and
// DecryptMessage after it), which matches SecureTransport's I/O callbacks: each context keeps the bytes received
// but not yet read by SecureTransport, and collects what it writes. Like Schannel, records are taken whole and one
// at a time: an incomplete record is SEC_E_INCOMPLETE_MESSAGE, and the bytes after the record that finished the
// handshake or was decrypted go back to the caller as SECBUFFER_EXTRA. The server certificate is validated against
// the system's roots (Schannel's default). Applications reach the functions through InitSecurityInterface's table,
// or import them by name.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <Security/SecureTransport.h>
#include <stdlib.h>
#include <string.h>
#include "rt.h"

static int trace = -1;   // RT_NET_TRACE=1: log each record
#define TR(...) do { if (trace < 0) trace = getenv("RT_NET_TRACE") != NULL; if (trace) rt_log(__VA_ARGS__); } while (0)

#define SEC_E_OK                    0x00000000u
#define SEC_I_CONTINUE_NEEDED       0x00090312u
#define SEC_I_CONTEXT_EXPIRED       0x00090317u
#define SEC_E_INSUFFICIENT_MEMORY   0x80090300u
#define SEC_E_INVALID_HANDLE        0x80090301u
#define SEC_E_UNSUPPORTED_FUNCTION  0x80090302u
#define SEC_E_INTERNAL_ERROR        0x80090304u
#define SEC_E_SECPKG_NOT_FOUND      0x80090305u
#define SEC_E_INVALID_TOKEN         0x80090308u
#define SEC_E_INCOMPLETE_MESSAGE    0x80090318u
#define SEC_E_BUFFER_TOO_SMALL      0x80090321u
#define SEC_E_UNTRUSTED_ROOT        0x80090325u
#define SEC_E_DECRYPT_FAILURE       0x80090330u
#define SEC_E_CERT_UNKNOWN          0x80090327u
#define SEC_E_ILLEGAL_MESSAGE       0x80090326u

enum { SB_EMPTY = 0, SB_DATA = 1, SB_TOKEN = 2, SB_MISSING = 4, SB_EXTRA = 5, SB_TRAILER = 6, SB_HEADER = 7 };
#define ISC_REQ_ALLOCATE_MEMORY 0x100
#define CRED_MAGIC 0x5343484E43524544ull   // "SCHNCRED"
#define CTX_MAGIC  0x5343484E43545854ull   // "SCHNCTXT"
#define HDR 5            // TLS record header
#define TRAILER 256      // the most a record adds after its header (IV, MAC or tag, padding)

typedef struct {
    SSLContextRef ssl;
    uint8_t *in; size_t in_len, in_off;     // received, not yet read by SecureTransport
    uint8_t *out; size_t out_len, out_cap;  // written by SecureTransport, not yet handed out
    int done, shutdown;
    char host[256];
} Sch;

static OSStatus st_read(SSLConnectionRef conn, void *data, size_t *len) {
    Sch *x = (Sch *)conn;
    size_t have = x->in_len - x->in_off, n = *len < have ? *len : have;
    memcpy(data, x->in + x->in_off, n); x->in_off += n;
    if (x->in_off == x->in_len) x->in_off = x->in_len = 0;
    OSStatus r = n < *len ? errSSLWouldBlock : noErr;
    *len = n;
    return r;
}
static OSStatus st_write(SSLConnectionRef conn, const void *data, size_t *len) {
    Sch *x = (Sch *)conn;
    if (x->out_len + *len > x->out_cap) {
        x->out_cap = (x->out_len + *len) * 2 + 4096;
        x->out = realloc(x->out, x->out_cap);
    }
    memcpy(x->out + x->out_len, data, *len); x->out_len += *len;
    return noErr;
}
static void feed(Sch *x, const uint8_t *p, size_t n) {
    if (x->in_off) { memmove(x->in, x->in + x->in_off, x->in_len - x->in_off); x->in_len -= x->in_off; x->in_off = 0; }
    x->in = realloc(x->in, x->in_len + n);
    memcpy(x->in + x->in_len, p, n); x->in_len += n;
}
// length of the whole TLS record at p, 0 if incomplete, -1 if it is not a record
static long record_len(const uint8_t *p, size_t n) {
    if (n >= 1 && (p[0] < 20 || p[0] > 24)) return -1;
    if (n < HDR) return 0;
    size_t l = HDR + ((size_t)p[3] << 8 | p[4]);
    return l <= n ? (long)l : 0;
}

static uint64_t sb(uint64_t desc, uint32_t i) { return rd64(desc + 8) + 16ull * i; }   // SecBuffer { cb, type, pv }
static uint32_t sb_count(uint64_t desc) { return desc ? rd32(desc + 4) : 0; }
static uint64_t sb_find(uint64_t desc, uint32_t type) {
    for (uint32_t i = 0; i < sb_count(desc); i++) if (rd32(sb(desc, i) + 4) == type) return sb(desc, i);
    return 0;
}
static void sb_set(uint64_t b, uint32_t type, uint64_t pv, uint32_t cb) { wr32(b, cb); wr32(b + 4, type); wr64(b + 8, pv); }

static Sch *ctx_of(uint64_t h) { return h && rd64(h + 8) == CTX_MAGIC ? (Sch *)PTR(rd64(h)) : NULL; }
static void expiry(uint64_t p) { if (p) wr64(p, 0x7FFFFFFFFFFFFFFFull); }

static uint32_t st_error(Sch *x, const char *what, OSStatus st) {
    rt_log("[schannel] %s with %s failed: OSStatus %d\n", what, x->host, (int)st);
    switch (st) {
    case errSSLXCertChainInvalid: case errSSLUnknownRootCert: case errSSLNoRootCert: return SEC_E_UNTRUSTED_ROOT;
    case errSSLBadCert: case errSSLCertExpired: case errSSLCertNotYetValid: case errSSLHostNameMismatch: return SEC_E_CERT_UNKNOWN;
    case errSSLProtocol: case errSSLPeerUnexpectedMsg: return SEC_E_ILLEGAL_MESSAGE;
    default: return SEC_E_INTERNAL_ERROR;
    }
}

// ---------------- credentials ----------------
static int schannel_package(const char *p) {
    return p && (!strcasecmp(p, "Microsoft Unified Security Protocol Provider") || !strcasecmp(p, "Schannel")
                 || !strcasecmp(p, "Default TLS SSP"));
}
// AcquireCredentialsHandle(principal, package, credUse, logonId, authData, getKeyFn, getKeyArg, phCredential, ptsExpiry)
static void acquire(CPU *c, const char *pkg) {
    if (!schannel_package(pkg)) {
        rt_log("[schannel] AcquireCredentialsHandle(%s): not available\n", pkg ? pkg : "(null)");
        RET(SEC_E_SECPKG_NOT_FOUND); return;
    }
    uint64_t auth = AN(4);
    if (auth) rt_log("[schannel] credentials: SCHANNEL_CRED version %u, protocols 0x%x, flags 0x%x\n", rd32(auth), rd32(auth + 56), rd32(auth + 72));
    uint64_t h = AN(7); if (h) { wr64(h, 1); wr64(h + 8, CRED_MAGIC); }
    expiry(AN(8));
    RET(SEC_E_OK);
}
static void AcquireCredentialsHandleA(CPU *c) { acquire(c, A1 ? PTR(A1) : NULL); }
static void AcquireCredentialsHandleW(CPU *c) { char *p = A1 ? w16_to_utf8(PTR(A1)) : NULL; acquire(c, p); free(p); }
static void FreeCredentialsHandle(CPU *c) { RET(A0 && rd64(A0 + 8) == CRED_MAGIC ? SEC_E_OK : SEC_E_INVALID_HANDLE); }

// ---------------- the handshake ----------------
static void give_output(Sch *x, uint64_t out_desc, uint32_t req) {
    uint64_t b = sb_find(out_desc, SB_TOKEN);
    if (!b) b = out_desc && sb_count(out_desc) ? sb(out_desc, 0) : 0;
    if (!b) { x->out_len = 0; return; }
    if (!x->out_len) { wr32(b, 0); if (req & ISC_REQ_ALLOCATE_MEMORY) wr64(b + 8, 0); return; }
    if (req & ISC_REQ_ALLOCATE_MEMORY) {
        void *m = malloc(x->out_len); memcpy(m, x->out, x->out_len);
        sb_set(b, SB_TOKEN, G(m), (uint32_t)x->out_len);
    } else {
        uint32_t cap = rd32(b);
        if (cap < x->out_len) rt_log("[schannel] output token of %zu bytes does not fit in %u\n", x->out_len, cap);
        size_t n = x->out_len < cap ? x->out_len : cap;
        memcpy(PTR(rd64(b + 8)), x->out, n); wr32(b, (uint32_t)n); wr32(b + 4, SB_TOKEN);
    }
    x->out_len = 0;
}
// InitializeSecurityContext(cred, ctx, target, req, reserved1, dataRep, input, reserved2, newCtx, output, attrs, expiry)
static void isc(CPU *c, const char *target) {
    uint64_t ctxh = A1, in_desc = AN(6), newh = AN(8), out_desc = AN(9);
    uint32_t req = (uint32_t)A3;
    Sch *x = ctx_of(ctxh);
    if (!x) {
        if (!A0 || rd64(A0 + 8) != CRED_MAGIC) { RET(SEC_E_INVALID_HANDLE); return; }
        x = calloc(1, sizeof *x);
        snprintf(x->host, sizeof x->host, "%s", target ? target : "");
        x->ssl = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
        SSLSetIOFuncs(x->ssl, st_read, st_write);
        SSLSetConnection(x->ssl, x);
        // the host name for SNI and the certificate check: callers may pass a URL ("wss://host:443/path")
        char host[256] = ""; const char *h = target ? target : "", *sch = strstr(h, "://");
        if (sch) h = sch + 3;
        size_t hl = strcspn(h, ":/?#"); if (hl >= sizeof host) hl = sizeof host - 1;
        memcpy(host, h, hl); host[hl] = 0;
        if (*host) SSLSetPeerDomainName(x->ssl, host, strlen(host));
        SSLSetProtocolVersionMin(x->ssl, kTLSProtocol12);
        if (newh) { wr64(newh, G(x)); wr64(newh + 8, CTX_MAGIC); }
        OSStatus st = SSLHandshake(x->ssl);   // the ClientHello
        if (st != errSSLWouldBlock && st != noErr) { RET(st_error(x, "handshake", st)); return; }
        give_output(x, out_desc, req);
        if (AN(10)) wr32(AN(10), req & ~0u);
        expiry(AN(11));
        RET(SEC_I_CONTINUE_NEEDED); return;
    }
    if (newh && newh != ctxh) { wr64(newh, G(x)); wr64(newh + 8, CTX_MAGIC); }
    if (AN(10)) wr32(AN(10), req);
    expiry(AN(11));
    if (x->shutdown) {   // after ApplyControlToken(SCHANNEL_SHUTDOWN): the close_notify alert
        SSLClose(x->ssl); x->shutdown = 0;
        give_output(x, out_desc, req);
        RET(SEC_E_OK); return;
    }
    uint64_t tok = in_desc && sb_count(in_desc) ? sb(in_desc, 0) : 0;
    const uint8_t *p = tok ? PTR(rd64(tok + 8)) : NULL; size_t n = tok ? rd32(tok) : 0, off = 0;
    OSStatus st = errSSLWouldBlock;
    while (!x->done) {
        long rl = record_len(p + off, n - off);
        if (rl < 0) { rt_log("[schannel] handshake with %s: not a TLS record\n", x->host); RET(SEC_E_INVALID_TOKEN); return; }
        if (!rl) break;
        feed(x, p + off, (size_t)rl); off += (size_t)rl;
        st = SSLHandshake(x->ssl);
        if (st == noErr) {
            x->done = 1;
            SSLProtocol v = kSSLProtocolUnknown; SSLCipherSuite cs = 0;
            SSLGetNegotiatedProtocolVersion(x->ssl, &v); SSLGetNegotiatedCipher(x->ssl, &cs);
            rt_log("[schannel] TLS with %s established (protocol %d, cipher 0x%04x)\n", x->host, (int)v, (unsigned)cs);
        } else if (st != errSSLWouldBlock) { give_output(x, out_desc, req); RET(st_error(x, "handshake", st)); return; }
    }
    if (!off && !x->done) {   // not even one whole record yet
        if (in_desc && sb_count(in_desc) > 1) sb_set(sb(in_desc, 1), SB_MISSING, 0, 0);
        give_output(x, out_desc, req);
        RET(SEC_E_INCOMPLETE_MESSAGE); return;
    }
    if (in_desc && sb_count(in_desc) > 1) {
        uint64_t e = sb(in_desc, 1);
        if (off < n) sb_set(e, SB_EXTRA, 0, (uint32_t)(n - off)); else sb_set(e, SB_EMPTY, 0, 0);
    }
    give_output(x, out_desc, req);
    RET(x->done ? SEC_E_OK : SEC_I_CONTINUE_NEEDED);
}
static void InitializeSecurityContextA(CPU *c) { isc(c, A2 ? PTR(A2) : NULL); }
static void InitializeSecurityContextW(CPU *c) { char *t = A2 ? w16_to_utf8(PTR(A2)) : NULL; isc(c, t); free(t); }

static void DeleteSecurityContext(CPU *c) {
    Sch *x = ctx_of(A0);
    if (!x) { RET(SEC_E_INVALID_HANDLE); return; }
    TR("[schannel] %s: context deleted\n", x->host);
    CFRelease(x->ssl); free(x->in); free(x->out); free(x);
    wr64(A0, 0); wr64(A0 + 8, 0);
    RET(SEC_E_OK);
}
// ApplyControlToken(ctx, desc): SCHANNEL_SHUTDOWN (1) makes the next InitializeSecurityContext send close_notify
static void ApplyControlToken(CPU *c) {
    Sch *x = ctx_of(A0);
    if (!x) { RET(SEC_E_INVALID_HANDLE); return; }
    uint64_t b = sb_find(A1, SB_TOKEN);
    if (b && rd32(b) >= 4 && rd32(rd64(b + 8)) == 1) { x->shutdown = 1; TR("[schannel] %s: shutdown requested\n", x->host); }
    RET(SEC_E_OK);
}

// ---------------- records ----------------
// EncryptMessage(ctx, qop, desc { HEADER, DATA, TRAILER, ... }, seq): the record fills header, data and trailer in turn
static void EncryptMessage(CPU *c) {
    Sch *x = ctx_of(A0);
    if (!x || !x->done) { RET(SEC_E_INVALID_HANDLE); return; }
    uint64_t h = sb_find(A2, SB_HEADER), d = sb_find(A2, SB_DATA), t = sb_find(A2, SB_TRAILER);
    if (!d) { RET(SEC_E_INVALID_TOKEN); return; }
    size_t processed = 0;
    OSStatus st = SSLWrite(x->ssl, PTR(rd64(d + 8)), rd32(d), &processed);
    if (st != noErr) { x->out_len = 0; RET(st_error(x, "encrypt", st)); return; }
    // header and data take what they hold, the trailer the rest: laid out back to back when the caller's buffers are
    size_t at = 0, total = x->out_len;
    uint64_t parts[3] = { h, d, t };
    for (int i = 0; i < 3; i++) {
        if (!parts[i]) continue;
        int last = i == 2 || (i == 1 && !t);
        size_t left = total - at, cap = last ? left : rd32(parts[i]), k = left < cap ? left : cap;
        memcpy(PTR(rd64(parts[i] + 8)), x->out + at, k); wr32(parts[i], (uint32_t)k); at += k;
    }
    TR("[schannel] %s: encrypt %u bytes -> %zu\n", x->host, rd32(d) ? (uint32_t)processed : 0, total);
    if (at < total) { rt_log("[schannel] encrypt: %zu record bytes did not fit\n", total - at); x->out_len = 0; RET(SEC_E_BUFFER_TOO_SMALL); return; }
    x->out_len = 0;
    RET(SEC_E_OK);
}
// DecryptMessage(ctx, desc { DATA, EMPTY, EMPTY, EMPTY }, seq, qop): one record, decrypted in place, becomes
// HEADER, DATA (plaintext), TRAILER, and EXTRA for the bytes after it
static void DecryptMessage(CPU *c) {
    Sch *x = ctx_of(A0);
    if (!x || !x->done) { RET(SEC_E_INVALID_HANDLE); return; }
    uint64_t desc = A1, d = sb_find(desc, SB_DATA);
    if (!d) { RET(SEC_E_INVALID_TOKEN); return; }
    uint8_t *p = PTR(rd64(d + 8)); size_t n = rd32(d);
    long rl = record_len(p, n);
    if (rl < 0) { RET(SEC_E_INVALID_TOKEN); return; }
    if (!rl) {
        uint64_t e = sb_find(desc, SB_EMPTY);
        if (e) sb_set(e, SB_MISSING, 0, (uint32_t)(n < HDR ? HDR - n : HDR + ((size_t)p[3] << 8 | p[4]) - n));
        RET(SEC_E_INCOMPLETE_MESSAGE); return;
    }
    feed(x, p, (size_t)rl);
    uint8_t *plain = malloc((size_t)rl); size_t plen = 0;
    OSStatus st;
    for (;;) {
        size_t got = 0;
        st = SSLRead(x->ssl, plain + plen, (size_t)rl - plen, &got);
        plen += got;
        if (st != noErr || plen == (size_t)rl) break;
    }
    uint32_t r = SEC_E_OK;
    if (st == errSSLClosedGraceful || st == errSSLClosedNoNotify) r = SEC_I_CONTEXT_EXPIRED;
    else if (st != noErr && st != errSSLWouldBlock) { free(plain); RET(st_error(x, "decrypt", st)); return; }
    if (x->out_len) { rt_log("[schannel] %s: post-handshake reply of %zu bytes dropped\n", x->host, x->out_len); x->out_len = 0; }
    TR("[schannel] %s: decrypt record of %ld bytes (type %u) -> %zu bytes, status %d, %zu left over\n", x->host, rl, p[0], plen, (int)st, n - (size_t)rl);
    if (plen && trace > 0) { char t[121]; size_t k = plen < 120 ? plen : 120; for (size_t i = 0; i < k; i++) t[i] = plain[i] >= 32 && plain[i] < 127 ? (char)plain[i] : '.'; t[k] = 0; rt_log("[schannel]   \"%s\"\n", t); }
    memcpy(p + HDR, plain, plen); free(plain);
    uint32_t nb = sb_count(desc);
    uint64_t pv = G(p);
    if (nb > 0) sb_set(sb(desc, 0), SB_HEADER, pv, HDR);
    if (nb > 1) sb_set(sb(desc, 1), SB_DATA, pv + HDR, (uint32_t)plen);
    if (nb > 2) sb_set(sb(desc, 2), SB_TRAILER, pv + HDR + plen, (uint32_t)((size_t)rl - HDR - plen));
    if (nb > 3) {
        if ((size_t)rl < n) sb_set(sb(desc, 3), SB_EXTRA, pv + (uint64_t)rl, (uint32_t)(n - (size_t)rl));
        else sb_set(sb(desc, 3), SB_EMPTY, 0, 0);
    }
    RET(r);
}

// QueryContextAttributes(ctx, attribute, buffer)
static void QueryContextAttributes(CPU *c) {
    Sch *x = ctx_of(A0);
    if (!x) { RET(SEC_E_INVALID_HANDLE); return; }
    uint32_t a = (uint32_t)A1; uint64_t b = A2;
    switch (a) {
    case 0:   // SECPKG_ATTR_SIZES { cbMaxToken, cbMaxSignature, cbBlockSize, cbSecurityTrailer }
        wr32(b, 16384 + HDR + TRAILER); wr32(b + 4, 0); wr32(b + 8, 16); wr32(b + 12, TRAILER); break;
    case 4:   // SECPKG_ATTR_STREAM_SIZES { cbHeader, cbTrailer, cbMaximumMessage, cBuffers, cbBlockSize }
        wr32(b, HDR); wr32(b + 4, TRAILER); wr32(b + 8, 16384); wr32(b + 12, 4); wr32(b + 16, 16); break;
    case 0x5a: {   // SECPKG_ATTR_CONNECTION_INFO { protocol, cipher, strength, hash, strength, exchange, strength }
        SSLProtocol v = kTLSProtocol12; SSLGetNegotiatedProtocolVersion(x->ssl, &v);
        wr32(b, v == kTLSProtocol12 ? 0x800 : v == kTLSProtocol11 ? 0x200 : 0x80);   // SP_PROT_TLS1_x_CLIENT
        wr32(b + 4, 0x660e); wr32(b + 8, 128);     // CALG_AES_128
        wr32(b + 12, 0x800c); wr32(b + 16, 256);   // CALG_SHA_256
        wr32(b + 20, 0xae06); wr32(b + 24, 256);   // CALG_ECDH_EPHEM
        break;
    }
    default:
        rt_log("[schannel] QueryContextAttributes(0x%x) not supported\n", a);
        RET(SEC_E_UNSUPPORTED_FUNCTION); return;
    }
    RET(SEC_E_OK);
}
static void FreeContextBuffer(CPU *c) { free(PTR(A0)); RET(SEC_E_OK); }
static void CompleteAuthToken(CPU *c) { RET(SEC_E_UNSUPPORTED_FUNCTION); }
static void Unsupported(CPU *c) { rt_log("[schannel] unsupported SSPI function called (fn 0x%llx)\n", (unsigned long long)c->fn); RET(SEC_E_UNSUPPORTED_FUNCTION); }

// ---------------- the function table ----------------
// SecurityFunctionTable: dwVersion, then 30 function pointers (the A and W tables differ only in string arguments)
typedef struct { int slot; gfn a, w; const char *name; } Slot;
static const Slot slots[] = {
    { 3, AcquireCredentialsHandleA, AcquireCredentialsHandleW, "AcquireCredentialsHandle" },
    { 4, FreeCredentialsHandle, FreeCredentialsHandle, "FreeCredentialsHandle" },
    { 6, InitializeSecurityContextA, InitializeSecurityContextW, "InitializeSecurityContext" },
    { 8, CompleteAuthToken, CompleteAuthToken, "CompleteAuthToken" },
    { 9, DeleteSecurityContext, DeleteSecurityContext, "DeleteSecurityContext" },
    { 10, ApplyControlToken, ApplyControlToken, "ApplyControlToken" },
    { 11, QueryContextAttributes, QueryContextAttributes, "QueryContextAttributes" },
    { 16, FreeContextBuffer, FreeContextBuffer, "FreeContextBuffer" },
    { 25, EncryptMessage, EncryptMessage, "EncryptMessage" },
    { 26, DecryptMessage, DecryptMessage, "DecryptMessage" },
};
static uint64_t table(int wide) {
    static uint64_t t[2][32];
    static int built[2];
    if (!built[wide]) {
        t[wide][0] = 4;   // SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_4
        for (int i = 1; i < 31; i++) t[wide][i] = rt_host_fn(Unsupported, "secur32!(unsupported)");
        for (size_t k = 0; k < sizeof slots / sizeof *slots; k++)
            t[wide][slots[k].slot] = rt_host_fn(wide ? slots[k].w : slots[k].a, slots[k].name);
        built[wide] = 1;
    }
    return G(t[wide]);
}

#define EXPORTS(dll) \
    void I_##dll##_dll_InitSecurityInterfaceA(CPU *c) { RET(table(0)); } \
    void I_##dll##_dll_InitSecurityInterfaceW(CPU *c) { RET(table(1)); } \
    void I_##dll##_dll_AcquireCredentialsHandleA(CPU *c) { AcquireCredentialsHandleA(c); } \
    void I_##dll##_dll_AcquireCredentialsHandleW(CPU *c) { AcquireCredentialsHandleW(c); } \
    void I_##dll##_dll_FreeCredentialsHandle(CPU *c) { FreeCredentialsHandle(c); } \
    void I_##dll##_dll_InitializeSecurityContextA(CPU *c) { InitializeSecurityContextA(c); } \
    void I_##dll##_dll_InitializeSecurityContextW(CPU *c) { InitializeSecurityContextW(c); } \
    void I_##dll##_dll_CompleteAuthToken(CPU *c) { CompleteAuthToken(c); } \
    void I_##dll##_dll_DeleteSecurityContext(CPU *c) { DeleteSecurityContext(c); } \
    void I_##dll##_dll_ApplyControlToken(CPU *c) { ApplyControlToken(c); } \
    void I_##dll##_dll_QueryContextAttributesA(CPU *c) { QueryContextAttributes(c); } \
    void I_##dll##_dll_QueryContextAttributesW(CPU *c) { QueryContextAttributes(c); } \
    void I_##dll##_dll_FreeContextBuffer(CPU *c) { FreeContextBuffer(c); } \
    void I_##dll##_dll_EncryptMessage(CPU *c) { EncryptMessage(c); } \
    void I_##dll##_dll_DecryptMessage(CPU *c) { DecryptMessage(c); }
EXPORTS(secur32)
EXPORTS(security)
EXPORTS(sspicli)
