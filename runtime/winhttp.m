// winhttp.dll on NSURLSession. Sessions, connections and requests are host structs (HINTERNET = pointer).
//
// Synchronous mode: the HTTP exchange runs in WinHttpReceiveResponse.
// Asynchronous mode (WinHttpOpen with WINHTTP_FLAG_ASYNC): calls return at once and a worker thread, with
// its own guest CPU, performs the work and calls the status callback with the usual notifications
// (SENDREQUEST_COMPLETE, WRITE_COMPLETE, HEADERS_AVAILABLE, DATA_AVAILABLE, READ_COMPLETE, REQUEST_ERROR,
// HANDLE_CLOSING), in order, one at a time.
// Bodies are buffered in memory (the game's requests and responses are small).
#import <Foundation/Foundation.h>
#include <pthread.h>
#include "rt.h"
#include "game.h"

#define FLAG_ASYNC 0x10000000u
#define FLAG_SECURE 0x00800000u
enum {
    ST_HANDLE_CLOSING = 0x00000800, ST_HEADERS_AVAILABLE = 0x00020000, ST_DATA_AVAILABLE = 0x00040000, ST_READ_COMPLETE = 0x00080000,
    ST_WRITE_COMPLETE = 0x00100000, ST_REQUEST_ERROR = 0x00200000, ST_SENDREQUEST_COMPLETE = 0x00400000,
};
enum { API_RECEIVE_RESPONSE = 1, API_QUERY_DATA_AVAILABLE = 2, API_READ_DATA = 3, API_WRITE_DATA = 4, API_SEND_REQUEST = 5 };
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_WINHTTP_TIMEOUT 12002
#define ERROR_WINHTTP_NAME_NOT_RESOLVED 12007
#define ERROR_WINHTTP_HEADER_NOT_FOUND 12150
#define ERROR_WINHTTP_CANNOT_CONNECT 12029
#define ERROR_WINHTTP_CONNECTION_ERROR 12030
#define ERROR_WINHTTP_SECURE_FAILURE 12175

enum { K_SESSION = 0x5345, K_CONNECT = 0x434F, K_REQUEST = 0x5251 };
typedef struct Hnd {
    int kind, async;
    uint64_t callback; uint32_t notify;   // status callback and its notification mask
    uint64_t context;
    struct Hnd *parent;
    int timeout_ms;
    // connect
    char *host; uint16_t port;
    // request
    char *verb, *path; int secure;
    NSMutableDictionary<NSString *, NSString *> *headers;
    NSMutableData *body;
    int status; NSDictionary *resp_headers; NSData *resp; size_t read_pos; char *status_text;
    int wk;   // async: 1 + the worker this handle's jobs run on (keeps its callbacks in order)
} Hnd;

static char *w2u(uint64_t p, int64_t n) {   // wide (n chars, or -1 = NUL-terminated) -> malloc'd UTF-8
    if (!p) return strdup("");
    if (n < 0) return w16_to_utf8(PTR(p));
    uint16_t *t = malloc(((size_t)n + 1) * 2); memcpy(t, PTR(p), (size_t)n * 2); t[n] = 0;
    char *s = w16_to_utf8(t); free(t); return s;
}
static void add_headers(Hnd *r, const char *text) {   // "Name: value\r\n..." lines
    char *dup = strdup(text), *save = NULL;
    for (char *line = strtok_r(dup, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0; char *v = colon + 1; while (*v == ' ') v++;
        r->headers[[NSString stringWithUTF8String:line]] = [NSString stringWithUTF8String:v];
    }
    free(dup);
}

// ---------------- the async worker ----------------
typedef struct Job { Hnd *h; int op; uint32_t n; uint64_t buf, out; struct Job *next; } Job;
// A pool of workers, each with its own guest CPU for status callbacks. Every request handle is pinned to
// one worker (round-robin), so its notifications stay in order while different requests run in parallel:
// the game probes several regional servers at once with a short timeout, and a slow one must not hold up
// the rest.
#define NWORKERS 16
typedef struct { Job *q, *tail; pthread_mutex_t mu; pthread_cond_t cv; CPU *cpu; int started; } Worker;
static Worker workers[NWORKERS];
static pthread_mutex_t wmu = PTHREAD_MUTEX_INITIALIZER;
static int next_worker;

static void notify(CPU *c, Hnd *h, uint32_t status, uint64_t info, uint32_t len) {
    Hnd *o = h; while (o && !o->callback) o = o->parent;   // the callback set on this handle or inherited
    if (!o || !(o->notify & status)) return;
    uint64_t a[5] = { G(h), h->context, status, info, len };
    guest_call(c, o->callback, 5, a);
}
static uint32_t ns_error(NSError *e) {
    if (!e) return 0;
    switch (e.code) {
    case NSURLErrorTimedOut: return ERROR_WINHTTP_TIMEOUT;
    case NSURLErrorCannotFindHost: case NSURLErrorDNSLookupFailed: return ERROR_WINHTTP_NAME_NOT_RESOLVED;
    case NSURLErrorCannotConnectToHost: case NSURLErrorNotConnectedToInternet: return ERROR_WINHTTP_CANNOT_CONNECT;
    case NSURLErrorSecureConnectionFailed: case NSURLErrorServerCertificateUntrusted: case NSURLErrorServerCertificateHasBadDate: return ERROR_WINHTTP_SECURE_FAILURE;
    default: return ERROR_WINHTTP_CONNECTION_ERROR;
    }
}
// perform the HTTP exchange (blocking); returns 0 or a WinHTTP error code
static uint32_t perform(Hnd *r) {
    Hnd *conn = r->parent, *sess = conn ? conn->parent : NULL;
    uint16_t port = conn->port ? conn->port : (r->secure ? 443 : 80);
    int default_port = port == (r->secure ? 443 : 80);
    NSString *url = [NSString stringWithFormat:@"%s://%s%@%s", r->secure ? "https" : "http", conn->host,
                     default_port ? @"" : [NSString stringWithFormat:@":%u", port], r->path[0] == '/' ? r->path : "/"];
    if (r->path[0] && r->path[0] != '/') url = [url stringByAppendingString:[NSString stringWithUTF8String:r->path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    if (!req.URL) { rt_log("[winhttp] bad URL %s\n", url.UTF8String); return ERROR_WINHTTP_NAME_NOT_RESOLVED; }
    req.HTTPMethod = [NSString stringWithUTF8String:r->verb];
    for (NSString *k in r->headers) [req setValue:r->headers[k] forHTTPHeaderField:k];
    if (r->body.length) req.HTTPBody = r->body;
    int tmo = r->timeout_ms ? r->timeout_ms : sess && sess->timeout_ms ? sess->timeout_ms : 30000;
    req.timeoutInterval = tmo / 1000.0;
    __block NSHTTPURLResponse *resp = nil; __block NSData *data = nil; __block NSError *err = nil;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg];
    [[s dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *rs, NSError *e) {
        data = d; resp = (NSHTTPURLResponse *)rs; err = e; dispatch_semaphore_signal(done);
    }] resume];
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    [s finishTasksAndInvalidate];
    static int logged;
    if (logged++ < 40) rt_log("[winhttp] %s %s -> %ld%s%s\n", r->verb, url.UTF8String, (long)(resp ? resp.statusCode : 0),
                              err ? " error: " : "", err ? err.localizedDescription.UTF8String : "");
    if (getenv("RT_HTTP_TRACE")) {   // full exchange, for debugging online services
        rt_log("[winhttp] >>> %s %s\n", r->verb, url.UTF8String);
        for (NSString *k in req.allHTTPHeaderFields) rt_log("[winhttp] >>> %s: %s\n", k.UTF8String, [req.allHTTPHeaderFields[k] UTF8String]);
        if (r->body.length) rt_log("[winhttp] >>> body (%lu): %.*s\n", (unsigned long)r->body.length, (int)(r->body.length > 4000 ? 4000 : r->body.length), (const char *)r->body.bytes);
        if (resp) for (NSString *k in resp.allHeaderFields) rt_log("[winhttp] <<< %s: %s\n", [k description].UTF8String, [[resp.allHeaderFields[k] description] UTF8String]);
        if (data.length) rt_log("[winhttp] <<< body (%lu): %.*s\n", (unsigned long)data.length, (int)(data.length > 4000 ? 4000 : data.length), (const char *)data.bytes);
    }
    if (err || !resp) return ns_error(err) ? ns_error(err) : ERROR_WINHTTP_CONNECTION_ERROR;
    r->status = (int)resp.statusCode;
    r->resp_headers = resp.allHeaderFields;
    r->resp = data ? data : [NSData data];
    r->read_pos = 0;
    free(r->status_text);
    r->status_text = strdup([NSHTTPURLResponse localizedStringForStatusCode:resp.statusCode].UTF8String);
    return 0;
}
static uint32_t avail(Hnd *r) { return r->resp ? (uint32_t)(r->resp.length - r->read_pos) : 0; }
static uint32_t read_into(Hnd *r, uint64_t buf, uint32_t n) {
    uint32_t k = avail(r); if (k > n) k = n;
    if (k) memcpy(PTR(buf), (const uint8_t *)r->resp.bytes + r->read_pos, k);
    r->read_pos += k;
    return k;
}
static void async_error(CPU *c, Hnd *h, int api, uint32_t err) {
    uint64_t res[2] = { (uint64_t)api, err };   // WINHTTP_ASYNC_RESULT { DWORD_PTR dwResult; DWORD dwError }
    notify(c, h, ST_REQUEST_ERROR, G(res), sizeof res);
}
static void *worker(void *p) {
    Worker *w = p;
    CPU *wcpu = w->cpu;
    rt_thread_signals();
    rt_set_cur(wcpu);
    pthread_setname_np("WinHTTP");
    for (;;) {
        pthread_mutex_lock(&w->mu);
        while (!w->q) pthread_cond_wait(&w->cv, &w->mu);
        Job *j = w->q; w->q = j->next; if (!w->q) w->tail = NULL;
        pthread_mutex_unlock(&w->mu);
        Hnd *h = j->h; uint32_t v;
        @autoreleasepool {
            switch (j->op) {
            case API_SEND_REQUEST: notify(wcpu, h, ST_SENDREQUEST_COMPLETE, 0, 0); break;
            case API_WRITE_DATA: v = j->n; notify(wcpu, h, ST_WRITE_COMPLETE, G(&v), 4); break;
            case API_RECEIVE_RESPONSE: { uint32_t e = perform(h); if (e) async_error(wcpu, h, API_RECEIVE_RESPONSE, e); else notify(wcpu, h, ST_HEADERS_AVAILABLE, 0, 0); break; }
            case API_QUERY_DATA_AVAILABLE: v = avail(h); if (j->out) wr32(j->out, v); notify(wcpu, h, ST_DATA_AVAILABLE, G(&v), 4); break;
            case API_READ_DATA: v = read_into(h, j->buf, j->n); if (j->out) wr32(j->out, v); notify(wcpu, h, ST_READ_COMPLETE, j->buf, v); break;
            case 99: {   // close
                uint64_t hv = G(h); notify(wcpu, h, ST_HANDLE_CLOSING, G(&hv), 8);
                free(h->host); free(h->verb); free(h->path); free(h->status_text);
                h->host = h->verb = h->path = h->status_text = NULL;
                h->headers = nil; h->body = nil; h->resp = nil; h->resp_headers = nil;
                // the struct itself stays: requests still walk ->parent to find the status callback after
                // their connection/session is closed (Windows keeps parents alive until children close)
                break;
            }
            }
        }
        free(j);
    }
    return NULL;
}
static void enqueue(Hnd *h, int op, uint32_t n, uint64_t buf, uint64_t out) {
    pthread_mutex_lock(&wmu);
    if (!h->wk) h->wk = 1 + next_worker++ % NWORKERS;
    Worker *w = &workers[h->wk - 1];
    if (!w->started) {
        pthread_mutex_init(&w->mu, NULL); pthread_cond_init(&w->cv, NULL);
        w->cpu = cpu_new(1u << 20); w->started = 1;
        pthread_t t; pthread_create(&t, NULL, worker, w); pthread_detach(t);
    }
    pthread_mutex_unlock(&wmu);
    Job *j = calloc(1, sizeof *j); *j = (Job){ h, op, n, buf, out, NULL };
    pthread_mutex_lock(&w->mu);
    if (w->tail) w->tail->next = j; else w->q = j;
    w->tail = j;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);
}
static Hnd *H(uint64_t p, int kind) { Hnd *h = PTR(p); return h && h->kind == kind ? h : NULL; }

// ---------------- API ----------------
// As if WinHTTP were unavailable: RT_NO_HTTP=1, or rt_game.offline_no_http with the Steam layer offline
void I_winhttp_dll_WinHttpCheckPlatform(CPU *c) {
    int off = getenv("RT_NO_HTTP") || (rt_game.offline_no_http && rt_steam_offline());
    if (off) rt_log("[winhttp] WinHttpCheckPlatform -> unavailable (%s)\n", getenv("RT_NO_HTTP") ? "RT_NO_HTTP" : "Steam offline");
    RET(!off);
}
// WinHttpOpen(agent, accessType, proxy, bypass, flags)
void I_winhttp_dll_WinHttpOpen(CPU *c) {
    Hnd *h = calloc(1, sizeof *h); h->kind = K_SESSION; h->async = ((uint32_t)AN(4) & FLAG_ASYNC) != 0;
    char *agent = w2u(A0, -1);
    rt_log("[winhttp] session \"%s\"%s\n", agent, h->async ? " (async)" : "");
    free(agent);
    RET(G(h));
}
// WinHttpConnect(session, server, port, reserved)
void I_winhttp_dll_WinHttpConnect(CPU *c) {
    Hnd *s = H(A0, K_SESSION); if (!s) { set_last_error(6); RET(0); return; }
    Hnd *h = calloc(1, sizeof *h); h->kind = K_CONNECT; h->parent = s; h->async = s->async;
    h->host = w2u(A1, -1); h->port = (uint16_t)A2;
    RET(G(h));
}
// WinHttpOpenRequest(connect, verb, object, version, referrer, acceptTypes, flags)
void I_winhttp_dll_WinHttpOpenRequest(CPU *c) {
    Hnd *cn = H(A0, K_CONNECT); if (!cn) { set_last_error(6); RET(0); return; }
    Hnd *h = calloc(1, sizeof *h); h->kind = K_REQUEST; h->parent = cn; h->async = cn->async;
    h->verb = A1 ? w2u(A1, -1) : strdup("GET"); h->path = A2 ? w2u(A2, -1) : strdup("/");
    h->secure = ((uint32_t)AN(6) & FLAG_SECURE) != 0;
    h->headers = [NSMutableDictionary new]; h->body = [NSMutableData new];
    RET(G(h));
}
// WinHttpAddRequestHeaders(request, headers, length, modifiers)
void I_winhttp_dll_WinHttpAddRequestHeaders(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r) { set_last_error(6); RET(0); return; }
    char *t = w2u(A1, (int32_t)A2 == -1 ? -1 : (int64_t)(uint32_t)A2); add_headers(r, t); free(t);
    RET(1);
}
// WinHttpSendRequest(request, headers, headersLength, optional, optionalLength, totalLength, context)
void I_winhttp_dll_WinHttpSendRequest(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r) { set_last_error(6); RET(0); return; }
    if (A1) { char *t = w2u(A1, (int32_t)A2 == -1 ? -1 : (int64_t)(uint32_t)A2); add_headers(r, t); free(t); }
    if (A3 && (uint32_t)AN(4)) [r->body appendBytes:PTR(A3) length:(uint32_t)AN(4)];   // optional data is the 4th arg (r9)
    r->context = AN(6);
    if (r->async) enqueue(r, API_SEND_REQUEST, 0, 0, 0);
    RET(1);
}
// WinHttpWriteData(request, buffer, length, *written)
void I_winhttp_dll_WinHttpWriteData(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r) { set_last_error(6); RET(0); return; }
    [r->body appendBytes:PTR(A1) length:(uint32_t)A2];
    if (A3) wr32(A3, (uint32_t)A2);
    if (r->async) enqueue(r, API_WRITE_DATA, (uint32_t)A2, 0, 0);
    RET(1);
}
// WinHttpReceiveResponse(request, reserved)
void I_winhttp_dll_WinHttpReceiveResponse(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r) { set_last_error(6); RET(0); return; }
    if (r->async) { enqueue(r, API_RECEIVE_RESPONSE, 0, 0, 0); RET(1); return; }
    uint32_t e;
    @autoreleasepool { e = perform(r); }
    if (e) { set_last_error(e); RET(0); return; }
    RET(1);
}
// WinHttpQueryDataAvailable(request, *bytes)
void I_winhttp_dll_WinHttpQueryDataAvailable(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r) { set_last_error(6); RET(0); return; }
    if (r->async) { enqueue(r, API_QUERY_DATA_AVAILABLE, 0, 0, A1); RET(1); return; }
    if (A1) wr32(A1, avail(r));
    RET(1);
}
// WinHttpReadData(request, buffer, toRead, *read)
void I_winhttp_dll_WinHttpReadData(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r) { set_last_error(6); RET(0); return; }
    if (r->async) { enqueue(r, API_READ_DATA, (uint32_t)A2, A1, A3); RET(1); return; }
    uint32_t k = read_into(r, A1, (uint32_t)A2);
    if (A3) wr32(A3, k);
    RET(1);
}
// WinHttpQueryHeaders(request, infoLevel, name, buffer, *bufferLength (bytes), *index)
static NSString *header(Hnd *r, NSString *name) {
    for (NSString *k in r->resp_headers) if ([k caseInsensitiveCompare:name] == NSOrderedSame) return [NSString stringWithFormat:@"%@", r->resp_headers[k]];
    return nil;
}
void I_winhttp_dll_WinHttpQueryHeaders(CPU *c) {
    Hnd *r = H(A0, K_REQUEST); if (!r || !r->resp) { set_last_error(r ? 12019 : 6); RET(0); return; }   // ERROR_WINHTTP_INCORRECT_HANDLE_STATE
    uint32_t level = (uint32_t)A1 & 0xFFFF, number = ((uint32_t)A1 & 0x20000000u) != 0;
    uint64_t buf = A3, plen = AN(4);
    NSString *v = nil;
    switch (level) {
    case 19: v = [NSString stringWithFormat:@"%d", r->status]; break;                                  // STATUS_CODE
    case 20: v = [NSString stringWithUTF8String:r->status_text ? r->status_text : ""]; break;           // STATUS_TEXT
    case 18: v = @"HTTP/1.1"; break;                                                                    // VERSION
    case 21: case 22: {                                                                                 // RAW_HEADERS(_CRLF)
        NSMutableString *s = [NSMutableString stringWithFormat:@"HTTP/1.1 %d %s\r\n", r->status, r->status_text ? r->status_text : ""];
        for (NSString *k in r->resp_headers) [s appendFormat:@"%@: %@\r\n", k, r->resp_headers[k]];
        [s appendString:@"\r\n"];
        if (level == 21) [s replaceOccurrencesOfString:@"\r\n" withString:@"\n" options:0 range:NSMakeRange(0, s.length)];
        v = s; break;
    }
    case 5: v = header(r, @"Content-Length"); if (!v) v = [NSString stringWithFormat:@"%lu", (unsigned long)r->resp.length]; break;
    case 1: v = header(r, @"Content-Type"); break;
    case 33: v = header(r, @"Location"); break;
    case 29: v = header(r, @"Content-Encoding"); break;
    case 65535: { char *n = w2u(A2, -1); v = header(r, [NSString stringWithUTF8String:n]); free(n); break; }   // CUSTOM
    default: rt_log("[winhttp] WinHttpQueryHeaders level %u not supported\n", level); break;
    }
    if (!v) { set_last_error(ERROR_WINHTTP_HEADER_NOT_FOUND); RET(0); return; }
    if (level == 21) v = [v stringByReplacingOccurrencesOfString:@"\n" withString:@"\0"];
    if (number) {
        if (rd32(plen) < 4 || !buf) { wr32(plen, 4); set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0); return; }
        wr32(buf, (uint32_t)v.longLongValue); wr32(plen, 4); RET(1); return;
    }
    uint16_t *w = utf8_to_w16(v.UTF8String); size_t chars = w16len(w);
    uint32_t need = (uint32_t)(chars + 1) * 2;
    if (!buf || rd32(plen) < need) { wr32(plen, need); free(w); set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0); return; }
    memcpy(PTR(buf), w, need); wr32(plen, need - 2);   // bytes, without the terminator
    free(w);
    RET(1);
}
// WinHttpSetStatusCallback(handle, callback, notificationFlags, reserved) -> previous callback
void I_winhttp_dll_WinHttpSetStatusCallback(CPU *c) {
    Hnd *h = PTR(A0); if (!h) { RET((uint64_t)-1); return; }
    uint64_t prev = h->callback; h->callback = A1; h->notify = (uint32_t)A2;
    RET(prev);
}
// WinHttpSetTimeouts(handle, resolve, connect, send, receive)
void I_winhttp_dll_WinHttpSetTimeouts(CPU *c) { Hnd *h = PTR(A0); if (h) { int t = (int)AN(4); h->timeout_ms = t > 0 ? t : 0; } RET(1); }
// WinHttpSetOption(handle, option, buffer, length): WINHTTP_OPTION_CONTEXT_VALUE (45) is honoured; others accepted
void I_winhttp_dll_WinHttpSetOption(CPU *c) {
    Hnd *h = PTR(A0);
    if (h && (uint32_t)A1 == 45 && A2) h->context = rd64(A2);
    RET(1);
}
void I_winhttp_dll_WinHttpCloseHandle(CPU *c) {
    Hnd *h = PTR(A0); if (!h) { RET(0); return; }
    if (h->async && h->kind == K_REQUEST) enqueue(h, 99, 0, 0, 0);   // after any pending work, with HANDLE_CLOSING
    else {   // sessions/connections: release the contents but keep the struct (queued requests walk ->parent)
        free(h->verb); free(h->path); free(h->status_text);
        h->verb = h->path = h->status_text = NULL;
        h->headers = nil; h->body = nil; h->resp = nil; h->resp_headers = nil;
    }
    RET(1);
}
