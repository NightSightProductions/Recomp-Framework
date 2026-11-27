// wsock32.dll (imported by ordinal) on BSD sockets, plus iphlpapi's adapter query.
// Ordinals 1-23 are alphabetical: ... 9 htons, 10 inet_addr, 11 inet_ntoa, 12 ioctlsocket, 13 listen ...
// SOCKET values are host fds. Windows sockaddr has a 16-bit family where macOS has sin_len + an 8-bit
// family; fd_set is a counted SOCKET array; timeval fields are 32-bit; SO_RCVTIMEO/SNDTIMEO are DWORD ms.
#include "rt.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define INVALID_SOCKET 0xFFFFFFFFFFFFFFFFull
#define SOCKET_ERROR 0xFFFFFFFFu
#define W_AF_INET6 23

static uint32_t wsa_err(int e) {
    switch (e) {
    case EWOULDBLOCK: return 10035;   // WSAEWOULDBLOCK (EAGAIN)
    case EINPROGRESS: return 10035;   // non-blocking connect: Windows reports WOULDBLOCK
    case EALREADY: return 10037;
    case ENOTSOCK: case EBADF: return 10038;
    case EMSGSIZE: return 10040;
    case EINVAL: return 10022;
    case EADDRINUSE: return 10048;
    case EADDRNOTAVAIL: return 10049;
    case ENETDOWN: return 10050;
    case ENETUNREACH: return 10051;
    case ECONNABORTED: return 10053;
    case ECONNRESET: return 10054;
    case ENOBUFS: return 10055;
    case EISCONN: return 10056;
    case ENOTCONN: return 10057;
    case ETIMEDOUT: return 10060;
    case ECONNREFUSED: return 10061;
    case EHOSTUNREACH: return 10065;
    case EAFNOSUPPORT: return 10047;
    case EACCES: return 10013;
    default: return 10004 + 0 * e;   // WSAEINTR as a generic failure
    }
}
static uint32_t fail(void) { set_last_error(wsa_err(errno)); return SOCKET_ERROR; }

// guest sockaddr -> host; returns the host length (0 if unsupported)
static socklen_t addr_in(uint64_t p, uint32_t len, struct sockaddr_storage *out) {
    memset(out, 0, sizeof *out);
    if (!p || len < 2) return 0;
    uint16_t fam = rd16(p);
    if (fam == AF_INET && len >= 16) {
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_len = sizeof *a; a->sin_family = AF_INET;
        memcpy(&a->sin_port, PTR(p + 2), 2); memcpy(&a->sin_addr, PTR(p + 4), 4);
        return sizeof *a;
    }
    if (fam == W_AF_INET6 && len >= 28) {   // sin6_port +2, sin6_flowinfo +4, sin6_addr +8, sin6_scope_id +24
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_len = sizeof *a; a->sin6_family = AF_INET6;
        memcpy(&a->sin6_port, PTR(p + 2), 2); memcpy(&a->sin6_flowinfo, PTR(p + 4), 4);
        memcpy(&a->sin6_addr, PTR(p + 8), 16); memcpy(&a->sin6_scope_id, PTR(p + 24), 4);
        return sizeof *a;
    }
    return 0;
}
// host sockaddr -> guest buffer with in/out length
static void addr_out(const struct sockaddr_storage *in, uint64_t p, uint64_t plen) {
    if (!p || !plen) return;
    uint32_t cap = rd32(plen);
    uint8_t buf[28] = { 0 }; uint32_t n = 0;
    if (in->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)in;
        buf[0] = AF_INET; memcpy(buf + 2, &a->sin_port, 2); memcpy(buf + 4, &a->sin_addr, 4); n = 16;
    } else if (in->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)in;
        buf[0] = W_AF_INET6; memcpy(buf + 2, &a->sin6_port, 2); memcpy(buf + 4, &a->sin6_flowinfo, 4);
        memcpy(buf + 8, &a->sin6_addr, 16); memcpy(buf + 24, &a->sin6_scope_id, 4); n = 28;
    }
    memcpy(PTR(p), buf, n < cap ? n : cap);
    wr32(plen, n);
}
static void net_addr_str(const struct sockaddr_storage *a, char *out, size_t n) {
    char ip[INET6_ADDRSTRLEN] = "?"; int port = 0;
    if (a->ss_family == AF_INET) { inet_ntop(AF_INET, &((const struct sockaddr_in *)a)->sin_addr, ip, sizeof ip); port = ntohs(((const struct sockaddr_in *)a)->sin_port); }
    else if (a->ss_family == AF_INET6) { inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)a)->sin6_addr, ip, sizeof ip); port = ntohs(((const struct sockaddr_in6 *)a)->sin6_port); }
    snprintf(out, n, "%s:%d", ip, port);
}
static int sfd(uint64_t s) { return s == INVALID_SOCKET ? -1 : (int)s; }
// RT_NET_TRACE=1: log socket setup and the first receive on each socket (with its blocking mode)
static int net_trace = -1;
#define NT(...) do { if (net_trace < 0) net_trace = getenv("RT_NET_TRACE") != NULL; if (net_trace) rt_log(__VA_ARGS__); } while (0)

// #115 WSAStartup(version, WSADATA*) / #116 WSACleanup / #111 WSAGetLastError / #112 WSASetLastError
void I_wsock32_dll__115(CPU *c) {
    uint64_t d = A1;
    if (d) { memset(PTR(d), 0, 408); wr16(d, 0x0202); wr16(d + 2, 0x0202); wr16(d + 4, 32767); wr16(d + 6, 65467); strcpy(PTR(d + 16), "WinSock 2.0"); strcpy(PTR(d + 273), "Running"); }
    RET(0);
}
void I_wsock32_dll__116(CPU *c) { RET(0); }
void I_wsock32_dll__111(CPU *c) { RET(get_last_error()); }
void I_wsock32_dll__112(CPU *c) { set_last_error((uint32_t)A0); }
// #23 socket(af, type, protocol)
void I_wsock32_dll__23(CPU *c) {
    int af = (int)A0 == W_AF_INET6 ? AF_INET6 : (int)A0;
    int fd = socket(af, (int)A1, (int)A2);
    if (fd < 0) { set_last_error(wsa_err(errno)); RET(INVALID_SOCKET); return; }
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    NT("[net] socket(af %d, type %d, proto %d) -> %d\n", (int)A0, (int)A1, (int)A2, fd);
    RET((uint64_t)fd);
}
static void ws_forget(int fd);
static void ws_connecting(int fd);
static void ws_write_blocked(int fd);
static void ws_rearm(int fd, uint32_t bits);
void I_wsock32_dll__3(CPU *c) { NT("[net] closesocket(%d)\n", sfd(A0)); ws_forget(sfd(A0)); RET(close(sfd(A0)) ? fail() : 0); }   // closesocket
// #2 bind(s, addr, len) / #4 connect(s, addr, len)
static void addr_call(CPU *c, int connect_) {
    struct sockaddr_storage a; socklen_t n = addr_in(A1, (uint32_t)A2, &a);
    if (!n) { set_last_error(10047); RET(SOCKET_ERROR); return; }
    if (connect_) ws_connecting(sfd(A0));
    int r = connect_ ? connect(sfd(A0), (struct sockaddr *)&a, n) : bind(sfd(A0), (struct sockaddr *)&a, n);
    { char h[64]; net_addr_str(&a, h, sizeof h); NT("[net] %s(%d, %s) -> %d (errno %d)\n", connect_ ? "connect" : "bind", sfd(A0), h, r, r ? errno : 0); }
    RET(r ? fail() : 0);
}
void I_wsock32_dll__2(CPU *c) { addr_call(c, 0); }
void I_wsock32_dll__4(CPU *c) { addr_call(c, 1); }
// #6 getsockname(s, addr, *len) / #5 getpeername
static void name_call(CPU *c, int peer) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    int r = peer ? getpeername(sfd(A0), (struct sockaddr *)&a, &n) : getsockname(sfd(A0), (struct sockaddr *)&a, &n);
    if (r) { RET(fail()); return; }
    addr_out(&a, A1, A2); RET(0);
}
void I_wsock32_dll__6(CPU *c) { name_call(c, 0); }
void I_wsock32_dll__5(CPU *c) { name_call(c, 1); }
// #12 ioctlsocket(s, cmd, *arg): FIONBIO, FIONREAD
void I_wsock32_dll__12(CPU *c) {
    int fd = sfd(A0); uint32_t cmd = (uint32_t)A1;
    NT("[net] ioctlsocket(%d, 0x%x, %u)\n", fd, cmd, A2 ? rd32(A2) : 0);
    if (cmd == 0x8004667Eu) {   // FIONBIO
        int fl = fcntl(fd, F_GETFL);
        if (fl < 0 || fcntl(fd, F_SETFL, rd32(A2) ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK))) { RET(fail()); return; }
        RET(0); return;
    }
    if (cmd == 0x4004667Fu) { int n = 0; if (ioctl(fd, FIONREAD, &n)) { RET(fail()); return; } wr32(A2, (uint32_t)n); RET(0); return; }
    set_last_error(10022); RET(SOCKET_ERROR);
}
// #21 setsockopt(s, level, name, value, len) / #7 getsockopt(s, level, name, value, *len)
static int map_opt(int level, int name, int *hl, int *hn) {
    *hl = level == 0xFFFF ? SOL_SOCKET : level; *hn = name;
    if (level == 0xFFFF) {
        switch (name) {
        case 0x0004: *hn = SO_REUSEADDR; return 1;  case 0x0020: *hn = SO_BROADCAST; return 1;
        case 0x0008: *hn = SO_KEEPALIVE; return 1;  case 0x0080: *hn = SO_LINGER; return 1;
        case 0x1001: *hn = SO_SNDBUF; return 1;     case 0x1002: *hn = SO_RCVBUF; return 1;
        case 0x1005: *hn = SO_SNDTIMEO; return 2;   case 0x1006: *hn = SO_RCVTIMEO; return 2;   // DWORD ms
        case 0x1007: *hn = SO_ERROR; return 1;      case 0x1008: *hn = SO_TYPE; return 1;
        case (int)0xFFFFFFFBu: return 0;            // SO_EXCLUSIVEADDRUSE: no equivalent; accept
        default: return 0;
        }
    }
    if (level == IPPROTO_TCP && name == 1) { *hn = TCP_NODELAY; return 1; }
    if (level == IPPROTO_IP && name == 4) { *hn = IP_TTL; return 1; }
    return 0;
}
void I_wsock32_dll__21(CPU *c) {
    int hl, hn, kind = map_opt((int)A1, (int)A2, &hl, &hn);
    if (!kind) { RET(0); return; }   // unknown options are accepted and ignored
    int r;
    if (kind == 2) { uint32_t ms = rd32(A3); struct timeval tv = { ms / 1000, (int)(ms % 1000) * 1000 }; r = setsockopt(sfd(A0), hl, hn, &tv, sizeof tv); }
    else if (hn == SO_LINGER) { struct linger l = { rd16(A3), rd16(A3 + 2) }; r = setsockopt(sfd(A0), hl, hn, &l, sizeof l); }
    else { int v = (uint32_t)AN(4) >= 4 ? (int)rd32(A3) : rd8(A3); r = setsockopt(sfd(A0), hl, hn, &v, sizeof v); }
    RET(r ? fail() : 0);
}
void I_wsock32_dll__7(CPU *c) {
    int hl, hn, kind = map_opt((int)A1, (int)A2, &hl, &hn);
    uint64_t out = A3, plen = AN(4);
    if (!kind) { if (rd32(plen) >= 4) { wr32(out, 0); wr32(plen, 4); } RET(0); return; }
    if (kind == 2) { struct timeval tv; socklen_t n = sizeof tv; if (getsockopt(sfd(A0), hl, hn, &tv, &n)) { RET(fail()); return; } wr32(out, (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000)); wr32(plen, 4); RET(0); return; }
    int v = 0; socklen_t n = sizeof v;
    if (getsockopt(sfd(A0), hl, hn, &v, &n)) { RET(fail()); return; }
    if (hn == SO_ERROR) v = v ? (int)wsa_err(v) : 0;
    wr32(out, (uint32_t)v); wr32(plen, 4); RET(0);
}
// #16 recv(s, buf, len, flags) / #19 send(s, buf, len, flags): MSG_OOB 1, MSG_PEEK 2 match
void I_wsock32_dll__16(CPU *c) { ws_rearm(sfd(A0), 1 | 32); ssize_t r = recv(sfd(A0), PTR(A1), (size_t)(int32_t)A2, (int)A3 & 3); RET(r < 0 ? fail() : (uint32_t)r); }
void I_wsock32_dll__19(CPU *c) {
    ssize_t r = send(sfd(A0), PTR(A1), (size_t)(int32_t)A2, (int)A3 & 1);
    if (r < 0 && errno == EWOULDBLOCK) ws_write_blocked(sfd(A0));
    RET(r < 0 ? fail() : (uint32_t)r);
}
// #17 recvfrom(s, buf, len, flags, from, *fromlen)
void I_wsock32_dll__17(CPU *c) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    { static uint8_t seen[1024]; int fd = sfd(A0);
      if (fd >= 0 && fd < 1024 && !seen[fd]) { seen[fd] = 1; NT("[net] first recvfrom(%d, flags %d): %s\n", fd, (int)A3, (fcntl(fd, F_GETFL) & O_NONBLOCK) ? "non-blocking" : "BLOCKING"); } }
    ws_rearm(sfd(A0), 1 | 32);   // FD_READ, FD_CLOSE: re-enabled by a receive
    ssize_t r = recvfrom(sfd(A0), PTR(A1), (size_t)(int32_t)A2, (int)A3 & 3, (struct sockaddr *)&a, &n);
    if (r >= 0 || errno != EWOULDBLOCK) { static int k; if (k < 200) { k++; char h[64] = "?"; net_addr_str(&a, h, sizeof h); NT("[net] recvfrom(%d) -> %zd from %s%s\n", sfd(A0), r, h, r < 0 ? strerror(errno) : ""); } }
    if (r < 0) { RET(fail()); return; }
    addr_out(&a, AN(4), AN(5));
    RET((uint32_t)r);
}
// #20 sendto(s, buf, len, flags, to, tolen)
void I_wsock32_dll__20(CPU *c) {
    struct sockaddr_storage a; socklen_t n = addr_in(AN(4), (uint32_t)AN(5), &a);
    ssize_t r = n ? sendto(sfd(A0), PTR(A1), (size_t)(int32_t)A2, (int)A3 & 1, (struct sockaddr *)&a, n)
                  : send(sfd(A0), PTR(A1), (size_t)(int32_t)A2, (int)A3 & 1);
    if (r < 0 && errno == EWOULDBLOCK) ws_write_blocked(sfd(A0));
    { static int k; if (k < 200) { k++; char h[64] = "?"; if (n) net_addr_str(&a, h, sizeof h); NT("[net] sendto(%d, %d bytes, %s) -> %zd%s%s\n", sfd(A0), (int)A2, h, r, r < 0 ? " " : "", r < 0 ? strerror(errno) : ""); } }
    RET(r < 0 ? fail() : (uint32_t)r);
}
// #18 select(nfds, read, write, except, timeval*): fd_set = { u_int fd_count; SOCKET fd_array[64] } (x64: array at +8)
static int set_in(uint64_t p, fd_set *s, int *maxfd) {
    FD_ZERO(s);
    if (!p) return 0;
    uint32_t n = rd32(p); if (n > 64) n = 64;
    for (uint32_t i = 0; i < n; i++) { int fd = (int)rd64(p + 8 + 8ull * i); if (fd >= 0 && fd < FD_SETSIZE) { FD_SET(fd, s); if (fd > *maxfd) *maxfd = fd; } }
    return 1;
}
static void set_out(uint64_t p, fd_set *s) {
    if (!p) return;
    uint32_t n = rd32(p), k = 0; if (n > 64) n = 64;
    for (uint32_t i = 0; i < n; i++) { uint64_t fd = rd64(p + 8 + 8ull * i); if ((int)fd >= 0 && (int)fd < FD_SETSIZE && FD_ISSET((int)fd, s)) wr64(p + 8 + 8ull * k++, fd); }
    wr32(p, k);
}
void I_wsock32_dll__18(CPU *c) {
    fd_set r, w, e; int maxfd = -1;
    { static int n; if (n < 5) { n++; NT("[net] select(read %u, write %u, except %u, timeout %s)\n", A1 ? rd32(A1) : 0, A2 ? rd32(A2) : 0, A3 ? rd32(A3) : 0, AN(4) ? "set" : "none"); } }
    set_in(A1, &r, &maxfd); set_in(A2, &w, &maxfd); set_in(A3, &e, &maxfd);
    struct timeval tv, *ptv = NULL;
    if (AN(4)) { tv.tv_sec = (int32_t)rd32(AN(4)); tv.tv_usec = (int32_t)rd32(AN(4) + 4); ptv = &tv; }
    int n = select(maxfd + 1, A1 ? &r : NULL, A2 ? &w : NULL, A3 ? &e : NULL, ptv);
    if (n < 0) { RET(fail()); return; }
    set_out(A1, &r); set_out(A2, &w); set_out(A3, &e);
    RET((uint32_t)n);
}
// #1 accept(s, addr, *len) / #13 listen(s, backlog) / #22 shutdown(s, how): SD_RECEIVE 0, SD_SEND 1, SD_BOTH 2 match
void I_wsock32_dll__1(CPU *c) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    ws_rearm(sfd(A0), 8);   // FD_ACCEPT
    int fd = accept(sfd(A0), (struct sockaddr *)&a, &n);
    if (fd < 0) { set_last_error(wsa_err(errno)); RET(INVALID_SOCKET); return; }
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    addr_out(&a, A1, A2); RET((uint64_t)fd);
}
void I_wsock32_dll__13(CPU *c) { RET(listen(sfd(A0), (int)A1) ? fail() : 0); }
void I_wsock32_dll__22(CPU *c) { RET(shutdown(sfd(A0), (int)A1) ? fail() : 0); }
// #8 htonl, #9 htons, #14 ntohl, #15 ntohs
void I_wsock32_dll__8(CPU *c) { RET(__builtin_bswap32((uint32_t)A0)); }
void I_wsock32_dll__9(CPU *c) { RET(__builtin_bswap16((uint16_t)A0)); }
void I_wsock32_dll__14(CPU *c) { RET(__builtin_bswap32((uint32_t)A0)); }
void I_wsock32_dll__15(CPU *c) { RET(__builtin_bswap16((uint16_t)A0)); }
// #11 inet_ntoa(in_addr by value) -> per-thread static string
void I_wsock32_dll__11(CPU *c) {
    static __thread char buf[16];
    uint32_t a = (uint32_t)A0;
    snprintf(buf, sizeof buf, "%u.%u.%u.%u", a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, a >> 24);
    RET(G(buf));
}
// #10 inet_addr("a.b.c.d")
void I_wsock32_dll__10(CPU *c) { struct in_addr a; RET(inet_aton(PTR(A0), &a) ? a.s_addr : 0xFFFFFFFFu); }
// #52 gethostbyname(name): IPv4 only. hostent (x64): h_name +0, h_aliases +8, h_addrtype +16, h_length +18, h_addr_list +24
void I_wsock32_dll__52(CPU *c) {
    static __thread uint8_t he[32]; static __thread char name[256]; static __thread uint32_t addrs[8]; static __thread uint64_t list[9], aliases[1];
    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family = AF_INET;
    if (!A0 || getaddrinfo(PTR(A0), NULL, &hints, &res)) { set_last_error(11001); RET(0); return; }   // WSAHOST_NOT_FOUND
    int n = 0;
    for (struct addrinfo *r = res; r && n < 8; r = r->ai_next) addrs[n++] = ((struct sockaddr_in *)r->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    strlcpy(name, PTR(A0), sizeof name);
    for (int i = 0; i < n; i++) list[i] = G(&addrs[i]);
    list[n] = 0; aliases[0] = 0;
    uint64_t p = G(he);
    wr64(p, G(name)); wr64(p + 8, G(aliases)); wr16(p + 16, AF_INET); wr16(p + 18, 4); wr64(p + 24, G(list));
    RET(p);
}
// #57 gethostname(buf, len)
void I_wsock32_dll__57(CPU *c) { if (gethostname(PTR(A0), (size_t)(int32_t)A1)) { RET(fail()); return; } RET(0); }

// iphlpapi GetAdaptersInfo(IP_ADAPTER_INFO*, *size): the active IPv4 interfaces (not loopback), with their MAC
// address. Win64 IP_ADAPTER_INFO is 704 bytes: Next +0, ComboIndex +8, AdapterName[260] +12, Description[132]
// +272, AddressLength +404, Address[8] +408, Index +416, Type +420, DhcpEnabled +424, CurrentIpAddress +432,
// IpAddressList +440 (IP_ADDR_STRING: Next +0, IpAddress[16] +8, IpMask[16] +24, Context +40), GatewayList +488.
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <arpa/inet.h>
#define ADAPTER_SIZE 704
void I_iphlpapi_dll_GetAdaptersInfo(CPU *c) {
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs)) { RET(232); return; }   // ERROR_NO_DATA
    struct { char name[IFNAMSIZ]; struct in_addr ip, mask; uint8_t mac[6]; int hasmac; unsigned idx; } a[16]; int n = 0;
    for (struct ifaddrs *i = ifs; i && n < 16; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET || (i->ifa_flags & IFF_LOOPBACK) || !(i->ifa_flags & IFF_UP)) continue;
        snprintf(a[n].name, sizeof a[n].name, "%s", i->ifa_name);
        a[n].ip = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
        a[n].mask = i->ifa_netmask ? ((struct sockaddr_in *)i->ifa_netmask)->sin_addr : (struct in_addr){ 0 };
        a[n].hasmac = 0; a[n].idx = if_nametoindex(i->ifa_name);
        for (struct ifaddrs *l = ifs; l; l = l->ifa_next)
            if (l->ifa_addr && l->ifa_addr->sa_family == AF_LINK && !strcmp(l->ifa_name, i->ifa_name)) {
                struct sockaddr_dl *dl = (struct sockaddr_dl *)l->ifa_addr;
                if (dl->sdl_alen == 6) { memcpy(a[n].mac, LLADDR(dl), 6); a[n].hasmac = 1; }
            }
        n++;
    }
    freeifaddrs(ifs);
    if (!n) { RET(232); return; }
    uint32_t need = (uint32_t)n * ADAPTER_SIZE, have = A1 ? rd32(A1) : 0;
    if (A1) wr32(A1, need);
    if (!A0 || have < need) { RET(111); return; }   // ERROR_BUFFER_OVERFLOW
    memset(PTR(A0), 0, need);
    for (int k = 0; k < n; k++) {
        uint64_t p = A0 + (uint64_t)k * ADAPTER_SIZE;
        wr64(p, k + 1 < n ? p + ADAPTER_SIZE : 0);
        wr32(p + 8, a[k].idx);
        snprintf(PTR(p + 12), 260, "{%08X-0000-0000-0000-%012X}", a[k].idx, a[k].idx);
        snprintf(PTR(p + 272), 132, "%s", a[k].name);
        wr32(p + 404, a[k].hasmac ? 6 : 0);
        memcpy(PTR(p + 408), a[k].mac, 6);
        wr32(p + 416, a[k].idx);
        wr32(p + 420, 6);   // MIB_IF_TYPE_ETHERNET
        wr32(p + 424, 1);
        wr64(p + 432, p + 440);
        inet_ntop(AF_INET, &a[k].ip, PTR(p + 440 + 8), 16);
        inet_ntop(AF_INET, &a[k].mask, PTR(p + 440 + 24), 16);
        snprintf(PTR(p + 488 + 8), 16, "0.0.0.0");
    }
    RET(0);
}

// iphlpapi GetAdaptersAddresses(family, flags, reserved, IP_ADAPTER_ADDRESSES *, *size): the interfaces that are up,
// with their IPv4 and IPv6 addresses. Win64 IP_ADAPTER_ADDRESSES_LH (448 bytes): Length +0, IfIndex +4, Next +8,
// AdapterName +16, FirstUnicastAddress +24, Anycast +32, Multicast +40, DnsServer +48, DnsSuffix +56,
// Description +64, FriendlyName +72, PhysicalAddress[8] +80, PhysicalAddressLength +88, Flags +92, Mtu +96,
// IfType +100, OperStatus +104, Ipv6IfIndex +108, ZoneIndices[16] +112, FirstPrefix +176, TransmitLinkSpeed +184,
// ReceiveLinkSpeed +192, FirstWinsServer +200, FirstGateway +208, Ipv4Metric +216, Ipv6Metric +220, Luid +224, ...,
// ConnectionType +268. IP_ADAPTER_UNICAST_ADDRESS_LH (64 bytes): Length +0, Flags +4, Next +8, Address
// { lpSockaddr +16, iSockaddrLength +24 }, PrefixOrigin +32, SuffixOrigin +36, DadState +40, ValidLifetime +44,
// PreferredLifetime +48, LeaseLifetime +52, OnLinkPrefixLength +56.
#define AA_SIZE 448
#define UA_SIZE 64
static uint8_t prefix_len(const struct sockaddr *m) {
    if (!m) return 0;
    const uint8_t *b; size_t n;
    if (m->sa_family == AF_INET) { b = (const uint8_t *)&((const struct sockaddr_in *)m)->sin_addr; n = 4; }
    else if (m->sa_family == AF_INET6) { b = (const uint8_t *)&((const struct sockaddr_in6 *)m)->sin6_addr; n = 16; }
    else return 0;
    uint8_t l = 0; for (size_t i = 0; i < n; i++) l += (uint8_t)__builtin_popcount(b[i]);
    return l;
}
void I_iphlpapi_dll_GetAdaptersAddresses(CPU *c) {
    uint32_t fam = (uint32_t)A0; uint64_t buf = A3, psize = AN(4);
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs)) { RET(232); return; }   // ERROR_NO_DATA
    // interfaces (by name, in order) that are up and have an address of the family asked for
    char names[32][IFNAMSIZ]; int nn = 0, nu[32] = { 0 };
    for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || !(i->ifa_flags & IFF_UP)) continue;
        int f = i->ifa_addr->sa_family;
        if (!((f == AF_INET && (fam == 0 || fam == AF_INET)) || (f == AF_INET6 && (fam == 0 || fam == W_AF_INET6)))) continue;
        int k = 0; while (k < nn && strcmp(names[k], i->ifa_name)) k++;
        if (k == nn) { if (nn == 32) continue; snprintf(names[nn++], IFNAMSIZ, "%s", i->ifa_name); }
        nu[k]++;
    }
    size_t need = 0;
    for (int k = 0; k < nn; k++) need += AA_SIZE + 64 + 3 * 2 * 64 + (size_t)nu[k] * 2 * (UA_SIZE + 32);
    if (!nn) { freeifaddrs(ifs); RET(232); return; }
    uint32_t have = psize ? rd32(psize) : 0;
    if (psize) wr32(psize, (uint32_t)need);
    if (!buf || have < need) { freeifaddrs(ifs); RET(111); return; }   // ERROR_BUFFER_OVERFLOW
    memset(PTR(buf), 0, need);
    uint64_t at = buf, prev = 0;
    for (int k = 0; k < nn; k++) {
        uint64_t a = at; at += AA_SIZE;
        if (prev) wr64(prev + 8, a);
        prev = a;
        unsigned idx = if_nametoindex(names[k]);
        int loop = 0, mtu = 1500; uint8_t mac[6]; int hasmac = 0;
        for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
            if (strcmp(i->ifa_name, names[k])) continue;
            if (i->ifa_flags & IFF_LOOPBACK) loop = 1;
            if (i->ifa_addr && i->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *dl = (struct sockaddr_dl *)i->ifa_addr;
                if (dl->sdl_alen == 6) { memcpy(mac, LLADDR(dl), 6); hasmac = 1; }
                if (i->ifa_data) mtu = (int)((struct if_data *)i->ifa_data)->ifi_mtu;
            }
        }
        wr32(a, AA_SIZE); wr32(a + 4, idx);
        // strings: AdapterName (a GUID, as Windows names adapters), DnsSuffix, Description, FriendlyName
        uint64_t name = at; at += 64;
        snprintf(PTR(name), 64, "{%08X-0000-0000-0000-%012X}", idx, idx);
        wr64(a + 16, name);
        uint64_t ws[3]; const char *txt[3] = { "", names[k], names[k] };
        for (int t = 0; t < 3; t++) {
            ws[t] = at; at += 2 * 64;
            for (int q = 0; txt[t][q] && q < 63; q++) wr16(ws[t] + 2 * (uint64_t)q, (uint8_t)txt[t][q]);
        }
        wr64(a + 56, ws[0]); wr64(a + 64, ws[1]); wr64(a + 72, ws[2]);
        if (hasmac && !loop) { memcpy(PTR(a + 80), mac, 6); wr32(a + 88, 6); }
        wr32(a + 92, 0x20 | 0x100 | 0x80);   // IP_ADAPTER_DHCP_ENABLED-ish defaults: IPV4_ENABLED 0x80, IPV6_ENABLED 0x100
        wr32(a + 96, (uint32_t)mtu);
        wr32(a + 100, loop ? 24 : 6);        // IF_TYPE_SOFTWARE_LOOPBACK / IF_TYPE_ETHERNET_CSMACD
        wr32(a + 104, 1);                    // IfOperStatusUp
        wr32(a + 108, idx);
        wr64(a + 184, 1000000000ull); wr64(a + 192, 1000000000ull);
        wr32(a + 216, loop ? 75 : 25); wr32(a + 220, loop ? 75 : 25);
        wr64(a + 224, ((uint64_t)(loop ? 24 : 6) << 48) | idx);   // NET_LUID: IfType in the top 16 bits
        wr32(a + 268, 1);                    // NET_IF_CONNECTION_DEDICATED
        uint64_t uprev = 0, pprev = 0;
        for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
            if (strcmp(i->ifa_name, names[k]) || !i->ifa_addr) continue;
            int f = i->ifa_addr->sa_family;
            if (!((f == AF_INET && (fam == 0 || fam == AF_INET)) || (f == AF_INET6 && (fam == 0 || fam == W_AF_INET6)))) continue;
            uint64_t u = at; at += UA_SIZE; uint64_t sa = at; at += 32;
            struct sockaddr_storage ss; memset(&ss, 0, sizeof ss);
            memcpy(&ss, i->ifa_addr, f == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            uint32_t len = 32; addr_out(&ss, sa, G(&len));
            wr32(u, UA_SIZE); wr32(u + 4, 0);
            wr64(u + 16, sa); wr32(u + 24, len);
            wr32(u + 32, 4); wr32(u + 36, 4); wr32(u + 40, 4);   // PrefixOrigin/SuffixOrigin Dhcp-like, IpDadStatePreferred
            wr32(u + 44, 0xFFFFFFFFu); wr32(u + 48, 0xFFFFFFFFu); wr32(u + 52, 0xFFFFFFFFu);
            wr8(u + 56, prefix_len(i->ifa_netmask));
            if (uprev) wr64(uprev + 8, u); else wr64(a + 24, u);
            uprev = u;
            // its on-link prefix (IP_ADAPTER_PREFIX: Length +0, Flags +4, Next +8, Address +16/+24, PrefixLength +32)
            uint8_t pl = prefix_len(i->ifa_netmask);
            uint64_t px = at; at += UA_SIZE; uint64_t psa = at; at += 32;
            struct sockaddr_storage ps = ss;
            uint8_t *ab = f == AF_INET ? (uint8_t *)&((struct sockaddr_in *)&ps)->sin_addr : (uint8_t *)&((struct sockaddr_in6 *)&ps)->sin6_addr;
            int nb = f == AF_INET ? 4 : 16;
            for (int b = 0; b < nb; b++) { int keep = pl - 8 * b; ab[b] &= keep >= 8 ? 0xFF : keep <= 0 ? 0 : (uint8_t)(0xFF << (8 - keep)); }
            if (f == AF_INET6) ((struct sockaddr_in6 *)&ps)->sin6_scope_id = 0;
            uint32_t plen2 = 32; addr_out(&ps, psa, G(&plen2));
            wr32(px, 40); wr64(px + 16, psa); wr32(px + 24, plen2); wr32(px + 32, pl);
            if (pprev) wr64(pprev + 8, px); else wr64(a + 176, px);
            pprev = px;
        }
        NT("[net] adapter %s (index %u, type %u)\n", names[k], idx, rd32(a + 100));
    }
    freeifaddrs(ifs);
    RET(0);
}

// ---------------- ws2_32.dll ----------------
// The by-ordinal exports are wsock32's (1-23 match except 10-12: ioctlsocket, inet_addr, inet_ntoa).
#define WS2_SAME(n) void I_ws2_32_dll__##n(CPU *c) { I_wsock32_dll__##n(c); }
WS2_SAME(1) WS2_SAME(2) WS2_SAME(3) WS2_SAME(4) WS2_SAME(5) WS2_SAME(6) WS2_SAME(7) WS2_SAME(8) WS2_SAME(9)
WS2_SAME(13) WS2_SAME(14) WS2_SAME(15) WS2_SAME(16) WS2_SAME(17) WS2_SAME(18) WS2_SAME(19) WS2_SAME(20)
WS2_SAME(21) WS2_SAME(22) WS2_SAME(23) WS2_SAME(52) WS2_SAME(57) WS2_SAME(111) WS2_SAME(112) WS2_SAME(115) WS2_SAME(116)
void I_ws2_32_dll__10(CPU *c) { I_wsock32_dll__12(c); }
void I_ws2_32_dll__11(CPU *c) { I_wsock32_dll__10(c); }
void I_ws2_32_dll__12(CPU *c) { I_wsock32_dll__11(c); }
// #151 __WSAFDIsSet(s, fd_set*)
void I_ws2_32_dll__151(CPU *c) {
    uint32_t n = rd32(A1); if (n > 64) n = 64;
    for (uint32_t i = 0; i < n; i++) if (rd64(A1 + 8 + 8ull * i) == A0) { RET(1); return; }
    RET(0);
}
#define WS2_NAMED(name, n) void I_ws2_32_dll_##name(CPU *c) { I_ws2_32_dll__##n(c); }
WS2_NAMED(accept, 1) WS2_NAMED(bind, 2) WS2_NAMED(closesocket, 3) WS2_NAMED(connect, 4) WS2_NAMED(getpeername, 5)
WS2_NAMED(getsockname, 6) WS2_NAMED(getsockopt, 7) WS2_NAMED(htonl, 8) WS2_NAMED(htons, 9) WS2_NAMED(ioctlsocket, 10)
WS2_NAMED(inet_addr, 11) WS2_NAMED(inet_ntoa, 12) WS2_NAMED(listen, 13) WS2_NAMED(ntohl, 14) WS2_NAMED(ntohs, 15)
WS2_NAMED(recv, 16) WS2_NAMED(recvfrom, 17) WS2_NAMED(select, 18) WS2_NAMED(send, 19) WS2_NAMED(sendto, 20)
WS2_NAMED(setsockopt, 21) WS2_NAMED(shutdown, 22) WS2_NAMED(socket, 23) WS2_NAMED(gethostbyname, 52)
WS2_NAMED(gethostname, 57) WS2_NAMED(WSAGetLastError, 111) WS2_NAMED(WSASetLastError, 112) WS2_NAMED(WSAStartup, 115)
WS2_NAMED(WSACleanup, 116) WS2_NAMED(__WSAFDIsSet, 151)

// WSASocketW(af, type, protocol, protocolInfo, group, flags): overlapped I/O is not used by the callers seen
void I_ws2_32_dll_WSASocketW(CPU *c) { I_wsock32_dll__23(c); }
void I_ws2_32_dll_WSASocketA(CPU *c) { I_wsock32_dll__23(c); }

// getaddrinfo / GetAddrInfoW. Win64 ADDRINFO: ai_flags +0, ai_family +4, ai_socktype +8, ai_protocol +12,
// ai_addrlen (size_t) +16, ai_canonname +24, ai_addr +32, ai_next +40. Flags 1-4 and AI_ADDRCONFIG (0x400) match.
static uint32_t eai_err(int e) {
    switch (e) {
    case EAI_AGAIN: return 11002;      // WSATRY_AGAIN
    case EAI_NONAME: return 11001;     // WSAHOST_NOT_FOUND
    case EAI_FAIL: return 11003;       // WSANO_RECOVERY
    case EAI_FAMILY: return 10047;     // WSAEAFNOSUPPORT
    case EAI_MEMORY: return 8;         // WSA_NOT_ENOUGH_MEMORY
    case EAI_SERVICE: return 10109;    // WSATYPE_NOT_FOUND
    case EAI_SOCKTYPE: return 10044;   // WSAESOCKTNOSUPPORT
    default: return 11001;
    }
}
static int addrinfo_call(CPU *c, const char *node, const char *serv, int wide) {
    struct addrinfo hints = { 0 }, *res = NULL;
    if (A2) {
        uint32_t fam = rd32(A2 + 4);
        hints.ai_flags = (int)(rd32(A2) & 0x407); hints.ai_family = fam == W_AF_INET6 ? AF_INET6 : (int)fam;
        hints.ai_socktype = (int)rd32(A2 + 8); hints.ai_protocol = (int)rd32(A2 + 12);
    }
    int e = getaddrinfo(node, serv, A2 ? &hints : NULL, &res);
    NT("[net] getaddrinfo(%s, %s) -> %d\n", node ? node : "(null)", serv ? serv : "(null)", e);
    if (e) { wr64(A3, 0); set_last_error(eai_err(e)); return (int)eai_err(e); }
    uint64_t head = 0, *link = &head;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        if (r->ai_family != AF_INET && r->ai_family != AF_INET6) continue;
        uint8_t *g = calloc(1, 48 + 32);
        uint64_t p = G(g);
        wr32(p, (uint32_t)r->ai_flags); wr32(p + 4, r->ai_family == AF_INET6 ? W_AF_INET6 : AF_INET);
        wr32(p + 8, (uint32_t)r->ai_socktype); wr32(p + 12, (uint32_t)r->ai_protocol);
        struct sockaddr_storage ss; memset(&ss, 0, sizeof ss); memcpy(&ss, r->ai_addr, r->ai_addrlen);
        uint32_t len = 32; addr_out(&ss, p + 48, G(&len));
        wr64(p + 16, len); wr64(p + 32, p + 48);
        if (r->ai_canonname) {
            if (wide) wr64(p + 24, G(utf8_to_w16(r->ai_canonname)));
            else wr64(p + 24, G(strdup(r->ai_canonname)));
        }
        *link = p; link = (uint64_t *)PTR(p + 40);
    }
    freeaddrinfo(res);
    wr64(A3, head);
    return 0;
}
void I_ws2_32_dll_getaddrinfo(CPU *c) { RET((uint32_t)addrinfo_call(c, A0 ? PTR(A0) : NULL, A1 ? PTR(A1) : NULL, 0)); }
void I_ws2_32_dll_GetAddrInfoW(CPU *c) {
    char *n = A0 ? w16_to_utf8(PTR(A0)) : NULL, *s = A1 ? w16_to_utf8(PTR(A1)) : NULL;
    RET((uint32_t)addrinfo_call(c, n, s, 1));
    free(n); free(s);
}
void I_ws2_32_dll_freeaddrinfo(CPU *c) {
    for (uint64_t p = A0; p;) { uint64_t nx = rd64(p + 40); free(PTR(rd64(p + 24))); free(PTR(p)); p = nx; }
}
void I_ws2_32_dll_FreeAddrInfoW(CPU *c) { I_ws2_32_dll_freeaddrinfo(c); }
// inet_ntop(family, addr, buf, size) / inet_pton(family, string, addr)
void I_ws2_32_dll_inet_ntop(CPU *c) {
    int fam = (int)A0 == W_AF_INET6 ? AF_INET6 : (int)A0;
    const char *r = inet_ntop(fam, PTR(A1), PTR(A2), (socklen_t)A3);
    if (!r) { set_last_error(10047); RET(0); return; }
    RET(A2);
}
void I_ws2_32_dll_inet_pton(CPU *c) {
    int fam = (int)A0 == W_AF_INET6 ? AF_INET6 : (int)A0;
    int r = inet_pton(fam, PTR(A1), PTR(A2));
    if (r < 0) set_last_error(10047);
    RET((uint32_t)r);
}

// ---- WSAEventSelect: network events on a socket signal an event object ----
// A poll thread watches the registered sockets. FD_READ and FD_CLOSE are level conditions, re-armed once the app
// has collected them (WSAEnumNetworkEvents); FD_CONNECT fires once when a connect completes, FD_WRITE then and
// again after a send that would have blocked, as on Windows.
#include <poll.h>
#include <pthread.h>
#include "handles.h"
enum { FD_READ_ = 1, FD_WRITE_ = 2, FD_OOB_ = 4, FD_ACCEPT_ = 8, FD_CONNECT_ = 16, FD_CLOSE_ = 32 };
typedef struct { int fd; uint64_t event; uint32_t mask, pending, armed; int connecting, closed, dgram; uint32_t err[10]; } WsSel;
static WsSel ws_sel[256]; static int ws_nsel;
static pthread_mutex_t ws_mu = PTHREAD_MUTEX_INITIALIZER;
static int ws_wake[2] = { -1, -1 };
static WsSel *ws_find(int fd) { for (int i = 0; i < ws_nsel; i++) if (ws_sel[i].fd == fd) return &ws_sel[i]; return NULL; }
static void ws_poke(void) { if (ws_wake[1] >= 0) { char b = 0; (void)!write(ws_wake[1], &b, 1); } }
static void ws_set_event(uint64_t h) {
    h_lock(); HObj *o = h_get(h); if (o) { o->state = 1; h_wake(o); } h_unlock();
}
static void ws_report(WsSel *s, uint32_t bits) {   // ws_mu held
    bits &= s->mask & s->armed;
    if (!bits) return;
    s->pending |= bits;
    s->armed &= ~bits;   // reported once, until the call that re-enables it (recv for FD_READ, ...)
    ws_set_event(s->event);
}
static void *ws_poller(void *arg) {
    (void)arg;
    for (;;) {
        struct pollfd pf[257]; int idx[257], n = 0;
        pthread_mutex_lock(&ws_mu);
        pf[n].fd = ws_wake[0]; pf[n].events = POLLIN; idx[n++] = -1;
        for (int i = 0; i < ws_nsel; i++) {
            WsSel *s = &ws_sel[i]; short ev = 0;
            uint32_t want = s->mask & s->armed;
            if (s->closed) continue;
            if (s->connecting) { if (want & (FD_CONNECT_ | FD_WRITE_ | FD_CLOSE_)) ev |= POLLOUT; }
            else {
                if (want & (FD_READ_ | FD_CLOSE_ | FD_ACCEPT_)) ev |= POLLIN;
                if (want & FD_WRITE_) ev |= POLLOUT;
            }
            if (ev) { pf[n].fd = s->fd; pf[n].events = ev; idx[n++] = i; }
        }
        pthread_mutex_unlock(&ws_mu);
        if (poll(pf, (nfds_t)n, -1) < 0) continue;
        if (pf[0].revents) { char b[64]; while (read(ws_wake[0], b, sizeof b) == sizeof b) {} }
        pthread_mutex_lock(&ws_mu);
        for (int k = 1; k < n; k++) {
            if (!pf[k].revents || idx[k] >= ws_nsel || ws_sel[idx[k]].fd != pf[k].fd) continue;
            WsSel *s = &ws_sel[idx[k]];
            if (s->connecting) {
                int e = 0; socklen_t l = sizeof e; getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &e, &l);
                s->connecting = 0;
                s->err[4] = e ? wsa_err(e) : 0;
                ws_report(s, e ? FD_CONNECT_ : (FD_CONNECT_ | FD_WRITE_));
                if (!e) s->armed &= ~FD_WRITE_;   // reported once; again after a blocked send
                continue;
            }
            if (s->dgram && pf[k].revents & (POLLIN | POLLERR)) {
                // a datagram socket never closes: a datagram, or an error (an ICMP report from an earlier send)
                // that the next recvfrom returns, is FD_READ
                ws_report(s, FD_READ_);
            } else if (!s->dgram && pf[k].revents & (POLLIN | POLLHUP | POLLERR)) {
                char b; ssize_t r = recv(s->fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
                if (s->mask & FD_ACCEPT_ && r < 0 && errno == ENOTCONN) ws_report(s, FD_ACCEPT_);
                else if (r > 0) ws_report(s, FD_READ_);
                else if (r == 0 || (r < 0 && errno != EWOULDBLOCK)) {
                    s->err[5] = r == 0 ? 0 : wsa_err(errno);
                    s->closed = 1; ws_report(s, FD_CLOSE_);
                    NT("[net] socket %d closed (%s)\n", s->fd, r == 0 ? "by the peer" : strerror(errno));
                }
            }
            if (pf[k].revents & POLLOUT) ws_report(s, FD_WRITE_);
        }
        pthread_mutex_unlock(&ws_mu);
    }
    return NULL;
}
static void ws_init(void) {
    if (pipe(ws_wake)) return;
    fcntl(ws_wake[0], F_SETFL, O_NONBLOCK); fcntl(ws_wake[1], F_SETFL, O_NONBLOCK);
    pthread_t t; pthread_create(&t, NULL, ws_poller, NULL); pthread_detach(t);
}
static void ws_start(void) { static pthread_once_t once = PTHREAD_ONCE_INIT; pthread_once(&once, ws_init); }
static void ws_forget(int fd) {
    pthread_mutex_lock(&ws_mu);
    WsSel *s = ws_find(fd); if (s) *s = ws_sel[--ws_nsel];
    pthread_mutex_unlock(&ws_mu); ws_poke();
}
static void ws_connecting(int fd) {
    pthread_mutex_lock(&ws_mu);
    WsSel *s = ws_find(fd); if (s) { s->connecting = 1; s->closed = 0; s->armed |= FD_CONNECT_ | FD_WRITE_ | FD_CLOSE_; }
    pthread_mutex_unlock(&ws_mu); if (s) ws_poke();
}
static void ws_rearm(int fd, uint32_t bits) {
    pthread_mutex_lock(&ws_mu);
    WsSel *s = ws_find(fd); if (s) s->armed |= bits;
    pthread_mutex_unlock(&ws_mu); if (s) ws_poke();
}
static void ws_write_blocked(int fd) {
    pthread_mutex_lock(&ws_mu);
    WsSel *s = ws_find(fd); if (s) s->armed |= FD_WRITE_;
    pthread_mutex_unlock(&ws_mu); if (s) ws_poke();
}
// WSAEventSelect(s, event, mask): the socket becomes non-blocking
void I_ws2_32_dll_WSAEventSelect(CPU *c) {
    int fd = sfd(A0); uint32_t mask = (uint32_t)A2;
    ws_start();
    pthread_mutex_lock(&ws_mu);
    WsSel *s = ws_find(fd);
    if (!mask || !A1) { if (s) *s = ws_sel[--ws_nsel]; pthread_mutex_unlock(&ws_mu); ws_poke(); RET(0); return; }
    if (!s) {
        if (ws_nsel == 256) { pthread_mutex_unlock(&ws_mu); set_last_error(10024); RET(SOCKET_ERROR); return; }
        s = &ws_sel[ws_nsel++]; memset(s, 0, sizeof *s); s->fd = fd;
        int ty = 0; socklen_t tl = sizeof ty; getsockopt(fd, SOL_SOCKET, SO_TYPE, &ty, &tl); s->dgram = ty == SOCK_DGRAM;
        // an already connected socket is writable now
        struct sockaddr_storage a; socklen_t l = sizeof a;
        s->armed = FD_READ_ | FD_CLOSE_ | FD_ACCEPT_ | FD_OOB_ | (s->dgram || getpeername(fd, (struct sockaddr *)&a, &l) == 0 ? FD_WRITE_ : 0);
    }
    else {
        // selecting again re-enables the level conditions, and an event not collected yet signals the (possibly
        // reset) event object again
        if (!s->closed) s->armed |= FD_READ_ | FD_CLOSE_ | FD_ACCEPT_ | FD_OOB_;
        if (s->pending & mask) ws_set_event(A1);
    }
    s->event = A1; s->mask = mask;
    pthread_mutex_unlock(&ws_mu);
    int fl = fcntl(fd, F_GETFL); if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    NT("[net] WSAEventSelect(%d, mask 0x%x)\n", fd, mask);
    ws_poke(); RET(0);
}
// WSAEnumNetworkEvents(s, event, WSANETWORKEVENTS { long lNetworkEvents; int iErrorCode[10]; })
void I_ws2_32_dll_WSAEnumNetworkEvents(CPU *c) {
    int fd = sfd(A0);
    pthread_mutex_lock(&ws_mu);
    WsSel *s = ws_find(fd); uint32_t ev = 0;
    if (s) {
        ev = s->pending; s->pending = 0;
        if (A2) { wr32(A2, ev); for (int i = 0; i < 10; i++) wr32(A2 + 4 + 4 * i, (ev >> i) & 1 ? s->err[i] : 0); }
    } else if (A2) memset(PTR(A2), 0, 44);
    pthread_mutex_unlock(&ws_mu);
    if (A1) { h_lock(); HObj *o = h_get(A1); if (o) o->state = 0; h_unlock(); }
    ws_poke();
    RET(0);
}
// WSA event objects are manual-reset kernel events
void I_kernel32_dll_CreateEventW(CPU *c);
void I_kernel32_dll_SetEvent(CPU *c);
void I_kernel32_dll_ResetEvent(CPU *c);
void I_kernel32_dll_CloseHandle(CPU *c);
void I_ws2_32_dll_WSACreateEvent(CPU *c) { c->rcx = 0; c->rdx = 1; c->r8 = 0; c->r9 = 0; I_kernel32_dll_CreateEventW(c); }
void I_ws2_32_dll_WSASetEvent(CPU *c) { I_kernel32_dll_SetEvent(c); }
void I_ws2_32_dll_WSAResetEvent(CPU *c) { I_kernel32_dll_ResetEvent(c); }
void I_ws2_32_dll_WSACloseEvent(CPU *c) { I_kernel32_dll_CloseHandle(c); }
// WSAWaitForMultipleEvents(n, events, waitAll, timeout, alertable): WSA_WAIT_EVENT_0 / WSA_WAIT_TIMEOUT as WAIT_*
void I_ws2_32_dll_WSAWaitForMultipleEvents(CPU *c) {
    uint32_t n = (uint32_t)A0; uint64_t hs[64];
    for (uint32_t i = 0; i < n && i < 64; i++) hs[i] = rd64(A1 + 8 * i);
    RET(h_wait((int)(n < 64 ? n : 64), hs, (int)A2, (uint32_t)A3));
}
