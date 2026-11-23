// Direct3D 9 bridge: the 32-bit guest's d3d9 COM calls -> a 64-bit host implementation of the standard d3d9.h
// interfaces (DXVK native today; any host d3d9 with the same ABI, such as a Metal one, later).
//
// Every guest interface pointer is a com32 object wrapping a host interface pointer. Methods are described by
// signature strings (one character per guest stack argument) and forwarded by one generic routine; the few that
// can't be described that way (locks, float arguments, structs whose layout differs between 32 and 64 bits) are
// written out. Locked memory lives outside the guest's 4 GiB window, so locks go through guest staging memory that
// is copied in at Lock and back at Unlock.
//
// Signature characters:
//   u  32-bit value          i  signed 32-bit value (sign-extended)
//   p  pointer to data (the host reads/writes the guest window directly)
//   I  interface in (guest wrapper -> host pointer)
//   O? interface out (guest IFoo** <- wrapped host pointer); ? = class letter, see class_for()
//   W  HWND (opaque: the guest's handle is the host WSI's window id)
//   n  ignored pointer (pSharedHandle, RGNDATA*): passed as NULL
//   P  D3DPRESENT_PARAMETERS* (converted both ways)
#include <windows.h>
#include <d3d9.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "native/wsi/native_host.h"
extern "C" {
#include "com32.h"
}

// ---------------- wrappers ----------------
namespace {

struct LockRec { uint32_t staging; void *host; uint32_t off, size, pitch, rows, rowbytes, slice, slices; bool readonly; uint32_t level; };

struct Wrap {
    ComObj base;
    IUnknown *host;
    char cls;
    // buffers: size and usage (for staging), textures: format
    uint32_t size = 0, usage = 0;
    uint32_t staging = 0;                 // persistent staging for vertex/index buffers
    std::vector<LockRec> locks;
};

std::mutex g_mu;
std::unordered_map<void *, Wrap *> g_wraps;   // host object -> wrapper (object identity across Get* calls)

const ComClass *class_for(char k);

Wrap *unwrap_w(uint32_t g) { return g ? reinterpret_cast<Wrap *>(com_host(g)) : nullptr; }
void *unwrap(uint32_t g) {
    if (!g) return nullptr;
    Wrap *w = unwrap_w(g);
    if (!w) { rt_log("[d3d9] guest passed an object that isn't ours: 0x%x", g); return nullptr; }
    return w->host;
}

uint32_t buffer_info(Wrap *w);

// wrap a host interface (already AddRef'd by the host call that returned it)
uint32_t wrap(void *host, char k) {
    if (!host) return 0;
    std::lock_guard<std::mutex> l(g_mu);
    if (k == 'b' || k == 'r') {   // base texture / resource: pick the interface from the resource type
        auto *r = static_cast<IDirect3DResource9 *>(host);
        switch (r->GetType()) {
        case D3DRTYPE_TEXTURE: k = 'T'; break;
        case D3DRTYPE_CUBETEXTURE: k = 'C'; break;
        case D3DRTYPE_VOLUMETEXTURE: k = 'V'; break;
        case D3DRTYPE_SURFACE: k = 'S'; break;
        case D3DRTYPE_VERTEXBUFFER: k = 'B'; break;
        case D3DRTYPE_INDEXBUFFER: k = 'X'; break;
        case D3DRTYPE_VOLUME: k = 'v'; break;
        default: k = 'T'; break;
        }
    }
    auto it = g_wraps.find(host);
    if (it != g_wraps.end()) {
        // Same object: the host counted a new reference and the wrapper forwards AddRef/Release. A wrapper of another
        // interface type is stale: DXVK's texture subresources (surfaces, volumes) never report 0 on Release, so their
        // wrappers outlive them, and a new object of another type can land at the same address.
        if (it->second->cls == k) return it->second->base.guest;
        g_wraps.erase(it);
    }
    Wrap *w = new Wrap();
    w->host = static_cast<IUnknown *>(host);
    w->cls = k;
    uint32_t g = com_wrap(&w->base, class_for(k));
    g_wraps[host] = w;
    if (k == 'B' || k == 'X') buffer_info(w);
    return g;
}

void forget(Wrap *w) {
    {
        std::lock_guard<std::mutex> l(g_mu);
        g_wraps.erase(w->host);
    }
    if (w->staging) gfree(w->staging);
    com_unwrap_free(&w->base);
    delete w;
}

// ---- generic forwarder ----
typedef uintptr_t U;
typedef uint32_t (*Fn12)(void *, U, U, U, U, U, U, U, U, U, U, U, U);

void *vfn(IUnknown *o, int idx) { return (*reinterpret_cast<void ***>(o))[idx]; }

struct HostPP { D3DPRESENT_PARAMETERS pp; };
void pp_in(uint32_t g, D3DPRESENT_PARAMETERS *h) {
    h->BackBufferWidth = rd32(g + 0); h->BackBufferHeight = rd32(g + 4); h->BackBufferFormat = (D3DFORMAT)rd32(g + 8);
    h->BackBufferCount = rd32(g + 12); h->MultiSampleType = (D3DMULTISAMPLE_TYPE)rd32(g + 16); h->MultiSampleQuality = rd32(g + 20);
    h->SwapEffect = (D3DSWAPEFFECT)rd32(g + 24); h->hDeviceWindow = (HWND)(uintptr_t)rd32(g + 28); h->Windowed = (BOOL)rd32(g + 32);
    h->EnableAutoDepthStencil = (BOOL)rd32(g + 36); h->AutoDepthStencilFormat = (D3DFORMAT)rd32(g + 40); h->Flags = rd32(g + 44);
    h->FullScreen_RefreshRateInHz = rd32(g + 48); h->PresentationInterval = rd32(g + 52);
}
void pp_out(const D3DPRESENT_PARAMETERS *h, uint32_t g) {
    wr32(g + 0, h->BackBufferWidth); wr32(g + 4, h->BackBufferHeight); wr32(g + 8, (uint32_t)h->BackBufferFormat);
    wr32(g + 12, h->BackBufferCount); wr32(g + 16, (uint32_t)h->MultiSampleType); wr32(g + 20, h->MultiSampleQuality);
    wr32(g + 24, (uint32_t)h->SwapEffect); wr32(g + 28, (uint32_t)(uintptr_t)h->hDeviceWindow); wr32(g + 32, (uint32_t)h->Windowed);
    wr32(g + 36, (uint32_t)h->EnableAutoDepthStencil); wr32(g + 40, (uint32_t)h->AutoDepthStencilFormat); wr32(g + 44, h->Flags);
    wr32(g + 48, h->FullScreen_RefreshRateInHz); wr32(g + 52, h->PresentationInterval);
}

int g_trace = -1;

// RT_DUMP_SHADERS=1: write every shader's bytecode (up to the end token) to <data dir>/shaders/{vs,ps}_<fnv>.bin
void dump_shader(const char *kind, uint32_t g) {
    static int on = -1;
    if (on < 0) on = getenv("RT_DUMP_SHADERS") != NULL;
    if (!on || !g) return;
    const uint32_t *t = (const uint32_t *)gp(g);
    uint32_t n = 1;
    while (n < (1u << 20) && t[n] != 0x0000FFFFu) {
        uint32_t op = t[n] & 0xFFFF;
        if (op == 0xFFFE) n += 1 + (t[n] >> 16);          // comment
        else n += 1 + ((t[n] >> 24) & 0xF);               // SM2+: instruction length in bits 24-27
    }
    n++;
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < n * 4; i++) h = (h ^ ((const uint8_t *)t)[i]) * 16777619u;
    char d[1200], f[1300];
    snprintf(d, sizeof d, "%s/shaders", rt_data_dir); mkdir(d, 0755);
    snprintf(f, sizeof f, "%s/%s_%08x.bin", d, kind, h);
    if (FILE *o = fopen(f, "wb")) { fwrite(t, 4, n, o); fclose(o); }
}

uint32_t forward(CPU *c, ComObj *self, const ComMethod *m) {
    Wrap *w = reinterpret_cast<Wrap *>(self);
    U a[12] = {0};
    void *outs[4] = {0}; uint32_t out_guest[4]; char out_cls[4]; int nout = 0;
    D3DPRESENT_PARAMETERS pps[2]; uint32_t pp_guest[2]; int npp = 0;
    int ai = 0, slot = 1;
    if (m->vidx == 91 || m->vidx == 106) dump_shader(m->vidx == 91 ? "vs" : "ps", M(1));
    for (const char *s = m->sig; *s; s++, slot++) {
        uint32_t v = M(slot);
        switch (*s) {
        case 'u': a[ai++] = v; break;
        case 'i': a[ai++] = (U)(intptr_t)(int32_t)v; break;
        case 'p': a[ai++] = (U)gp(v); break;
        case 'I': a[ai++] = (U)unwrap(v); break;
        case 'W': a[ai++] = (U)v; break;
        case 'n': a[ai++] = 0; break;
        case 'P':
            if (v) { pp_in(v, &pps[npp]); pp_guest[npp] = v; a[ai++] = (U)&pps[npp]; npp++; } else a[ai++] = 0;
            break;
        case 'O':
            s++;
            if (v) { out_guest[nout] = v; out_cls[nout] = *s; a[ai++] = (U)&outs[nout]; nout++; }
            else a[ai++] = 0;
            break;
        default: rt_fatal("d3d9 bridge: bad signature %s", m->sig);
        }
    }
    uint32_t r = reinterpret_cast<Fn12>(vfn(w->host, m->vidx))(w->host, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]);
    for (int k = 0; k < nout; k++) wr32(out_guest[k], wrap(outs[k], out_cls[k]));
    // failures are always worth a line (queries' "not ready" S_FALSE and D3DERR_NOTAVAILABLE probes are not failures)
    if ((int32_t)r < 0 && r != 0x8876086Au && strcmp(m->name, "GetData") && strcmp(m->name, "TestCooperativeLevel")) {
        rt_log("[d3d9] %s failed: 0x%08x", m->name, r);
        for (int k = 0; k < npp; k++) {
            const D3DPRESENT_PARAMETERS &q = pps[k];
            rt_log("[d3d9]   present params: %ux%u fmt %u x%u ms %u swap %u hwnd %p windowed %d depth %d/%u flags 0x%x refresh %u interval 0x%x",
                   q.BackBufferWidth, q.BackBufferHeight, q.BackBufferFormat, q.BackBufferCount, q.MultiSampleType, q.SwapEffect,
                   (void *)q.hDeviceWindow, q.Windowed, q.EnableAutoDepthStencil, q.AutoDepthStencilFormat, q.Flags,
                   q.FullScreen_RefreshRateInHz, q.PresentationInterval);
        }
    }
    for (int k = 0; k < npp; k++) pp_out(&pps[k], pp_guest[k]);
    if (g_trace < 0) g_trace = getenv("RT_D3D9_TRACE") != NULL;
    if (g_trace) rt_log("[d3d9] %s(%s) -> 0x%x", m->name, m->sig, r);
    return r;
}

// ---- IUnknown ----
uint32_t m_AddRef(CPU *c, ComObj *self, const ComMethod *m) { return reinterpret_cast<Wrap *>(self)->host->AddRef(); }
uint32_t m_Release(CPU *c, ComObj *self, const ComMethod *m) {
    Wrap *w = reinterpret_cast<Wrap *>(self);
    ULONG r = w->host->Release();
    if (r == 0) forget(w);
    return r;
}
char class_for_iid(REFIID iid) {
    if (iid == __uuidof(IDirect3DTexture9)) return 'T';
    if (iid == __uuidof(IDirect3DCubeTexture9)) return 'C';
    if (iid == __uuidof(IDirect3DVolumeTexture9)) return 'V';
    if (iid == __uuidof(IDirect3DBaseTexture9) || iid == __uuidof(IDirect3DResource9)) return 'b';
    if (iid == __uuidof(IDirect3DSurface9)) return 'S';
    if (iid == __uuidof(IDirect3DDevice9)) return 'd';
    if (iid == __uuidof(IDirect3D9)) return '3';
    if (iid == __uuidof(IDirect3DSwapChain9)) return 'W';
    return 0;
}
uint32_t m_QueryInterface(CPU *c, ComObj *self, const ComMethod *m) {
    Wrap *w = reinterpret_cast<Wrap *>(self);
    if (!M(1) || !M(2)) return E_POINTER;
    IID iid; memcpy(&iid, G2H(M(1)), sizeof iid);
    void *out = nullptr;
    HRESULT hr = w->host->QueryInterface(iid, &out);
    if (FAILED(hr)) { wr32(M(2), 0); return (uint32_t)hr; }
    char k = class_for_iid(iid);
    if (!k) {
        if (iid == __uuidof(IUnknown)) k = w->cls;
        else { static_cast<IUnknown *>(out)->Release(); wr32(M(2), 0); return (uint32_t)E_NOINTERFACE; }
    }
    wr32(M(2), wrap(out, k));
    return 0;
}

// ---- specials ----
// IDirect3D9::GetAdapterIdentifier: the 64-bit struct is 4 bytes longer (tail padding after the 8-byte member)
uint32_t m_GetAdapterIdentifier(CPU *c, ComObj *self, const ComMethod *m) {
    auto *d = reinterpret_cast<IDirect3D9 *>(reinterpret_cast<Wrap *>(self)->host);
    D3DADAPTER_IDENTIFIER9 id = {};
    HRESULT hr = d->GetAdapterIdentifier(M(1), M(2), &id);
    if (SUCCEEDED(hr) && M(3)) memcpy(G2H(M(3)), &id, 1100);
    return (uint32_t)hr;
}
uint32_t m_GetAdapterMonitor(CPU *c, ComObj *self, const ComMethod *m) { return 1; }
// IDirect3DDevice9::GetCreationParameters: HWND inside
uint32_t m_GetCreationParameters(CPU *c, ComObj *self, const ComMethod *m) {
    auto *d = reinterpret_cast<IDirect3DDevice9 *>(reinterpret_cast<Wrap *>(self)->host);
    D3DDEVICE_CREATION_PARAMETERS p = {};
    HRESULT hr = d->GetCreationParameters(&p);
    if (SUCCEEDED(hr) && M(1)) { wr32(M(1), p.AdapterOrdinal); wr32(M(1) + 4, (uint32_t)p.DeviceType); wr32(M(1) + 8, (uint32_t)(uintptr_t)p.hFocusWindow); wr32(M(1) + 12, p.BehaviorFlags); }
    return (uint32_t)hr;
}
uint32_t m_GetPresentParameters(CPU *c, ComObj *self, const ComMethod *m) {
    auto *s = reinterpret_cast<IDirect3DSwapChain9 *>(reinterpret_cast<Wrap *>(self)->host);
    D3DPRESENT_PARAMETERS p = {};
    HRESULT hr = s->GetPresentParameters(&p);
    if (SUCCEEDED(hr) && M(1)) pp_out(&p, M(1));
    return (uint32_t)hr;
}
uint32_t m_Clear(CPU *c, ComObj *self, const ComMethod *m) {
    auto *d = reinterpret_cast<IDirect3DDevice9 *>(reinterpret_cast<Wrap *>(self)->host);
    return (uint32_t)d->Clear(M(1), (const D3DRECT *)gp(M(2)), M(3), M(4), MF(5), M(6));
}
uint32_t m_SetNPatchMode(CPU *c, ComObj *self, const ComMethod *m) {
    return (uint32_t)reinterpret_cast<IDirect3DDevice9 *>(reinterpret_cast<Wrap *>(self)->host)->SetNPatchMode(MF(1));
}
uint32_t m_GetNPatchMode(CPU *c, ComObj *self, const ComMethod *m) {
    FPUSH(c, reinterpret_cast<IDirect3DDevice9 *>(reinterpret_cast<Wrap *>(self)->host)->GetNPatchMode());   // float results come back in st0
    return 0;
}
uint32_t m_GetDC(CPU *c, ComObj *self, const ComMethod *m) { return (uint32_t)D3DERR_INVALIDCALL; }
// a 32-bit game can read more than 2 GiB as a negative number: report at most 2 GiB - 4 MiB, like 32-bit drivers do
uint32_t m_GetAvailableTextureMem(CPU *c, ComObj *self, const ComMethod *m) {
    UINT v = reinterpret_cast<IDirect3DDevice9 *>(reinterpret_cast<Wrap *>(self)->host)->GetAvailableTextureMem();
    return v > 0x7FC00000u ? 0x7FC00000u : v;
}

// ---- locks: guest staging memory ----
uint32_t buffer_info(Wrap *w) {
    if (w->cls == 'B') { D3DVERTEXBUFFER_DESC d = {}; static_cast<IDirect3DVertexBuffer9 *>((void *)w->host)->GetDesc(&d); w->size = d.Size; w->usage = d.Usage; }
    else { D3DINDEXBUFFER_DESC d = {}; static_cast<IDirect3DIndexBuffer9 *>((void *)w->host)->GetDesc(&d); w->size = d.Size; w->usage = d.Usage; }
    return w->size;
}
uint32_t m_BufLock(CPU *c, ComObj *self, const ComMethod *m) {
    Wrap *w = reinterpret_cast<Wrap *>(self);
    uint32_t off = M(1), size = M(2), pp = M(3), flags = M(4);
    void *hp = nullptr;
    HRESULT hr = w->cls == 'B' ? static_cast<IDirect3DVertexBuffer9 *>((void *)w->host)->Lock(off, size, &hp, flags)
                               : static_cast<IDirect3DIndexBuffer9 *>((void *)w->host)->Lock(off, size, &hp, flags);
    if (FAILED(hr)) return (uint32_t)hr;
    if (!w->staging) w->staging = gmalloc(w->size ? w->size : 16);
    if (off > w->size) off = w->size;
    uint32_t n = size ? size : w->size - off;
    if (off + n > w->size) n = w->size - off;
    // write-only buffers and discards don't need the current contents
    if (!(flags & D3DLOCK_DISCARD) && !(w->usage & D3DUSAGE_WRITEONLY)) memcpy(G2H(w->staging + off), hp, n);
    w->locks.push_back(LockRec{w->staging + off, hp, off, n, 0, 0, 0, 0, 0, (flags & D3DLOCK_READONLY) != 0, 0});
    wr32(pp, w->staging + off);
    return 0;
}
uint32_t m_BufUnlock(CPU *c, ComObj *self, const ComMethod *m) {
    Wrap *w = reinterpret_cast<Wrap *>(self);
    for (auto &l : w->locks) if (!l.readonly) memcpy(l.host, G2H(l.staging), l.size);
    w->locks.clear();
    return (uint32_t)(w->cls == 'B' ? static_cast<IDirect3DVertexBuffer9 *>((void *)w->host)->Unlock()
                                    : static_cast<IDirect3DIndexBuffer9 *>((void *)w->host)->Unlock());
}

// bytes per row / rows of a rect in a format
void fmt_rows(D3DFORMAT f, uint32_t w, uint32_t h, uint32_t *rowbytes, uint32_t *rows) {
    uint32_t bpp;
    switch ((uint32_t)f) {
    case D3DFMT_DXT1: case MAKEFOURCC('A', 'T', 'I', '1'): *rowbytes = ((w + 3) / 4) * 8; *rows = (h + 3) / 4; return;
    case D3DFMT_DXT2: case D3DFMT_DXT3: case D3DFMT_DXT4: case D3DFMT_DXT5: case MAKEFOURCC('A', 'T', 'I', '2'):
        *rowbytes = ((w + 3) / 4) * 16; *rows = (h + 3) / 4; return;
    case D3DFMT_A8: case D3DFMT_L8: case D3DFMT_P8: case D3DFMT_A4L4: bpp = 1; break;
    case D3DFMT_R5G6B5: case D3DFMT_X1R5G5B5: case D3DFMT_A1R5G5B5: case D3DFMT_A4R4G4B4: case D3DFMT_A8L8: case D3DFMT_V8U8:
    case D3DFMT_L16: case D3DFMT_R16F: case D3DFMT_D16: case D3DFMT_D16_LOCKABLE: case D3DFMT_A8R3G3B2: case D3DFMT_X4R4G4B4: bpp = 2; break;
    case D3DFMT_A16B16G16R16: case D3DFMT_A16B16G16R16F: case D3DFMT_G32R32F: case D3DFMT_Q16W16V16U16: bpp = 8; break;
    case D3DFMT_A32B32G32R32F: bpp = 16; break;
    case D3DFMT_R8G8B8: bpp = 3; break;
    default: bpp = 4; break;
    }
    *rowbytes = w * bpp; *rows = h;
}
// lock a 2D level (texture level, cube face level, or surface) through staging
uint32_t lock2d(Wrap *w, uint32_t level, uint32_t face, uint32_t lr, uint32_t rectp, uint32_t flags) {
    D3DSURFACE_DESC desc = {};
    D3DLOCKED_RECT hl = {};
    RECT *rect = (RECT *)gp(rectp);   // RECT is four LONGs (32-bit) on both sides
    HRESULT hr;
    switch (w->cls) {
    case 'T': { auto *t = static_cast<IDirect3DTexture9 *>((void *)w->host); t->GetLevelDesc(level, &desc); hr = t->LockRect(level, &hl, rect, flags); break; }
    case 'C': { auto *t = static_cast<IDirect3DCubeTexture9 *>((void *)w->host); t->GetLevelDesc(level, &desc); hr = t->LockRect((D3DCUBEMAP_FACES)face, level, &hl, rect, flags); break; }
    default:  { auto *s = static_cast<IDirect3DSurface9 *>((void *)w->host); s->GetDesc(&desc); hr = s->LockRect(&hl, rect, flags); break; }
    }
    if (FAILED(hr)) return (uint32_t)hr;
    uint32_t rw = desc.Width, rh = desc.Height;
    if (rect) { rw = (uint32_t)(rect->right - rect->left); rh = (uint32_t)(rect->bottom - rect->top); }
    uint32_t rowbytes, rows;
    fmt_rows(desc.Format, rw, rh, &rowbytes, &rows);
    uint32_t pitch = (uint32_t)hl.Pitch;
    uint32_t bytes = rows ? pitch * (rows - 1) + rowbytes : 0;
    uint32_t st = gmalloc(bytes ? bytes : 16);
    if (!(flags & D3DLOCK_DISCARD) && bytes) memcpy(G2H(st), hl.pBits, bytes);
    w->locks.push_back(LockRec{st, hl.pBits, 0, bytes, pitch, rows, rowbytes, 0, 0, (flags & D3DLOCK_READONLY) != 0, level | (face << 16)});
    wr32(lr, pitch); wr32(lr + 4, st);
    return 0;
}
uint32_t unlock2d(Wrap *w, uint32_t level, uint32_t face) {
    uint32_t key = level | (face << 16);
    for (size_t k = 0; k < w->locks.size(); k++) {
        LockRec &l = w->locks[k];
        if (l.level != key) continue;
        if (!l.readonly && l.size) memcpy(l.host, G2H(l.staging), l.size);
        gfree(l.staging);
        w->locks.erase(w->locks.begin() + (long)k);
        break;
    }
    switch (w->cls) {
    case 'T': return (uint32_t)static_cast<IDirect3DTexture9 *>((void *)w->host)->UnlockRect(level);
    case 'C': return (uint32_t)static_cast<IDirect3DCubeTexture9 *>((void *)w->host)->UnlockRect((D3DCUBEMAP_FACES)face, level);
    default:  return (uint32_t)static_cast<IDirect3DSurface9 *>((void *)w->host)->UnlockRect();
    }
}
uint32_t m_TexLockRect(CPU *c, ComObj *self, const ComMethod *m) { return lock2d(reinterpret_cast<Wrap *>(self), M(1), 0, M(2), M(3), M(4)); }
uint32_t m_TexUnlockRect(CPU *c, ComObj *self, const ComMethod *m) { return unlock2d(reinterpret_cast<Wrap *>(self), M(1), 0); }
uint32_t m_CubeLockRect(CPU *c, ComObj *self, const ComMethod *m) { return lock2d(reinterpret_cast<Wrap *>(self), M(2), M(1), M(3), M(4), M(5)); }
uint32_t m_CubeUnlockRect(CPU *c, ComObj *self, const ComMethod *m) { return unlock2d(reinterpret_cast<Wrap *>(self), M(2), M(1)); }
uint32_t m_SurfLockRect(CPU *c, ComObj *self, const ComMethod *m) { return lock2d(reinterpret_cast<Wrap *>(self), 0, 0, M(1), M(2), M(3)); }
uint32_t m_SurfUnlockRect(CPU *c, ComObj *self, const ComMethod *m) { return unlock2d(reinterpret_cast<Wrap *>(self), 0, 0); }
uint32_t m_LockBox(CPU *c, ComObj *self, const ComMethod *m) { rt_log("[d3d9] volume texture locks are not bridged yet"); return (uint32_t)D3DERR_INVALIDCALL; }

// ---------------- method tables ----------------
#define FWD(name, sig, idx) {name, (uint8_t)(1 + sizeof(sig) - 1 - count_O(sig)), forward, 0, sig, idx}
constexpr int count_O(const char *s) { return *s ? (*s == 'O' ? 1 : 0) + count_O(s + 1) : 0; }
#define SPC(name, nargs, fn) {name, (uint8_t)(nargs), fn, 0, "", 0}
#define UNK SPC("QueryInterface", 3, m_QueryInterface), SPC("AddRef", 1, m_AddRef), SPC("Release", 1, m_Release)

const ComMethod d3d9_m[] = {
    UNK,
    FWD("RegisterSoftwareDevice", "p", 3), FWD("GetAdapterCount", "", 4), SPC("GetAdapterIdentifier", 4, m_GetAdapterIdentifier),
    FWD("GetAdapterModeCount", "uu", 6), FWD("EnumAdapterModes", "uuup", 7), FWD("GetAdapterDisplayMode", "up", 8),
    FWD("CheckDeviceType", "uuuuu", 9), FWD("CheckDeviceFormat", "uuuuuu", 10), FWD("CheckDeviceMultiSampleType", "uuuuup", 11),
    FWD("CheckDepthStencilMatch", "uuuuu", 12), FWD("CheckDeviceFormatConversion", "uuuu", 13), FWD("GetDeviceCaps", "uup", 14),
    SPC("GetAdapterMonitor", 2, m_GetAdapterMonitor), FWD("CreateDevice", "uuWuPOd", 16),
};
const ComMethod device_m[] = {
    UNK,
    FWD("TestCooperativeLevel", "", 3), SPC("GetAvailableTextureMem", 1, m_GetAvailableTextureMem), FWD("EvictManagedResources", "", 5),
    FWD("GetDirect3D", "O3", 6), FWD("GetDeviceCaps", "p", 7), FWD("GetDisplayMode", "up", 8),
    SPC("GetCreationParameters", 2, m_GetCreationParameters), FWD("SetCursorProperties", "uuI", 10),
    FWD("SetCursorPosition", "iiu", 11), FWD("ShowCursor", "u", 12), FWD("CreateAdditionalSwapChain", "POW", 13),
    FWD("GetSwapChain", "uOW", 14), FWD("GetNumberOfSwapChains", "", 15), FWD("Reset", "P", 16),
    FWD("Present", "ppWn", 17), FWD("GetBackBuffer", "uuuOS", 18), FWD("GetRasterStatus", "up", 19),
    FWD("SetDialogBoxMode", "u", 20), FWD("SetGammaRamp", "uup", 21), FWD("GetGammaRamp", "up", 22),
    FWD("CreateTexture", "uuuuuuOTn", 23), FWD("CreateVolumeTexture", "uuuuuuuOVn", 24), FWD("CreateCubeTexture", "uuuuuOCn", 25),
    FWD("CreateVertexBuffer", "uuuuOBn", 26), FWD("CreateIndexBuffer", "uuuuOXn", 27), FWD("CreateRenderTarget", "uuuuuuOSn", 28),
    FWD("CreateDepthStencilSurface", "uuuuuuOSn", 29), FWD("UpdateSurface", "IpIp", 30), FWD("UpdateTexture", "II", 31),
    FWD("GetRenderTargetData", "II", 32), FWD("GetFrontBufferData", "uI", 33), FWD("StretchRect", "IpIpu", 34),
    FWD("ColorFill", "Ipu", 35), FWD("CreateOffscreenPlainSurface", "uuuuOSn", 36), FWD("SetRenderTarget", "uI", 37),
    FWD("GetRenderTarget", "uOS", 38), FWD("SetDepthStencilSurface", "I", 39), FWD("GetDepthStencilSurface", "OS", 40),
    FWD("BeginScene", "", 41), FWD("EndScene", "", 42), SPC("Clear", 7, m_Clear), FWD("SetTransform", "up", 44),
    FWD("GetTransform", "up", 45), FWD("MultiplyTransform", "up", 46), FWD("SetViewport", "p", 47), FWD("GetViewport", "p", 48),
    FWD("SetMaterial", "p", 49), FWD("GetMaterial", "p", 50), FWD("SetLight", "up", 51), FWD("GetLight", "up", 52),
    FWD("LightEnable", "uu", 53), FWD("GetLightEnable", "up", 54), FWD("SetClipPlane", "up", 55), FWD("GetClipPlane", "up", 56),
    FWD("SetRenderState", "uu", 57), FWD("GetRenderState", "up", 58), FWD("CreateStateBlock", "uOL", 59),
    FWD("BeginStateBlock", "", 60), FWD("EndStateBlock", "OL", 61), FWD("SetClipStatus", "p", 62), FWD("GetClipStatus", "p", 63),
    FWD("GetTexture", "uOb", 64), FWD("SetTexture", "uI", 65), FWD("GetTextureStageState", "uup", 66),
    FWD("SetTextureStageState", "uuu", 67), FWD("GetSamplerState", "uup", 68), FWD("SetSamplerState", "uuu", 69),
    FWD("ValidateDevice", "p", 70), FWD("SetPaletteEntries", "up", 71), FWD("GetPaletteEntries", "up", 72),
    FWD("SetCurrentTexturePalette", "u", 73), FWD("GetCurrentTexturePalette", "p", 74), FWD("SetScissorRect", "p", 75),
    FWD("GetScissorRect", "p", 76), FWD("SetSoftwareVertexProcessing", "u", 77), FWD("GetSoftwareVertexProcessing", "", 78),
    SPC("SetNPatchMode", 2, m_SetNPatchMode), SPC("GetNPatchMode", 1, m_GetNPatchMode),
    FWD("DrawPrimitive", "uuu", 81), FWD("DrawIndexedPrimitive", "uiuuuu", 82), FWD("DrawPrimitiveUP", "uupu", 83),
    FWD("DrawIndexedPrimitiveUP", "uuuupupu", 84), FWD("ProcessVertices", "uuuIIu", 85), FWD("CreateVertexDeclaration", "pOD", 86),
    FWD("SetVertexDeclaration", "I", 87), FWD("GetVertexDeclaration", "OD", 88), FWD("SetFVF", "u", 89), FWD("GetFVF", "p", 90),
    FWD("CreateVertexShader", "pOK", 91), FWD("SetVertexShader", "I", 92), FWD("GetVertexShader", "OK", 93),
    FWD("SetVertexShaderConstantF", "upu", 94), FWD("GetVertexShaderConstantF", "upu", 95),
    FWD("SetVertexShaderConstantI", "upu", 96), FWD("GetVertexShaderConstantI", "upu", 97),
    FWD("SetVertexShaderConstantB", "upu", 98), FWD("GetVertexShaderConstantB", "upu", 99),
    FWD("SetStreamSource", "uIuu", 100), FWD("GetStreamSource", "uOBpp", 101), FWD("SetStreamSourceFreq", "uu", 102),
    FWD("GetStreamSourceFreq", "up", 103), FWD("SetIndices", "I", 104), FWD("GetIndices", "OX", 105),
    FWD("CreatePixelShader", "pOP", 106), FWD("SetPixelShader", "I", 107), FWD("GetPixelShader", "OP", 108),
    FWD("SetPixelShaderConstantF", "upu", 109), FWD("GetPixelShaderConstantF", "upu", 110),
    FWD("SetPixelShaderConstantI", "upu", 111), FWD("GetPixelShaderConstantI", "upu", 112),
    FWD("SetPixelShaderConstantB", "upu", 113), FWD("GetPixelShaderConstantB", "upu", 114),
    FWD("DrawRectPatch", "upp", 115), FWD("DrawTriPatch", "upp", 116), FWD("DeletePatch", "u", 117), FWD("CreateQuery", "uOQ", 118),
};
#define RESOURCE \
    FWD("GetDevice", "Od", 3), FWD("SetPrivateData", "ppuu", 4), FWD("GetPrivateData", "ppp", 5), FWD("FreePrivateData", "p", 6), \
    FWD("SetPriority", "u", 7), FWD("GetPriority", "", 8), FWD("PreLoad", "", 9), FWD("GetType", "", 10)
#define BASETEX \
    FWD("SetLOD", "u", 11), FWD("GetLOD", "", 12), FWD("GetLevelCount", "", 13), FWD("SetAutoGenFilterType", "u", 14), \
    FWD("GetAutoGenFilterType", "", 15), FWD("GenerateMipSubLevels", "", 16)
const ComMethod texture_m[] = { UNK, RESOURCE, BASETEX,
    FWD("GetLevelDesc", "up", 17), FWD("GetSurfaceLevel", "uOS", 18), SPC("LockRect", 5, m_TexLockRect),
    SPC("UnlockRect", 2, m_TexUnlockRect), FWD("AddDirtyRect", "p", 21) };
const ComMethod cube_m[] = { UNK, RESOURCE, BASETEX,
    FWD("GetLevelDesc", "up", 17), FWD("GetCubeMapSurface", "uuOS", 18), SPC("LockRect", 6, m_CubeLockRect),
    SPC("UnlockRect", 3, m_CubeUnlockRect), FWD("AddDirtyRect", "up", 21) };
const ComMethod volume_tex_m[] = { UNK, RESOURCE, BASETEX,
    FWD("GetLevelDesc", "up", 17), FWD("GetVolumeLevel", "uOv", 18), SPC("LockBox", 5, m_LockBox),
    FWD("UnlockBox", "u", 20), FWD("AddDirtyBox", "p", 21) };
const ComMethod volume_m[] = { UNK, FWD("GetDevice", "Od", 3), FWD("SetPrivateData", "ppuu", 4), FWD("GetPrivateData", "ppp", 5),
    FWD("FreePrivateData", "p", 6), FWD("GetContainer", "pOr", 7), FWD("GetDesc", "p", 8), SPC("LockBox", 4, m_LockBox), FWD("UnlockBox", "", 10) };
const ComMethod surface_m[] = { UNK, RESOURCE,
    FWD("GetContainer", "pOr", 11), FWD("GetDesc", "p", 12), SPC("LockRect", 4, m_SurfLockRect), SPC("UnlockRect", 1, m_SurfUnlockRect),
    SPC("GetDC", 2, m_GetDC), FWD("ReleaseDC", "u", 16) };
const ComMethod vbuffer_m[] = { UNK, RESOURCE, SPC("Lock", 5, m_BufLock), SPC("Unlock", 1, m_BufUnlock), FWD("GetDesc", "p", 13) };
const ComMethod ibuffer_m[] = { UNK, RESOURCE, SPC("Lock", 5, m_BufLock), SPC("Unlock", 1, m_BufUnlock), FWD("GetDesc", "p", 13) };
const ComMethod decl_m[] = { UNK, FWD("GetDevice", "Od", 3), FWD("GetDeclaration", "pp", 4) };
const ComMethod shader_m[] = { UNK, FWD("GetDevice", "Od", 3), FWD("GetFunction", "pp", 4) };
const ComMethod query_m[] = { UNK, FWD("GetDevice", "Od", 3), FWD("GetType", "", 4), FWD("GetDataSize", "", 5),
    FWD("Issue", "u", 6), FWD("GetData", "puu", 7) };
const ComMethod stateblock_m[] = { UNK, FWD("GetDevice", "Od", 3), FWD("Capture", "", 4), FWD("Apply", "", 5) };
const ComMethod swapchain_m[] = { UNK, FWD("Present", "ppWnu", 3), FWD("GetFrontBufferData", "I", 4), FWD("GetBackBuffer", "uuOS", 5),
    FWD("GetRasterStatus", "p", 6), FWD("GetDisplayMode", "p", 7), FWD("GetDevice", "Od", 8), SPC("GetPresentParameters", 2, m_GetPresentParameters) };

#define CLS(var, name, tbl) ComClass var = {name, (int)(sizeof tbl / sizeof tbl[0]), tbl, 0, nullptr}
CLS(c_d3d9, "IDirect3D9", d3d9_m);
CLS(c_device, "IDirect3DDevice9", device_m);
CLS(c_texture, "IDirect3DTexture9", texture_m);
CLS(c_cube, "IDirect3DCubeTexture9", cube_m);
CLS(c_voltex, "IDirect3DVolumeTexture9", volume_tex_m);
CLS(c_volume, "IDirect3DVolume9", volume_m);
CLS(c_surface, "IDirect3DSurface9", surface_m);
CLS(c_vb, "IDirect3DVertexBuffer9", vbuffer_m);
CLS(c_ib, "IDirect3DIndexBuffer9", ibuffer_m);
CLS(c_decl, "IDirect3DVertexDeclaration9", decl_m);
CLS(c_vs, "IDirect3DVertexShader9", shader_m);
CLS(c_ps, "IDirect3DPixelShader9", shader_m);
CLS(c_query, "IDirect3DQuery9", query_m);
CLS(c_sb, "IDirect3DStateBlock9", stateblock_m);
CLS(c_swap, "IDirect3DSwapChain9", swapchain_m);

const ComClass *class_for(char k) {
    switch (k) {
    case '3': return &c_d3d9; case 'd': return &c_device; case 'T': return &c_texture; case 'C': return &c_cube;
    case 'V': return &c_voltex; case 'v': return &c_volume; case 'S': return &c_surface; case 'B': return &c_vb;
    case 'X': return &c_ib; case 'D': return &c_decl; case 'K': return &c_vs; case 'P': return &c_ps; case 'Q': return &c_query;
    case 'L': return &c_sb; case 'W': return &c_swap;
    default: rt_fatal("d3d9 bridge: no class '%c'", k);
    }
}

// ---------------- backend loading and the host WSI ----------------
extern "C" {
int rt_cocoa_refresh_hz(void);
int rt_cocoa_set_fullscreen(uint32_t hwnd, int on);
void *rt_window_layer(uint32_t hwnd);
void rt_window_size(uint32_t hwnd, int *w, int *h);
void rt_cocoa_screen_size(int *w, int *h);
}
void wsi_size(void *hwnd, uint32_t *w, uint32_t *h) { int a = 0, b = 0; rt_window_size((uint32_t)(uintptr_t)hwnd, &a, &b); *w = (uint32_t)a; *h = (uint32_t)b; }
void *wsi_layer(void *hwnd) { return rt_window_layer((uint32_t)(uintptr_t)hwnd); }
int wsi_is_window(void *hwnd) { return rt_window_layer((uint32_t)(uintptr_t)hwnd) != nullptr; }
int wsi_fullscreen(void *hwnd, int on) { return rt_cocoa_set_fullscreen((uint32_t)(uintptr_t)hwnd, on); }
void wsi_display(uint32_t *w, uint32_t *h, uint32_t *mhz) { int a, b; rt_cocoa_screen_size(&a, &b); *w = (uint32_t)a; *h = (uint32_t)b; *mhz = (uint32_t)rt_cocoa_refresh_hz() * 1000; }

typedef IDirect3D9 *(WINAPI *PFN_Create9)(UINT);

bool readable(const std::string &p) { return access(p.c_str(), R_OK) == 0; }

// The Vulkan driver: KosmicKrisp built by `make kosmickrisp` (<exe dir>/kosmickrisp in a dev build; in an app
// bundle the ICD json is in Contents/Resources/kosmickrisp and the driver + loader in Contents/Frameworks/kosmickrisp).
// VK_DRIVER_FILES / VK_ICD_FILENAMES set by the user win.
void setup_vulkan() {
    std::string exe = rt_exe_dir;
    const char *vars[] = {"VK_DRIVER_FILES", "VK_ICD_FILENAMES"};
    bool user_icd = getenv(vars[0]) || getenv(vars[1]);
    struct { std::string icd, loader; } layouts[] = {
        { exe + "/kosmickrisp/kosmickrisp_icd.json", exe + "/kosmickrisp/libvulkan.1.dylib" },
        { exe + "/../Resources/kosmickrisp/kosmickrisp_icd.json", exe + "/../Frameworks/kosmickrisp/libvulkan.1.dylib" },
    };
    for (auto &l : layouts) {
        if (!readable(l.icd)) continue;
        if (!user_icd) setenv("VK_DRIVER_FILES", l.icd.c_str(), 1);
        if (readable(l.loader)) setenv("DXVK_VULKAN_LOADER", l.loader.c_str(), 0);
        rt_log("[d3d9] Vulkan driver: %s", user_icd ? getenv(getenv(vars[0]) ? vars[0] : vars[1]) : l.icd.c_str());
        return;
    }
    if (!user_icd) rt_log("[d3d9] no bundled KosmicKrisp (make kosmickrisp); using the system's Vulkan drivers");
}

PFN_Create9 load_backend() {
    static PFN_Create9 create;
    if (create) return create;
    setup_vulkan();
    // DXVK's logs and caches go to the app's data folder, never the game's (the working directory)
    std::string logs = std::string(rt_data_dir) + "/dxvk";
    mkdir(logs.c_str(), 0755);
    setenv("DXVK_LOG_PATH", logs.c_str(), 0);
    setenv("DXVK_SHADER_CACHE_PATH", logs.c_str(), 0);
    setenv("DXVK_STATE_CACHE_PATH", logs.c_str(), 0);
    setenv("DXVK_FRAME_RATE", "0", 0);   // no built-in limiter: CAMetalLayer's vsync paces the frames
    const char *path = getenv("RT_D3D9_LIBRARY");
    std::vector<std::string> tries;
    if (path) tries.push_back(path);
    tries.push_back(std::string(rt_exe_dir) + "/../Frameworks/libdxvk_d3d9.dylib");
    tries.push_back(std::string(rt_exe_dir) + "/dxvk/libdxvk_d3d9.dylib");
    tries.push_back("libdxvk_d3d9.dylib");
    void *lib = nullptr;
    for (auto &t : tries) if ((lib = dlopen(t.c_str(), RTLD_NOW | RTLD_LOCAL))) { rt_log("[d3d9] backend: %s", t.c_str()); break; }
    if (!lib) { rt_log("[d3d9] no d3d9 backend found (set RT_D3D9_LIBRARY): %s", dlerror()); return nullptr; }
    auto setcb = reinterpret_cast<void (*)(const DxvkHostWsiCallbacks *)>(dlsym(lib, "dxvk_host_wsi_set_callbacks"));
    if (setcb) {
        static DxvkHostWsiCallbacks cb = {};
        cb.version = 1; cb.get_window_size = wsi_size; cb.get_metal_layer = wsi_layer; cb.is_window = wsi_is_window; cb.get_display = wsi_display; cb.set_fullscreen = wsi_fullscreen;
        setcb(&cb);
        setenv("DXVK_WSI_DRIVER", "Host", 0);
    }
    create = reinterpret_cast<PFN_Create9>(dlsym(lib, "Direct3DCreate9"));
    return create;
}

}   // namespace

extern "C" {
extern char rt_exe_dir[1024];

SHIM(d3d9_Direct3DCreate9, 1) {
    PFN_Create9 create = load_backend();
    if (!create) return 0;
    IDirect3D9 *d = create(ARG(0));
    rt_log("[d3d9] Direct3DCreate9(%u) -> %p", ARG(0), (void *)d);
    return wrap(d, '3');
}
SHIM(d3d9_D3DPERF_GetStatus, 0) { return 0; }
SHIM(d3d9_D3DPERF_SetOptions, 1) { return 0; }
}
