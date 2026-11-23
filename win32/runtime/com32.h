// COM objects for 32-bit guests: the guest sees {vtable, magic, host index} in its memory; every vtable slot is a
// host trampoline that finds the host object from `this` (stack argument 0), runs the method and pops the stdcall
// arguments. Methods without an implementation log their name once and return a default.
#pragma once
#include "rt32.h"

typedef struct ComObj ComObj;
typedef struct ComMethod ComMethod;
typedef uint32_t (*ComFn)(CPU *c, ComObj *self, const ComMethod *m);   // arguments: M(1).. (M(0) is `this`)
struct ComMethod {
    const char *name;
    uint8_t nargs;           // stack slots popped, including `this`
    ComFn fn;
    uint32_t dflt;           // result when fn is NULL (logged once)
    const char *sig;         // optional: argument signature for generic forwarders (d3d9_bridge.cpp)
    int vidx;                // optional: vtable index in the host interface
};
typedef struct ComClass {
    const char *name;
    int nmethods;
    const ComMethod *methods;
    uint32_t vtable;                 // guest vtable (built on first use)
    void (*destroy)(ComObj *self);   // last Release
} ComClass;
struct ComObj {
    const ComClass *cls;
    uint32_t guest;                  // the guest object
    int refs;
};
#define M(i) ARG(i)
#define MF(i) ARGF(i)

// allocate the guest side for a host object (whose struct starts with ComObj) and return the guest pointer
uint32_t com_wrap(ComObj *o, const ComClass *cls);
ComObj *com_host(uint32_t guest);          // NULL if not one of ours
#define COM_AS(T, g) ((T *)com_host(g))
uint32_t com_addref(ComObj *o);
uint32_t com_release(ComObj *o);
// shared IUnknown methods
uint32_t com_QueryInterface(CPU *c, ComObj *self, const ComMethod *m);
uint32_t com_AddRef(CPU *c, ComObj *self, const ComMethod *m);
uint32_t com_Release(CPU *c, ComObj *self, const ComMethod *m);
// detach and free the guest side of an object whose host lifetime ended (bridged objects)
void com_unwrap_free(ComObj *o);
// RT_COM_CALLSITES: write the call-site histogram now (also done at exit)
void com_callsites_dump(void);
#define COM_IUNKNOWN {"QueryInterface", 3, com_QueryInterface, 0}, {"AddRef", 1, com_AddRef, 0}, {"Release", 1, com_Release, 0}
