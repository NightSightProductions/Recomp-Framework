// Native replacement switch for the win32 target (see rt32.h: natives, CALL_ORIG).
#include <stdlib.h>
#include <string.h>
#include "rt32.h"

// RT_NATIVE_OFF=all or a comma list of guest addresses (hex): those replacements are switched off and the
// translated guest code (F_<addr>__orig) runs instead. For A/B testing a native against the original.
int rt_native_enabled(uint32_t a) {
    const char *e = getenv("RT_NATIVE_OFF");
    if (!e || !*e) return 1;
    if (!strcmp(e, "all")) { rt_log("[native] 0x%x: using the translated code", a); return 0; }
    for (const char *p = e; *p;) {
        char *end; unsigned long v = strtoul(p, &end, 16);
        if (end == p) break;
        if (v == a) { rt_log("[native] 0x%x: using the translated code", a); return 0; }
        p = *end ? end + 1 : end;
    }
    return 1;
}
