// Shared between the C runtime shims (ucrt.c, ucrt_stdio.c, vcruntime.c, msvcp.c).
#pragma once
#include <stdint.h>
#include "cpu.h"

void ucrt_set_errno(int e);
int ucrt_errno_from_host(int e);
void I_kernel32_dll_GetCommandLineA(CPU *c);
void I_kernel32_dll_GetCurrentDirectoryA(CPU *c);

// Microsoft-format printf over a guest format string and a Win64 va_list (a guest pointer to 8-byte slots).
// wide: the format and the output are UTF-16; opts: the UCRT's _CRT_INTERNAL_PRINTF_* options word.
// Returns the output (malloc'd, null-terminated in its own unit size) and its length in units.
void *ucrt_format(int wide, uint64_t opts, const void *fmt, uint64_t va, size_t *len);
