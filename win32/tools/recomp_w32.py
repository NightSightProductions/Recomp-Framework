#!/usr/bin/env python3
"""Static recompiler: Win32 i386 PE -> C (compiled for arm64).

The 32-bit Windows counterpart of tools/recomp64.py; its instruction semantics, register caching and packed-SSE
codegen are carried over, with the i386 differences:
  - guest memory is a 4 GiB window at GUEST_BASE (cpu32.h): guest address a is host GUEST_BASE + a. arm64 macOS
    reserves the low 4 GiB of every process (__PAGEZERO can't shrink), so the image can't sit at its own address;
  - eight 32-bit GPRs; fs: addresses the thread's TEB (C.fsbase, SEH chain at fs:[0]);
  - no .pdata and (MSVC /FIXED) no relocations: functions are found from the entry point, direct call targets,
    and code pointers in the data sections (vtables, callbacks) that sit on a 16-byte function boundary;
  - jump tables hold absolute addresses ("jmp [idx*4 + table]"), optionally behind a byte index table;
  - imports are called through IAT slots: stdcall shims pop their own arguments (see win32/runtime/rt32.h);
  - x87 compares set the status word (C.fsw) for the fnstsw ax / sahf / test ah idioms of 32-bit MSVC code.

usage: recomp_w32.py ORIG.exe OUTDIR [--native FILE] [--patches FILE] [--probes FILE] [--only ADDR,...]
  --patches FILE: lines "ADDR C code" replace the instruction at ADDR with C; "ADDR @call N_name" turns it into a
  call to the host native N_name (which reads ARG(i) and pops its own arguments, like an import shim)
                                     [--no-abi-trim] [--jobs N]
"""
import os, re, sys, collections, multiprocessing as mp, struct
sys.path.insert(0, os.path.dirname(__file__))
import capstone as cs
from capstone import x86 as X
from pe32 import PE32, dll_key


class Unsupported(Exception):
    pass


def cname(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def imp_sym(full):
    """'KERNEL32.dll!CreateFileA' -> 'kernel32_CreateFileA', 'XINPUT1_4.dll!#3' -> 'xinput1_4_ord3'."""
    dll, n = full.split("!", 1)
    n = "ord%s" % n[1:] if n.startswith("#") else n
    return cname("%s_%s" % (dll_key(dll), n))


# ---------------- registers ----------------
GPRS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
REG = {}   # capstone name -> (gpr, size, high byte?)
for n in GPRS: REG[n] = (n, 4, False)
for n, b in zip(["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"], GPRS): REG[n] = (b, 2, False)
for n, b in zip(["al", "cl", "dl", "bl"], GPRS): REG[n] = (b, 1, False)
for n, b in zip(["ah", "ch", "dh", "bh"], GPRS): REG[n] = (b, 1, True)

U = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
S = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}
MASK = {1: "0xFFu", 2: "0xFFFFu", 4: "0xFFFFFFFFu", 8: "0xFFFFFFFFFFFFFFFFull"}
BITS = {1: 8, 2: 16, 4: 32, 8: 64}
RD = {1: "rd8", 2: "rd16", 4: "rd32", 8: "rd64"}
WR = {1: "wr8", 2: "wr16", 4: "wr32", 8: "wr64"}

CC = {
    "o": "of", "no": "!of", "b": "cf", "c": "cf", "nae": "cf", "ae": "!cf", "nb": "!cf", "nc": "!cf",
    "e": "zf", "z": "zf", "ne": "!zf", "nz": "!zf", "be": "(cf||zf)", "na": "(cf||zf)",
    "a": "(!cf&&!zf)", "nbe": "(!cf&&!zf)", "s": "sf", "ns": "!sf", "p": "parity8(pr)", "pe": "parity8(pr)",
    "np": "!parity8(pr)", "po": "!parity8(pr)", "l": "(sf!=of)", "nge": "(sf!=of)", "ge": "(sf==of)",
    "nl": "(sf==of)", "le": "(zf||sf!=of)", "ng": "(zf||sf!=of)", "g": "(!zf&&sf==of)", "nle": "(!zf&&sf==of)",
}

NORETURN_IMPORTS = {"ExitProcess", "TerminateProcess", "FatalExit", "_exit", "exit", "abort", "terminate",
                    "_invoke_watson", "_invalid_parameter_noinfo_noreturn", "_CxxThrowException", "RaiseException__noreturn"}

STACK_ACCESS = re.compile(r"\b(rd|wr)(8|16|32|64|f|d|x)\(\(uint32_t\)\(C\.esp\b")

# ---------------- register caching (see tools/recomp64.py) ----------------
_GPR_RE = re.compile(r"\bC\.(%s)\b" % "|".join(GPRS))
_XMM_RE = re.compile(r"\bC\.xmm\[(\d+)\]")
_ASSIGN = r"\s*(?:[-+*/&|^%]|<<|>>)?=(?!=)"
_GPR_W = re.compile(r"\bR_(\w+)(?:%s|\s*(?:\+\+|--))" % _ASSIGN)
_XMM_W = re.compile(r"\bX_(\d+)(?:\.\w+(?:\[[^\]]*\])?)?%s" % _ASSIGN)
_BARRIER = re.compile(r"\b(F_[0-9a-f]+|I_\w+|N_\w+|call_ind|missing_func|bad_insn|bad_jump|cpu_cpuid|unimpl_import|cpu_int)"
                      r"\(c(?:,(?:\"(?:[^\"\\]|\\.)*\"|[^;\"])*)?\);")
_RETURN = re.compile(r"\breturn;")
# i386 C ABI (cdecl/stdcall/thiscall/fastcall): ebx, ebp, esi, edi survive a call; eax, ecx, edx and every xmm
# register don't. LTCG can give internal functions custom conventions, so trimming is opt-in (--abi-trim).
_VOLATILE_G = {"eax", "ecx", "edx", "esp"}
ABI_TRIM = "--abi-trim" in sys.argv

CONST_LOAD = re.compile(r"\b(rd8|rd16|rd32|rd64|rdf|rdd|rdx)\(0x([0-9a-f]+)u\)")
_CONST_NAME = {"rd8": "rdc8", "rd16": "rdc16", "rd32": "rdc32", "rd64": "rdc64", "rdf": "rdcf", "rdd": "rdcd", "rdx": "rdcx"}
_SIZE = {"rd8": 1, "rd16": 2, "rd32": 4, "rd64": 8, "rdf": 4, "rdd": 8, "rdx": 16}


def const_loads(pe, text):
    ro = [(va, va + vs) for n, va, vs, fo, fs, ch in pe.sections if not (ch & 0x80000000)]
    iat = set(pe.iat)
    def sub(m):
        a = int(m.group(2), 16)
        if a in iat: return m.group(0)   # the runtime fills the IAT at load time: still constant afterwards, but keep it plain
        if any(lo <= a and a + _SIZE[m.group(1)] <= hi for lo, hi in ro): return "%s(0x%su)" % (_CONST_NAME[m.group(1)], m.group(2))
        return m.group(0)
    return CONST_LOAD.sub(sub, text)


def cache_registers(text):
    text = re.sub(r"\bPUSH\(c, ", "PUSHL(", text)
    text = re.sub(r"\bPOP\(c\)", "POPL()", text)
    text = _GPR_RE.sub(r"R_\1", text)
    text = _XMM_RE.sub(r"X_\1", text)
    used_g = set(re.findall(r"\bR_(\w+)\b", text)) & set(GPRS)
    used_x = set(int(x) for x in re.findall(r"\bX_(\d+)\b", text))
    dirty_g = set(_GPR_W.findall(text)) & set(GPRS)
    dirty_x = set(int(x) for x in _XMM_W.findall(text))
    if re.search(r"\b(PUSHL\(|POPL\(\))", text):
        used_g.add("esp"); dirty_g.add("esp")
    if not used_g and not used_x:
        return text
    order_g = [g for g in GPRS if g in used_g]
    flush = "".join("C.%s = R_%s; " % (g, g) for g in GPRS if g in dirty_g) + "".join("C.xmm[%d] = X_%d; " % (x, x) for x in sorted(dirty_x))
    reload = "".join("R_%s = C.%s; " % (g, g) for g in order_g) + "".join("X_%d = C.xmm[%d]; " % (x, x) for x in sorted(used_x))
    reload_v = "".join("R_%s = C.%s; " % (g, g) for g in order_g if g in _VOLATILE_G) \
             + "".join("X_%d = C.xmm[%d]; " % (x, x) for x in sorted(used_x))
    text = _BARRIER.sub(lambda m: "{ %s%s %s}" % (flush, m.group(0), reload_v if ABI_TRIM and m.group(1).startswith(("F_", "I_", "call_ind")) else reload), text)
    text = _RETURN.sub("{ %sreturn; }" % flush, text)
    decl = ""
    if order_g: decl += "    uint32_t %s;\n" % ", ".join("R_%s = C.%s" % (g, g) for g in order_g)
    if used_x: decl += "    XMM %s;\n" % ", ".join("X_%d = C.xmm[%d]" % (x, x) for x in sorted(used_x))
    i = text.index("c->fn = ")
    j = text.index("\n", i) + 1
    text = text[:j] + decl + text[j:]
    if text.rstrip().endswith("}"):
        k = text.rstrip().rfind("}")
        text = text[:k] + "    " + flush + "\n" + text[k:]
    return text


# ---------------- per-function code generation ----------------
class FuncGen:
    MAX_INSNS = 400000

    def __init__(self, tr, addr):
        self.tr, self.pe, self.addr = tr, tr.pe, addr
        self.out = []
        self.ins = self.descend()
        self.addrs = {i.address for i in self.ins}
        self.labels = set()

    # A function is every instruction reachable from its start that isn't another function's start: control that
    # reaches another start (jump or fall-through) becomes a tail call. Shared code is translated in each function
    # that reaches it, which is always correct for code that doesn't modify itself.
    def in_region(self, a):
        return self.pe.text_lo <= a < self.pe.text_hi and (a == self.addr or a not in self.tr.strong) and self.pe.is_code(a)

    def decode(self, a):
        if not self.in_region(a): return None
        for i in self.tr.md.disasm(self.pe.read(a, min(16, self.pe.code_end(a) - a)), a, 1):
            return i
        return None

    def descend(self):
        seen, work = {}, [self.addr]
        self.tables = {}
        pending = []
        while True:
            while work:
                a = work.pop()
                while a not in seen and self.in_region(a):
                    i = self.decode(a)
                    if i is None:
                        seen[a] = None; break
                    seen[a] = i
                    if len(seen) > self.MAX_INSNS: raise Unsupported("function too large")
                    m = i.mnemonic
                    if (i.group(cs.CS_GRP_JUMP) or m in ("loop", "loope", "loopne", "jecxz", "jcxz")) and i.operands and i.operands[0].type == X.X86_OP_IMM:
                        t = i.operands[0].imm & 0xFFFFFFFF
                        if self.in_region(t): work.append(t)
                    if m == "jmp" and i.operands and i.operands[0].type in (X.X86_OP_REG, X.X86_OP_MEM):
                        pending.append(i)
                    if self.ends_block(i):
                        break
                    a = i.address + i.size
            for i in pending:
                if i.address in self.tables: continue
                res = self.jump_table(seen, i)
                if res:
                    self.tables[i.address] = res
                    work.extend(t for t in res if t not in seen)
            pending = []
            if not work: break
        ins = sorted((x for x in seen.values() if x), key=lambda x: x.address)
        self.bad_decode = [a for a, x in seen.items() if x is None]
        return ins

    def iat_slot(self, op):
        if op.type == X.X86_OP_MEM and not op.mem.base and not op.mem.index and op.mem.segment in (0, X.X86_REG_DS):
            a = op.mem.disp & 0xFFFFFFFF
            if a in self.pe.iat: return a
        return None

    def noreturn_call(self, i):
        op = i.operands[0]
        slot = self.iat_slot(op)
        if slot is not None:
            return self.pe.iat[slot].split("!")[-1] in NORETURN_IMPORTS
        if op.type == X.X86_OP_IMM:
            return (op.imm & 0xFFFFFFFF) in self.tr.noreturn
        return False

    def same_gpr(self, a, b):
        na, nb = REG.get(self.tr.md.reg_name(a)), REG.get(self.tr.md.reg_name(b))
        return na and nb and na[0] == nb[0]

    def read_table(self, ta, lim, bound):
        tbl, n = [], 0
        while n < lim:
            try: t = self.pe.u32(ta + 4 * n)
            except (KeyError, StopIteration): break
            n += 1
            if not self.pe.is_code(t):
                break
            if not self.in_region(t):
                if bound: continue   # a case that leaves the function (tail call): not a label
                break
            tbl.append(t)
        return tbl

    def jump_table(self, seen, i):
        """MSVC x86: jmp dword ptr [idx*4 + table] (absolute entries), or mov r, [idx*4 + table] ; jmp r."""
        op = i.operands[0]
        prev = sorted((x for x in seen.values() if x and i.address - 96 <= x.address < i.address), key=lambda x: x.address)
        if op.type == X.X86_OP_MEM:
            mm = op.mem
            if mm.base or not mm.index or mm.scale != 4 or self.iat_slot(op) is not None: return None
            ta = mm.disp & 0xFFFFFFFF
            bound = self.table_limit(prev, len(prev), mm.index)
            return self.read_table(ta, bound or 4096, bound) or None
        r = op.reg
        for k in range(len(prev) - 1, -1, -1):
            x = prev[k]; ops = x.operands
            if x.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and self.same_gpr(ops[0].reg, r) \
                    and ops[1].type == X.X86_OP_MEM:
                mm = ops[1].mem
                if mm.base or not mm.index or mm.scale != 4: return None
                bound = self.table_limit(prev, k, mm.index)
                return self.read_table(mm.disp & 0xFFFFFFFF, bound or 4096, bound) or None
            if ops and ops[0].type == X.X86_OP_REG and self.same_gpr(ops[0].reg, r):
                return None
        return None

    def table_limit(self, prev, k, idx):
        """Look back for 'cmp idx, N' (guarding ja) -> N+1 entries.  Also follows a byte index table."""
        for j in range(k - 1, max(-1, k - 12), -1):
            p = prev[j]
            po = p.operands
            if p.mnemonic in ("mov", "movzx", "movsx") and len(po) == 2 and po[0].type == X.X86_OP_REG \
                    and po[1].type == X.X86_OP_REG and self.same_gpr(po[0].reg, idx):
                idx = po[1].reg; continue
            if p.mnemonic in ("cmp",) and len(po) == 2 and po[1].type == X.X86_OP_IMM \
                    and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, idx):
                return (po[1].imm & 0xFFFFFFFF) + 1
            if p.mnemonic in ("add", "sub", "dec", "inc") and po and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, idx):
                continue   # case values rebased (lea/add/sub before the cmp): the cmp bound still counts entries
            if p.mnemonic == "lea" and len(po) == 2 and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, idx) \
                    and po[1].mem.base and not po[1].mem.index:
                idx = po[1].mem.base; continue
            if p.mnemonic == "movzx" and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, idx) and po[1].type == X.X86_OP_MEM:
                mm = po[1].mem   # two-level: dword table has max(byte table)+1 entries
                ix = mm.index or mm.base
                bl = self.table_limit(prev, j, ix) if ix else None
                if bl and (mm.disp & 0xFFFFFFFF):
                    try: return max(self.pe.read(mm.disp & 0xFFFFFFFF, bl)) + 1
                    except (KeyError, StopIteration): return None
                return None
            if po and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, idx) and p.mnemonic not in ("test", "cmp"):
                return None
        return None

    # -- operand access --
    def rn(self, r):
        return self.tr.md.reg_name(r)

    def ea(self, op):
        m = op.mem
        parts = []
        if m.base:
            b = REG.get(self.rn(m.base))
            if not b or b[1] != 4: raise Unsupported("base " + self.rn(m.base))
            parts.append("C.%s" % b[0])
        if m.index:
            ix = REG.get(self.rn(m.index))
            if not ix or ix[1] != 4: raise Unsupported("index " + self.rn(m.index))
            parts.append("C.%s*%du" % (ix[0], m.scale) if m.scale != 1 else "C.%s" % ix[0])
        if m.disp or not parts:
            parts.append("0x%xu" % (m.disp & 0xFFFFFFFF))
        if m.segment == X.X86_REG_FS: parts.insert(0, "C.fsbase")
        elif m.segment == X.X86_REG_GS: raise Unsupported("gs")
        if len(parts) == 1 and parts[0].startswith("0x"): return parts[0]
        return "(uint32_t)(%s)" % " + ".join(parts)

    def rd(self, op, size=None):
        size = size or op.size
        if op.type == X.X86_OP_REG:
            n = self.rn(op.reg)
            if n not in REG: raise Unsupported("reg " + n)
            g, sz, hi = REG[n]
            if hi: return "(uint8_t)(C.%s >> 8)" % g
            return "C.%s" % g if sz == 4 else "(%s)C.%s" % (U[sz], g)
        if op.type == X.X86_OP_IMM:
            if size >= 8: return "0x%xull" % (op.imm & 0xFFFFFFFFFFFFFFFF)
            return "(%s)0x%xu" % (U[size], op.imm & ((1 << (8 * size)) - 1))
        return "%s(%s)" % (RD[size], self.ea(op))

    def wr(self, op, v, size=None):
        size = size or op.size
        if op.type == X.X86_OP_REG:
            n = self.rn(op.reg)
            if n not in REG: raise Unsupported("wreg " + n)
            g, sz, hi = REG[n]
            if hi: return "C.%s = (C.%s & ~0xFF00u) | ((uint32_t)(uint8_t)(%s) << 8);" % (g, g, v)
            if sz == 4: return "C.%s = (uint32_t)(%s);" % (g, v)
            return "C.%s = (C.%s & ~%s) | (%s)(%s);" % (g, g, MASK[sz], U[sz], v)
        return "%s(%s, (%s)(%s));" % (WR[size], self.ea(op), U[size], v)

    def wr_name(self, reg, v):
        g, sz, hi = REG[reg]
        if hi: return "C.%s = (C.%s & ~0xFF00u) | ((uint32_t)(uint8_t)(%s) << 8);" % (g, g, v)
        if sz == 4: return "C.%s = (uint32_t)(%s);" % (g, v)
        return "C.%s = (C.%s & ~%s) | (%s)(%s);" % (g, g, MASK[sz], U[sz], v)

    def xmm(self, op):
        n = self.rn(op.reg)
        if not n.startswith("xmm"): raise Unsupported("not xmm " + n)
        return "C.xmm[%d]" % int(n[3:])

    def isx(self, op):
        return op.type == X.X86_OP_REG and (self.rn(op.reg) or "").startswith("xmm")

    def e(self, s):
        self.out.append("    " + s)

    def szf(self, r, size):
        return "zf = ((%s) & %s) == 0; sf = ((%s) >> %d) & 1; pr = (uint8_t)(%s);" % (r, MASK[size], r, BITS[size] - 1, r)

    # -- control transfer --
    def tail(self, t, frm):
        if t in self.tr.funcs:
            return "F_%x(c); return;" % t
        return "missing_func(c, 0x%xu, 0x%xu); return;" % (t, frm)

    def goto(self, t, frm):
        return "goto L_%x;" % t if t in self.addrs else self.tail(t, frm)

    def goto_block(self, t, frm):
        g = self.goto(t, frm)
        return g if g.startswith("goto") else "{ %s }" % g

    def call(self, i, op, nxt):
        e = self.e
        if op.type == X.X86_OP_IMM:
            t = op.imm & 0xFFFFFFFF
            if t == nxt: e("PUSH(c, 0x%xu);" % nxt); return   # call $+5 ; pop reg  (get EIP)
            if t in self.tr.funcs: e("PUSH(c, 0x%xu); F_%x(c);" % (nxt, t))
            else: e("PUSH(c, 0x%xu); missing_func(c, 0x%xu, 0x%xu);" % (nxt, t, i.address))
            return
        slot = self.iat_slot(op)
        if slot is not None:
            name = self.pe.iat[slot]; self.tr.imports_used.add(name)
            e("PUSH(c, 0x%xu); I_%s(c); C.esp += 4;" % (nxt, imp_sym(name)))
            return
        e("{ uint32_t t = %s; PUSH(c, 0x%xu); call_ind(c, t); }" % (self.rd(op, 4), nxt))

    # -- generation --
    def gen(self):
        for i in self.ins:
            if (i.group(cs.CS_GRP_JUMP) or i.mnemonic in ("loop", "loope", "loopne", "jecxz", "jcxz")) and i.operands and i.operands[0].type == X.X86_OP_IMM:
                if (i.operands[0].imm & 0xFFFFFFFF) in self.addrs: self.labels.add(i.operands[0].imm & 0xFFFFFFFF)
            for t in self.tables.get(i.address, []): self.labels.add(t)
        for k, i in enumerate(self.ins):
            nx = i.address + i.size
            if not self.ends_block(i) and (k + 1 >= len(self.ins) or self.ins[k + 1].address != nx) and nx in self.addrs:
                self.labels.add(nx)
        f = self.out
        f.append("void F_%x(CPU *c) {" % self.addr)
        f.append("    uint32_t cf = 0, zf = 0, sf = 0, of = 0, pr = 0, df = 0; (void)cf; (void)zf; (void)sf; (void)of; (void)pr; (void)df;")
        f.append("    c->fn = 0x%xu;" % self.addr)
        # code is emitted in address order; a function that reaches code below its entry (a backward tail jump into
        # shared code) must still start executing at its entry
        if self.ins and self.ins[0].address != self.addr:
            self.labels.add(self.addr)
            f.append("    goto L_%x;" % self.addr)
        last = None
        for i in self.ins:
            if last is not None and not self.ends_block(last) and i.address != last.address + last.size:
                self.e(self.goto(last.address + last.size, last.address))
            self.cur = i
            if i.address in self.labels:
                f.append("L_%x:;" % i.address)
            try:
                for pc in PROBES.get(i.address, ()): self.e("{ void rt_log(const char *, ...); " + pc + " }   /* probe */")
                n0 = len(self.out)
                if i.address in PATCHES and PATCHES[i.address].startswith("@call "):
                    # the instruction becomes a call to a host native N_* that sees the guest stack the original
                    # callee would (arguments already pushed; it pops them itself, like an import shim)
                    self.e("PUSH(c, 0x%xu); %s(c); C.esp += 4;   /* patched: %s %s */" % (i.address + i.size, PATCHES[i.address].split()[1], i.mnemonic, i.op_str))
                elif i.address in PATCHES: self.e(PATCHES[i.address] + "   /* patched: %s %s */" % (i.mnemonic, i.op_str))
                else: self.insn(i)
                # tag the C with the guest address (debugger file:line -> guest instruction)
                for k in range(n0, len(self.out)): self.out[k] += " /*@%x*/" % i.address
            except Unsupported as ex:
                self.e('bad_insn(c, 0x%xu, "%s %s"); return; /* %s */' % (i.address, i.mnemonic, i.op_str, ex))
                self.tr.unsupported[i.mnemonic] += 1
            last = i
        if last is not None and not self.ends_block(last):
            self.e(self.tail(last.address + last.size, last.address))
        f.append("}")
        return cache_registers(const_loads(self.pe, STACK_ACCESS.sub(r"\1s\2((uint32_t)(C.esp", "\n".join(f))))

    def ends_block(self, i):
        m = i.mnemonic
        if m == "call": return self.noreturn_call(i)
        return m in ("ret", "retf", "jmp", "ud2", "hlt", "int3", "iretd", "ljmp") or m.startswith("ret") or \
            (m == "int" and i.operands and i.operands[0].imm == 0x29)

    # ---------------- instructions ----------------
    def insn(self, i):
        m = i.mnemonic
        ops = i.operands
        e = self.e
        nxt = i.address + i.size
        if m in ("repz ret", "rep ret", "bnd ret"): m = "ret"
        if m.startswith("bnd "): m = m[4:]
        if m == "movnti": m = "mov"
        if self.mmx(i, m, ops): return
        if m in ("nop", "pause", "lfence", "sfence", "mfence", "wait", "fwait", "endbr32", "clflush") or m.startswith(("prefetch", "nop")):
            return
        if m == "cld": e("df = 0;"); return
        if m == "std": e("df = 1;"); return
        if m in ("int3", "ud2", "hlt"):
            e('bad_insn(c, 0x%xu, "%s"); return;' % (i.address, m)); return
        if m == "int":
            e("cpu_int(c, 0x%xu, %d); return;" % (i.address, ops[0].imm)); return
        if m == "mov":
            d, s = ops
            for o in (d, s):
                if o.type == X.X86_OP_REG and self.rn(o.reg) not in REG: raise Unsupported("mov special " + self.rn(o.reg))
            e(self.wr(d, self.rd(s, d.size))); return
        if m == "lea":
            d, s = ops
            e(self.wr(d, self.ea(s).replace("C.fsbase + ", ""))); return
        if m == "movzx":
            d, s = ops
            e(self.wr(d, "(%s)%s" % (U[d.size], self.rd(s)))); return
        if m == "movsx":
            d, s = ops
            e(self.wr(d, "(%s)(%s)(%s)%s" % (U[d.size], S[d.size], S[s.size], self.rd(s)))); return
        if m == "cwde": e("C.eax = (uint32_t)(int32_t)(int16_t)C.eax;"); return
        if m == "cbw": e("C.eax = (C.eax & ~0xFFFFu) | (uint16_t)(int16_t)(int8_t)C.eax;"); return
        if m == "cdq": e("C.edx = (uint32_t)((int32_t)C.eax >> 31);"); return
        if m == "cwd": e("C.edx = (C.edx & ~0xFFFFu) | (uint16_t)((int16_t)C.eax >> 15);"); return
        if m == "push":
            o = ops[0]
            if o.type == X.X86_OP_REG and self.rn(o.reg) not in REG: raise Unsupported("push " + self.rn(o.reg))
            if o.type == X.X86_OP_IMM: e("PUSH(c, 0x%xu);" % (o.imm & 0xFFFFFFFF))
            elif o.size == 2: e("C.esp -= 2; wrs16(C.esp, %s);" % self.rd(o))
            else: e("PUSH(c, %s);" % self.rd(o, 4))
            return
        if m == "pop":
            o = ops[0]
            if o.type == X.X86_OP_REG and self.rn(o.reg) not in REG: raise Unsupported("pop " + self.rn(o.reg))
            if o.size == 2: e("{ uint16_t v = rds16(C.esp); C.esp += 2; %s }" % self.wr(o, "v")); return
            e("{ uint32_t v = POP(c); %s }" % self.wr(o, "v")); return
        if m == "pushal":
            e("{ uint32_t s_ = C.esp; PUSH(c, C.eax); PUSH(c, C.ecx); PUSH(c, C.edx); PUSH(c, C.ebx); PUSH(c, s_); PUSH(c, C.ebp); PUSH(c, C.esi); PUSH(c, C.edi); }"); return
        if m == "popal":
            e("{ C.edi = POP(c); C.esi = POP(c); C.ebp = POP(c); (void)POP(c); C.ebx = POP(c); C.edx = POP(c); C.ecx = POP(c); C.eax = POP(c); }"); return
        if m == "pushfd":
            e("PUSH(c, 0x202u | (cf ? 1 : 0) | (parity8(pr) ? 4 : 0) | (zf ? 0x40 : 0) | (sf ? 0x80 : 0) | (df ? 0x400 : 0) | (of ? 0x800 : 0));"); return
        if m == "popfd":
            e("{ uint32_t v = POP(c); cf = v & 1; zf = (v >> 6) & 1; sf = (v >> 7) & 1; df = (v >> 10) & 1; of = (v >> 11) & 1; pr = (v & 4) ? 0 : 1; }"); return
        if m == "lahf":
            e("C.eax = (C.eax & ~0xFF00u) | ((uint32_t)(2 | (cf ? 1 : 0) | (parity8(pr) ? 4 : 0) | (zf ? 0x40 : 0) | (sf ? 0x80 : 0)) << 8);"); return
        if m == "sahf":
            e("{ uint32_t v = C.eax >> 8; cf = v & 1; zf = (v >> 6) & 1; sf = (v >> 7) & 1; pr = (v & 4) ? 0 : 1; }"); return
        if m in ("clc", "stc", "cmc"):
            e({"clc": "cf = 0;", "stc": "cf = 1;", "cmc": "cf = !cf;"}[m]); return
        if m == "leave":
            e("C.esp = C.ebp; C.ebp = POP(c);"); return
        if m == "enter":
            n, lvl = ops[0].imm, ops[1].imm
            if lvl: raise Unsupported("enter level")
            e("PUSH(c, C.ebp); C.ebp = C.esp; C.esp -= %du;" % n); return
        if m == "ret":
            n = ops[0].imm if ops else 0
            e("C.esp += %d; return;" % (4 + n)); return
        if m == "call":
            self.call(i, ops[0], nxt); return
        if m == "jmp":
            op = ops[0]
            if op.type == X.X86_OP_IMM:
                e(self.goto(op.imm & 0xFFFFFFFF, i.address)); return
            tbl = self.tables.get(i.address)
            if tbl:
                cases = " ".join("case 0x%xu: goto L_%x;" % (t, t) for t in sorted(set(tbl)))
                e("{ uint32_t t = %s; switch (t) { %s default: call_ind(c, t); return; } }" % (self.rd(op, 4), cases))
                return
            slot = self.iat_slot(op)
            if slot is not None:
                name = self.pe.iat[slot]; self.tr.imports_used.add(name)
                e("I_%s(c); C.esp += 4; return;" % imp_sym(name)); return
            e("{ uint32_t t = %s; call_ind(c, t); return; }" % self.rd(op, 4)); return
        if m in ("jecxz", "jcxz"):
            r = "C.ecx" if m == "jecxz" else "(uint16_t)C.ecx"
            e("if (%s == 0) %s" % (r, self.goto_block(ops[0].imm & 0xFFFFFFFF, i.address))); return
        if m in ("loop", "loope", "loopne"):
            cond = {"loop": "C.ecx != 0", "loope": "C.ecx != 0 && zf", "loopne": "C.ecx != 0 && !zf"}[m]
            e("C.ecx--; if (%s) %s" % (cond, self.goto_block(ops[0].imm & 0xFFFFFFFF, i.address))); return
        if m.startswith("j"):
            cc = CC.get(m[1:])
            if cc is None: raise Unsupported(m)
            e("if (%s) %s" % (cc, self.goto_block(ops[0].imm & 0xFFFFFFFF, i.address))); return
        if m.startswith("set") and m[3:] in CC:
            e(self.wr(ops[0], "(%s) ? 1 : 0" % CC[m[3:]])); return
        if m.startswith("cmov") and m[4:] in CC:
            d = ops[0]
            e("if (%s) %s" % (CC[m[4:]], self.wr(d, self.rd(ops[1], d.size)))); return
        if m == "xlatb":
            e("C.eax = (C.eax & ~0xFFu) | rd8((uint32_t)(C.ebx + (uint8_t)C.eax));"); return
        if self.alu(i, m, ops): return
        if self.strop(i, m, ops): return
        if self.atomic(i, m, ops): return
        if m == "cpuid": e("cpu_cpuid(c);"); return
        if m == "xgetbv": e("C.eax = 7; C.edx = 0;"); return
        if m == "rdtsc":
            e("{ uint64_t t = __builtin_readcyclecounter(); C.eax = (uint32_t)t; C.edx = (uint32_t)(t >> 32); }"); return
        if self.sse(i, m, ops): return
        if self.vec(i, m, ops): return
        if self.x87(i, m, ops): return
        raise Unsupported(m)

    # -- integer ALU --
    def alu(self, i, m, ops):
        e = self.e
        if m in ("add", "sub", "cmp", "adc", "sbb") and len(ops) == 2:
            d, s = ops; n = d.size
            a, b = self.rd(d), self.rd(s, n)
            car = " + (%s)cf" % U[n] if m == "adc" else " - (%s)cf" % U[n] if m == "sbb" else ""
            if m in ("add", "adc"):
                cfe = "r < a || (cf_in && r == a)" if m == "adc" else "r < a"
                e("{ %s a = %s, b = %s, r; uint32_t cf_in = cf; (void)cf_in; r = (%s)(a + b%s); cf = %s; of = ((~(a ^ b) & (a ^ r)) >> %d) & 1; %s %s }"
                  % (U[n], a, b, U[n], car, cfe, BITS[n] - 1, self.szf("r", n), self.wr(d, "r")))
            else:
                cfe = "a < b || (cf_in && a == b)" if m == "sbb" else "a < b"
                wb = "" if m == "cmp" else self.wr(d, "r")
                e("{ %s a = %s, b = %s, r; uint32_t cf_in = cf; (void)cf_in; r = (%s)(a - b%s); cf = %s; of = (((a ^ b) & (a ^ r)) >> %d) & 1; %s %s }"
                  % (U[n], a, b, U[n], car, cfe, BITS[n] - 1, self.szf("r", n), wb))
            return True
        if m in ("and", "or", "xor", "test") and len(ops) == 2:
            d, s = ops; n = d.size
            if m == "xor" and s.type == X.X86_OP_REG and d.type == X.X86_OP_REG and s.reg == d.reg:
                e(self.wr(d, "0") + " cf = 0; of = 0; zf = 1; sf = 0; pr = 0;"); return True
            op = {"and": "&", "or": "|", "xor": "^", "test": "&"}[m]
            wb = "" if m == "test" else self.wr(d, "r")
            e("{ %s r = (%s)(%s %s %s); cf = 0; of = 0; %s %s }" % (U[n], U[n], self.rd(d), op, self.rd(s, n), self.szf("r", n), wb))
            return True
        if m in ("inc", "dec"):
            d = ops[0]; n = d.size
            op = "+" if m == "inc" else "-"
            ofc = "r == (%s)((%s)1 << %d)" % (U[n], U[n], BITS[n] - 1) if m == "inc" else "a == (%s)((%s)1 << %d)" % (U[n], U[n], BITS[n] - 1)
            e("{ %s a = %s, r = (%s)(a %s 1); of = %s; %s %s }" % (U[n], self.rd(d), U[n], op, ofc, self.szf("r", n), self.wr(d, "r")))
            return True
        if m == "neg":
            d = ops[0]; n = d.size
            e("{ %s a = %s, r = (%s)(0 - a); cf = a != 0; of = a == (%s)((%s)1 << %d); %s %s }" % (U[n], self.rd(d), U[n], U[n], U[n], BITS[n] - 1, self.szf("r", n), self.wr(d, "r")))
            return True
        if m == "not":
            d = ops[0]; e(self.wr(d, "~%s" % self.rd(d))); return True
        if m in ("shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr"):
            d = ops[0]; n = d.size; bits = BITS[n]
            cnt = "%d" % (ops[1].imm & 31) if len(ops) > 1 and ops[1].type == X.X86_OP_IMM else \
                  ("(uint32_t)(%s & 31)" % self.rd(ops[1], 1) if len(ops) > 1 else "1")
            a = self.rd(d)
            W = "uint32_t"   # shifts in 32-bit arithmetic (counts up to 31 on 8/16-bit operands)
            if m in ("shl", "sal"):
                body = "r = (%s)((%s)a << k); cf = k <= %d ? ((%s)a >> (%d - k)) & 1 : 0; of = ((r >> %d) & 1) ^ cf;" % (U[n], W, bits, W, bits, bits - 1)
            elif m == "shr":
                body = "r = (%s)((%s)a >> k); cf = ((%s)a >> (k - 1)) & 1; of = (a >> %d) & 1;" % (U[n], W, W, bits - 1)
            elif m == "sar":
                body = "r = (%s)((int32_t)(%s)a >> (k > %d ? %d : k)); cf = ((int32_t)(%s)a >> (k - 1 > %d ? %d : k - 1)) & 1; of = 0;" % (U[n], S[n], bits - 1, bits - 1, S[n], bits - 1, bits - 1)
            elif m in ("rol", "ror"):
                if m == "rol":
                    body = "k %%= %d; r = k ? (%s)((a << k) | (a >> (%d - k))) : a; cf = r & 1; of = ((r >> %d) & 1) ^ cf;" % (bits, U[n], bits, bits - 1)
                else:
                    body = "k %%= %d; r = k ? (%s)((a >> k) | (a << (%d - k))) : a; cf = (r >> %d) & 1; of = cf ^ ((r >> %d) & 1);" % (bits, U[n], bits, bits - 1, bits - 2)
                e("{ %s a = %s, r; uint32_t k = %s; if (k) { %s %s } }" % (U[n], a, cnt, body, self.wr(d, "r"))); return True
            else:
                if m == "rcl":
                    body = "for (uint32_t j = 0; j < k; j++) { uint32_t nc = (r >> %d) & 1; r = (%s)((r << 1) | cf); cf = nc; } if (k == 1) of = ((r >> %d) & 1) ^ cf;" % (bits - 1, U[n], bits - 1)
                else:
                    body = "if (k == 1) of = ((r >> %d) & 1) ^ cf; for (uint32_t j = 0; j < k; j++) { uint32_t nc = r & 1; r = (%s)((r >> 1) | ((%s)cf << %d)); cf = nc; }" % (bits - 1, U[n], W, bits - 1)
                e("{ %s r = %s; uint32_t k = %s; %s %s }" % (U[n], a, cnt, body, self.wr(d, "r"))); return True
            e("{ %s a = %s, r; uint32_t k = %s; if (k) { %s %s %s } }" % (U[n], a, cnt, body, self.szf("r", n), self.wr(d, "r")))
            return True
        if m in ("shld", "shrd"):
            d, s = ops[0], ops[1]; n = d.size; bits = BITS[n]
            if n != 4: raise Unsupported(m + "16")
            cnt = "%d" % (ops[2].imm & 31) if ops[2].type == X.X86_OP_IMM else "(uint32_t)(C.ecx & 31)"
            if m == "shld": body = "r = (a << k) | (b >> (32 - k)); cf = (a >> (32 - k)) & 1;"
            else: body = "r = (a >> k) | (b << (32 - k)); cf = (a >> (k - 1)) & 1;"
            e("{ uint32_t a = %s, b = %s, r; uint32_t k = %s; if (k) { %s %s %s } }" % (self.rd(d), self.rd(s, n), cnt, body, self.szf("r", n), self.wr(d, "r")))
            return True
        if m in ("bt", "bts", "btr", "btc"):
            d, s = ops; n = d.size
            if d.type == X.X86_OP_MEM and s.type == X.X86_OP_REG:
                ad = self.ea(d)
                e("{ int32_t o = (%s)%s; uint32_t a = %s + (uint32_t)(o >> 3); uint8_t v = rd8(a), k = o & 7; cf = (v >> k) & 1; %s }"
                  % (S[n], self.rd(s), ad, {"bt": "", "bts": "wr8(a, v | (1u << k));", "btr": "wr8(a, v & ~(1u << k));", "btc": "wr8(a, v ^ (1u << k));"}[m]))
                return True
            k = "(%s & %d)" % (self.rd(s, n) if s.type != X.X86_OP_IMM else "%d" % s.imm, BITS[n] - 1)
            op = {"bt": None, "bts": "v | b", "btr": "v & ~b", "btc": "v ^ b"}[m]
            e("{ %s v = %s, b = (%s)(1u << %s); cf = (v & b) != 0; %s }" % (U[n], self.rd(d), U[n], k, self.wr(d, op) if op else ""))
            return True
        if m in ("bsf", "bsr", "tzcnt", "lzcnt", "popcnt"):
            d, s = ops; n = d.size
            v = "(uint32_t)%s" % self.rd(s)
            if m == "bsf": e("{ uint32_t v = %s; zf = v == 0; if (v) %s }" % (v, self.wr(d, "__builtin_ctz(v)")))
            elif m == "bsr": e("{ uint32_t v = %s; zf = v == 0; if (v) %s }" % (v, self.wr(d, "31 - __builtin_clz(v)")))
            elif m == "popcnt": e("{ uint32_t v = %s; %s zf = v == 0; cf = 0; }" % (v, self.wr(d, "__builtin_popcount(v)")))
            elif m == "tzcnt": e("{ uint32_t v = %s; uint32_t r = v ? (uint32_t)__builtin_ctz(v) : %d; cf = v == 0; zf = r == 0; %s }" % (v, BITS[n], self.wr(d, "r")))
            else: e("{ uint32_t v = %s; uint32_t r = v ? (uint32_t)__builtin_clz(v) - %d : %d; cf = v == 0; zf = r == 0; %s }" % (v, 32 - BITS[n], BITS[n], self.wr(d, "r")))
            return True
        if m == "bswap":
            d = ops[0]; e(self.wr(d, "__builtin_bswap32(%s)" % self.rd(d))); return True
        if m == "xchg":
            a, b = ops
            if a.type == X.X86_OP_MEM or b.type == X.X86_OP_MEM:
                mem, reg = (a, b) if a.type == X.X86_OP_MEM else (b, a)
                e("{ %s v = __atomic_exchange_n((%s *)G2H(%s), %s, __ATOMIC_SEQ_CST); %s }" % (U[mem.size], U[mem.size], self.ea(mem), self.rd(reg), self.wr(reg, "v")))
            else:
                e("{ %s t = %s; %s %s }" % (U[a.size], self.rd(a), self.wr(a, self.rd(b)), self.wr(b, "t")))
            return True
        if m in ("imul", "mul", "div", "idiv"):
            return self.muldiv(m, ops)
        return False

    def muldiv(self, m, ops):
        e = self.e
        if m == "imul" and len(ops) >= 2:
            d = ops[0]; n = d.size
            a = self.rd(ops[1], n) if len(ops) == 3 else self.rd(d)
            b = self.rd(ops[2], n) if len(ops) == 3 else self.rd(ops[1], n)
            e("{ int64_t p = (int64_t)(%s)%s * (int64_t)(%s)%s; %s r = (%s)p; cf = of = p != (int64_t)(%s)r; %s %s }"
              % (S[n], a, S[n], b, U[n], U[n], S[n], self.szf("r", n), self.wr(d, "r")))
            return True
        s = ops[0]; n = s.size; v = self.rd(s)
        if n == 4:
            if m == "mul": e("{ uint64_t p = (uint64_t)C.eax * %s; C.eax = (uint32_t)p; C.edx = (uint32_t)(p >> 32); cf = of = C.edx != 0; }" % v)
            elif m == "imul": e("{ int64_t p = (int64_t)(int32_t)C.eax * (int32_t)%s; C.eax = (uint32_t)p; C.edx = (uint32_t)((uint64_t)p >> 32); cf = of = p != (int32_t)p; }" % v)
            elif m == "div": e("{ uint64_t nn = ((uint64_t)C.edx << 32) | C.eax; uint32_t dd = %s; C.eax = (uint32_t)(nn / dd); C.edx = (uint32_t)(nn %% dd); }" % v)
            else: e("{ int64_t nn = (int64_t)(((uint64_t)C.edx << 32) | C.eax); int32_t dd = (int32_t)%s; C.eax = (uint32_t)(int32_t)(nn / dd); C.edx = (uint32_t)(int32_t)(nn %% dd); }" % v)
        elif n == 2:
            if m in ("mul", "imul"):
                t = "uint32_t" if m == "mul" else "int32_t"; c16 = "uint16_t" if m == "mul" else "int16_t"
                ov = "(C.edx & 0xFFFF) != 0" if m == "mul" else "p != (int16_t)p"
                e("{ %s p = (%s)(%s)C.eax * (%s)%s; C.eax = (C.eax & ~0xFFFFu) | (uint16_t)p; C.edx = (C.edx & ~0xFFFFu) | (uint16_t)((uint32_t)p >> 16); cf = of = %s; }" % (t, t, c16, c16, v, ov))
            else:
                t, c16 = ("uint32_t", "uint16_t") if m == "div" else ("int32_t", "int16_t")
                e("{ %s nn = (%s)(((uint32_t)(uint16_t)C.edx << 16) | (uint16_t)C.eax); %s dd = (%s)%s; C.eax = (C.eax & ~0xFFFFu) | (uint16_t)(nn / dd); C.edx = (C.edx & ~0xFFFFu) | (uint16_t)(nn %% dd); }" % (t, t, c16, c16, v))
        else:
            if m in ("mul", "imul"):
                t, c8 = ("uint32_t", "uint8_t") if m == "mul" else ("int32_t", "int8_t")
                ov = "(p >> 8) != 0" if m == "mul" else "p != (int8_t)p"
                e("{ %s p = (%s)(%s)C.eax * (%s)%s; C.eax = (C.eax & ~0xFFFFu) | (uint16_t)p; cf = of = %s; }" % (t, t, c8, c8, v, ov))
            else:
                t, c8 = ("uint32_t", "uint8_t") if m == "div" else ("int32_t", "int8_t")
                e("{ %s nn = (%s)(%s)C.eax; %s dd = (%s)%s; C.eax = (C.eax & ~0xFFFFu) | (uint8_t)(nn / dd) | ((uint16_t)(uint8_t)(nn %% dd) << 8); }" % (t, t, "uint16_t" if m == "div" else "int16_t", c8, c8, v))
        return True

    # -- string ops (honour DF, a function-local flag set by std/cld) --
    def strop(self, i, m, ops):
        e = self.e
        mm = re.match(r"(rep |repe |repne |repz |repnz )?(movs|stos|lods|cmps|scas)([bwd])$", m)
        if not mm: return False
        if any(self.isx(o) for o in ops): return False
        rep, op, w = mm.groups()
        n = {"b": 1, "w": 2, "d": 4}[w]
        T = U[n]
        st = "(df ? -%d : %d)" % (n, n)
        if op == "movs" and rep:
            # forward, element by element when the destination starts inside the source (MSVC fills arrays that way)
            e("if (!df) { uint32_t k = C.ecx, s_ = C.esi, d_ = C.edi; if (d_ > s_ && d_ < s_ + k * %d) { for (uint32_t j = 0; j < k; j++) %s(d_ + j * %d, %s(s_ + j * %d)); }"
              " else memmove(G2H(d_), G2H(s_), (size_t)k * %d); C.esi += k * %d; C.edi += k * %d; C.ecx = 0; }"
              " else { while (C.ecx) { %s(C.edi, %s(C.esi)); C.esi -= %d; C.edi -= %d; C.ecx--; } }" % (n, WR[n], n, RD[n], n, n, n, n, WR[n], RD[n], n, n))
            return True
        if op == "stos" and rep:
            if n == 1: e("if (!df) { uint32_t k = C.ecx; memset(G2H(C.edi), (uint8_t)C.eax, k); C.edi += k; C.ecx = 0; } else { while (C.ecx) { wr8(C.edi, (uint8_t)C.eax); C.edi--; C.ecx--; } }")
            else: e("{ uint32_t k = C.ecx; %s v = (%s)C.eax; for (uint32_t j = 0; j < k; j++) { %s(C.edi, v); C.edi += %s; } C.ecx = 0; }" % (T, T, WR[n], st))
            return True
        if op == "movs": e("%s(C.edi, %s(C.esi)); C.esi += %s; C.edi += %s;" % (WR[n], RD[n], st, st)); return True
        if op == "stos": e("%s(C.edi, (%s)C.eax); C.edi += %s;" % (WR[n], T, st)); return True
        if op == "lods":
            reg = {1: "al", 2: "ax", 4: "eax"}[n]
            one = "{ %s v = %s(C.esi); C.esi += %s; %s }" % (T, RD[n], st, self.wr_name(reg, "v"))
            if rep: e("while (C.ecx) { %s C.ecx--; }" % one)
            else: e(one)
            return True
        lhs = "%s(C.esi)" % RD[n] if op == "cmps" else "(%s)C.eax" % T
        adv = "C.esi += %s; C.edi += %s;" % (st, st) if op == "cmps" else "C.edi += %s;" % st
        one = "{ %s a = %s, b = %s(C.edi), r = (%s)(a - b); cf = a < b; of = (((a ^ b) & (a ^ r)) >> %d) & 1; %s %s }" % (T, lhs, RD[n], T, BITS[n] - 1, self.szf("r", n), adv)
        if not rep: e(one); return True
        cond = "zf" if rep.strip() in ("repe", "repz", "rep") else "!zf"
        e("while (C.ecx) { %s C.ecx--; if (!(%s)) break; }" % (one, cond)); return True

    # -- lock-prefixed atomics --
    def atomic(self, i, m, ops):
        e = self.e
        if not m.startswith("lock ") and m not in ("cmpxchg", "xadd", "cmpxchg8b"): return False
        base = m[5:] if m.startswith("lock ") else m
        d = ops[0]; n = d.size; T = U[n]
        if base == "cmpxchg8b":
            p = "(uint64_t *)G2H(%s)" % self.ea(d)
            e("{ uint64_t exp = ((uint64_t)C.edx << 32) | C.eax, nv = ((uint64_t)C.ecx << 32) | C.ebx; zf = __atomic_compare_exchange_n(%s, &exp, nv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); if (!zf) { C.eax = (uint32_t)exp; C.edx = (uint32_t)(exp >> 32); } }" % p)
            return True
        if d.type != X.X86_OP_MEM:
            if base == "xadd":
                e("{ %s a = %s, b = %s, r = (%s)(a + b); %s %s cf = r < a; %s }" % (T, self.rd(d), self.rd(ops[1]), T, self.wr(ops[1], "a"), self.wr(d, "r"), self.szf("r", n)))
                return True
            if base == "cmpxchg":
                acc = {1: "al", 2: "ax", 4: "eax"}[n]
                e("{ %s cur = %s, exp = (%s)C.eax, r = (%s)(exp - cur); cf = exp < cur; of = (((exp ^ cur) & (exp ^ r)) >> %d) & 1; %s if (zf) { %s } else { %s } }"
                  % (T, self.rd(d), T, T, BITS[n] - 1, self.szf("r", n), self.wr(d, self.rd(ops[1])), self.wr_name(acc, "cur")))
                return True
            raise Unsupported(m)
        p = "(%s *)G2H(%s)" % (T, self.ea(d))
        if base == "xadd":
            e("{ %s b = %s, a = __atomic_fetch_add(%s, b, __ATOMIC_SEQ_CST), r = (%s)(a + b); %s cf = r < a; of = ((~(a ^ b) & (a ^ r)) >> %d) & 1; %s }"
              % (T, self.rd(ops[1]), p, T, self.wr(ops[1], "a"), BITS[n] - 1, self.szf("r", n)))
            return True
        if base == "cmpxchg":
            acc = {1: "al", 2: "ax", 4: "eax"}[n]
            e("{ %s exp = (%s)C.eax, acc = exp, r; int ok = __atomic_compare_exchange_n(%s, &exp, %s, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); %s r = (%s)(acc - exp); cf = acc < exp; of = (((acc ^ exp) & (acc ^ r)) >> %d) & 1; %s zf = ok; }"
              % (T, T, p, self.rd(ops[1]), "if (!ok) { %s }" % self.wr_name(acc, "exp"), T, BITS[n] - 1, self.szf("r", n)))
            return True
        if base in ("inc", "dec", "add", "sub", "or", "and", "xor"):
            v = "1" if base in ("inc", "dec") else self.rd(ops[1], n)
            fn = {"inc": "add", "dec": "sub", "add": "add", "sub": "sub", "or": "or", "and": "and", "xor": "xor"}[base]
            op = {"add": "+", "sub": "-", "or": "|", "and": "&", "xor": "^"}[fn]
            fl = ("cf = r < a; of = ((~(a ^ b) & (a ^ r)) >> %d) & 1;" % (BITS[n] - 1) if base == "add" else
                  "cf = a < b; of = (((a ^ b) & (a ^ r)) >> %d) & 1;" % (BITS[n] - 1) if base == "sub" else
                  "of = 0; cf = 0;" if fn in ("or", "and", "xor") else
                  "of = r == (%s)((%s)1 << %d);" % (T, T, BITS[n] - 1) if base == "inc" else "of = a == (%s)((%s)1 << %d);" % (T, T, BITS[n] - 1))
            e("{ %s b = (%s)%s, a = __atomic_fetch_%s(%s, b, __ATOMIC_SEQ_CST), r = (%s)(a %s b); %s %s }" % (T, T, v, fn, p, T, op, self.szf("r", n), fl))
            return True
        if base in ("bts", "btr", "btc"):
            k = "(%s & %d)" % (self.rd(ops[1], n) if ops[1].type != X.X86_OP_IMM else "%d" % ops[1].imm, BITS[n] - 1)
            fn = {"bts": "or", "btr": "and", "btc": "xor"}[base]
            mk = "(%s)~(1u << %s)" % (T, k) if base == "btr" else "(%s)(1u << %s)" % (T, k)
            e("{ %s a = __atomic_fetch_%s(%s, %s, __ATOMIC_SEQ_CST); cf = (a >> %s) & 1; }" % (T, fn, p, mk, k))
            return True
        if base == "xchg":
            return self.alu(i, "xchg", ops)
        raise Unsupported(m)

    # -- scalar SSE / moves --
    def sse(self, i, m, ops):
        e = self.e
        def src32(op): return "%s.f[0]" % self.xmm(op) if self.isx(op) else "rdf(%s)" % self.ea(op)
        def src64(op): return "%s.d[0]" % self.xmm(op) if self.isx(op) else "rdd(%s)" % self.ea(op)
        def x128(op): return self.xmm(op) if self.isx(op) else "rdx(%s)" % self.ea(op)
        if m in ("movaps", "movups", "movdqa", "movdqu", "movapd", "movupd", "movntps", "movntdq", "movntpd", "lddqu", "movntdqa"):
            d, s = ops
            if self.isx(d): e("%s = %s;" % (self.xmm(d), x128(s)))
            else: e("wrx(%s, %s);" % (self.ea(d), self.xmm(s)))
            return True
        if m in ("movss", "movsd") and len(ops) == 2 and (self.isx(ops[0]) or self.isx(ops[1])):
            d, s = ops
            f = "f" if m == "movss" else "d"
            if self.isx(d) and self.isx(s): e("%s.%s[0] = %s.%s[0];" % (self.xmm(d), f, self.xmm(s), f))
            elif self.isx(d):
                if m == "movss": e("{ XMM x = {0}; x.f[0] = rdf(%s); %s = x; }" % (self.ea(s), self.xmm(d)))
                else: e("{ XMM x = {0}; x.d[0] = rdd(%s); %s = x; }" % (self.ea(s), self.xmm(d)))
            else: e("%s(%s, %s.%s[0]);" % ("wrf" if m == "movss" else "wrd", self.ea(d), self.xmm(s), f))
            return True
        if m in ("movd", "movq") and (self.isx(ops[0]) or self.isx(ops[1])):
            d, s = ops
            if self.isx(d) and self.isx(s): e("{ XMM x = {0}; x.q[0] = %s.q[0]; %s = x; }" % (self.xmm(s), self.xmm(d))); return True
            if self.isx(d):
                e("{ XMM x = {0}; x.q[0] = (uint64_t)%s; %s = x; }" % (self.rd(s), self.xmm(d))); return True
            e(self.wr(d, "%s.%s[0]" % (self.xmm(s), "q" if d.size == 8 else "u"))); return True
        if m in ("movlps", "movlpd", "movhps", "movhpd"):
            d, s = ops; k = 0 if m.startswith("movl") else 1
            if self.isx(d): e("%s.q[%d] = rd64(%s);" % (self.xmm(d), k, self.ea(s)))
            else: e("wr64(%s, %s.q[%d]);" % (self.ea(d), self.xmm(s), k))
            return True
        if m in ("movmskps", "movmskpd"):
            d, s = ops; X_ = self.xmm(s)
            if m == "movmskps": e(self.wr(d, "(%s.u[0] >> 31) | ((%s.u[1] >> 31) << 1) | ((%s.u[2] >> 31) << 2) | ((%s.u[3] >> 31) << 3)" % (X_, X_, X_, X_), 4))
            else: e(self.wr(d, "(uint32_t)((%s.q[0] >> 63) | ((%s.q[1] >> 63) << 1))" % (X_, X_), 4))
            return True
        if m == "pmovmskb" and self.isx(ops[1]):
            d, s = ops; X_ = self.xmm(s)
            e("{ uint32_t r = 0; for (int k = 0; k < 16; k++) r |= (uint32_t)(%s.b[k] >> 7) << k; %s }" % (X_, self.wr(d, "r", 4))); return True
        ar = {"add": "+", "sub": "-", "mul": "*", "div": "/"}
        mm = re.match(r"(add|sub|mul|div|min|max|sqrt)(ss|sd)$", m)
        if mm:
            op, t = mm.groups(); d, s = ops
            f = "f" if t == "ss" else "d"; v = src32(s) if t == "ss" else src64(s)
            D = "%s.%s[0]" % (self.xmm(d), f)
            if op in ar: e("%s = %s %s %s;" % (D, D, ar[op], v))
            elif op == "min": e("{ __typeof__(%s) b = %s; %s = %s < b ? %s : b; }" % (D, v, D, D, D))
            elif op == "max": e("{ __typeof__(%s) b = %s; %s = %s > b ? %s : b; }" % (D, v, D, D, D))
            else: e("%s = %s(%s);" % (D, "sqrtf" if t == "ss" else "sqrt", v))
            return True
        mm = re.match(r"(add|sub|mul|div)(ps|pd)$", m)
        if mm:
            op, t = mm.groups(); d, s = ops
            v = "v" + ("f" if t == "ps" else "d")
            e("{ XMM b = %s, a = %s; a.%s = a.%s %s b.%s; %s = a; }" % (x128(s), self.xmm(d), v, v, ar[op], v, self.xmm(d)))
            return True
        if m in ("andps", "andpd", "pand", "orps", "orpd", "por", "xorps", "xorpd", "pxor", "andnps", "andnpd", "pandn"):
            d, s = ops
            if not self.isx(d): return False   # MMX form: mmx()
            if m in ("xorps", "xorpd", "pxor") and self.isx(s) and s.reg == d.reg:
                e("%s = (XMM){0};" % self.xmm(d)); return True
            if "andn" in m: ex = "~a.vq & b.vq"
            else: ex = "a.vq %s b.vq" % ("^" if "xor" in m else "&" if "and" in m else "|")
            e("{ XMM b = %s, a = %s; a.vq = %s; %s = a; }" % (x128(s), self.xmm(d), ex, self.xmm(d)))
            return True
        if m in ("comiss", "ucomiss", "comisd", "ucomisd"):
            a, b = ops
            va = "%s.%s[0]" % (self.xmm(a), "f" if m.endswith("ss") else "d")
            vb = src32(b) if m.endswith("ss") else src64(b)
            e("{ double a = %s, b = %s; if (a != a || b != b) { zf = cf = 1; pr = 0; } else { zf = a == b; cf = a < b; pr = 1; } of = 0; sf = 0; }" % (va, vb))
            return True
        if m == "cvtss2sd": e("%s.d[0] = (double)%s;" % (self.xmm(ops[0]), src32(ops[1]))); return True
        if m == "cvtsd2ss": e("%s.f[0] = (float)%s;" % (self.xmm(ops[0]), src64(ops[1]))); return True
        if m in ("cvtsi2ss", "cvtsi2sd"):
            d, s = ops
            t = "f" if m == "cvtsi2ss" else "d"
            e("%s.%s[0] = (%s)(int32_t)%s;" % (self.xmm(d), t, "float" if t == "f" else "double", self.rd(s, 4)))
            return True
        mm = re.match(r"cvt(t?)(ss|sd)2si$", m)
        if mm:
            tr, t = mm.groups(); d, s = ops
            v = src32(s) if t == "ss" else src64(s)
            v = "(double)(%s)" % v if tr else "sse_round(c, %s)" % v
            e(self.wr(d, "(uint32_t)cvt_i32(%s)" % v))
            return True
        mm = re.match(r"cmp(eq|lt|le|unord|neq|nlt|nle|ord)(ss|sd)$", m)
        if mm:
            cond, t = mm.groups(); d, s = ops
            C_ = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "a != a || b != b", "neq": "!(a == b)",
                  "nlt": "!(a < b)", "nle": "!(a <= b)", "ord": "a == a && b == b"}[cond]
            if t == "ss": e("{ float a = %s.f[0], b = %s; %s.u[0] = (%s) ? 0xFFFFFFFFu : 0; }" % (self.xmm(d), src32(s), self.xmm(d), C_))
            else: e("{ double a = %s.d[0], b = %s; %s.q[0] = (%s) ? ~0ull : 0; }" % (self.xmm(d), src64(s), self.xmm(d), C_))
            return True
        if m in ("cmpss", "cmpsd", "cmpps", "cmppd") and len(ops) == 3 and self.isx(ops[0]):
            pred = ["eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord"][ops[2].imm & 7]
            return self.sse(i, "cmp" + pred + m[3:], ops[:2]) or self.vec(i, "cmp" + pred + m[3:], ops[:2])
        if m in ("rsqrtss", "rcpss"):
            v = src32(ops[1])
            e("%s.f[0] = %s;" % (self.xmm(ops[0]), ("1.0f / sqrtf(%s)" if m == "rsqrtss" else "1.0f / (%s)") % v)); return True
        if m in ("roundss", "roundsd", "roundps", "roundpd"):
            d, s, im = ops
            r = {0: "nearbyint", 1: "floor", 2: "ceil", 3: "trunc"}[im.imm & 3] if not (im.imm & 4) else "nearbyint"
            if m == "roundss": e("%s.f[0] = (float)%s(%s);" % (self.xmm(d), r, src32(s)))
            elif m == "roundsd": e("%s.d[0] = %s(%s);" % (self.xmm(d), r, src64(s)))
            elif m == "roundps": e("{ XMM b = %s; for (int k = 0; k < 4; k++) b.f[k] = (float)%s(b.f[k]); %s = b; }" % (x128(s), r, self.xmm(d)))
            else: e("{ XMM b = %s; for (int k = 0; k < 2; k++) b.d[k] = %s(b.d[k]); %s = b; }" % (x128(s), r, self.xmm(d)))
            return True
        if m == "stmxcsr": e(self.wr(ops[0], "C.mxcsr", 4)); return True
        if m == "ldmxcsr": e("C.mxcsr = %s;" % self.rd(ops[0], 4)); return True
        return False

    LANES = {
        "paddb": ("b", 16, "a + b"), "paddw": ("w", 8, "a + b"), "paddd": ("u", 4, "a + b"), "paddq": ("q", 2, "a + b"),
        "psubb": ("b", 16, "a - b"), "psubw": ("w", 8, "a - b"), "psubd": ("u", 4, "a - b"), "psubq": ("q", 2, "a - b"),
        "pmullw": ("h", 8, "(int16_t)(a * b)"), "pmulhw": ("h", 8, "(int16_t)(((int32_t)a * b) >> 16)"),
        "pmulhuw": ("w", 8, "(uint16_t)(((uint32_t)a * b) >> 16)"), "pmulld": ("i", 4, "(int32_t)((int64_t)a * b)"),
        "paddsw": ("h", 8, "(int16_t)(a + b > 32767 ? 32767 : a + b < -32768 ? -32768 : a + b)"),
        "psubsw": ("h", 8, "(int16_t)(a - b > 32767 ? 32767 : a - b < -32768 ? -32768 : a - b)"),
        "paddsb": ("c", 16, "(int8_t)(a + b > 127 ? 127 : a + b < -128 ? -128 : a + b)"),
        "psubsb": ("c", 16, "(int8_t)(a - b > 127 ? 127 : a - b < -128 ? -128 : a - b)"),
        "paddusb": ("b", 16, "(uint8_t)(a + b > 255 ? 255 : a + b)"), "paddusw": ("w", 8, "(uint16_t)(a + b > 65535 ? 65535 : a + b)"),
        "psubusb": ("b", 16, "(uint8_t)(a > b ? a - b : 0)"), "psubusw": ("w", 8, "(uint16_t)(a > b ? a - b : 0)"),
        "pcmpeqb": ("b", 16, "a == b ? 0xFF : 0"), "pcmpeqw": ("w", 8, "a == b ? 0xFFFF : 0"), "pcmpeqd": ("u", 4, "a == b ? 0xFFFFFFFFu : 0"),
        "pcmpgtb": ("c", 16, "a > b ? -1 : 0"), "pcmpgtw": ("h", 8, "a > b ? -1 : 0"), "pcmpgtd": ("i", 4, "a > b ? -1 : 0"),
        "pmaxsw": ("h", 8, "a > b ? a : b"), "pminsw": ("h", 8, "a < b ? a : b"), "pmaxub": ("b", 16, "a > b ? a : b"),
        "pminub": ("b", 16, "a < b ? a : b"),
        "pavgb": ("b", 16, "(uint8_t)((a + b + 1) >> 1)"), "pavgw": ("w", 8, "(uint16_t)((a + b + 1) >> 1)"),
        "minps": ("f", 4, "a < b ? a : b"), "maxps": ("f", 4, "a > b ? a : b"), "minpd": ("d", 2, "a < b ? a : b"), "maxpd": ("d", 2, "a > b ? a : b"),
        "sqrtps": ("f", 4, "sqrtf(b)"), "sqrtpd": ("d", 2, "sqrt(b)"), "rcpps": ("f", 4, "1.0f / b"), "rsqrtps": ("f", 4, "1.0f / sqrtf(b)"),
    }
    VLANES = {
        "paddb": ("vb", "a + b"), "paddw": ("vw", "a + b"), "paddd": ("vu", "a + b"), "paddq": ("vq", "a + b"),
        "psubb": ("vb", "a - b"), "psubw": ("vw", "a - b"), "psubd": ("vu", "a - b"), "psubq": ("vq", "a - b"),
        "pmullw": ("vw", "a * b"), "pmulld": ("vu", "a * b"),
        "pcmpeqb": ("vb", "(v16b)(a == b)"), "pcmpeqw": ("vw", "(v8w)(a == b)"), "pcmpeqd": ("vu", "(v4u)(a == b)"),
        "pcmpgtb": ("vc", "(v16c)(a > b)"), "pcmpgtw": ("vh", "(v8h)(a > b)"), "pcmpgtd": ("vi", "(v4i)(a > b)"),
        "pmaxsw": ("vh", "VSEL(a > b, a, b)"), "pminsw": ("vh", "VSEL(a < b, a, b)"), "pmaxub": ("vb", "VSEL(a > b, a, b)"),
        "pminub": ("vb", "VSEL(a < b, a, b)"),
        "minps": ("vf", "VSEL(a < b, a, b)"), "maxps": ("vf", "VSEL(a > b, a, b)"),
        "minpd": ("vd", "VSEL(a < b, a, b)"), "maxpd": ("vd", "VSEL(a > b, a, b)"),
    }

    def ismm(self, op):
        return op.type == X.X86_OP_REG and re.match(r"mm[0-7]$", self.rn(op.reg) or "") is not None

    def mmx(self, i, m, ops):
        if m == "emms": return True
        if not any(self.ismm(o) for o in ops): return False
        e = self.e
        def mm(op): return "C.mm[%d]" % int(self.rn(op.reg)[2])
        def rd64(op):
            if self.ismm(op): return mm(op)
            if op.type == X.X86_OP_IMM: return "%dull" % (op.imm & 0xFFFFFFFFFFFFFFFF)
            if self.isx(op): return "%s.q[0]" % self.xmm(op)
            return "(uint64_t)%s" % self.rd(op)
        d = ops[0]
        if m in ("movd", "movq"):
            if self.ismm(d):
                v = rd64(ops[1]) if m == "movq" or self.ismm(ops[1]) else "(uint64_t)(uint32_t)%s" % self.rd(ops[1], 4)
                e("%s = %s;" % (mm(d), v))
            elif m == "movd": e(self.wr(d, "(uint32_t)%s" % mm(ops[1]), 4))
            else: e(self.wr(d, mm(ops[1]), 8))
            return True
        if m in ("movdq2q",): e("%s = %s.q[0];" % (mm(d), self.xmm(ops[1]))); return True
        if m in ("movq2dq",): e("{ XMM x = {0}; x.q[0] = %s; %s = x; }" % (mm(ops[1]), self.xmm(d))); return True
        if not self.ismm(d): raise Unsupported("mmx dest " + m)
        D = mm(d)
        src = rd64(ops[1]) if len(ops) > 1 else None
        imm = ops[-1].imm if ops[-1].type == X.X86_OP_IMM else None
        bit = {"pand": "a & b", "por": "a | b", "pxor": "a ^ b", "pandn": "~a & b"}
        if m in bit:
            e("{ uint64_t a = %s, b = %s; %s = %s; }" % (D, src, D, bit[m])); return True
        if m in self.LANES and m.startswith("p") and src:
            fl, n, ex = self.LANES[m]
            e("{ MM64 s_ = {.q = {%s}}, d_ = {.q = {%s}}, r_; for (int k = 0; k < %d; k++) { __typeof__(d_.%s[0]) a = d_.%s[k], b = s_.%s[k]; (void)a; r_.%s[k] = (%s); } %s = r_.q[0]; }"
              % (src, D, n // 2, fl, fl, fl, fl, ex, D)); return True
        msh = re.match(r"ps(ll|rl|ra)(w|d|q)$", m)
        if msh:
            kind, w = msh.groups()
            fl, n, bits = {"w": ("w", 4, 16), "d": ("u", 2, 32), "q": ("q", 1, 64)}[w]
            cnt = "%dull" % imm if imm is not None else src
            if kind == "ll": ex = "c_ >= %d ? 0 : d_.%s[k] << c_" % (bits, fl)
            elif kind == "rl": ex = "c_ >= %d ? 0 : d_.%s[k] >> c_" % (bits, fl)
            else: ex = "(d_.%s[k] >> (c_ >= %d ? %d : c_))" % ({"w": "h", "d": "i", "q": "l"}[w], bits, bits - 1)
            e("{ MM64 d_ = {.q = {%s}}; uint64_t c_ = %s; for (int k = 0; k < %d; k++) d_.%s[k] = %s; %s = d_.q[0]; }" % (D, cnt, n, fl, ex, D)); return True
        mu = re.match(r"punpck(l|h)(bw|wd|dq)$", m)
        if mu and src:
            hl, t = mu.groups()
            fl, n = {"bw": ("b", 8), "wd": ("w", 4), "dq": ("u", 2)}[t]
            base = 0 if hl == "l" else n // 2
            e("{ MM64 s_ = {.q = {%s}}, d_ = {.q = {%s}}, r_; for (int k = 0; k < %d; k++) { r_.%s[2*k] = d_.%s[%d+k]; r_.%s[2*k+1] = s_.%s[%d+k]; } %s = r_.q[0]; }"
              % (src, D, n // 2, fl, fl, base, fl, fl, base, D)); return True
        pk = {"packuswb": ("h", "b", 4, 0, 255), "packsswb": ("h", "c", 4, -128, 127), "packssdw": ("i", "h", 2, -32768, 32767)}
        if m in pk and src:
            fi, fo, n, lo, hi = pk[m]
            sat = "(v < %d ? %d : v > %d ? %d : v)" % (lo, lo, hi, hi)
            e("{ MM64 s_ = {.q = {%s}}, d_ = {.q = {%s}}, r_; for (int k = 0; k < %d; k++) { int32_t v = d_.%s[k]; r_.%s[k] = %s; v = s_.%s[k]; r_.%s[%d+k] = %s; } %s = r_.q[0]; }"
              % (src, D, n, fi, fo, sat, fi, fo, n, sat, D)); return True
        if m == "pmaddwd" and src:
            e("{ MM64 s_ = {.q = {%s}}, d_ = {.q = {%s}}, r_; for (int k = 0; k < 2; k++) r_.i[k] = (int32_t)((uint32_t)(d_.h[2*k] * s_.h[2*k]) + (uint32_t)(d_.h[2*k+1] * s_.h[2*k+1])); %s = r_.q[0]; }" % (src, D, D)); return True
        if m == "pshufw" and imm is not None:
            e("{ MM64 s_ = {.q = {%s}}, r_; for (int k = 0; k < 4; k++) r_.w[k] = s_.w[(%d >> (2 * k)) & 3]; %s = r_.q[0]; }" % (src, imm, D)); return True
        raise Unsupported("mmx " + m)

    def vec(self, i, m, ops):
        if not ops or not self.isx(ops[0]):
            if m == "pextrw" and len(ops) == 3 and self.isx(ops[1]):
                self.e(self.wr(ops[0], "(uint32_t)%s.w[%d]" % (self.xmm(ops[1]), ops[2].imm & 7), 4)); return True
            if m in ("pextrd", "pextrb", "extractps") and len(ops) == 3 and self.isx(ops[1]):
                f, n = {"pextrd": ("u", 4), "extractps": ("u", 4), "pextrb": ("b", 16)}[m]
                self.e(self.wr(ops[0], "%s.%s[%d]" % (self.xmm(ops[1]), f, ops[2].imm % n))); return True
            return False
        e = self.e
        D = self.xmm(ops[0])
        def S_(op):
            if self.isx(op): return self.xmm(op)
            if op.type == X.X86_OP_MEM:
                if op.size == 16: return "rdx(%s)" % self.ea(op)
                return "({ XMM t_ = {0}; t_.q[0] = (uint64_t)%s; t_; })" % self.rd(op)
            raise Unsupported("src " + m)
        imm = ops[-1].imm if ops[-1].type == X.X86_OP_IMM else None
        src = S_(ops[1]) if len(ops) > 1 and (self.isx(ops[1]) or ops[1].type == X.X86_OP_MEM) else None
        if m in self.VLANES and src:
            fv, ex = self.VLANES[m]
            e("{ XMM s_ = %s, d_ = %s; __typeof__(d_.%s) a = d_.%s, b = s_.%s; d_.%s = %s; %s = d_; }" % (src, D, fv, fv, fv, fv, ex, D)); return True
        if m in self.LANES and src:
            fl, n, ex = self.LANES[m]
            e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < %d; k++) { __typeof__(d_.%s[0]) a = d_.%s[k], b = s_.%s[k]; (void)a; r_.%s[k] = (%s); } %s = r_; }"
              % (src, D, n, fl, fl, fl, fl, ex, D)); return True
        mf = re.match(r"cmp(eq|lt|le|unord|neq|nlt|nle|ord)(ps|pd)$", m)
        if mf and src:
            vcond = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "(a != a) | (b != b)", "neq": "~(a == b)",
                     "nlt": "~(a < b)", "nle": "~(a <= b)", "ord": "(a == a) & (b == b)"}[mf.group(1)]
            if mf.group(2) == "ps": e("{ XMM s_ = %s, d_ = %s; v4f a = d_.vf, b = s_.vf; d_.vi = (v4i)(%s); %s = d_; }" % (src, D, vcond, D))
            else: e("{ XMM s_ = %s, d_ = %s; v2d a = d_.vd, b = s_.vd; d_.vl = (v2l)(%s); %s = d_; }" % (src, D, vcond, D))
            return True
        msh = re.match(r"ps(ll|rl|ra)(w|d|q)$", m)
        if msh:
            kind, w = msh.groups()
            fl, n, bits = {"w": ("w", 8, 16), "d": ("u", 4, 32), "q": ("q", 2, 64)}[w]
            if imm is not None:
                vf = {"w": "vw", "d": "vu", "q": "vq"}[w]; sv = {"w": "vh", "d": "vi", "q": "vl"}[w]
                if kind == "ra": e("%s.%s = %s.%s >> %d;" % (D, sv, D, sv, min(imm, bits - 1)))
                elif imm >= bits: e("%s = (XMM){0};" % D)
                else: e("%s.%s = %s.%s %s %d;" % (D, vf, D, vf, "<<" if kind == "ll" else ">>", imm))
                return True
            cnt = "(%s).q[0]" % src
            if kind == "ll": ex = "c_ >= %d ? 0 : d_.%s[k] << c_" % (bits, fl)
            elif kind == "rl": ex = "c_ >= %d ? 0 : d_.%s[k] >> c_" % (bits, fl)
            else: ex = "(d_.%s[k] >> (c_ >= %d ? %d : c_))" % ({"w": "h", "d": "i", "q": "l"}[w], bits, bits - 1)
            e("{ XMM d_ = %s; uint64_t c_ = %s; for (int k = 0; k < %d; k++) d_.%s[k] = %s; %s = d_; }" % (D, cnt, n, fl, ex, D)); return True
        if m in ("pslldq", "psrldq") and imm is not None:
            sh = min(imm, 16)
            if m == "pslldq": e("{ XMM d_ = %s, r_ = {0}; for (int k = %d; k < 16; k++) r_.b[k] = d_.b[k - %d]; %s = r_; }" % (D, sh, sh, D))
            else: e("{ XMM d_ = %s, r_ = {0}; for (int k = 0; k + %d < 16; k++) r_.b[k] = d_.b[k + %d]; %s = r_; }" % (D, sh, sh, D))
            return True
        mu = re.match(r"p?unpck(l|h)(bw|wd|dq|qdq|ps|pd)$", m)
        if mu and src:
            hl, t = mu.groups()
            fl, n = {"bw": ("b", 16), "wd": ("w", 8), "dq": ("u", 4), "qdq": ("q", 2), "ps": ("u", 4), "pd": ("q", 2)}[t]
            base = 0 if hl == "l" else n // 2
            idx = ", ".join("%d, %d" % (base + k, n + base + k) for k in range(n // 2))
            e("{ XMM s_ = %s, d_ = %s; d_.v%s = __builtin_shufflevector(d_.v%s, s_.v%s, %s); %s = d_; }" % (src, D, fl, fl, fl, idx, D)); return True
        if m in ("packsswb", "packuswb", "packssdw") and src:
            if m == "packssdw":
                e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 4; k++) { int32_t a = d_.i[k], b = s_.i[k]; r_.w[k] = (uint16_t)(a > 32767 ? 32767 : a < -32768 ? -32768 : a); r_.w[k + 4] = (uint16_t)(b > 32767 ? 32767 : b < -32768 ? -32768 : b); } %s = r_; }" % (src, D, D))
            else:
                lo, hi = ("-128", "127") if m == "packsswb" else ("0", "255")
                e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 8; k++) { int a = d_.h[k], b = s_.h[k]; r_.b[k] = (uint8_t)(a > %s ? %s : a < %s ? %s : a); r_.b[k + 8] = (uint8_t)(b > %s ? %s : b < %s ? %s : b); } %s = r_; }"
                  % (src, D, hi, hi, lo, lo, hi, hi, lo, lo, D))
            return True
        if m == "pmuludq" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; r_.q[0] = (uint64_t)d_.u[0] * s_.u[0]; r_.q[1] = (uint64_t)d_.u[2] * s_.u[2]; %s = r_; }" % (src, D, D)); return True
        if m == "pmaddwd" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 4; k++) r_.i[k] = d_.h[2*k] * s_.h[2*k] + d_.h[2*k+1] * s_.h[2*k+1]; %s = r_; }" % (src, D, D)); return True
        if m == "psadbw" and src:
            e("{ XMM s_ = %s, d_ = %s, r_ = {0}; for (int h = 0; h < 2; h++) { uint32_t t = 0; for (int k = 0; k < 8; k++) { int v = d_.b[h*8+k] - s_.b[h*8+k]; t += v < 0 ? -v : v; } r_.q[h] = t; } %s = r_; }" % (src, D, D)); return True
        if m == "pshufb" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 16; k++) r_.b[k] = (s_.b[k] & 0x80) ? 0 : d_.b[s_.b[k] & 15]; %s = r_; }" % (src, D, D)); return True
        if m == "shufps" and imm is not None:
            e("{ XMM s_ = %s, d_ = %s; d_.vu = __builtin_shufflevector(d_.vu, s_.vu, %d, %d, %d, %d); %s = d_; }"
              % (S_(ops[1]), D, imm & 3, (imm >> 2) & 3, 4 + ((imm >> 4) & 3), 4 + ((imm >> 6) & 3), D)); return True
        if m == "shufpd" and imm is not None:
            e("{ XMM s_ = %s, d_ = %s; d_.vq = __builtin_shufflevector(d_.vq, s_.vq, %d, %d); %s = d_; }" % (S_(ops[1]), D, imm & 1, 2 + ((imm >> 1) & 1), D)); return True
        if m == "pshufd" and imm is not None:
            e("{ XMM s_ = %s; s_.vu = __builtin_shufflevector(s_.vu, s_.vu, %d, %d, %d, %d); %s = s_; }"
              % (S_(ops[1]), imm & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3, D)); return True
        if m in ("pshuflw", "pshufhw") and imm is not None:
            o = 0 if m == "pshuflw" else 4
            idx = list(range(8)); idx[o:o + 4] = [o + ((imm >> (2 * k)) & 3) for k in range(4)]
            e("{ XMM s_ = %s; s_.vw = __builtin_shufflevector(s_.vw, s_.vw, %s); %s = s_; }" % (S_(ops[1]), ", ".join(map(str, idx)), D)); return True
        if m == "pinsrw" and imm is not None:
            v = self.rd(ops[1], 2) if ops[1].type == X.X86_OP_MEM else "(uint16_t)" + self.rd(ops[1])
            e("%s.w[%d] = %s;" % (D, imm & 7, v)); return True
        if m == "movlhps" and src: e("{ XMM s_ = %s, d_ = %s; d_.vq = __builtin_shufflevector(d_.vq, s_.vq, 0, 2); %s = d_; }" % (src, D, D)); return True
        if m == "movhlps" and src: e("{ XMM s_ = %s, d_ = %s; d_.vq = __builtin_shufflevector(d_.vq, s_.vq, 3, 1); %s = d_; }" % (src, D, D)); return True
        if m == "movshdup" and src: e("{ XMM s_ = %s; s_.vu = __builtin_shufflevector(s_.vu, s_.vu, 1, 1, 3, 3); %s = s_; }" % (src, D)); return True
        if m == "movsldup" and src: e("{ XMM s_ = %s; s_.vu = __builtin_shufflevector(s_.vu, s_.vu, 0, 0, 2, 2); %s = s_; }" % (src, D)); return True
        if m == "movddup" and src: e("{ XMM s_ = %s; s_.vq = __builtin_shufflevector(s_.vq, s_.vq, 0, 0); %s = s_; }" % (src, D)); return True
        if m in ("haddps", "hsubps") and src:
            o = "+" if m == "haddps" else "-"
            e("{ XMM s_ = %s, d_ = %s; d_.vf = __builtin_shufflevector(d_.vf, s_.vf, 0, 2, 4, 6) %s __builtin_shufflevector(d_.vf, s_.vf, 1, 3, 5, 7); %s = d_; }" % (src, D, o, D)); return True
        conv = {
            "cvtps2pd": "r_.d[0] = s_.f[0]; r_.d[1] = s_.f[1];",
            "cvtpd2ps": "r_.q[1] = 0; r_.f[0] = (float)s_.d[0]; r_.f[1] = (float)s_.d[1];",
            "cvtdq2ps": "r_.vf = __builtin_convertvector(s_.vi, v4f);",
            "cvtdq2pd": "r_.d[0] = s_.i[0]; r_.d[1] = s_.i[1];",
            "cvtps2dq": "for (int k = 0; k < 4; k++) r_.i[k] = cvt_i32(sse_round(c, s_.f[k]));",
            "cvttps2dq": "v4i bad_ = (s_.vf != s_.vf) | (s_.vf >= 2147483648.0f) | (s_.vf < -2147483648.0f); "
                         "r_.vi = VSEL(bad_, V4I_MIN, __builtin_convertvector(VSEL(bad_, (v4f){0}, s_.vf), v4i));",
            "cvtpd2dq": "r_.q[1] = 0; r_.i[0] = cvt_i32(sse_round(c, s_.d[0])); r_.i[1] = cvt_i32(sse_round(c, s_.d[1]));",
            "cvttpd2dq": "r_.q[1] = 0; r_.i[0] = cvt_i32(s_.d[0]); r_.i[1] = cvt_i32(s_.d[1]);",
        }
        if m in conv and src:
            e("{ XMM s_ = %s, r_; %s %s = r_; }" % (src, conv[m], D)); return True
        if m == "cvtpi2ps":
            e("{ MM64 s_ = {.q = {%s}}; %s.f[0] = (float)s_.i[0]; %s.f[1] = (float)s_.i[1]; }" % ("C.mm[%d]" % int(self.rn(ops[1].reg)[2]) if self.ismm(ops[1]) else self.rd(ops[1], 8), D, D)); return True
        return False

    # -- x87 (status word in C.fsw for fnstsw; double precision) --
    def x87(self, i, m, ops):
        e = self.e
        if not m.startswith("f"): return False
        def st(op): return "ST(%d)" % int(self.rn(op.reg)[2:].strip("()") or 0)
        def fmem(op): return {4: "(double)rdf(%s)", 8: "rdd(%s)", 10: "rd80(%s)"}[op.size] % self.ea(op)
        cmpset = "C.fsw = (C.fsw & ~0x4500u) | ((a != a || b != b) ? 0x4500u : a < b ? 0x0100u : a == b ? 0x4000u : 0);"
        if m in ("fld", "fild") and ops and ops[0].type == X.X86_OP_MEM:
            op = ops[0]
            if m == "fild": e("FPUSH(c, (double)(%s)%s);" % (S[op.size], self.rd(op)))
            else: e("FPUSH(c, %s);" % fmem(op))
            return True
        if m == "fld" and ops: e("{ double v = %s; FPUSH(c, v); }" % st(ops[0])); return True
        if m in ("fst", "fstp") and ops:
            op = ops[0]
            if op.type == X.X86_OP_MEM:
                w = {4: "wrf(%s, (float)ST(0));", 8: "wrd(%s, ST(0));", 10: "wr80(%s, ST(0));"}[op.size] % self.ea(op)
                e(w + (" FPOP(c);" if m == "fstp" else ""))
            else:
                e("%s = ST(0);%s" % (st(op), " FPOP(c);" if m == "fstp" else ""))
            return True
        if m in ("fistp", "fist", "fisttp") and ops:
            n = ops[0].size
            v = "trunc(ST(0))" if m == "fisttp" else "fpu_round(c, ST(0))"
            cv = "cvt_i64(%s)" % v if n == 8 else "cvt_i32(%s)" % v if n == 4 else "(int16_t)cvt_i32(%s)" % v
            e("%s%s" % (self.wr(ops[0], "(%s)%s" % (U[n], cv)), "" if m == "fist" else " FPOP(c);")); return True
        if m in ("fnstcw", "fstcw"): e(self.wr(ops[0], "C.fcw", 2)); return True
        if m == "fldcw": e("C.fcw = %s;" % self.rd(ops[0], 2)); return True
        if m in ("fnstsw", "fstsw"):
            v = "(uint16_t)((C.fsw & ~0x3800u) | ((c->top & 7) << 11))"
            if ops and ops[0].type == X.X86_OP_REG: e("C.eax = (C.eax & ~0xFFFFu) | %s;" % v)
            else: e(self.wr(ops[0], v, 2))
            return True
        if m in ("fnclex", "fclex"): e("C.fsw &= 0x7F00u;"); return True
        if m in ("fninit", "finit"): e("C.fcw = 0x37F; C.fsw = 0; c->top = 0;"); return True
        consts = {"fld1": "1.0", "fldz": "0.0", "fldpi": "M_PI", "fldl2e": "M_LOG2E", "fldln2": "M_LN2", "fldlg2": "0.30102999566398119521", "fldl2t": "3.32192809488736234787"}
        if m in consts: e("FPUSH(c, %s);" % consts[m]); return True
        ar = {"add": "a + b", "sub": "a - b", "subr": "b - a", "mul": "a * b", "div": "a / b", "divr": "b / a"}
        mm = re.match(r"f(i?)(add|subr|sub|mul|divr|div)(p?)$", m)
        if mm:
            isint, op, pop = mm.groups()
            if ops and ops[0].type == X.X86_OP_MEM:
                o = ops[0]
                b = "(double)(%s)%s" % (S[o.size], self.rd(o)) if isint else fmem(o)
                e("{ double a = ST(0), b = %s; ST(0) = %s; }" % (b, ar[op])); return True
            if len(ops) == 2:
                d, s_ = st(ops[0]), st(ops[1])
                e("{ double a = %s, b = %s; %s = %s;%s }" % (d, s_, d, ar[op], " FPOP(c);" if pop else "")); return True
            if len(ops) == 1:
                # capstone prints both register forms with one operand: the popping ones (DE: faddp st(i)) are
                # st(i) = st(i) op st(0), pop; the plain ones (D8: fadd st(i)) are st(0) = st(0) op st(i)
                d = st(ops[0])
                if pop: e("{ double a = %s, b = ST(0); %s = %s; FPOP(c); }" % (d, d, ar[op]))
                else: e("{ double a = ST(0), b = %s; ST(0) = %s; }" % (d, ar[op]))
                return True
            if not ops and pop:
                e("{ double a = ST(1), b = ST(0); ST(1) = %s; FPOP(c); }" % ar[op]); return True
        un = {"fchs": "-ST(0)", "fabs": "fabs(ST(0))", "fsqrt": "sqrt(ST(0))", "fsin": "sin(ST(0))", "fcos": "cos(ST(0))",
              "frndint": "fpu_round(c, ST(0))", "f2xm1": "exp2(ST(0)) - 1.0"}
        if m in un: e("ST(0) = %s;" % un[m]); return True
        if m == "fxch":   # capstone may list the implicit st(0) first: the register exchanged is the last operand
            o = st(ops[-1]) if ops else "ST(1)"
            if o == "ST(0)": o = "ST(1)" if len(ops) < 2 else o
            e("{ double t = ST(0); ST(0) = %s; %s = t; }" % (o, o)); return True
        if m == "fpatan": e("{ double v = atan2(ST(1), ST(0)); FPOP(c); ST(0) = v; }"); return True
        if m == "fptan": e("ST(0) = tan(ST(0)); FPUSH(c, 1.0);"); return True
        if m == "fsincos": e("{ double v = ST(0); ST(0) = sin(v); FPUSH(c, cos(v)); }"); return True
        if m == "fyl2x": e("{ double v = ST(1) * log2(ST(0)); FPOP(c); ST(0) = v; }"); return True
        if m == "fyl2xp1": e("{ double v = ST(1) * log2(ST(0) + 1.0); FPOP(c); ST(0) = v; }"); return True
        if m == "fscale": e("ST(0) = ldexp(ST(0), (int)trunc(ST(1)));"); return True
        if m in ("fprem", "fprem1"):
            e("{ double r = %s(ST(0), ST(1)); ST(0) = r; C.fsw &= ~0x0400u; }" % ("fmod" if m == "fprem" else "remainder")); return True
        if m == "fxtract": e("{ int ex; double mnt = frexp(ST(0), &ex); ST(0) = (double)(ex - 1); FPUSH(c, mnt * 2.0); }"); return True
        if m in ("fucompi", "fcompi"): m = m[:-2] + "ip"   # capstone's spelling of fcomip / fucomip
        if m in ("fucomip", "fcomip", "fucomi", "fcomi"):
            e("{ double a = ST(0), b = %s; if (a != a || b != b) { zf = cf = 1; pr = 0; } else { zf = a == b; cf = a < b; pr = 1; } of = sf = 0;%s }"
              % (st(ops[-1]) if ops and st(ops[-1]) != "ST(0)" else "ST(1)", " FPOP(c);" if m.endswith("p") else "")); return True
        mc = re.match(r"f(i?)u?com(p{0,2})$", m)
        if mc:
            isint, pops = mc.groups()
            if ops and ops[0].type == X.X86_OP_MEM:
                b = "(double)(%s)%s" % (S[ops[0].size], self.rd(ops[0])) if isint else fmem(ops[0])
            elif ops: b = st(ops[-1])
            else: b = "ST(1)"
            e("{ double a = ST(0), b = %s; %s%s }" % (b, cmpset, " FPOP(c);" * len(pops)))
            return True
        if m == "ftst": e("{ double a = ST(0), b = 0.0; %s }" % cmpset); return True
        if m == "fxam":
            e("{ double v = ST(0); uint32_t s_ = signbit(v) ? 0x200u : 0; C.fsw = (C.fsw & ~0x4700u) | s_ | (v != v ? 0x100u : isinf(v) ? 0x500u : v == 0 ? 0x4000u : 0x400u); }"); return True
        mc = re.match(r"fcmov(n?)(b|e|be|u)$", m)
        if mc:
            neg, cc = mc.groups()
            cond = {"b": "cf", "e": "zf", "be": "(cf||zf)", "u": "parity8(pr)"}[cc]
            e("if (%s(%s)) ST(0) = %s;" % ("!" if neg else "", cond, st(ops[1]) if len(ops) > 1 else st(ops[0]))); return True
        if m == "fstp" and not ops: e("FPOP(c);"); return True
        if m in ("fincstp",): e("c->top = (c->top + 1) & 7;"); return True
        if m in ("fdecstp",): e("c->top = (c->top - 1) & 7;"); return True
        if m in ("ffree", "ffreep", "fnop", "fdisi8087_nop", "feni8087_nop", "fsetpm287_nop"):
            if m == "ffreep": e("FPOP(c);")
            return True
        raise Unsupported(m)


# ---------------- whole-program translation ----------------
class Translator:
    def __init__(self, path):
        self.pe = PE32(path)
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.md.detail = True
        self.unsupported = collections.Counter()
        self.imports_used = set()
        self.noreturn = set()
        self.discover()

    def discover(self):
        """Function starts: the entry point, every direct call target reachable from known code, code addresses
        in instruction immediates, and code pointers in the data sections (vtables, callback tables) that sit on a
        16-byte boundary after int3/ret padding -- MSVC's function alignment, which data never mimics by chance."""
        pe = self.pe
        lite = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        codes = {va: pe.read(va, vs) for _, va, vs, _, _, _ in pe.code}
        def byte_at(a):
            for va, b in codes.items():
                if va <= a < va + len(b): return b[a - va]
            return None
        weak = set()
        def ends_flow(a):
            """the instruction that ends exactly at a is a ret / jmp (any form) / int3: a can start new code"""
            for k in range(2, 8):
                try: blob = pe.read(a - k, k)
                except (KeyError, StopIteration): continue
                ins = next(lite.disasm_lite(blob, a - k, 1), None)
                if ins and ins[1] == k and (ins[2].startswith("ret") or ins[2] == "jmp" or ins[2] == "int3"): return True
            return False
        def boundary(a, weak_ok=True):
            if not pe.is_code(a): return False
            if a in codes: return True
            p = byte_at(a - 1)
            if a % 16 == 0 and p in (0xCC, 0xC3, 0x90) or (p == 0xCC and byte_at(a - 2) == 0xCC): return True
            if a % 16 == 0 and byte_at(a - 3) == 0xC2: return True   # aligned, right after ret imm16 (no padding needed)
            if a % 16 == 0 and pe.is_code(a - 4):   # aligned, right after the previous function's inline switch table
                try:
                    if pe.is_code(pe.u32(a - 4)): return True
                except (KeyError, StopIteration): pass
            # packed CRT code (no padding): right after a ret / ret imm16 / jmp rel32. Weaker evidence: such a start
            # gets a function but never ends another function's body (it might be mid-instruction there)
            if weak_ok and (p == 0xC3 or byte_at(a - 3) == 0xC2 or byte_at(a - 5) == 0xE9 or ends_flow(a)):
                weak.add(a); return True
            return False
        starts = {pe.entry}
        # code pointers in data
        for name, va, vs, fo, fs, ch in pe.sections:
            if ch & 0x20000000 or name in (".rsrc", ".reloc", ".bind"): continue
            blob = pe.read(va, min(vs, fs) if fs else 0)
            for o in range(0, len(blob) - 3, 4):
                v = struct.unpack_from("<I", blob, o)[0]
                if pe.text_lo <= v < pe.text_hi and boundary(v): starts.add(v)
        n_data = len(starts)
        # closure over direct calls / tail jumps / immediates, following each function's flow
        IMM = re.compile(r"0x([0-9a-f]{6,8})\b")
        scanned = set()
        work = list(starts)
        iat_names = pe.iat
        noret_slots = {a for a, n in iat_names.items() if n.split("!")[-1] in NORETURN_IMPORTS}
        while work:
            s0 = work.pop()
            if s0 in scanned or not pe.is_code(s0): continue
            scanned.add(s0)
            seen = set(); stack = [s0]
            while stack:
                a = stack.pop()
                while a not in seen and pe.is_code(a) and (a == s0 or a not in starts or a in weak):
                    seen.add(a)
                    end = pe.code_end(a)
                    blob = pe.read(a, min(16, end - a))
                    ins = next(lite.disasm_lite(blob, a, 1), None)
                    if ins is None: break
                    ia, sz, mn, opst = ins
                    nxt = ia + sz
                    t = None
                    if opst.startswith("0x") and (mn == "call" or mn[0] == "j" or mn.startswith("loop")):
                        t = int(opst, 16)
                    if mn == "call":
                        if t is not None and pe.is_code(t) and t != nxt:
                            weak.discard(t)   # a call target is a real start
                            if t not in starts: starts.add(t); work.append(t)
                        if "dword ptr [0x" in opst:
                            slot = int(opst.split("[")[1].rstrip("]"), 16)
                            if slot in noret_slots: break
                    elif mn[0] == "j" or mn.startswith("loop"):
                        if t is not None and pe.is_code(t) and (t == s0 or t not in starts or t in weak): stack.append(t)
                        if mn == "jmp" and opst.startswith("dword ptr [") and "*4" in opst:
                            m_ = re.search(r"\*\s*4\s*\+\s*0x([0-9a-f]+)\]", opst)
                            if m_:   # jump table: follow entries while they look like code near the jump
                                ta = int(m_.group(1), 16)
                                for k in range(1024):
                                    try: v = pe.u32(ta + 4 * k)
                                    except (KeyError, StopIteration): break
                                    if not pe.is_code(v) or abs(v - ia) > 0x40000: break
                                    stack.append(v)
                    else:
                        for m_ in IMM.finditer(opst):
                            v = int(m_.group(1), 16)
                            if (mn in ("push", "mov", "lea") and pe.text_lo <= v < pe.text_hi and boundary(v)) and v not in starts:
                                starts.add(v); work.append(v)
                    if mn in ("ret", "retf", "jmp", "int3", "ud2", "hlt") or (mn == "int" and opst == "0x29"):
                        break
                    a = nxt
        self.funcs = sorted(starts)
        self.strong = starts - weak
        print("weak starts (boundary only by a preceding ret/jmp): %d" % len(weak))
        print("functions: %d (from data pointers %d, entry/calls/immediates %d)" % (len(self.funcs), n_data, len(self.funcs) - n_data))


TR = None
NATIVE, PROBES, PATCHES = {}, {}, {}


def _work(chunk):
    TR.unsupported = collections.Counter(); TR.imports_used = set()
    out = []
    for a in chunk:
        if a in NATIVE:
            try:
                orig = FuncGen(TR, a).gen().replace("void F_%x(CPU *c) {" % a, "void F_%x__orig(CPU *c) {" % a, 1)
            except Exception:
                orig = "void F_%x__orig(CPU *c) { bad_insn(c, 0x%xu, \"no translation\"); }" % (a, a)
            # the native body reads stack arguments from c and sets eax; the wrapper does the guest's plain `ret`
            # (callee-cleanup natives pop their own arguments, see rt32.h NATIVE_POP); F_<addr>__orig stays callable
            # (rt32.h CALL_ORIG) so a native can wrap the original
            out.append("void %s(CPU *c);\nint rt_native_enabled(uint32_t a);\n%s\nvoid F_%x(CPU *c) { static int on = -1; if (on < 0) on = rt_native_enabled(0x%xu);"
                       " if (on) { %s(c); c->esp += 4; } else F_%x__orig(c); }" % (NATIVE[a], orig, a, a, NATIVE[a], a))
            continue
        try:
            out.append(FuncGen(TR, a).gen())
        except Exception as ex:
            out.append("void F_%x(CPU *c) { bad_insn(c, 0x%xu, \"translator error: %s\"); }" % (a, a, str(ex).replace('"', "'").replace("\\", "/")[:80]))
            TR.unsupported["<error: %s>" % str(ex)[:40]] += 1
    return out, TR.unsupported, TR.imports_used


def write_if_changed(path, text):
    try:
        with open(path) as f:
            if f.read() == text: return
    except FileNotFoundError:
        pass
    with open(path, "w") as f: f.write(text)


def main():
    global TR
    args = sys.argv[1:]
    path, outdir = args[0], args[1]
    def opt(name):
        return args[args.index(name) + 1] if name in args else None
    jobs = int(opt("--jobs") or os.cpu_count())
    only = [int(x, 16) for x in opt("--only").split(",")] if opt("--only") else None
    if opt("--patches"):
        for line in open(opt("--patches")):
            line = line.split("#")[0].strip()
            if line: a, code = line.split(None, 1); PATCHES[int(a, 16)] = code
    if opt("--probes"):
        for line in open(opt("--probes")):
            line = line.strip()
            if line and not line.startswith("#"): a, code = line.split(None, 1); PROBES.setdefault(int(a, 16), []).append(code)
    if opt("--native"):
        for line in open(opt("--native")):
            line = line.split("#")[0].split()
            if line: NATIVE[int(line[0], 16)] = line[1]
    TR = Translator(path)
    TR.funcs_list = TR.funcs
    TR.funcs = set(TR.funcs)
    order = TR.funcs_list if not only else only
    os.makedirs(outdir, exist_ok=True)
    stale = {f for f in os.listdir(outdir) if f.startswith("code_") and f.endswith(".c")}
    per = 400
    chunks = [order[k:k + per] for k in range(0, len(order), per)]
    unsup = collections.Counter(); imps = set()
    hdr = '#include "cpu32.h"\n#include "funcs.h"\n#pragma clang diagnostic ignored "-Wunused-label"\n'
    with mp.get_context("fork").Pool(jobs) as pool:
        for n, (bodies, u, im) in enumerate(pool.imap(_work, chunks)):
            unsup.update(u); imps |= im
            name = "code_%04d.c" % n
            stale.discard(name)
            write_if_changed(os.path.join(outdir, name), hdr + "\n\n".join(bodies) + "\n")
            if n % 20 == 0: print("  %d/%d files" % (n + 1, len(chunks)), flush=True)
    for f in stale: os.remove(os.path.join(outdir, f))
    pe = TR.pe
    allimp = sorted(set(pe.iat.values()), key=imp_sym)
    write_if_changed(os.path.join(outdir, "funcs.h"), "#pragma once\n" + "".join("void F_%x(CPU *c);\n" % a for a in TR.funcs_list)
                     + "".join("void %s(CPU *c);\n" % n for n in sorted({v.split()[1] for v in PATCHES.values() if v.startswith("@call ")}))
                     + "".join("void I_%s(CPU *c);\n" % imp_sym(n) for n in allimp))
    t = []
    t.append('#include "cpu32.h"\n#include "tables32.h"\n#include "funcs.h"\n')
    t.append("const GFunc gfuncs[] = {\n" + "".join("  {0x%xu, F_%x},\n" % (a, a) for a in TR.funcs_list) + "};\n")
    t.append("const int ngfuncs = %d;\n" % len(TR.funcs_list))
    for n in allimp:
        t.append('__attribute__((weak)) void I_%s(CPU *c) { unimpl_import(c, "%s"); }\n' % (imp_sym(n), n))
    t.append("const GImport gimports[] = {\n" + "".join('  {0x%xu, "%s", I_%s},\n' % (a, n, imp_sym(n)) for a, n in sorted(pe.iat.items())) + "};\n")
    t.append("const int ngimports = %d;\n" % len(pe.iat))
    t.append("const GSection gsections[] = {\n" + "".join('  {"%s", 0x%xu, 0x%x, 0x%x, 0x%x, 0x%x},\n' % s for s in pe.sections) + "};\n")
    t.append("const int ngsections = %d;\n" % len(pe.sections))
    t.append("const uint32_t gimage_base = 0x%xu, gimage_size = 0x%xu, gentry = 0x%xu;\n" % (pe.base, pe.size, pe.entry))
    write_if_changed(os.path.join(outdir, "tables.c"), "".join(t))
    print("translated %d functions (%d native), %d of %d imports referenced" % (len(order), len(NATIVE), len(imps), len(pe.iat)))
    print("UNSUPPORTED:", dict(unsup.most_common(60)))


if __name__ == "__main__":
    main()
