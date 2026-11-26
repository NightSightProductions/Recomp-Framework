#!/usr/bin/env python3
"""Static recompiler: Win64 x86-64 PE -> C (compiled for arm64).

Each guest function becomes  void F_<addr>(CPU *c).  Guest memory is identity-mapped, so
memory operands become direct loads/stores.  Flags are function-local variables computed per
instruction; clang removes the ones that are never read.

usage: recomp64.py ORIG.exe OUTDIR [--jobs N] [--only ADDR,...]
"""
import os, re, sys, bisect, collections, multiprocessing as mp, struct
sys.path.insert(0, os.path.dirname(__file__))
import capstone as cs
from capstone import x86 as X
from pe import PE

class Unsupported(Exception):
    pass

def cname(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)

# ---------------- registers ----------------
G64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + ["r%d" % i for i in range(8, 16)]
REG = {}   # name -> (gpr name, size, high-byte?)
for i, n in enumerate(G64):
    REG[n] = (n, 8, False)
for n, b in zip(["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"], G64): REG[n] = (b, 4, False)
for n, b in zip(["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"], G64): REG[n] = (b, 2, False)
for n, b in zip(["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"], G64): REG[n] = (b, 1, False)
for n, b in zip(["ah", "ch", "dh", "bh"], G64[:4]): REG[n] = (b, 1, True)
for i in range(8, 16):
    REG["r%dd" % i] = ("r%d" % i, 4, False); REG["r%dw" % i] = ("r%d" % i, 2, False); REG["r%db" % i] = ("r%d" % i, 1, False)

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


STACK_ACCESS = re.compile(r"\b(rd|wr)(8|16|32|64|f|d|x)\(\(uint64_t\)\(C\.rsp\b")

# ---------------- register caching ----------------
# Guest registers live in locals (R_rax, X_3, ...) inside each function, so clang keeps them in host
# registers instead of loading/storing the CPU struct for every instruction. They are synced with the CPU
# struct only where other code can observe them: before calls out of the function (translated functions,
# indirect calls, runtime shims, helpers taking c) the registers this function writes are stored, and
# after them every register it uses is reloaded; before returning, the written ones are stored.
GPRS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + ["r%d" % i for i in range(8, 16)]
_GPR_RE = re.compile(r"\bC\.(%s)\b" % "|".join(GPRS))
_XMM_RE = re.compile(r"\bC\.xmm\[(\d+)\]")
_ASSIGN = r"\s*(?:[-+*/&|^%]|<<|>>)?=(?!=)"
_GPR_W = re.compile(r"\bR_(\w+)(?:%s|\s*(?:\+\+|--))" % _ASSIGN)
_XMM_W = re.compile(r"\bX_(\d+)(?:\.\w+(?:\[[^\]]*\])?)?%s" % _ASSIGN)   # X_n =, X_n.f[k] =, X_n.vu =
# statements that hand control (and the CPU struct) to other code
_BARRIER = re.compile(r"\b(F_[0-9a-f]+|I_\w+|call_ind|missing_func|bad_insn|bad_jump|cpu_cpuid|cpu_syscall_trap|unimpl_import|rt_setjmp_site)"
                      r"\(c(?:,(?:\"(?:[^\"\\]|\\.)*\"|[^;\"])*)?\);")
_RETURN = re.compile(r"\breturn;")
# Win64 ABI: a call preserves rbx, rbp, rsi, rdi, r12-r15 and xmm6-15, so after a call only the volatile
# registers (and rsp, which the callee's `ret` moved) need reloading. Guest code is compiled C/C++ and the
# runtime never writes those registers except in cpuid (no exceptions or longjmp unwinding exist).
_VOLATILE_G = {"rax", "rcx", "rdx", "rsp", "r8", "r9", "r10", "r11"}
_VOLATILE_X = set(range(6))
_FULL_RELOAD = ("cpu_cpuid", "cpu_syscall_trap", "rt_setjmp_site")   # after a longjmp every register comes back
ABI_TRIM = "--no-abi-trim" not in sys.argv   # off for hand-written asm-heavy modules (Bink)

# Loads from fixed addresses inside the image's read-only sections (.rdata, .text, .pdata...) read data that never
# changes: they become plain loads (rdc*) instead of the acquire loads that keep x86 ordering for shared data.
CONST_LOAD = re.compile(r"\b(rd8|rd16|rd32|rd64|rdf|rdd|rdx)\(0x([0-9a-f]+)ull\)")
_CONST_NAME = {"rd8": "rdc8", "rd16": "rdc16", "rd32": "rdc32", "rd64": "rdc64", "rdf": "rdcf", "rdd": "rdcd", "rdx": "rdcx"}
_SIZE = {"rd8": 1, "rd16": 2, "rd32": 4, "rd64": 8, "rdf": 4, "rdd": 8, "rdx": 16}
def readonly_ranges(pe):
    if not hasattr(pe, "_ro"):
        secs = getattr(pe, "sections", None) or []
        pe._ro = [(va, va + vs) for n, va, vs, fo, fs, ch in secs if not (ch & 0x80000000)]   # IMAGE_SCN_MEM_WRITE
    return pe._ro
def const_loads(pe, text):
    ro = readonly_ranges(pe)
    if not ro: return text
    def sub(m):
        a = int(m.group(2), 16)
        if any(lo <= a and a + _SIZE[m.group(1)] <= hi for lo, hi in ro): return "%s(0x%sull)" % (_CONST_NAME[m.group(1)], m.group(2))
        return m.group(0)
    return CONST_LOAD.sub(sub, text)

def cache_registers(text):
    # \b: leave the x87 FPUSH(c, v) / FPOP(c) alone
    text = re.sub(r"\bPUSH\(c, ", "PUSHL(", text)
    text = re.sub(r"\bPOP\(c\)", "POPL()", text)
    text = _GPR_RE.sub(r"R_\1", text)
    text = _XMM_RE.sub(r"X_\1", text)
    used_g = set(re.findall(r"\bR_(\w+)\b", text)) & set(GPRS)
    used_x = set(int(x) for x in re.findall(r"\bX_(\d+)\b", text))
    dirty_g = set(_GPR_W.findall(text)) & set(GPRS)
    dirty_x = set(int(x) for x in _XMM_W.findall(text))
    if re.search(r"\b(PUSHL\(|POPL\(\))", text):
        used_g.add("rsp"); dirty_g.add("rsp")
    if not used_g and not used_x:
        return text
    order_g = [g for g in GPRS if g in used_g]
    flush = "".join("C.%s = R_%s; " % (g, g) for g in GPRS if g in dirty_g) + "".join("C.xmm[%d] = X_%d; " % (x, x) for x in sorted(dirty_x))
    reload = "".join("R_%s = C.%s; " % (g, g) for g in order_g) + "".join("X_%d = C.xmm[%d]; " % (x, x) for x in sorted(used_x))
    reload_v = "".join("R_%s = C.%s; " % (g, g) for g in order_g if g in _VOLATILE_G) \
             + "".join("X_%d = C.xmm[%d]; " % (x, x) for x in sorted(used_x) if x in _VOLATILE_X)
    text = _BARRIER.sub(lambda m: "{ %s%s %s}" % (flush, m.group(0), reload if m.group(1) in _FULL_RELOAD or not ABI_TRIM else reload_v), text)
    text = _RETURN.sub("{ %sreturn; }" % flush, text)
    decl = ""
    if order_g: decl += "    uint64_t %s;\n" % ", ".join("R_%s = C.%s" % (g, g) for g in order_g)
    if used_x: decl += "    XMM %s;\n" % ", ".join("X_%d = C.xmm[%d]" % (x, x) for x in sorted(used_x))
    # declarations right after "c->fn = ...;" (before any label)
    i = text.index("c->fn = ")
    j = text.index("\n", i) + 1
    text = text[:j] + decl + text[j:]
    # a function that falls off the end (no explicit return) must still store its registers
    if text.rstrip().endswith("}"):
        k = text.rstrip().rfind("}")
        text = text[:k] + "    " + flush + "\n" + text[k:]
    return text

# ---------------- per-function code generation ----------------
class FuncGen:
    def __init__(self, tr, addr):
        self.tr, self.pe, self.addr = tr, tr.pe, addr
        self.ranges = tr.regions[addr]            # [(lo, hi)] primary + chained parts
        self.out = []
        self.ins = self.descend()
        self.addrs = {i.address for i in self.ins}
        self.labels = set()

    # -- decoding --
    def in_region(self, a):
        return any(lo <= a < hi for lo, hi in self.ranges)

    def decode(self, a):
        if not self.in_region(a): return None
        hi = next(h for l, h in self.ranges if l <= a < h)
        for i in self.tr.md.disasm(self.pe.read(a, min(16, hi - a)), a, 1):
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
                    m = i.mnemonic
                    if i.group(cs.CS_GRP_JUMP) and i.operands and i.operands[0].type == X.X86_OP_IMM:
                        t = i.operands[0].imm
                        if self.in_region(t): work.append(t)
                    if m == "jmp" and i.operands and i.operands[0].type == X.X86_OP_REG:
                        pending.append(i)
                    if m in ("ret", "jmp", "ud2", "hlt", "int3") or m.startswith("ret") or m.endswith(" ret") or m == "bnd jmp":
                        break
                    if m == "call" and self.noreturn_call(i):
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

    def noreturn_call(self, i):
        op = i.operands[0]
        if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
            slot = i.address + i.size + op.mem.disp
            n = self.pe.iat.get(slot, "")
            return n.split("!")[-1] in ("ExitProcess", "TerminateProcess", "FatalExit")
        if op.type == X.X86_OP_IMM:
            return op.imm in self.tr.noreturn
        return False

    def jump_table(self, seen, i):
        """MSVC x64: mov r32,[B+I*4+rva] ; add r,B ; jmp r   (B = image base).  Entries are RVAs."""
        r = i.operands[0].reg
        prev = sorted((x for x in seen.values() if x and i.address - 64 <= x.address < i.address), key=lambda x: x.address)
        for k in range(len(prev) - 1, -1, -1):
            x = prev[k]
            ops = x.operands
            if x.mnemonic == "movsxd" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM and ops[0].type == X.X86_OP_REG:
                # GCC/MinGW: lea rB,[rip+T] ; movsxd rX,[rB+rI*4] ; add rX,rB ; jmp rX   (signed entries relative to T)
                mm = ops[1].mem
                if mm.index and mm.scale == 4 and mm.base and mm.base != X.X86_REG_RIP and mm.disp == 0:
                    ta = None
                    for j in range(k - 1, max(-1, k - 12), -1):
                        p = prev[j]
                        po = p.operands
                        if p.mnemonic == "lea" and len(po) == 2 and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, mm.base) \
                                and po[1].type == X.X86_OP_MEM and po[1].mem.base == X.X86_REG_RIP and not po[1].mem.index:
                            ta = p.address + p.size + po[1].mem.disp
                            break
                        if po and po[0].type == X.X86_OP_REG and self.same_gpr(po[0].reg, mm.base):
                            break
                    if ta is None:   # table base hoisted out of a loop: last write to the base register earlier in the function
                        for y in sorted((v for v in seen.values() if v and v.address < x.address), key=lambda v: v.address, reverse=True):
                            yo = y.operands
                            # pop: an epilogue on a returning path, which cannot reach this jump
                            if not (yo and yo[0].type == X.X86_OP_REG and self.same_gpr(yo[0].reg, mm.base)) or y.mnemonic in ("cmp", "test", "push", "pop"):
                                continue
                            if y.mnemonic == "lea" and len(yo) == 2 and yo[1].type == X.X86_OP_MEM and yo[1].mem.base == X.X86_REG_RIP and not yo[1].mem.index:
                                ta = y.address + y.size + yo[1].mem.disp
                            break
                    if ta is None:   # address order is not path order: any rip-relative lea into the base register whose table validates
                        cands = []
                        for y in seen.values():
                            if not y or y.mnemonic != "lea" or len(y.operands) != 2: continue
                            yo = y.operands
                            if yo[0].type == X.X86_OP_REG and self.same_gpr(yo[0].reg, mm.base) and yo[1].type == X.X86_OP_MEM \
                                    and yo[1].mem.base == X.X86_REG_RIP and not yo[1].mem.index:
                                cands.append(y.address + y.size + yo[1].mem.disp)
                        bound0 = self.table_limit(prev, k, mm.index)
                        good = []
                        for ca in set(cands):
                            try: v = struct.unpack("<i", self.pe.read(ca, 4))[0]
                            except KeyError: continue
                            t = (ca + v) & 0xFFFFFFFFFFFFFFFF
                            if self.in_region(t) and t in self.linear_starts() and self.is_code_addr(t) and not self.pe.is_code(ca): good.append(ca)
                        if len(good) == 1 and bound0: ta = good[0]
                    if ta is not None:
                        bound = self.table_limit(prev, k, mm.index)
                        lim = bound or 2048
                        starts = self.linear_starts()
                        tbl = []; n = 0
                        while n < lim:
                            try: v = struct.unpack("<i", self.pe.read(ta + 4 * n, 4))[0]
                            except KeyError: break
                            n += 1
                            t = (ta + v) & 0xFFFFFFFFFFFFFFFF
                            if not self.in_region(t) or t not in starts:
                                # With a known bound, an entry can point at the shared "default" block outside this
                                # function (GCC does that); it is simply not a case. Without one, this is where the
                                # table ends (the next word is data).
                                if bound: continue
                                break
                            tbl.append(t)
                        return tbl or None
            if x.mnemonic in ("mov", "movsxd") and len(ops) == 2 and ops[1].type == X.X86_OP_MEM and ops[0].type == X.X86_OP_REG:
                mm = ops[1].mem
                if mm.index and mm.scale == 4 and mm.base and mm.base != X.X86_REG_RIP and 0 < mm.disp < self.pe.size:
                    ta = self.pe.base + mm.disp
                    lim = self.table_limit(prev, k, mm.index) or 2048
                    tbl = []
                    while len(tbl) < lim:
                        try: v = struct.unpack("<I", self.pe.read(ta + 4 * len(tbl), 4))[0]
                        except KeyError: break
                        t = self.pe.base + v
                        if not self.in_region(t): break
                        tbl.append(t)
                    return tbl or None
            if ops and ops[0].type == X.X86_OP_REG and self.same_gpr(ops[0].reg, r) and x.mnemonic not in ("add", "mov", "movsxd"):
                return None
        return None

    def is_code_addr(self, a):
        return self.pe.text_lo <= a < self.pe.text_hi

    def linear_starts(self):
        """Instruction starts of this function's ranges by linear sweep (GCC code keeps no data inside functions)."""
        if getattr(self, "_linear_starts", None) is None:
            st = set()
            for lo, hi in self.ranges:
                try: code = self.pe.read(lo, hi - lo)
                except KeyError: continue
                st.update(a for a, _, _, _ in self.tr.md.disasm_lite(code, lo))
            self._linear_starts = st
        return self._linear_starts

    def same_gpr(self, a, b):
        na, nb = REG.get(self.tr.md.reg_name(a)), REG.get(self.tr.md.reg_name(b))
        return na and nb and na[0] == nb[0]

    def table_limit(self, prev, k, idx):
        """Look back for 'cmp idx, N' (guarding ja) -> N+1 entries.  Also follows a byte index table."""
        for j in range(k - 1, max(-1, k - 12), -1):
            p = prev[j]
            if p.mnemonic in ("mov", "movzx", "movsxd") and len(p.operands) == 2 and p.operands[0].type == X.X86_OP_REG \
                    and p.operands[1].type == X.X86_OP_REG and self.same_gpr(p.operands[0].reg, idx):
                idx = p.operands[1].reg   # index copied from another register (movzx eax, dx): follow it to its bound check
                continue
            if p.mnemonic in ("mov", "movzx", "movsxd") and len(p.operands) == 2 and p.operands[0].type == X.X86_OP_REG \
                    and p.operands[1].type == X.X86_OP_MEM and self.same_gpr(p.operands[0].reg, idx) and not p.operands[1].mem.index:
                # index loaded from memory (mov eax, [rsi+4]): GCC compares the memory operand itself (cmp dword ptr [rsi+4], N)
                m1 = p.operands[1].mem
                for q in prev[max(0, j - 6):j][::-1]:
                    if q.mnemonic == "cmp" and len(q.operands) == 2 and q.operands[0].type == X.X86_OP_MEM and q.operands[1].type == X.X86_OP_IMM:
                        m0 = q.operands[0].mem
                        if m0.base == m1.base and m0.disp == m1.disp and not m0.index: return q.operands[1].imm + 1
                return None
            if p.mnemonic == "cmp" and len(p.operands) == 2 and p.operands[1].type == X.X86_OP_IMM \
                    and p.operands[0].type == X.X86_OP_REG and self.same_gpr(p.operands[0].reg, idx):
                return p.operands[1].imm + 1
            if p.mnemonic == "movzx" and p.operands[0].type == X.X86_OP_REG and self.same_gpr(p.operands[0].reg, idx) \
                    and p.operands[1].type == X.X86_OP_MEM:
                # two-level table: the dword table has max(byte table)+1 entries
                mm = p.operands[1].mem
                bl = self.table_limit(prev, j, mm.index) if mm.index else None
                if bl and 0 < mm.disp < self.pe.size:
                    return max(self.pe.read(self.pe.base + mm.disp, bl)) + 1
                return None
        return None

    # -- operand access --
    def rn(self, r):
        return self.tr.md.reg_name(r)

    def ea(self, op):
        m = op.mem
        parts = []
        if m.base == X.X86_REG_RIP:
            return "0x%xull" % ((self.cur.address + self.cur.size + m.disp) & 0xFFFFFFFFFFFFFFFF)
        if m.base:
            b = REG.get(self.rn(m.base))
            if not b: raise Unsupported("base " + self.rn(m.base))
            parts.append("C.%s" % b[0] if b[1] == 8 else "(uint32_t)C.%s" % b[0])
        if m.index:
            ix = REG.get(self.rn(m.index))
            if not ix: raise Unsupported("index " + self.rn(m.index))
            v = "C.%s" % ix[0] if ix[1] == 8 else "(uint32_t)C.%s" % ix[0]
            parts.append("%s*%du" % (v, m.scale) if m.scale != 1 else v)
        if m.disp or not parts:
            parts.append("0x%xull" % (m.disp & 0xFFFFFFFFFFFFFFFF))
        e = " + ".join(parts)
        if m.segment == X.X86_REG_GS: e = "C.gsbase + " + e
        elif m.segment == X.X86_REG_FS: raise Unsupported("fs")
        return "(uint64_t)(%s)" % e

    def rd(self, op, size=None):
        size = size or op.size
        if op.type == X.X86_OP_REG:
            n = self.rn(op.reg)
            if n not in REG: raise Unsupported("reg " + n)
            g, sz, hi = REG[n]
            if hi: return "(uint8_t)(C.%s >> 8)" % g
            return "C.%s" % g if sz == 8 else "(%s)C.%s" % (U[sz], g)
        if op.type == X.X86_OP_IMM:
            return "(%s)0x%xull" % (U[size], op.imm & ((1 << (8 * size)) - 1))
        return "%s(%s)" % (RD[size], self.ea(op))

    def wr(self, op, v, size=None):
        size = size or op.size
        if op.type == X.X86_OP_REG:
            n = self.rn(op.reg)
            if n not in REG: raise Unsupported("wreg " + n)
            g, sz, hi = REG[n]
            if hi: return "C.%s = (C.%s & ~0xFF00ull) | ((uint64_t)(uint8_t)(%s) << 8);" % (g, g, v)
            if sz == 8: return "C.%s = (uint64_t)(%s);" % (g, v)
            if sz == 4: return "C.%s = (uint32_t)(%s);" % (g, v)
            return "C.%s = (C.%s & ~%sull) | (%s)(%s);" % (g, g, MASK[sz].rstrip("u"), U[sz], v)
        return "%s(%s, (%s)(%s));" % (WR[size], self.ea(op), U[size], v)

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
        return "missing_func(c, 0x%xull, 0x%xull); return;" % (t, frm)

    def goto(self, t, frm):
        return "goto L_%x;" % t if t in self.addrs else self.tail(t, frm)

    def call(self, i, op, nxt):
        e = self.e
        # setjmp must run in this function's own native frame (it returns again when longjmp comes back), so the call
        # becomes an inline site (see funcs.h); the barrier around it reloads every register afterwards
        if (op.type == X.X86_OP_IMM and op.imm in self.tr.setjmp_thunks) or (op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP
                and self.pe.iat.get(i.address + i.size + op.mem.disp, "").split("!")[-1] in ("__intrinsic_setjmp", "_setjmp", "setjmp")):
            e("PUSH(c, 0x%xull); rt_setjmp_site(c); C.rsp += 8;" % nxt)
            return
        if op.type == X.X86_OP_IMM:
            t = op.imm
            if t in self.tr.funcs:
                e("PUSH(c, 0x%xull); F_%x(c);" % (nxt, t))
            else:
                e("PUSH(c, 0x%xull); missing_func(c, 0x%xull, 0x%xull);" % (nxt, t, i.address))
            return
        if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
            slot = i.address + i.size + op.mem.disp
            if slot in self.pe.iat:
                name = self.pe.iat[slot]
                self.tr.imports_used.add(name)
                e("PUSH(c, 0x%xull); I_%s(c); C.rsp += 8;" % (nxt, cname(name)))
                return
        e("{ uint64_t t = %s; PUSH(c, 0x%xull); call_ind(c, t); }" % (self.rd(op, 8), nxt))

    # -- generation --
    def gen(self):
        for i in self.ins:
            # capstone does not put loop/loope/loopne/jrcxz/jecxz in CS_GRP_JUMP, so name them explicitly (their targets need labels)
            if (i.group(cs.CS_GRP_JUMP) or i.mnemonic in ("loop", "loope", "loopne", "jrcxz", "jecxz")) and i.operands and i.operands[0].type == X.X86_OP_IMM:
                if i.operands[0].imm in self.addrs: self.labels.add(i.operands[0].imm)
            for t in self.tables.get(i.address, []): self.labels.add(t)
        for k, i in enumerate(self.ins):   # fall-through into a non-adjacent decoded block needs a label
            nx = i.address + i.size
            if not self.ends_block(i) and (k + 1 >= len(self.ins) or self.ins[k + 1].address != nx) and nx in self.addrs:
                self.labels.add(nx)
        f = self.out
        f.append("void F_%x(CPU *c) {" % self.addr)
        f.append("    uint64_t cf = 0, zf = 0, sf = 0, of = 0, pr = 0; (void)cf; (void)zf; (void)sf; (void)of; (void)pr;")
        f.append("    c->fn = 0x%xull;" % self.addr)
        if self.addr in getattr(self.tr, "eh_sites", ()): f.append("    rt_eh_site(c);")
        last = None
        for i in self.ins:
            if last is not None and not self.ends_block(last) and i.address != last.address + last.size:
                ft = last.address + last.size
                self.e(self.goto(ft, last.address))
            self.cur = i
            if i.address in self.labels:
                f.append("L_%x:;" % i.address)
            try:
                for pc in PROBES.get(i.address, ()): self.e("{ void rt_log(const char *, ...); " + pc + " }   /* probe */")
                if i.address in PATCHES: self.e(PATCHES[i.address] + "   /* patched: %s %s */" % (i.mnemonic, i.op_str))
                else: self.insn(i)
            except Unsupported as ex:
                self.e('bad_insn(c, 0x%xull, "%s %s"); return; /* %s */' % (i.address, i.mnemonic, i.op_str, ex))
                self.tr.unsupported[i.mnemonic] += 1
            last = i
        if last is not None and not self.ends_block(last):
            self.e(self.tail(last.address + last.size, last.address))
        f.append("}")
        # rsp-relative accesses touch only this thread's stack: use the plain (unordered) accessors
        return cache_registers(const_loads(self.tr.pe, STACK_ACCESS.sub(r"\1s\2((uint64_t)(C.rsp", "\n".join(f))))

    def ends_block(self, i):
        m = i.mnemonic
        if m == "call": return self.noreturn_call(i)
        return m in ("ret", "jmp", "ud2", "hlt", "int3", "bnd jmp") or m.startswith("ret") or m.endswith(" ret")

    # ---------------- instructions ----------------
    def insn(self, i):
        m = i.mnemonic
        ops = i.operands
        e = self.e
        nxt = i.address + i.size
        if m.startswith("bnd "): m = m[4:]
        if m in ("repz ret", "rep ret", "repz ret ", "bnd ret"): m = "ret"
        if m == "movnti": m = "mov"   # non-temporal hint only
        if self.mmx(i, m, ops): return
        if m in ("nop", "pause", "lfence", "sfence", "mfence", "cld", "wait", "fwait", "endbr64", "clflush") or m.startswith(("prefetch", "nop")):
            return
        if m == "int3" or m == "ud2" or m == "hlt":
            e('bad_insn(c, 0x%xull, "%s"); return;' % (i.address, m)); return
        if m == "mov" or m == "movabs":
            d, s = ops
            if d.type == X.X86_OP_REG and self.rn(d.reg) not in REG: raise Unsupported("mov special " + self.rn(d.reg))
            e(self.wr(d, self.rd(s, d.size))); return
        if m == "lea":
            d, s = ops
            e(self.wr(d, self.ea(s))); return
        if m in ("movzx",):
            d, s = ops
            e(self.wr(d, "(%s)%s" % (U[d.size], self.rd(s)))); return
        if m in ("movsx", "movsxd"):
            d, s = ops
            e(self.wr(d, "(%s)(%s)(%s)%s" % (U[d.size], S[d.size], S[s.size], self.rd(s)))); return
        if m in ("cdqe", "cwde", "cbw"):
            if m == "cdqe": e("C.rax = (uint64_t)(int64_t)(int32_t)C.rax;")
            elif m == "cwde": e("C.rax = (uint32_t)(int32_t)(int16_t)C.rax;")
            else: e("C.rax = (C.rax & ~0xFFFFull) | (uint16_t)(int16_t)(int8_t)C.rax;")
            return
        if m in ("cdq", "cqo", "cwd"):
            if m == "cdq": e("C.rdx = (uint32_t)((int32_t)C.rax >> 31);")
            elif m == "cqo": e("C.rdx = (uint64_t)((int64_t)C.rax >> 63);")
            else: e("C.rdx = (C.rdx & ~0xFFFFull) | (uint16_t)((int16_t)C.rax >> 15);")
            return
        if m == "push":
            e("PUSH(c, %s);" % ("(uint64_t)(int64_t)(int32_t)%s" % self.rd(ops[0], 4) if ops[0].type == X.X86_OP_IMM else self.rd(ops[0], 8)))
            return
        if m == "pop":
            e("{ uint64_t v = POP(c); %s }" % self.wr(ops[0], "v", 8)); return
        if m == "pushfq":
            e("PUSH(c, 0x202ull | (cf ? 1 : 0) | (parity8(pr) ? 4 : 0) | (zf ? 0x40 : 0) | (sf ? 0x80 : 0) | (of ? 0x800 : 0));"); return
        if m == "popfq":
            e("{ uint64_t v = POP(c); cf = v & 1; zf = (v >> 6) & 1; sf = (v >> 7) & 1; of = (v >> 11) & 1; pr = (v & 4) ? 0 : 1; }"); return
        if m == "lahf":
            e("C.rax = (C.rax & ~0xFF00ull) | ((uint64_t)(2 | (cf ? 1 : 0) | (parity8(pr) ? 4 : 0) | (zf ? 0x40 : 0) | (sf ? 0x80 : 0)) << 8);"); return
        if m == "sahf":
            e("{ uint64_t v = C.rax >> 8; cf = v & 1; zf = (v >> 6) & 1; sf = (v >> 7) & 1; pr = (v & 4) ? 0 : 1; }"); return
        if m in ("clc", "stc", "cmc"):
            e({"clc": "cf = 0;", "stc": "cf = 1;", "cmc": "cf = !cf;"}[m]); return
        if m == "leave":
            e("C.rsp = C.rbp; C.rbp = POP(c);"); return
        if m == "ret":
            n = ops[0].imm if ops else 0
            e("C.rsp += %d; return;" % (8 + n)); return
        if m == "call":
            self.call(i, ops[0], nxt); return
        if m == "jmp":
            op = ops[0]
            if op.type == X.X86_OP_IMM:
                e(self.goto(op.imm, i.address)); return
            tbl = self.tables.get(i.address)
            if tbl:
                cases = " ".join("case 0x%xull: goto L_%x;" % (t, t) for t in sorted(set(tbl)))
                e("{ uint64_t t = %s; switch (t) { %s default: bad_jump(c, t, 0x%xull); return; } }" % (self.rd(op, 8), cases, i.address))
                return
            if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                slot = i.address + i.size + op.mem.disp
                if slot in self.pe.iat:
                    name = self.pe.iat[slot]; self.tr.imports_used.add(name)
                    e("I_%s(c); C.rsp += 8; return;" % cname(name)); return
            e("{ uint64_t t = %s; call_ind(c, t); return; }" % self.rd(op, 8)); return
        if m in ("jrcxz", "jecxz"):
            r = "C.rcx" if m == "jrcxz" else "(uint32_t)C.rcx"
            e("if (%s == 0) %s" % (r, self.goto_block(ops[0].imm, i.address))); return
        if m in ("loop", "loope", "loopne"):
            cond = {"loop": "C.rcx != 0", "loope": "C.rcx != 0 && zf", "loopne": "C.rcx != 0 && !zf"}[m]
            e("C.rcx--; if (%s) %s" % (cond, self.goto_block(ops[0].imm, i.address))); return
        if m.startswith("j"):
            cc = CC.get(m[1:])
            if cc is None: raise Unsupported(m)
            e("if (%s) %s" % (cc, self.goto_block(ops[0].imm, i.address))); return
        if m.startswith("set"):
            e(self.wr(ops[0], "(%s) ? 1 : 0" % CC[m[3:]])); return
        if m.startswith("cmov"):
            d = ops[0]
            v = self.rd(ops[1], d.size)
            # a 32-bit cmov zero-extends the destination even when the condition is false
            if d.size == 4: e("C.%s = (uint32_t)((%s) ? %s : (uint32_t)C.%s);" % (REG[self.rn(d.reg)][0], CC[m[4:]], v, REG[self.rn(d.reg)][0]))
            else: e("if (%s) %s" % (CC[m[4:]], self.wr(d, v)))
            return
        if self.alu(i, m, ops): return
        if self.strop(i, m, ops): return
        if self.atomic(i, m, ops): return
        if m == "cpuid": e("cpu_cpuid(c);"); return
        if m == "xgetbv": e("C.rax = 7; C.rdx = 0;"); return
        if m == "rdtsc":
            e("{ uint64_t t = __builtin_readcyclecounter(); C.rax = (uint32_t)t; C.rdx = t >> 32; }"); return
        if m == "syscall" or m == "int":
            e("cpu_syscall_trap(c, 0x%xull); return;" % i.address); return
        if self.sse(i, m, ops): return
        if self.vec(i, m, ops): return
        if self.x87(i, m, ops): return
        raise Unsupported(m)

    def goto_block(self, t, frm):
        g = self.goto(t, frm)
        return g if g.startswith("goto") else "{ %s }" % g

    # -- integer ALU --
    def alu(self, i, m, ops):
        e = self.e
        if m in ("add", "sub", "cmp", "adc", "sbb") and len(ops) == 2:
            d, s = ops; n = d.size
            a, b = self.rd(d), self.rd(s, n)
            car = " + (%s)cf" % U[n] if m == "adc" else " - (%s)cf" % U[n] if m == "sbb" else ""
            if m in ("add", "adc"):
                cfe = "r < a || (cf_in && r == a)" if m == "adc" else "r < a"
                e("{ %s a = %s, b = %s, r; uint64_t cf_in = cf; (void)cf_in; r = (%s)(a + b%s); cf = %s; of = ((~(a ^ b) & (a ^ r)) >> %d) & 1; %s %s }"
                  % (U[n], a, b, U[n], car, cfe, BITS[n] - 1, self.szf("r", n), self.wr(d, "r")))
            else:
                cfe = "a < b || (cf_in && a == b)" if m == "sbb" else "a < b"
                wb = "" if m == "cmp" else self.wr(d, "r")
                e("{ %s a = %s, b = %s, r; uint64_t cf_in = cf; (void)cf_in; r = (%s)(a - b%s); cf = %s; of = (((a ^ b) & (a ^ r)) >> %d) & 1; %s %s }"
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
            ofc = "r == (%s)1 << %d" % (U[n], BITS[n] - 1) if m == "inc" else "a == (%s)1 << %d" % (U[n], BITS[n] - 1)
            e("{ %s a = %s, r = (%s)(a %s 1); of = %s; %s %s }" % (U[n], self.rd(d), U[n], op, ofc, self.szf("r", n), self.wr(d, "r")))
            return True
        if m == "neg":
            d = ops[0]; n = d.size
            e("{ %s a = %s, r = (%s)(0 - a); cf = a != 0; of = a == (%s)1 << %d; %s %s }" % (U[n], self.rd(d), U[n], U[n], BITS[n] - 1, self.szf("r", n), self.wr(d, "r")))
            return True
        if m == "not":
            d = ops[0]; e(self.wr(d, "~%s" % self.rd(d))); return True
        if m in ("shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr"):
            d = ops[0]; n = d.size; bits = BITS[n]
            # a zero count changes nothing, except that a 32-bit register write still clears the upper half
            z = " else { %s }" % self.wr(d, "a") if n == 4 and d.type == X.X86_OP_REG else ""
            cnt = "%d" % (ops[1].imm & (63 if n == 8 else 31)) if len(ops) > 1 and ops[1].type == X.X86_OP_IMM else \
                  ("(uint32_t)(%s & %d)" % (self.rd(ops[1], 1), 63 if n == 8 else 31) if len(ops) > 1 else "1")
            a = self.rd(d)
            if m in ("shl", "sal"):
                body = "r = (%s)(a << k); cf = (a >> (%d - k)) & 1; of = ((r >> %d) & 1) ^ cf;" % (U[n], bits, bits - 1)
            elif m == "shr":
                body = "r = (%s)(a >> k); cf = (a >> (k - 1)) & 1; of = (a >> %d) & 1;" % (U[n], bits - 1)
            elif m == "sar":
                body = "r = (%s)((%s)a >> k); cf = ((%s)a >> (k - 1)) & 1; of = 0;" % (U[n], S[n], S[n])
            elif m == "rol":
                body = "k %%= %d; r = k ? (%s)((a << k) | (a >> (%d - k))) : a; cf = r & 1; of = ((r >> %d) & 1) ^ cf;" % (bits, U[n], bits, bits - 1)
                e("{ %s a = %s, r; uint32_t k = %s; if (k) { %s %s }%s }" % (U[n], a, cnt, body, self.wr(d, "r"), z)); return True
            elif m == "ror":
                body = "k %%= %d; r = k ? (%s)((a >> k) | (a << (%d - k))) : a; cf = (r >> %d) & 1; of = cf ^ ((r >> %d) & 1);" % (bits, U[n], bits, bits - 1, bits - 2)
                e("{ %s a = %s, r; uint32_t k = %s; if (k) { %s %s }%s }" % (U[n], a, cnt, body, self.wr(d, "r"), z)); return True
            else:   # rcl/rcr one bit at a time (rare)
                if m == "rcl":   # OF (count 1) = MSB(result) ^ CF
                    body = "for (uint32_t j = 0; j < k; j++) { uint64_t nc = (r >> %d) & 1; r = (%s)((r << 1) | cf); cf = nc; } if (k == 1) of = ((r >> %d) & 1) ^ cf;" % (bits - 1, U[n], bits - 1)
                else:            # OF (count 1) = MSB(original) ^ CF(original)
                    body = "if (k == 1) of = ((r >> %d) & 1) ^ cf; for (uint32_t j = 0; j < k; j++) { uint64_t nc = r & 1; r = (%s)((r >> 1) | ((%s)cf << %d)); cf = nc; }" % (bits - 1, U[n], U[n], bits - 1)
                e("{ %s r = %s; uint32_t k = %s; %s %s }" % (U[n], a, cnt, body, self.wr(d, "r"))); return True
            e("{ %s a = %s, r; uint32_t k = %s; if (k) { %s %s %s }%s }" % (U[n], a, cnt, body, self.szf("r", n), self.wr(d, "r"), z))
            return True
        if m in ("shld", "shrd"):
            d, s = ops[0], ops[1]; n = d.size; bits = BITS[n]
            cnt = "%d" % (ops[2].imm & (63 if n == 8 else 31)) if ops[2].type == X.X86_OP_IMM else "(uint32_t)(C.rcx & %d)" % (63 if n == 8 else 31)
            if m == "shld":
                body = "r = (%s)((a << k) | (b >> (%d - k))); cf = (a >> (%d - k)) & 1;" % (U[n], bits, bits)
            else:
                body = "r = (%s)((a >> k) | (b << (%d - k))); cf = (a >> (k - 1)) & 1;" % (U[n], bits)
            z = " else { %s }" % self.wr(d, "a") if n == 4 and d.type == X.X86_OP_REG else ""
            e("{ %s a = %s, b = %s, r; uint32_t k = %s; if (k) { %s %s %s }%s }" % (U[n], self.rd(d), self.rd(s, n), cnt, body, self.szf("r", n), self.wr(d, "r"), z))
            return True
        if m in ("bt", "bts", "btr", "btc"):
            d, s = ops; n = d.size
            if d.type == X.X86_OP_MEM and s.type == X.X86_OP_REG:
                # bit string in memory: the register offset may address beyond the operand
                ad = self.ea(d)
                e("{ int64_t o = (%s)%s; uint64_t a = %s + (o >> 3); uint8_t v = rd8(a), k = o & 7; cf = (v >> k) & 1; %s }"
                  % (S[n], self.rd(s), ad, {"bt": "", "bts": "wr8(a, v | (1u << k));", "btr": "wr8(a, v & ~(1u << k));", "btc": "wr8(a, v ^ (1u << k));"}[m]))
                return True
            k = "(%s & %d)" % (self.rd(s, n) if s.type != X.X86_OP_IMM else "%d" % s.imm, BITS[n] - 1)
            op = {"bt": None, "bts": "v | b", "btr": "v & ~b", "btc": "v ^ b"}[m]
            e("{ %s v = %s, b = (%s)1 << %s; cf = (v & b) != 0; %s }" % (U[n], self.rd(d), U[n], k, self.wr(d, op) if op else ""))
            return True
        if m in ("bsf", "bsr", "tzcnt", "lzcnt", "popcnt"):
            d, s = ops; n = d.size
            fn = {8: "ll", 4: "", 2: ""}[n]
            v = "(%s)%s" % ("uint64_t" if n == 8 else "uint32_t", self.rd(s))
            if m == "bsf":
                e("{ uint64_t v = %s; zf = v == 0; if (v) %s }" % (v, self.wr(d, "__builtin_ctz%s(v)" % fn)))
            elif m == "bsr":
                e("{ uint64_t v = %s; zf = v == 0; if (v) %s }" % (v, self.wr(d, "%d - __builtin_clz%s(v)" % (63 if n == 8 else 31, fn))))
            elif m == "popcnt":
                e("{ uint64_t v = %s; %s zf = v == 0; cf = 0; }" % (v, self.wr(d, "__builtin_popcount%s(v)" % fn)))
            elif m == "tzcnt":   # GCC emits it (rep bsf) for __builtin_ctz even without -mbmi; same result as bsf for v != 0
                e("{ uint64_t v = %s; uint64_t r = v ? (uint64_t)__builtin_ctz%s(v) : %d; cf = v == 0; zf = r == 0; %s }" % (v, fn, BITS[n], self.wr(d, "r")))
            else:                # lzcnt
                e("{ uint64_t v = %s; uint64_t r = v ? (uint64_t)__builtin_clz%s(v) - %d : %d; cf = v == 0; zf = r == 0; %s }" % (v, fn, 0 if n != 2 else 16, BITS[n], self.wr(d, "r")))
            return True
        if m == "bswap":
            d = ops[0]
            e(self.wr(d, "__builtin_bswap%d(%s)" % (BITS[d.size], self.rd(d)))); return True
        if m == "xchg":
            a, b = ops
            if a.type == X.X86_OP_MEM or b.type == X.X86_OP_MEM:
                mem, reg = (a, b) if a.type == X.X86_OP_MEM else (b, a)
                e("{ %s v = __atomic_exchange_n((%s *)(uintptr_t)%s, %s, __ATOMIC_SEQ_CST); %s }"
                  % (U[mem.size], U[mem.size], self.ea(mem), self.rd(reg), self.wr(reg, "v")))
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
            if n == 8:
                e("{ __int128 p = (__int128)(int64_t)%s * (int64_t)%s; uint64_t r = (uint64_t)p; cf = of = p != (__int128)(int64_t)r; %s %s }" % (a, b, self.szf("r", 8), self.wr(d, "r")))
            else:
                e("{ int64_t p = (int64_t)(%s)%s * (int64_t)(%s)%s; %s r = (%s)p; cf = of = p != (int64_t)(%s)r; %s %s }"
                  % (S[n], a, S[n], b, U[n], U[n], S[n], self.szf("r", n), self.wr(d, "r")))
            return True
        s = ops[0]; n = s.size; v = self.rd(s)
        if n == 8:
            if m == "mul": e("{ unsigned __int128 p = (unsigned __int128)C.rax * %s; C.rax = (uint64_t)p; C.rdx = (uint64_t)(p >> 64); cf = of = C.rdx != 0; }" % v)
            elif m == "imul": e("{ __int128 p = (__int128)(int64_t)C.rax * (int64_t)%s; C.rax = (uint64_t)p; C.rdx = (uint64_t)((unsigned __int128)p >> 64); cf = of = p != (int64_t)C.rax; }" % v)
            elif m == "div": e("{ unsigned __int128 nn = ((unsigned __int128)C.rdx << 64) | C.rax; uint64_t dd = %s; C.rax = (uint64_t)(nn / dd); C.rdx = (uint64_t)(nn %% dd); }" % v)
            else: e("{ __int128 nn = (__int128)(((unsigned __int128)C.rdx << 64) | C.rax); int64_t dd = (int64_t)%s; C.rax = (uint64_t)(int64_t)(nn / dd); C.rdx = (uint64_t)(int64_t)(nn %% dd); }" % v)
        elif n == 4:
            if m == "mul": e("{ uint64_t p = (uint64_t)(uint32_t)C.rax * %s; C.rax = (uint32_t)p; C.rdx = (uint32_t)(p >> 32); cf = of = C.rdx != 0; }" % v)
            elif m == "imul": e("{ int64_t p = (int64_t)(int32_t)C.rax * (int32_t)%s; C.rax = (uint32_t)p; C.rdx = (uint32_t)((uint64_t)p >> 32); cf = of = p != (int32_t)p; }" % v)
            elif m == "div": e("{ uint64_t nn = ((uint64_t)(uint32_t)C.rdx << 32) | (uint32_t)C.rax; uint32_t dd = %s; C.rax = (uint32_t)(nn / dd); C.rdx = (uint32_t)(nn %% dd); }" % v)
            else: e("{ int64_t nn = (int64_t)(((uint64_t)(uint32_t)C.rdx << 32) | (uint32_t)C.rax); int32_t dd = (int32_t)%s; C.rax = (uint32_t)(int32_t)(nn / dd); C.rdx = (uint32_t)(int32_t)(nn %% dd); }" % v)
        elif n == 2:
            if m in ("mul", "imul"):
                t = "uint32_t" if m == "mul" else "int32_t"; c16 = "uint16_t" if m == "mul" else "int16_t"
                # CF/OF: mul, the high half is non-zero; imul, the product doesn't fit in 16 signed bits
                ov = "(C.rdx & 0xFFFF) != 0" if m == "mul" else "p != (int16_t)p"
                e("{ %s p = (%s)(%s)C.rax * (%s)%s; C.rax = (C.rax & ~0xFFFFull) | (uint16_t)p; C.rdx = (C.rdx & ~0xFFFFull) | (uint16_t)((uint32_t)p >> 16); cf = of = %s; }" % (t, t, c16, c16, v, ov))
            else:
                t, c16 = ("uint32_t", "uint16_t") if m == "div" else ("int32_t", "int16_t")
                e("{ %s nn = (%s)(((uint32_t)(uint16_t)C.rdx << 16) | (uint16_t)C.rax); %s dd = (%s)%s; C.rax = (C.rax & ~0xFFFFull) | (uint16_t)(nn / dd); C.rdx = (C.rdx & ~0xFFFFull) | (uint16_t)(nn %% dd); }" % (t, t, c16, c16, v))
        else:
            if m in ("mul", "imul"):
                t, c8 = ("uint32_t", "uint8_t") if m == "mul" else ("int32_t", "int8_t")
                ov = "(p >> 8) != 0" if m == "mul" else "p != (int8_t)p"   # imul: doesn't fit in 8 signed bits
                e("{ %s p = (%s)(%s)C.rax * (%s)%s; C.rax = (C.rax & ~0xFFFFull) | (uint16_t)p; cf = of = %s; }" % (t, t, c8, c8, v, ov))
            else:
                t, c8 = ("uint32_t", "uint8_t") if m == "div" else ("int32_t", "int8_t")
                e("{ %s nn = (%s)(%s)C.rax; %s dd = (%s)%s; C.rax = (C.rax & ~0xFFFFull) | (uint8_t)(nn / dd) | ((uint16_t)(uint8_t)(nn %% dd) << 8); }" % (t, t, "uint16_t" if m == "div" else "int16_t", c8, c8, v))
        return True

    # -- string ops (DF = 0) --
    def strop(self, i, m, ops):
        e = self.e
        mm = re.match(r"(rep |repe |repne |repz |repnz )?(movs|stos|lods|cmps|scas)([bwdq])$", m)
        if not mm: return False
        if any(self.isx(o) for o in ops): return False   # SSE movsd/cmpsd share the mnemonic
        rep, op, w = mm.groups()
        n = {"b": 1, "w": 2, "d": 4, "q": 8}[w]
        T = U[n]
        if op == "movs" and rep:
            # x86 copies element by element, forward: when the destination starts inside the source
            # (src < dst < src + len) values propagate (MSVC uses `rep movsd` with rsi = rdi - 4 to fill an array
            # with its last element), which memmove would not do. Other cases are a plain memmove.
            e("{ uint64_t k = C.rcx, s_ = C.rsi, d_ = C.rdi; if (d_ > s_ && d_ < s_ + k * %d) { for (uint64_t j = 0; j < k; j++) %s(d_ + j * %d, %s(s_ + j * %d)); }"
              " else memmove(P8(d_), P8(s_), k * %d); C.rsi += k * %d; C.rdi += k * %d; C.rcx = 0; }" % (n, WR[n], n, RD[n], n, n, n, n))
            return True
        if op == "stos" and rep:
            if n == 1: e("{ uint64_t k = C.rcx; memset(P8(C.rdi), (uint8_t)C.rax, k); C.rdi += k; C.rcx = 0; }")
            else: e("{ uint64_t k = C.rcx; %s v = (%s)C.rax; for (uint64_t j = 0; j < k; j++) %s(C.rdi + j * %d, v); C.rdi += k * %d; C.rcx = 0; }" % (T, T, WR[n], n, n))
            return True
        if op == "movs": e("%s(C.rdi, %s(C.rsi)); C.rsi += %d; C.rdi += %d;" % (WR[n], RD[n], n, n)); return True
        if op == "stos": e("%s(C.rdi, (%s)C.rax); C.rdi += %d;" % (WR[n], T, n)); return True
        if op == "lods":
            if rep: raise Unsupported("rep lods")
            reg = {1: "al", 2: "ax", 4: "eax", 8: "rax"}[n]
            e("{ %s v = %s(C.rsi); C.rsi += %d; %s }" % (T, RD[n], n, self.wr_name(reg, "v"))); return True
        # cmps / scas
        lhs = "%s(C.rsi)" % RD[n] if op == "cmps" else "(%s)C.rax" % T
        adv = "C.rsi += %d; C.rdi += %d;" % (n, n) if op == "cmps" else "C.rdi += %d;" % n
        one = "{ %s a = %s, b = %s(C.rdi), r = (%s)(a - b); cf = a < b; of = (((a ^ b) & (a ^ r)) >> %d) & 1; %s %s }" % (T, lhs, RD[n], T, BITS[n] - 1, self.szf("r", n), adv)
        if not rep: e(one); return True
        cond = "zf" if rep.strip() in ("repe", "repz", "rep") else "!zf"
        e("while (C.rcx) { %s C.rcx--; if (!(%s)) break; }" % (one, cond)); return True

    def wr_name(self, reg, v):
        g, sz, hi = REG[reg]
        if sz == 8: return "C.%s = %s;" % (g, v)
        if sz == 4: return "C.%s = (uint32_t)(%s);" % (g, v)
        return "C.%s = (C.%s & ~%sull) | (%s)(%s);" % (g, g, MASK[sz].rstrip("u"), U[sz], v)

    # -- lock-prefixed atomics (identity memory: host atomics) --
    def atomic(self, i, m, ops):
        e = self.e
        if not m.startswith("lock "):
            if m in ("cmpxchg", "xadd", "cmpxchg16b"): pass
            else: return False
        base = m[5:] if m.startswith("lock ") else m
        if base == "cmpxchg16b" and ops[0].type == X.X86_OP_MEM:
            # compare rdx:rax with m128: equal -> ZF=1, m128 = rcx:rbx; else ZF=0, rdx:rax = m128 (other flags kept).
            # A 16-byte compare-exchange is CASP on arm64 (LSE); the operand is 16-byte aligned, as x86 requires.
            p = "(unsigned __int128 *)(uintptr_t)%s" % self.ea(ops[0])
            e("{ unsigned __int128 exp = ((unsigned __int128)C.rdx << 64) | C.rax, des = ((unsigned __int128)C.rcx << 64) | C.rbx; "
              "zf = __atomic_compare_exchange_n(%s, &exp, des, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); "
              "if (!zf) { C.rax = (uint64_t)exp; C.rdx = (uint64_t)(exp >> 64); } }" % p)
            return True
        d = ops[0]; n = d.size; T = U[n]
        if d.type != X.X86_OP_MEM:
            if base == "xadd":
                e("{ %s a = %s, b = %s, r = (%s)(a + b); %s %s cf = r < a; %s }" % (T, self.rd(d), self.rd(ops[1]), T, self.wr(ops[1], "a"), self.wr(d, "r"), self.szf("r", n)))
                return True
            if base == "cmpxchg":
                acc = {1: "al", 2: "ax", 4: "eax", 8: "rax"}[n]
                e("{ %s cur = %s, exp = (%s)C.rax, r = (%s)(exp - cur); cf = exp < cur; of = (((exp ^ cur) & (exp ^ r)) >> %d) & 1; %s if (zf) { %s } else { %s } }"
                  % (T, self.rd(d), T, T, BITS[n] - 1, self.szf("r", n), self.wr(d, self.rd(ops[1])), self.wr_name(acc, "cur")))
                return True
            raise Unsupported(m)
        p = "(%s *)(uintptr_t)%s" % (T, self.ea(d))
        if base == "xadd":
            e("{ %s a = __atomic_fetch_add(%s, %s, __ATOMIC_SEQ_CST), b = %s, r = (%s)(a + b); %s cf = r < a; of = ((~(a ^ b) & (a ^ r)) >> %d) & 1; %s }"
              % (T, p, self.rd(ops[1]), self.rd(ops[1]), T, self.wr(ops[1], "a"), BITS[n] - 1, self.szf("r", n)))
            return True
        if base == "cmpxchg":
            acc = {1: "al", 2: "ax", 4: "eax", 8: "rax"}[n]
            e("{ %s exp = (%s)C.rax, acc = exp, r; int ok = __atomic_compare_exchange_n(%s, &exp, %s, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); %s r = (%s)(acc - exp); cf = acc < exp; of = (((acc ^ exp) & (acc ^ r)) >> %d) & 1; %s zf = ok; }"
              % (T, T, p, self.rd(ops[1]), "if (!ok) { %s }" % self.wr_name(acc, "exp"), T, BITS[n] - 1, self.szf("r", n)))
            return True
        if base in ("inc", "dec", "add", "sub", "or", "and", "xor"):
            v = "1" if base in ("inc", "dec") else self.rd(ops[1], n)
            fn = {"inc": "add", "dec": "sub", "add": "add", "sub": "sub", "or": "or", "and": "and", "xor": "xor"}[base]
            op = {"add": "+", "sub": "-", "or": "|", "and": "&", "xor": "^"}[fn]
            e("{ %s b = (%s)%s, a = __atomic_fetch_%s(%s, b, __ATOMIC_SEQ_CST), r = (%s)(a %s b); %s %s }"
              % (T, T, v, fn, p, T, op, self.szf("r", n),
                 "cf = r < a; of = ((~(a ^ b) & (a ^ r)) >> %d) & 1;" % (BITS[n] - 1) if fn == "add" and base == "add" else
                 "cf = a < b; of = (((a ^ b) & (a ^ r)) >> %d) & 1;" % (BITS[n] - 1) if fn == "sub" and base == "sub" else
                 "of = 0; cf = 0;" if fn in ("or", "and", "xor") else ""))
            return True
        if base in ("bts", "btr", "btc"):
            k = "(%s & %d)" % (self.rd(ops[1], n) if ops[1].type != X.X86_OP_IMM else "%d" % ops[1].imm, BITS[n] - 1)
            fn = {"bts": "or", "btr": "and", "btc": "xor"}[base]
            mk = "~((%s)1 << %s)" % (T, k) if base == "btr" else "((%s)1 << %s)" % (T, k)
            e("{ %s a = __atomic_fetch_%s(%s, %s, __ATOMIC_SEQ_CST); cf = (a >> %s) & 1; }" % (T, fn, p, mk, k))
            return True
        raise Unsupported(m)

    # -- scalar SSE / moves --
    def sse(self, i, m, ops):
        e = self.e
        def src32(op):
            return "%s.f[0]" % self.xmm(op) if self.isx(op) else "rdf(%s)" % self.ea(op)
        def src64(op):
            return "%s.d[0]" % self.xmm(op) if self.isx(op) else "rdd(%s)" % self.ea(op)
        def x128(op):
            return self.xmm(op) if self.isx(op) else "rdx(%s)" % self.ea(op)
        if m in ("movaps", "movups", "movdqa", "movdqu", "movapd", "movupd", "movntps", "movntdq", "movntpd", "lddqu", "movntdqa"):
            d, s = ops
            if self.isx(d): e("%s = %s;" % (self.xmm(d), x128(s)))
            else: e("wrx(%s, %s);" % (self.ea(d), self.xmm(s)))
            return True
        if m in ("movss", "movsd") and len(ops) == 2:
            d, s = ops
            f = "f" if m == "movss" else "d"
            if self.isx(d) and self.isx(s): e("%s.%s[0] = %s.%s[0];" % (self.xmm(d), f, self.xmm(s), f))
            elif self.isx(d):
                if m == "movss": e("{ XMM x = {0}; x.f[0] = rdf(%s); %s = x; }" % (self.ea(s), self.xmm(d)))
                else: e("{ XMM x = {0}; x.d[0] = rdd(%s); %s = x; }" % (self.ea(s), self.xmm(d)))
            else: e("%s(%s, %s.%s[0]);" % ("wrf" if m == "movss" else "wrd", self.ea(d), self.xmm(s), f))
            return True
        if m in ("movd", "movq"):
            d, s = ops
            if self.isx(d) and self.isx(s): e("{ XMM x = {0}; x.q[0] = %s.q[0]; %s = x; }" % (self.xmm(s), self.xmm(d))); return True
            if self.isx(d):
                v = self.rd(s)
                e("{ XMM x = {0}; x.q[0] = (%s)%s; %s = x; }" % ("uint64_t" if s.size == 8 else "uint32_t", v, self.xmm(d))); return True
            if self.isx(s):
                n = d.size
                e(self.wr(d, "%s.%s[0]" % (self.xmm(s), "q" if n == 8 else "u"))); return True
            raise Unsupported("mmx " + m)
        if m in ("movlps", "movlpd", "movhps", "movhpd"):
            d, s = ops; k = 0 if m.startswith("movl") else 1
            if self.isx(d): e("%s.q[%d] = rd64(%s);" % (self.xmm(d), k, self.ea(s)))
            else: e("wr64(%s, %s.q[%d]);" % (self.ea(d), self.xmm(s), k))
            return True
        if m in ("movmskps", "movmskpd"):
            d, s = ops; X_ = self.xmm(s)
            if m == "movmskps": e(self.wr(d, "(%s.u[0] >> 31) | ((%s.u[1] >> 31) << 1) | ((%s.u[2] >> 31) << 2) | ((%s.u[3] >> 31) << 3)" % (X_, X_, X_, X_), 4))
            else: e(self.wr(d, "(%s.q[0] >> 63) | ((%s.q[1] >> 63) << 1)" % (X_, X_), 4))
            return True
        if m == "pmovmskb":
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
            f, n = ("f", 4) if t == "ps" else ("d", 2)
            v = "v" + f
            e("{ XMM b = %s, a = %s; a.%s = a.%s %s b.%s; %s = a; }" % (x128(s), self.xmm(d), v, v, ar[op], v, self.xmm(d)))
            return True
        if m in ("andps", "andpd", "pand", "orps", "orpd", "por", "xorps", "xorpd", "pxor", "andnps", "andnpd", "pandn"):
            d, s = ops
            if not self.isx(d): raise Unsupported("mmx " + m)
            if m in ("xorps", "xorpd", "pxor") and self.isx(s) and s.reg == d.reg:
                e("%s = (XMM){0};" % self.xmm(d)); return True
            # test "xor" before "or": "pxor"/"xorps"/"xorpd" contain "or"
            if "andn" in m: ex = "~a.q[k] & b.q[k]"
            else: ex = "a.q[k] %s b.q[k]" % ("^" if "xor" in m else "&" if "and" in m else "|")
            e("{ XMM b = %s, a = %s; a.vq = %s; %s = a; }" % (x128(s), self.xmm(d), ex.replace(".q[k]", ".vq"), self.xmm(d)))
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
            e("%s.%s[0] = (%s)(%s)%s;" % (self.xmm(d), t, "float" if t == "f" else "double", S[s.size], self.rd(s)))
            return True
        mm = re.match(r"cvt(t?)(ss|sd)2si$", m)
        if mm:
            tr, t = mm.groups(); d, s = ops
            v = src32(s) if t == "ss" else src64(s)
            if not tr: v = "sse_round(c, %s)" % v
            else: v = "(double)(%s)" % v
            e(self.wr(d, "(uint64_t)%s(%s)" % ("cvt_i64" if d.size == 8 else "(uint32_t)cvt_i32", v)))
            return True
        mm = re.match(r"cmp(eq|lt|le|unord|neq|nlt|nle|ord)(ss|sd)$", m)
        if mm:
            cond, t = mm.groups(); d, s = ops
            C_ = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "a != a || b != b", "neq": "!(a == b)",
                  "nlt": "!(a < b)", "nle": "!(a <= b)", "ord": "a == a && b == b"}[cond]
            if t == "ss": e("{ float a = %s.f[0], b = %s; %s.u[0] = (%s) ? 0xFFFFFFFFu : 0; }" % (self.xmm(d), src32(s), self.xmm(d), C_))
            else: e("{ double a = %s.d[0], b = %s; %s.q[0] = (%s) ? ~0ull : 0; }" % (self.xmm(d), src64(s), self.xmm(d), C_))
            return True
        if m in ("rsqrtss", "rcpss"):
            v = src32(ops[1])
            e("%s.f[0] = %s;" % (self.xmm(ops[0]), ("1.0f / sqrtf(%s)" if m == "rsqrtss" else "1.0f / (%s)") % v)); return True
        if m in ("roundss", "roundsd", "roundps", "roundpd"):
            d, s, im = ops
            mode = im.imm & 3 if not (im.imm & 4) else None
            fn = {0: "nearbyint", 1: "floor", 2: "ceil", 3: "trunc"}
            r = fn[mode] if mode is not None else "nearbyint"
            if m == "roundss": e("%s.f[0] = (float)%s(%s);" % (self.xmm(d), r, src32(s)))
            elif m == "roundsd": e("%s.d[0] = %s(%s);" % (self.xmm(d), r, src64(s)))
            elif m == "roundps": e("{ XMM b = %s; for (int k = 0; k < 4; k++) b.f[k] = (float)%s(b.f[k]); %s = b; }" % (x128(s), r, self.xmm(d)))
            else: e("{ XMM b = %s; for (int k = 0; k < 2; k++) b.d[k] = %s(b.d[k]); %s = b; }" % (x128(s), r, self.xmm(d)))
            return True
        if m in ("stmxcsr", "vstmxcsr"): e(self.wr(ops[0], "C.mxcsr", 4)); return True
        if m in ("ldmxcsr", "vldmxcsr"): e("C.mxcsr = %s;" % self.rd(ops[0], 4)); return True
        return False

    # -- packed SSE/SSE2/SSE3/SSSE3/SSE4.1 (xmm only) --
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
        "pcmpeqq": ("q", 2, "a == b ? ~0ull : 0"),
        "pcmpgtb": ("c", 16, "a > b ? -1 : 0"), "pcmpgtw": ("h", 8, "a > b ? -1 : 0"), "pcmpgtd": ("i", 4, "a > b ? -1 : 0"),
        "pmaxsw": ("h", 8, "a > b ? a : b"), "pminsw": ("h", 8, "a < b ? a : b"), "pmaxub": ("b", 16, "a > b ? a : b"),
        "pminub": ("b", 16, "a < b ? a : b"), "pmaxsd": ("i", 4, "a > b ? a : b"), "pminsd": ("i", 4, "a < b ? a : b"),
        "pmaxud": ("u", 4, "a > b ? a : b"), "pminud": ("u", 4, "a < b ? a : b"),
        "pavgb": ("b", 16, "(uint8_t)((a + b + 1) >> 1)"), "pavgw": ("w", 8, "(uint16_t)((a + b + 1) >> 1)"),
        "pabsd": ("i", 4, "b < 0 ? -b : b"), "pabsw": ("h", 8, "(int16_t)(b < 0 ? -b : b)"), "pabsb": ("c", 16, "(int8_t)(b < 0 ? -b : b)"),
        "minps": ("f", 4, "a < b ? a : b"), "maxps": ("f", 4, "a > b ? a : b"), "minpd": ("d", 2, "a < b ? a : b"), "maxpd": ("d", 2, "a > b ? a : b"),
        "sqrtps": ("f", 4, "sqrtf(b)"), "sqrtpd": ("d", 2, "sqrt(b)"), "rcpps": ("f", 4, "1.0f / b"), "rsqrtps": ("f", 4, "1.0f / sqrtf(b)"),
    }

    # whole-vector forms (clang vector extensions; see XMM in cpu.h): field, expression of a (dest) and b (src)
    VLANES = {
        "paddb": ("vb", "a + b"), "paddw": ("vw", "a + b"), "paddd": ("vu", "a + b"), "paddq": ("vq", "a + b"),
        "psubb": ("vb", "a - b"), "psubw": ("vw", "a - b"), "psubd": ("vu", "a - b"), "psubq": ("vq", "a - b"),
        "pmullw": ("vw", "a * b"), "pmulld": ("vu", "a * b"),
        "pcmpeqb": ("vb", "(v16b)(a == b)"), "pcmpeqw": ("vw", "(v8w)(a == b)"), "pcmpeqd": ("vu", "(v4u)(a == b)"), "pcmpeqq": ("vq", "(v2q)(a == b)"),
        "pcmpgtb": ("vc", "(v16c)(a > b)"), "pcmpgtw": ("vh", "(v8h)(a > b)"), "pcmpgtd": ("vi", "(v4i)(a > b)"),
        "pmaxsw": ("vh", "VSEL(a > b, a, b)"), "pminsw": ("vh", "VSEL(a < b, a, b)"), "pmaxub": ("vb", "VSEL(a > b, a, b)"),
        "pminub": ("vb", "VSEL(a < b, a, b)"), "pmaxsd": ("vi", "VSEL(a > b, a, b)"), "pminsd": ("vi", "VSEL(a < b, a, b)"),
        "pmaxud": ("vu", "VSEL(a > b, a, b)"), "pminud": ("vu", "VSEL(a < b, a, b)"),
        "minps": ("vf", "VSEL(a < b, a, b)"), "maxps": ("vf", "VSEL(a > b, a, b)"),   # NaN or equal: the source, like SSE
        "minpd": ("vd", "VSEL(a < b, a, b)"), "maxpd": ("vd", "VSEL(a > b, a, b)"),
    }

    # -- MMX (64-bit integer SIMD on mm0-7); lane ops reuse the SSE tables at half the lane count --
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
            return "(uint64_t)%s" % self.rd(op)
        d = ops[0]
        if m in ("movd", "movq"):
            if self.ismm(d):
                v = rd64(ops[1]) if m == "movq" or self.ismm(ops[1]) else "(uint64_t)(uint32_t)%s" % self.rd(ops[1], 4)
                e("%s = %s;" % (mm(d), v))
            elif m == "movd": e(self.wr(d, "(uint32_t)%s" % mm(ops[1]), 4))
            else: e(self.wr(d, mm(ops[1]), 8))
            return True
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
        raise Unsupported("mmx " + m)

    def vec(self, i, m, ops):
        if not ops or not self.isx(ops[0]):
            if m == "pextrw" and len(ops) == 3 and self.isx(ops[1]):
                self.e(self.wr(ops[0], "(uint32_t)%s.w[%d]" % (self.xmm(ops[1]), ops[2].imm & 7), 4)); return True
            if m in ("pextrd", "pextrq", "pextrb", "extractps") and len(ops) == 3 and self.isx(ops[1]):
                f, n = {"pextrd": ("u", 4), "extractps": ("u", 4), "pextrq": ("q", 2), "pextrb": ("b", 16)}[m]
                self.e(self.wr(ops[0], "%s.%s[%d]" % (self.xmm(ops[1]), f, ops[2].imm % n))); return True
            if m in ("movss", "movsd", "movaps", "movups") : return False
            if m[0] == "p" or m in ("movq2dq",): raise Unsupported("mmx " + m)
            return False
        e = self.e
        D = self.xmm(ops[0])
        def S_(op):
            if self.isx(op): return self.xmm(op)
            if op.type == X.X86_OP_MEM:
                if op.size == 16: return "rdx(%s)" % self.ea(op)
                return "({ XMM t_ = {0}; t_.q[0] = %s; t_; })" % self.rd(op)
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
            cond = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "a != a || b != b", "neq": "!(a == b)",
                    "nlt": "!(a < b)", "nle": "!(a <= b)", "ord": "a == a && b == b"}[mf.group(1)]
            vcond = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "(a != a) | (b != b)", "neq": "~(a == b)",
                     "nlt": "~(a < b)", "nle": "~(a <= b)", "ord": "(a == a) & (b == b)"}[mf.group(1)]
            if mf.group(2) == "ps": e("{ XMM s_ = %s, d_ = %s; v4f a = d_.vf, b = s_.vf; d_.vi = (v4i)(%s); %s = d_; }" % (src, D, vcond, D))
            else: e("{ XMM s_ = %s, d_ = %s; v2d a = d_.vd, b = s_.vd; d_.vl = (v2l)(%s); %s = d_; }" % (src, D, vcond, D))
            return True
        msh = re.match(r"ps(ll|rl|ra)(w|d|q)$", m)
        if msh:
            kind, w = msh.groups()
            fl, n, bits = {"w": ("w", 8, 16), "d": ("u", 4, 32), "q": ("q", 2, 64)}[w]
            if imm is not None:   # whole-vector shift by a constant
                vf = {"w": "vw", "d": "vu", "q": "vq"}[w]; sv = {"w": "vh", "d": "vi", "q": "vl"}[w]
                if kind == "ra": e("%s.%s = %s.%s >> %d;" % (D, sv, D, sv, min(imm, bits - 1)))
                elif imm >= bits: e("%s = (XMM){0};" % D)
                else: e("%s.%s = %s.%s %s %d;" % (D, vf, D, vf, "<<" if kind == "ll" else ">>", imm))
                return True
            cnt = "%du" % imm if imm is not None else "(%s).q[0]" % src
            if kind == "ll": ex = "c_ >= %d ? 0 : d_.%s[k] << c_" % (bits, fl)
            elif kind == "rl": ex = "c_ >= %d ? 0 : d_.%s[k] >> c_" % (bits, fl)
            else:
                sf = {"w": "h", "d": "i", "q": "l"}[w]
                ex = "(d_.%s[k] >> (c_ >= %d ? %d : c_))" % (sf, bits, bits - 1)
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
        if m in ("packsswb", "packuswb", "packssdw", "packusdw") and src:
            if m in ("packssdw", "packusdw"):
                lo, hi = ("-32768", "32767") if m == "packssdw" else ("0", "65535")
                e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 4; k++) { int32_t a = d_.i[k], b = s_.i[k]; r_.w[k] = (uint16_t)(a > %s ? %s : a < %s ? %s : a); r_.w[k + 4] = (uint16_t)(b > %s ? %s : b < %s ? %s : b); } %s = r_; }"
                  % (src, D, hi, hi, lo, lo, hi, hi, lo, lo, D))
            else:
                lo, hi = ("-128", "127") if m == "packsswb" else ("0", "255")
                e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 8; k++) { int a = d_.h[k], b = s_.h[k]; r_.b[k] = (uint8_t)(a > %s ? %s : a < %s ? %s : a); r_.b[k + 8] = (uint8_t)(b > %s ? %s : b < %s ? %s : b); } %s = r_; }"
                  % (src, D, hi, hi, lo, lo, hi, hi, lo, lo, D))
            return True
        if m == "pmuludq" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; r_.q[0] = (uint64_t)d_.u[0] * s_.u[0]; r_.q[1] = (uint64_t)d_.u[2] * s_.u[2]; %s = r_; }" % (src, D, D)); return True
        if m == "pmuldq" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; r_.l[0] = (int64_t)d_.i[0] * s_.i[0]; r_.l[1] = (int64_t)d_.i[2] * s_.i[2]; %s = r_; }" % (src, D, D)); return True
        if m == "pmaddubsw" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; for (int k = 0; k < 8; k++) { int t = d_.b[2*k] * s_.c[2*k] + d_.b[2*k+1] * s_.c[2*k+1]; r_.h[k] = (int16_t)(t > 32767 ? 32767 : t < -32768 ? -32768 : t); } %s = r_; }" % (src, D, D)); return True
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
            sel = [o + ((imm >> (2 * k)) & 3) for k in range(4)]
            idx = list(range(8)); idx[o:o + 4] = sel
            e("{ XMM s_ = %s; s_.vw = __builtin_shufflevector(s_.vw, s_.vw, %s); %s = s_; }" % (S_(ops[1]), ", ".join(map(str, idx)), D)); return True
        if m == "pinsrw" and imm is not None:
            v = self.rd(ops[1], 2) if ops[1].type == X.X86_OP_MEM else "(uint16_t)" + self.rd(ops[1])
            e("%s.w[%d] = %s;" % (D, imm & 7, v)); return True
        if m in ("pinsrb", "pinsrd", "pinsrq") and imm is not None:
            f, n, sz = {"pinsrb": ("b", 16, 1), "pinsrd": ("u", 4, 4), "pinsrq": ("q", 2, 8)}[m]
            v = self.rd(ops[1], sz) if ops[1].type == X.X86_OP_MEM else "(%s)%s" % (U[sz], self.rd(ops[1]))
            e("%s.%s[%d] = %s;" % (D, f, imm % n, v)); return True
        if m == "insertps" and imm is not None:
            v = "%s.f[%d]" % (self.xmm(ops[1]), (imm >> 6) & 3) if self.isx(ops[1]) else "rdf(%s)" % self.ea(ops[1])
            e("{ XMM d_ = %s; d_.f[%d] = %s; for (int k = 0; k < 4; k++) if (%d >> k & 1) d_.u[k] = 0; %s = d_; }" % (D, (imm >> 4) & 3, v, imm & 15, D)); return True
        if m in ("blendps", "blendpd", "pblendw") and imm is not None:
            f, n = {"blendps": ("u", 4), "blendpd": ("q", 2), "pblendw": ("w", 8)}[m]
            idx = ", ".join(str(n + k if imm >> k & 1 else k) for k in range(n))
            e("{ XMM s_ = %s, d_ = %s; d_.v%s = __builtin_shufflevector(d_.v%s, s_.v%s, %s); %s = d_; }" % (S_(ops[1]), D, f, f, f, idx, D)); return True
        if m in ("pmovsxdq", "pmovzxdq", "pmovsxwd", "pmovzxwd", "pmovsxbd", "pmovzxbd", "pmovsxbw", "pmovzxbw", "pmovsxwq", "pmovzxwq", "pmovsxbq", "pmovzxbq") and src:
            sf = m[4]; a, b = m[6], m[7]   # p m o v [s/z] x a b
            sw = {"b": 1, "w": 2, "d": 4}[a]; dw = {"w": 2, "d": 4, "q": 8}[b]; n = 16 // dw
            sl = {1: "c" if sf == "s" else "b", 2: "h" if sf == "s" else "w", 4: "i" if sf == "s" else "u"}[sw]
            dl = {2: "w", 4: "u", 8: "q"}[dw]
            e("{ XMM s_ = %s, r_; for (int k = 0; k < %d; k++) r_.%s[k] = (%s)s_.%s[k]; %s = r_; }" % (src, n, dl, U[dw] if sf == "z" else "%s)(%s" % (U[dw], S[dw]), sl, D)); return True
        if m == "movshdup" and src:
            e("{ XMM s_ = %s; s_.vu = __builtin_shufflevector(s_.vu, s_.vu, 1, 1, 3, 3); %s = s_; }" % (src, D)); return True
        if m == "movsldup" and src:
            e("{ XMM s_ = %s; s_.vu = __builtin_shufflevector(s_.vu, s_.vu, 0, 0, 2, 2); %s = s_; }" % (src, D)); return True
        if m == "movddup" and src:
            e("{ XMM s_ = %s; s_.vq = __builtin_shufflevector(s_.vq, s_.vq, 0, 0); %s = s_; }" % (src, D)); return True
        if m == "movlhps" and src: e("{ XMM s_ = %s, d_ = %s; d_.vq = __builtin_shufflevector(d_.vq, s_.vq, 0, 2); %s = d_; }" % (src, D, D)); return True
        if m == "movhlps" and src: e("{ XMM s_ = %s, d_ = %s; d_.vq = __builtin_shufflevector(d_.vq, s_.vq, 3, 1); %s = d_; }" % (src, D, D)); return True
        if m in ("haddps", "hsubps") and src:
            o = "+" if m == "haddps" else "-"
            e("{ XMM s_ = %s, d_ = %s; d_.vf = __builtin_shufflevector(d_.vf, s_.vf, 0, 2, 4, 6) %s __builtin_shufflevector(d_.vf, s_.vf, 1, 3, 5, 7); %s = d_; }" % (src, D, o, D)); return True
        if m in ("haddpd", "hsubpd") and src:
            o = "+" if m == "haddpd" else "-"
            e("{ XMM s_ = %s, d_ = %s, r_; r_.d[0] = d_.d[0] %s d_.d[1]; r_.d[1] = s_.d[0] %s s_.d[1]; %s = r_; }" % (src, D, o, o, D)); return True
        if m == "addsubps" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; r_.f[0] = d_.f[0] - s_.f[0]; r_.f[1] = d_.f[1] + s_.f[1]; r_.f[2] = d_.f[2] - s_.f[2]; r_.f[3] = d_.f[3] + s_.f[3]; %s = r_; }" % (src, D, D)); return True
        if m == "addsubpd" and src:
            e("{ XMM s_ = %s, d_ = %s, r_; r_.d[0] = d_.d[0] - s_.d[0]; r_.d[1] = d_.d[1] + s_.d[1]; %s = r_; }" % (src, D, D)); return True
        if m in ("dpps",) and imm is not None:
            e("{ XMM s_ = %s, d_ = %s, r_ = {0}; float t = 0; for (int k = 0; k < 4; k++) if (%d >> (4 + k) & 1) t += d_.f[k] * s_.f[k]; for (int k = 0; k < 4; k++) if (%d >> k & 1) r_.f[k] = t; %s = r_; }" % (S_(ops[1]), D, imm, imm, D)); return True
        conv = {
            "cvtps2pd": "r_.d[0] = s_.f[0]; r_.d[1] = s_.f[1];",
            "cvtpd2ps": "r_.q[1] = 0; r_.f[0] = (float)s_.d[0]; r_.f[1] = (float)s_.d[1];",
            "cvtdq2ps": "r_.vf = __builtin_convertvector(s_.vi, v4f);",
            "cvtdq2pd": "r_.d[0] = s_.i[0]; r_.d[1] = s_.i[1];",
            "cvtps2dq": "for (int k = 0; k < 4; k++) r_.i[k] = cvt_i32(sse_round(c, s_.f[k]));",
            # out of range or NaN -> 0x80000000 like SSE (convert only in-range lanes: out-of-range is poison)
            "cvttps2dq": "v4i bad_ = (s_.vf != s_.vf) | (s_.vf >= 2147483648.0f) | (s_.vf < -2147483648.0f); "
                         "r_.vi = VSEL(bad_, V4I_MIN, __builtin_convertvector(VSEL(bad_, (v4f){0}, s_.vf), v4i));",
            "cvtpd2dq": "r_.q[1] = 0; r_.i[0] = cvt_i32(sse_round(c, s_.d[0])); r_.i[1] = cvt_i32(sse_round(c, s_.d[1]));",
            "cvttpd2dq": "r_.q[1] = 0; r_.i[0] = cvt_i32(s_.d[0]); r_.i[1] = cvt_i32(s_.d[1]);",
        }
        if m in conv and src:
            e("{ XMM s_ = %s, r_; %s %s = r_; }" % (src, conv[m], D)); return True
        if m in ("blendvps", "blendvpd", "pblendvb") and src:   # SSE4.1: mask is xmm0
            sv, sh = {"blendvps": ("vi", 31), "blendvpd": ("vl", 63), "pblendvb": ("vc", 7)}[m]
            e("{ XMM s_ = %s, d_ = %s, m_ = C.xmm[0]; d_.%s = VSEL(m_.%s >> %d, s_.%s, d_.%s); %s = d_; }" % (src, D, sv, sv, sh, sv, sv, D)); return True
        if m == "ptest" and src:
            e("{ XMM s_ = %s, d_ = %s; zf = ((d_.q[0] & s_.q[0]) | (d_.q[1] & s_.q[1])) == 0; cf = ((~d_.q[0] & s_.q[0]) | (~d_.q[1] & s_.q[1])) == 0; of = sf = 0; }" % (src, D)); return True
        if m == "phminposuw" and src:   # SSE4.1: the smallest unsigned word and its index (the first, on a tie)
            e("{ XMM s_ = %s, r_ = {0}; int k_ = 0; for (int k = 1; k < 8; k++) if (s_.w[k] < s_.w[k_]) k_ = k; r_.w[0] = s_.w[k_]; r_.w[1] = (uint16_t)k_; %s = r_; }" % (src, D)); return True
        if m == "palignr" and imm is not None:
            e("{ XMM s_ = %s, d_ = %s, r_ = {0}; uint8_t t[32]; memcpy(t, &s_, 16); memcpy(t + 16, &d_, 16); for (int k = 0; k < 16; k++) r_.b[k] = k + %d < 32 ? t[k + %d] : 0; %s = r_; }" % (S_(ops[1]), D, imm, imm, D)); return True
        return False

    # -- x87 (rare: CRT math) --
    def x87(self, i, m, ops):
        e = self.e
        if not m.startswith("f"): return False
        def st(op): return "ST(%d)" % int(self.rn(op.reg)[2:].strip("()") or 0)
        if m in ("fld", "fild") and ops and ops[0].type == X.X86_OP_MEM:
            op = ops[0]
            if m == "fild": e("FPUSH(c, (double)(%s)%s);" % (S[op.size], self.rd(op)))
            else: e("FPUSH(c, %s);" % {4: "rdf(%s)", 8: "rdd(%s)", 10: "rd80(%s)"}[op.size] % self.ea(op))
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
            v = "trunc(ST(0))" if m == "fisttp" else "fpu_round(c, ST(0))"
            e("%s%s" % (self.wr(ops[0], "(%s)(%s)%s" % (U[ops[0].size], S[ops[0].size], v)), "" if m == "fist" else " FPOP(c);")); return True
        if m in ("fnstcw", "fstcw"): e(self.wr(ops[0], "C.fcw", 2)); return True
        if m == "fldcw": e("C.fcw = %s;" % self.rd(ops[0], 2)); return True
        if m in ("fnclex", "fninit"): return True
        if m == "fld1": e("FPUSH(c, 1.0);"); return True
        if m == "fldz": e("FPUSH(c, 0.0);"); return True
        ar = {"add": "a + b", "sub": "a - b", "subr": "b - a", "mul": "a * b", "div": "a / b", "divr": "b / a"}
        mm = re.match(r"f(i?)(add|subr|sub|mul|divr|div)(p?)$", m)
        if mm:
            isint, op, pop = mm.groups()
            if ops and ops[0].type == X.X86_OP_MEM:
                o = ops[0]
                b = "(double)(%s)%s" % (S[o.size], self.rd(o)) if isint else ("rdf(%s)" if o.size == 4 else "rdd(%s)") % self.ea(o)
                e("{ double a = ST(0), b = %s; ST(0) = %s; }" % (b, ar[op])); return True
            if len(ops) == 2:
                d, s_ = st(ops[0]), st(ops[1])
                e("{ double a = %s, b = %s; %s = %s;%s }" % (d, s_, d, ar[op], " FPOP(c);" if pop else "")); return True
            if not ops and pop:
                e("{ double a = ST(1), b = ST(0); ST(1) = %s; FPOP(c); }" % ar[op]); return True
        un = {"fchs": "-ST(0)", "fabs": "fabs(ST(0))", "fsqrt": "sqrt(ST(0))", "fsin": "sin(ST(0))", "fcos": "cos(ST(0))", "frndint": "fpu_round(c, ST(0))"}
        if m in un: e("ST(0) = %s;" % un[m]); return True
        if m == "fxch":
            o = st(ops[0]) if ops else "ST(1)"
            e("{ double t = ST(0); ST(0) = %s; %s = t; }" % (o, o)); return True
        if m == "fpatan": e("{ double v = atan2(ST(1), ST(0)); FPOP(c); ST(0) = v; }"); return True
        if m in ("fucomip", "fcomip", "fucomi", "fcomi"):
            e("{ double a = ST(0), b = %s; if (a != a || b != b) { zf = cf = 1; pr = 0; } else { zf = a == b; cf = a < b; pr = 1; } of = sf = 0;%s }"
              % (st(ops[1]) if len(ops) > 1 else "ST(1)", " FPOP(c);" if m.endswith("p") else "")); return True
        if m == "fstp" and not ops: e("FPOP(c);"); return True
        raise Unsupported(m)



RIPREL = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+|\d+)\]")
def lea_target(a, sz, opst):
    m = RIPREL.search(opst)
    if not m: return None
    d = int(m.group(2), 0)
    return a + sz + (d if m.group(1) == "+" else -d)

# ---------------- whole-program translation ----------------
class Translator:
    def __init__(self, path, base=None):
        self.pe = PE(path, base)
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.md.detail = True
        self.unsupported = collections.Counter()
        self.imports_used = set()
        self.noreturn = set()
        self.discover()

    def discover(self):
        """Function set: .pdata primaries + direct call targets + code pointers found through relocations."""
        pe = self.pe
        self.setjmp_conts = set(); self.setjmp_thunks = set()
        starts = set(pe.func_starts) | {pe.entry} | {v for v in pe.exports.values() if pe.is_code(v)}
        lite = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        code = pe.read_code()
        # pdata ranges (including chained parts) are known code
        covered = sorted((s, e) for s, (e, u) in pe.pdata.items())
        cov_lo = [s for s, e in covered]
        def inside(a):
            k = bisect.bisect_right(cov_lo, a) - 1
            return k >= 0 and covered[k][0] <= a < covered[k][1]
        calls = set()
        for s, (e, u) in pe.pdata.items():
            o = s - pe.text_lo
            for (a, sz, mn, opst) in lite.disasm_lite(code[o:e - pe.text_lo], s):
                if mn == "lea":
                    t = lea_target(a, sz, opst)
                    if t is not None and not (s <= t < e): calls.add(t)
                    continue
                if opst.startswith("0x") and (mn == "call" or mn[0] == "j"):
                    t = int(opst, 16)
                    if mn == "call" or not (s <= t < e):   # tail jumps leaving the function
                        calls.add(t)
        for t in calls:
            if pe.is_code(t) and (t in pe.pdata or not inside(t)):
                starts.add(t)
        # setjmp continuations: longjmp (runtime) re-enters the guest at the instruction after `call setjmp`, so each
        # such return address becomes a function of its own (the containing function also keeps that code inline).
        # Byte scan: the import thunks (jmp [slot]) have no .pdata, so a per-function sweep would not see them.
        sj_slots = {a for a, n in pe.iat.items() if n.split("!")[-1] in ("__intrinsic_setjmp", "_setjmp", "setjmp")}
        sj_targets = self.setjmp_thunks
        for i in range(len(code) - 6):
            if code[i] == 0xFF and code[i + 1] == 0x25:   # jmp qword ptr [rip+disp32]
                if pe.text_lo + i + 6 + struct.unpack_from("<i", code, i + 2)[0] in sj_slots: sj_targets.add(pe.text_lo + i)
        for i in range(len(code) - 5):
            if code[i] == 0xE8:   # call rel32
                t = pe.text_lo + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if t in sj_targets: starts.add(pe.text_lo + i + 5); self.setjmp_conts.add(pe.text_lo + i + 5)
            elif code[i] == 0xFF and code[i + 1] == 0x15:   # call qword ptr [rip+disp32]
                if pe.text_lo + i + 6 + struct.unpack_from("<i", code, i + 2)[0] in sj_slots: starts.add(pe.text_lo + i + 6); self.setjmp_conts.add(pe.text_lo + i + 6)
        if self.setjmp_conts: print("setjmp continuations: %d" % len(self.setjmp_conts))
        # C++ catch: a function with a __CxxFrameHandler3 try block keeps a host jmp_buf for its frame (rt_eh_site),
        # and the address each catch block (a funclet) returns, where the function goes on after the catch, becomes a
        # function of its own that the runtime enters there (runtime/cxxeh.c)
        self.eh_sites = set(); self.eh_conts = set()
        def u32s(fmt, a): return struct.unpack(fmt, pe.read(a, struct.calcsize(fmt)))
        for s, (h, hd) in pe.handler.items():
            try:
                fi = pe.base + u32s("<I", hd)[0]
                magic, maxst, umap, ntry, tmap = u32s("<IiIII", fi)
            except KeyError: continue
            if not (0x19930520 <= magic <= 0x19930522) or not (0 < ntry < 100000): continue
            self.eh_sites.add(s)
            for t in range(ntry):
                lo, hi, ch, nc, hs = u32s("<iiiII", pe.base + tmap + 20 * t)
                for k in range(min(nc, 1000)):
                    adj, pt, disp, haddr, dframe = u32s("<IIiII", pe.base + hs + 20 * k)
                    fa = pe.base + haddr
                    if fa not in pe.pdata: continue
                    fe = pe.pdata[fa][0]
                    for (a, sz, mn, opst) in lite.disasm_lite(code[fa - pe.text_lo:fe - pe.text_lo], fa):
                        if mn == "lea" and opst.startswith("rax,"):
                            t2 = lea_target(a, sz, opst)
                            if t2 is not None and pe.is_code(t2) and not (fa <= t2 < fe):
                                starts.add(t2); self.eh_conts.add(t2)
        if self.eh_sites: print("catching functions: %d, catch continuations: %d" % (len(self.eh_sites), len(self.eh_conts)))
        for slot in pe.relocs:
            try: v = struct.unpack("<Q", pe.read(slot, 8))[0]
            except KeyError: continue
            if pe.is_code(v) and (v in pe.pdata or not inside(v)):
                starts.add(v)
        # leaf functions (no .pdata) are scanned too, until no new targets appear
        scanned = set()
        while True:
            srt = sorted(starts)
            new = set()
            for k, s0 in enumerate(srt):
                if s0 in pe.pdata or s0 in scanned or not pe.is_code(s0): continue
                scanned.add(s0)
                nxt = srt[k + 1] if k + 1 < len(srt) else pe.text_hi
                k2 = bisect.bisect_right(cov_lo, s0)
                hi = min(nxt, cov_lo[k2] if k2 < len(cov_lo) else pe.text_hi, pe.code_end(s0))
                o = s0 - pe.text_lo
                for (a, sz, mn, opst) in lite.disasm_lite(code[o:hi - pe.text_lo], s0):
                    if mn == "lea":
                        t = lea_target(a, sz, opst)
                        # hi is only the next *known* start, so a target inside [s0, hi) may still be
                        # another function: take it when it sits on a boundary (after int3 padding or a ret)
                        boundary = t is not None and s0 < t < hi and code[t - pe.text_lo - 1] in (0xCC, 0xC3)
                        if t is not None and (not (s0 <= t < hi) or boundary) and pe.is_code(t) and t not in starts \
                                and (t in pe.pdata or not inside(t)):
                            new.add(t)
                        continue
                    if opst.startswith("0x") and (mn == "call" or mn[0] == "j"):
                        t = int(opst, 16)
                        if (mn == "call" or not (s0 <= t < hi)) and pe.is_code(t) and t not in starts \
                                and (t in pe.pdata or not inside(t)):
                            new.add(t)
                    if mn in ("ret", "int3") or (mn == "jmp" and opst.startswith("0x")): 
                        if mn == "int3": break
            if not new: break
            starts |= new
        starts = {s for s in starts if s not in pe.chain_parent}
        # Scanning junk (padding, embedded data) can yield "starts" in the middle of a real instruction.
        # Such a start would cut the previous function's region short (even to nothing), so drop any
        # non-.pdata start that the previous start's straight-line code runs across.
        TERM = ("ret", "jmp", "int3", "ud2", "hlt", "bnd ")
        JTAB_LOAD = re.compile(r"\[\w+ \+ \w+\*4 \+ (0x[0-9a-f]+)\]")
        while True:
            srt = sorted(starts); drop = set()
            for k in range(1, len(srt)):
                s, t = srt[k - 1], srt[k]
                if t in pe.pdata or s in drop: continue
                a, ended, cases, table = s, False, False, None
                for (x, sz, mn, opst) in lite.disasm_lite(pe.read(s, t - s + 16), s):
                    if x >= t: break
                    if cases and (mn == "nop" or (table is not None and x >= table)):
                        ended = True; break   # padding, or the jump table (data) after the case blocks
                    a = x + sz
                    tm = JTAB_LOAD.search(opst) if mn in ("mov", "movsxd") else None
                    if tm: table = pe.base + int(tm.group(1), 16)
                    if mn.startswith(TERM):
                        # an MSVC switch dispatch (mov r32,[B+idx*4+rva]; add r,B; jmp r) is followed by its case
                        # blocks, which often end in tail jumps or rets themselves: keep sweeping them, up to the table
                        if mn == "jmp" and opst in REG and table is not None and table > x: cases = True; continue
                        if cases and mn in ("jmp", "ret"): continue
                        ended = True; break
                if not ended and a > t: drop.add(t)
            if not drop: break
            print("dropped %d mid-instruction starts: %s" % (len(drop), " ".join("%x" % t for t in sorted(drop))))
            starts -= drop
        self.funcs = sorted(starts)
        fset = set(self.funcs)
        # regions: pdata primaries use their exact range (+ chained parts); others run to the next start
        parts = collections.defaultdict(list)
        for s, p in pe.chain_parent.items():
            parts[p].append((s, pe.pdata[s][0]))
        self.regions = {}
        for k, s in enumerate(self.funcs):
            nxt = min(self.funcs[k + 1] if k + 1 < len(self.funcs) else pe.text_hi, pe.code_end(s))
            if s in pe.pdata:
                hi = min(pe.pdata[s][0], nxt) if pe.pdata[s][0] > s else nxt
                self.regions[s] = [(s, hi)] + parts.get(s, [])
            else:
                # leaf function without unwind data: until the next known start or covered range
                k2 = bisect.bisect_right(cov_lo, s)
                cap = min(cov_lo[k2] if k2 < len(cov_lo) else pe.text_hi, pe.code_end(s))
                self.regions[s] = [(s, min(nxt, cap))]
        # a setjmp continuation is entered mid-function and branches anywhere in it (loops back to before itself):
        # give it the whole range of the function that contains it
        # (the continuation's own start must not cut the containing function's region short either)
        conts = getattr(self, "setjmp_conts", set()) | getattr(self, "eh_conts", set())
        if conts:
            allp = sorted(pe.pdata)
            for cont in conts:
                k = bisect.bisect_right(allp, cont) - 1
                if k < 0 or not (allp[k] <= cont < pe.pdata[allp[k]][0]): continue
                s0 = pe.chain_parent.get(allp[k], allp[k])   # a catch continuation may sit in a cold part
                if s0 == cont: continue
                full = [(s0, pe.pdata[s0][0])] + parts.get(s0, [])
                self.regions[s0] = full
                self.regions[cont] = list(full)
        self.funcs_set = fset
        print("functions: %d (pdata %d, extra %d)" % (len(self.funcs), len(pe.func_starts), len(self.funcs) - len(set(pe.func_starts) & fset)))


TR = None
NATIVE = {}   # guest function address -> native C replacement (from --native FILE: "addr name" lines)
PROBES = {}   # guest instruction address -> [C run before it] (from --probes FILE: "addr C code" lines; debugging)
PATCHES = {}  # guest instruction address -> C replacing its translation (from --patches FILE: "addr C code" lines)
def _work(chunk):
    TR.unsupported = collections.Counter(); TR.imports_used = set()
    out = []
    for a in chunk:
        if a in NATIVE:
            # replaced by a native implementation (runtime/native.c): the native code takes Win64 args from c and
            # sets rax; the wrapper does the guest `ret`. The translation is kept as F_<addr>__orig and runs instead
            # when RT_NATIVE_OFF lists the address (or "all"), for A/B testing a replacement.
            try:
                orig = FuncGen(TR, a).gen().replace("void F_%x(CPU *c) {" % a, "static void F_%x__orig(CPU *c) {" % a, 1)
            except Exception:
                orig = "static void F_%x__orig(CPU *c) { bad_insn(c, 0x%xull, \"no translation\"); }" % (a, a)
            out.append("void %s(CPU *c);\nint rt_native_enabled(uint64_t a);\n%s\nvoid F_%x(CPU *c) { static int on = -1; if (on < 0) on = rt_native_enabled(0x%xull);"
                       " if (on) { %s(c); c->rsp += 8; } else F_%x__orig(c); }" % (NATIVE[a], orig, a, a, NATIVE[a], a))
            continue
        try:
            g = FuncGen(TR, a)
            out.append(g.gen())
        except Exception as ex:
            out.append("void F_%x(CPU *c) { bad_insn(c, 0x%xull, \"translator error: %s\"); }" % (a, a, str(ex).replace('"', "'")[:80]))
            TR.unsupported["<error>"] += 1
    return out, TR.unsupported, TR.imports_used


def write_if_changed(path, text):
    """Leave unchanged generated files alone so make only rebuilds what changed."""
    try:
        with open(path) as f:
            if f.read() == text: return
    except FileNotFoundError:
        pass
    with open(path, "w") as f: f.write(text)


def write_module_tables(outdir, module, pe, allimp):
    """A DLL: the same tables, file-local, behind one GModule that registers itself at startup."""
    m = cname(module)
    with open(os.path.join(outdir, "tables.c"), "w") as f:
        f.write('#include "cpu.h"\n#include "tables.h"\n#include "funcs.h"\n')
        f.write("static const GFunc funcs[] = {\n")
        f.write("".join("  {0x%xull, F_%x},\n" % (a, a) for a in sorted(TR.funcs_set)))
        f.write("};\n")
        for n in allimp:
            f.write('__attribute__((weak)) void I_%s(CPU *c) { unimpl_import(c, "%s"); }\n' % (cname(n), n))
        f.write("static const GImport imports[] = {\n")
        f.write("".join('  {0x%xull, "%s", I_%s},\n' % (a, n, cname(n)) for a, n in sorted(pe.iat.items())))
        f.write("  {0, 0, 0}\n};\n")
        f.write("static const GSection sections[] = {\n")
        f.write("".join('  {"%s", 0x%xull, 0x%x, 0x%x, 0x%x, 0x%x},\n' % s for s in pe.sections))
        f.write("};\n")
        # relocated slots: the loader adds `delta` to these after reading the file (only when rebased)
        rel = pe.relocs if pe.delta else []
        f.write("static const uint64_t relocs[] = {\n%s  0\n};\n" % "".join("  0x%xull,\n" % r for r in rel))
        f.write('const GModule gmod_%s = { "%s", funcs, %d, imports, %d, sections, %d, 0x%xull, 0x%xull, 0x%xull, relocs, %d, %dll };\n'
                % (m, module.lower(), len(TR.funcs_set), len(pe.iat), len(pe.sections), pe.base, pe.size, pe.entry, len(rel), pe.delta))
        if pe.tls:   # static TLS: the runtime assigns the index and gives every thread a copy of the template
            t = pe.tls
            f.write("void rt_register_module_tls(const GModule *m, uint64_t start, uint64_t end, uint64_t index, uint32_t zero);\n")
            f.write("__attribute__((constructor)) static void register_tls(void) { rt_register_module_tls(&gmod_%s, 0x%xull, 0x%xull, 0x%xull, %d); }\n"
                    % (m, t["start"], t["end"], t["index"], t["zero"]))
        # exports called through another module's import table (I_<dll>_dll_<name>): load the DLL on first use, then run the code
        dll = module.lower() + ".dll"
        for name, addr in sorted(pe.exports.items()):
            if name.startswith("#"): continue
            f.write("void I_%s(CPU *c) { rt_module_call(c, &gmod_%s, 0x%xull); }\n" % (cname(dll + "!" + name), m, addr))
        f.write("__attribute__((constructor)) static void register_module(void) { rt_register_module(&gmod_%s); }\n" % m)


def main():
    global TR
    path, outdir = sys.argv[1], sys.argv[2]
    jobs = os.cpu_count()
    only = None
    module = sys.argv[sys.argv.index("--module") + 1] if "--module" in sys.argv else None
    if "--only" in sys.argv:
        only = [int(x, 16) for x in sys.argv[sys.argv.index("--only") + 1].split(",")]
    rebase = int(sys.argv[sys.argv.index("--rebase") + 1], 16) if "--rebase" in sys.argv else None
    if "--patches" in sys.argv:
        for line in open(sys.argv[sys.argv.index("--patches") + 1]):
            line = line.split("#")[0].strip()
            if line: a, code = line.split(None, 1); PATCHES[int(a, 16)] = code
    if "--probes" in sys.argv:
        for line in open(sys.argv[sys.argv.index("--probes") + 1]):
            line = line.strip()
            if line and not line.startswith("#"): a, code = line.split(None, 1); PROBES.setdefault(int(a, 16), []).append(code)
    if "--native" in sys.argv:
        for line in open(sys.argv[sys.argv.index("--native") + 1]):
            line = line.split("#")[0].split()
            if line: NATIVE[int(line[0], 16)] = line[1]
    TR = Translator(path, rebase)
    TR.funcs_set = set(TR.funcs)
    TR.funcs = TR.funcs_set   # membership tests in FuncGen
    order = sorted(TR.funcs_set) if not only else only
    os.makedirs(outdir, exist_ok=True)
    stale = {f for f in os.listdir(outdir) if f.startswith("code_") and f.endswith(".c")}
    per = 300
    chunks = [order[k:k + per] for k in range(0, len(order), per)]
    unsup = collections.Counter(); imps = set()
    with mp.get_context("fork").Pool(jobs) as pool:
        for n, (bodies, u, im) in enumerate(pool.imap(_work, chunks)):
            unsup.update(u); imps |= im
            name = "code_%04d.c" % n
            stale.discard(name)
            write_if_changed(os.path.join(outdir, name), '#include "cpu.h"\n#include "funcs.h"\n#pragma clang diagnostic ignored "-Wunused-label"\n'
                             + "\n\n".join(bodies) + "\n")
    for f in stale: os.remove(os.path.join(outdir, f))
    # unsupported counts from workers are cumulative per worker process; report the max view
    pe = TR.pe
    allimp = sorted(set(pe.iat.values()))
    with open(os.path.join(outdir, "funcs.h"), "w") as f:
        f.write("#pragma once\n")
        # setjmp sites: the host setjmp runs in the translated caller's frame; longjmp (runtime) restores the guest
        # registers saved here and jumps back, and the site then returns its value in rax
        f.write("#include <setjmp.h>\njmp_buf *rt_sj_prepare(CPU *c);\nvoid rt_sj_resumed(CPU *c);\n"
                "#define rt_setjmp_site(c) do { if (setjmp(*rt_sj_prepare(c))) rt_sj_resumed(c); } while (0)\n")
        # catch sites: a function with a try block, entered again here when one of its catch blocks has run; it then
        # finishes in the catch continuation, which returns for it (runtime/cxxeh.c)
        f.write("jmp_buf *rt_eh_prepare(CPU *c);\nvoid rt_eh_resumed(CPU *c);\n"
                "#define rt_eh_site(c) do { if (_setjmp(*rt_eh_prepare(c))) { rt_eh_resumed(c); return; } } while (0)\n")
        f.write("".join("void F_%x(CPU *c);\n" % a for a in sorted(TR.funcs_set)))
        f.write("".join("void I_%s(CPU *c);\n" % cname(n) for n in allimp))
    if module:
        write_module_tables(outdir, module, pe, allimp)
        print("translated %d functions (module %s), %d imports referenced" % (len(order), module, len(imps)))
        print("UNSUPPORTED:", dict(unsup.most_common(60)))
        return
    with open(os.path.join(outdir, "tables.c"), "w") as f:
        f.write('#include "cpu.h"\n#include "tables.h"\n#include "funcs.h"\n')
        f.write("const GFunc gfuncs[] = {\n")
        f.write("".join("  {0x%xull, F_%x},\n" % (a, a) for a in sorted(TR.funcs_set)))
        f.write("};\nconst int ngfuncs = %d;\n" % len(TR.funcs_set))
        for n in allimp:
            f.write('__attribute__((weak)) void I_%s(CPU *c) { unimpl_import(c, "%s"); }\n' % (cname(n), n))
        f.write("const GImport gimports[] = {\n")
        f.write("".join('  {0x%xull, "%s", I_%s},\n' % (a, n, cname(n)) for a, n in sorted(pe.iat.items())))
        f.write("};\nconst int ngimports = %d;\n" % len(pe.iat))
        f.write("const GSection gsections[] = {\n")
        f.write("".join('  {"%s", 0x%xull, 0x%x, 0x%x, 0x%x, 0x%x},\n' % s for s in pe.sections))
        f.write("};\nconst int ngsections = %d;\n" % len(pe.sections))
        f.write("const uint64_t gimage_base = 0x%xull, gimage_size = 0x%xull, gentry = 0x%xull;\n" % (pe.base, pe.size, pe.entry))
        t = pe.tls or dict(start=0, end=0, index=0, callbacks=[], zero=0)
        f.write("const uint64_t gtls_start = 0x%xull, gtls_end = 0x%xull, gtls_index = 0x%xull;\n" % (t["start"], t["end"], t["index"]))
    print("translated %d functions (%d native), %d imports referenced" % (len(order), len(NATIVE), len(imps)))
    print("UNSUPPORTED:", dict(unsup.most_common(60)))


if __name__ == "__main__":
    main()
