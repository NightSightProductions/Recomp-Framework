#!/usr/bin/env python3
"""Differential test of the win32 (i386) translator, one instruction at a time (the 32-bit counterpart of
tests/insn_fuzz.py).

Every distinct instruction form of a 32-bit PE that encodes the same way in 64-bit mode (register and [base+index]
memory forms; not the 1-byte inc/dec, push/pop, absolute [disp32] -- RIP-relative in 64-bit mode --, stack or
segment operations) goes into `insn; pushf; pop <spare>; ret`. The same bytes run with the same random registers,
XMM registers and memory:
  - natively, under Rosetta, in an x86_64 harness whose data buffer sits below 4 GiB (small __PAGEZERO), so 32-bit
    register values address it exactly as they do in the guest, and
  - translated by recomp_w32.py and compiled for arm64 against cpu32.h, the buffer at GUEST_BASE + the same address.
The low 32 bits of eax..edi, xmm0-7, the flags (CF PF ZF SF OF) and the changed memory are compared.

usage: w32_fuzz.py GAME_EXE [--trials N] [--only mnemonic,...] [--max-forms N]
"""
import os, sys, re, random, struct, subprocess, collections

HERE = os.path.dirname(os.path.abspath(__file__))
W32 = os.path.dirname(HERE)
FW = os.path.dirname(W32)
sys.path.insert(0, os.path.join(W32, "tools"))
import capstone as cs
from capstone import x86 as X
import recomp_w32 as R

OUT = os.path.join(os.getcwd(), "build", "w32fuzz")
CODE_BASE = 0x00500000          # where the snippets pretend to live (guest addresses)
SLOT = 64
BUF = 0x20000000                # data buffer, the same 32-bit address on both sides
BUF_SIZE = 1 << 20
BUF_MID = BUF + BUF_SIZE // 2
GPRS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
POP = {"ebx": b"\x5b", "ebp": b"\x5d", "esi": b"\x5e", "edi": b"\x5f", "ecx": b"\x59", "edx": b"\x5a"}
SKIP = {"push", "pop", "pushal", "popal", "pushfd", "popfd", "leave", "enter", "cpuid", "rdtsc", "pause", "nop", "int3",
        "ud2", "hlt", "lfence", "sfence", "mfence", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta", "prefetchw",
        "clflush", "stmxcsr", "ldmxcsr", "lea", "int", "into", "cld", "std", "sti", "cli", "inc", "dec", "bound", "arpl",
        "aaa", "aas", "aam", "aad", "daa", "das", "salc", "xlatb", "les", "lds", "lfs", "lgs", "lss", "fwait", "wait",
        "in", "out", "insb", "insd", "insw", "outsb", "outsd", "outsw", "iretd", "retf", "lahf", "sahf", "emms"}

def gpr(name):
    r = R.REG.get(name.lower())
    return r[0] if r else None

def collect(pe, md, starts, max_per=2):
    forms = collections.OrderedDict()
    for s in starts:
        try: data = pe.read(s, min(0x600, pe.code_end(s) - s))
        except (KeyError, StopIteration): continue
        for i in md.disasm(data, s):
            m = i.mnemonic
            if m in ("ret", "jmp", "int3"): break
            if i.group(cs.CS_GRP_JUMP) or i.group(cs.CS_GRP_CALL) or i.group(cs.CS_GRP_RET) or i.group(cs.CS_GRP_INT): continue
            if m in SKIP or m.startswith(("v", "f", "rep", "loop", "lock", "j", "cmov")) and not m.startswith("cmov"): continue
            if re.match(r"(movs|stos|lods|cmps|scas)[bwd]$", m) and not any(op.type == X.X86_OP_REG and i.reg_name(op.reg).startswith("xmm") for op in i.operands): continue
            if i.bytes[0] in range(0x40, 0x50) or i.bytes[0] == 0x67: continue   # REX in 64-bit mode / address size
            regs_read, regs_write = i.regs_access()
            touched = {i.reg_name(r) for r in list(regs_read) + list(regs_write)}
            if touched & {"esp", "sp", "eip", "fs", "gs", "cs", "ds", "es", "ss"}: continue
            ok, key = True, [m]
            for op in i.operands:
                if op.type == X.X86_OP_MEM:
                    if op.mem.segment != 0 or not op.mem.base or op.mem.base == op.mem.index or abs(op.mem.disp) > 0x40000: ok = False; break
                    key.append("m%d%s" % (op.size, "i" if op.mem.index else ""))
                elif op.type == X.X86_OP_REG:
                    rn = i.reg_name(op.reg)
                    if rn.startswith(("st", "mm", "ymm")) or (rn not in R.REG and not rn.startswith("xmm")): ok = False; break
                    key.append(("x" if rn.startswith("xmm") else "r") + str(op.size) + ("h" if rn in ("ah", "bh", "ch", "dh") else ""))
                else:
                    key.append("i%d" % op.size)
            if not ok: continue
            lst = forms.setdefault(tuple(key), [])
            if len(lst) < max_per and not any(b == bytes(i.bytes) for b, _ in lst): lst.append((bytes(i.bytes), i))
    return forms

class FakePE:
    def __init__(self, code): self.code, self.base, self.size, self.iat, self.sections = code, CODE_BASE, len(code), {}, []
    def read(self, a, n): o = a - CODE_BASE; return bytes(self.code[o:o + n])
    def is_code(self, a): return CODE_BASE <= a < CODE_BASE + len(self.code)
    def code_end(self, a): return CODE_BASE + len(self.code)
    text_lo = CODE_BASE
    @property
    def text_hi(self): return CODE_BASE + len(self.code)

class FakeTR:
    def __init__(self, pe, md, addrs):
        self.pe, self.md = pe, md
        self.funcs = self.strong = set(addrs)
        self.unsupported, self.imports_used, self.noreturn = collections.Counter(), set(), set()

def main():
    exe = sys.argv[1]
    trials = int(sys.argv[sys.argv.index("--trials") + 1]) if "--trials" in sys.argv else 24
    only = set(sys.argv[sys.argv.index("--only") + 1].split(",")) if "--only" in sys.argv else None
    max_forms = int(sys.argv[sys.argv.index("--max-forms") + 1]) if "--max-forms" in sys.argv else 100000
    os.makedirs(OUT, exist_ok=True)
    tr = R.Translator(exe)
    md32 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32); md32.detail = True
    forms = collect(tr.pe, md32, sorted(tr.funcs))
    tests = []
    for key, samples in forms.items():
        if only and key[0] not in only: continue
        for b, i in samples:
            regs_read, regs_write = i.regs_access()
            touched = {gpr(i.reg_name(r)) for r in list(regs_read) + list(regs_write)} - {None}
            for op in i.operands:
                if op.type == X.X86_OP_REG and gpr(i.reg_name(op.reg)): touched.add(gpr(i.reg_name(op.reg)))
                if op.type == X.X86_OP_MEM:
                    if op.mem.base: touched.add(gpr(i.reg_name(op.mem.base)))
                    if op.mem.index: touched.add(gpr(i.reg_name(op.mem.index)))
            spare = next((r for r in POP if r not in touched), None)
            if not spare: continue
            addr_regs = set()
            for op in i.operands:
                if op.type == X.X86_OP_MEM:
                    addr_regs.add(("b", gpr(i.reg_name(op.mem.base))))
                    if op.mem.index: addr_regs.add(("i", gpr(i.reg_name(op.mem.index))))
            if any(r is None for _, r in addr_regs): continue
            tests.append((key, b, spare, addr_regs, i.mnemonic + " " + i.op_str))
        if len(tests) >= max_forms: break
    print("%d instruction forms, %d tests x %d trials" % (len(forms), len(tests), trials))

    code = bytearray()
    for _, b, spare, _, _ in tests:
        snip = b + b"\x9c" + POP[spare] + b"\xc3"
        code += snip + b"\xcc" * (SLOT - len(snip))
    addrs = [CODE_BASE + SLOT * k for k in range(len(tests))]

    ftr = FakeTR(FakePE(code), md32, addrs)
    R.TR = ftr
    bodies = []
    for a in addrs:
        try: bodies.append(R.FuncGen(ftr, a).gen())
        except Exception as ex: bodies.append('void F_%x(CPU *c) { bad_insn(c, 0x%xu, "translator error"); }' % (a, a))
    with open(os.path.join(OUT, "arm_code.c"), "w") as f:
        f.write('#include "cpu32.h"\n#pragma clang diagnostic ignored "-Wunused-label"\n')
        f.write("".join("void F_%x(CPU *c);\n" % a for a in addrs))
        f.write("\n\n".join(bodies))
        f.write("\nconst gfn fuzz_fns[] = {%s};\nconst int fuzz_n = %d;\n" % (",".join("F_%x" % a for a in addrs), len(addrs)))
    with open(os.path.join(OUT, "code.bin"), "wb") as f: f.write(code)

    rnd = random.Random(1234)
    def fval():
        r = rnd.random()
        if r < 0.1: return rnd.choice([0.0, -0.0, 1.0, -1.0, 0.5, 2.0, 1e-30, 65536.0, 2147483648.0, -2147483649.0, 1e10, 3.5, -2.5])
        if r < 0.55: return rnd.uniform(-1000, 1000)
        return rnd.uniform(-1, 1)
    def xmm_rand():
        k = rnd.random()
        if k < 0.4: return struct.pack("<4f", *[fval() for _ in range(4)])
        if k < 0.6: return struct.pack("<2d", fval(), fval())
        if k < 0.8: return bytes(rnd.getrandbits(8) for _ in range(16))
        return struct.pack("<4i", *[rnd.randint(-40000, 40000) for _ in range(4)])
    def gpr_rand():
        k = rnd.random()
        if k < 0.4: return rnd.getrandbits(32)
        if k < 0.65: return rnd.randint(0, 70)
        if k < 0.8: return rnd.choice([0, 1, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0xFFFF, 0x8000])
        return (-rnd.randint(1, 1000)) & 0xFFFFFFFF
    with open(os.path.join(OUT, "inputs.bin"), "wb") as f:
        f.write(struct.pack("<III", len(tests), trials, SLOT))
        for key, b, spare, addr_regs, text in tests:
            for _ in range(trials):
                g = [gpr_rand() for _ in range(16)]
                for kind, r in addr_regs:
                    idx = GPRS.index(r)
                    g[idx] = BUF_MID + rnd.randint(-64, 64) if kind == "b" else rnd.randint(0, 16)
                    if kind == "b" and any(k2 == "i" and r2 == r for k2, r2 in addr_regs): g[idx] = rnd.randint(0, 16)
                if key[0] in ("div", "idiv"):
                    g[0] = rnd.randint(0, 1 << 20); g[2] = 0
                    src = text.split(" ", 1)[1].strip() if " " in text else ""
                    rr = gpr(src) if src else None
                    if rr: g[GPRS.index(rr)] = rnd.randint(1, 1000)
                g[4] = 0
                x = b"".join(xmm_rand() for _ in range(16))
                f.write(struct.pack("<16Q", *g) + x + struct.pack("<I", rnd.getrandbits(32)))
    with open(os.path.join(OUT, "tests.txt"), "w") as f:
        for key, b, spare, _, text in tests: f.write("%s\t%s\t%s\n" % (" ".join(key), spare, text))

    harness = os.path.join(HERE, "w32_fuzz_harness.c")
    def run(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode: print(" ".join(cmd)); print(r.stdout[-3000:], r.stderr[-3000:]); sys.exit(1)
    run(["clang", "-O1", "-arch", "x86_64", "-DX86", "-Wl,-pagezero_size,0x1000", "-Wl,-image_base,0x100000000",
         harness, os.path.join(FW, "tests", "fuzz_x86.S"), "-o", os.path.join(OUT, "x86h")])
    run(["clang", "-O1", "-arch", "arm64", "-I" + os.path.join(W32, "runtime"), "-w", harness, os.path.join(OUT, "arm_code.c"), "-o", os.path.join(OUT, "armh")])
    for side in ("x86h", "armh"):
        with open(os.path.join(OUT, side + ".out"), "wb") as o:
            r = subprocess.run(["arch", "-x86_64" if side == "x86h" else "-arm64", os.path.join(OUT, side), OUT], stdout=o, stderr=subprocess.PIPE)
            if r.returncode: print(side, "failed:", r.stderr.decode()[-2000:]); sys.exit(1)
    compare(tests, trials)

FLAGS_MASK = 0x8c5
UNDEF = {"imul": 0xc4, "mul": 0xc4, "div": 0x8c5, "idiv": 0x8c5, "bsf": 0x885, "bsr": 0x885,
         "bt": 0x8c4, "bts": 0x8c4, "btr": 0x8c4, "btc": 0x8c4}
def undef_mask(text):
    m = text.split(" ")[0]
    if m in UNDEF: return UNDEF[m]
    if m in ("shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr", "shld", "shrd"):
        last = text.split(",")[-1].strip()
        try: n = int(last, 0)
        except ValueError: n = None
        return 0x800 if n != 1 else 0
    return 0

def compare(tests, trials):
    rec = 16 * 8 + 16 * 16 + 8 + 4 + 64 * 5
    a, b = open(os.path.join(OUT, "x86h.out"), "rb").read(), open(os.path.join(OUT, "armh.out"), "rb").read()
    bad = collections.OrderedDict()
    for t, (key, _, spare, _, text) in enumerate(tests):
        for k in range(trials):
            o = (t * trials + k) * rec
            ra, rb = a[o:o + rec], b[o:o + rec]
            if ra == rb: continue
            if struct.unpack_from("<I", ra, 392)[0] == 0xFFFFFFFF: continue
            ga, gb = struct.unpack_from("<16Q", ra), struct.unpack_from("<16Q", rb)
            diffs = []
            for r in range(8):
                if r == 4: continue
                va, vb = ga[r] & 0xFFFFFFFF, gb[r] & 0xFFFFFFFF
                if GPRS[r] == spare:
                    mask = FLAGS_MASK & ~undef_mask(text); va &= mask; vb &= mask; name = "flags"
                else: name = GPRS[r]
                if va != vb: diffs.append("%s x86=%x arm=%x" % (name, va, vb))
            for r in range(8):
                xa, xb = ra[128 + 16 * r:144 + 16 * r], rb[128 + 16 * r:144 + 16 * r]
                if xa != xb: diffs.append("xmm%d x86=%s arm=%s" % (r, xa.hex(), xb.hex()))
            if ra[384:] != rb[384:]: diffs.append("memory differs")
            if diffs: bad.setdefault(text, []).append(diffs)
    print("%d of %d tests differ" % (len(bad), len(tests)))
    for text, d in bad.items():
        print("  %-42s %2d/%d  %s" % (text[:42], len(d), trials, "; ".join(d[0])[:200]))
    print("by mnemonic:", dict(collections.Counter(t.split(" ")[0] for t in bad).most_common()))

if __name__ == "__main__":
    main()
