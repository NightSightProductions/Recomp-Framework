#!/usr/bin/env python3
"""Differential test of the win32 translator's x87 code (w32_fuzz.py skips x87: its state can't be set from
registers). Every x87 opcode (D8-DF) is tested in register form (st(1), st(2)) and in memory form ([esi+0x18]):

    movsd [esi], xmm0 ; movsd [esi+8], xmm1 ; movsd [esi+0x10], xmm2 ; movsd [esi+0x18], xmm3
    fld qword [esi+0x10] ; fld qword [esi+8] ; fld qword [esi]       ; st0..st2 = xmm0, xmm1, xmm2
    <insn>
    fnstsw ax ; fstp qword [edi] ; fstp qword [edi+8] ; fstp qword [edi+0x10] ; fstp qword [edi+0x18]

natively under Rosetta and translated; the stored stack, and the status word's condition codes and stack top in ax,
must match. usage: w32_x87_fuzz.py GAME_EXE [--trials N]
"""
import os, sys, random, struct, subprocess, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import w32_fuzz as F
import capstone as cs

PRE = bytes.fromhex("f20f1106" "f20f114e08" "f20f115610" "f20f115e18" "dd4610" "dd4608" "dd06")
POST = bytes.fromhex("dfe0" "dd1f" "dd5f08" "dd5f10" "dd5f18")
SKIP_REG = {"fstp1", "fst", "fstp", "fnop", "fstpnce", "ffree", "ffreep", "fdecstp", "fincstp", "fninit", "fnclex"}

def main():
    trials = int(sys.argv[sys.argv.index("--trials") + 1]) if "--trials" in sys.argv else 32
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32); md.detail = True
    tests = []
    seen = set()
    for op in range(0xD8, 0xE0):
        for reg in range(8):
            for form in ("r1", "r2", "m"):
                b = bytes([op, (0xC0 | reg << 3 | (1 if form == "r1" else 2)) if form != "m" else (0x46 | reg << 3)]) + (b"\x18" if form == "m" else b"")
                i = next(md.disasm(b, 0), None)
                if not i or i.size != len(b): continue
                m = i.mnemonic
                if m in SKIP_REG or m.startswith(("fn", "fld", "fst", "fx", "fb", "fist", "fisttp")) and m not in ("fld", "fxch"):
                    if m not in ("fxch",): continue
                if m in ("fld", "fldcw", "fldenv", "frstor", "fsave", "fnsave", "fldt") : continue
                text = m + " " + i.op_str
                if text in seen: continue
                seen.add(text)
                tests.append((("x87", m), PRE + b + POST, "ebx", {("b", "esi"), ("b", "edi")}, text))
    # plus the no-operand forms seen in real code
    for b in (b"\xd9\xe0", b"\xd9\xe1", b"\xd9\xe4", b"\xd9\xe8", b"\xd9\xee", b"\xd9\xfa", b"\xd9\xfc", b"\xde\xc9", b"\xde\xe9",
              b"\xde\xe1", b"\xde\xf9", b"\xde\xf1", b"\xde\xd9", b"\xd9\xc9", b"\xdd\xd9", b"\xdd\xe1", b"\xdd\xe9", b"\xda\xe9"):
        i = next(md.disasm(b, 0))
        tests.append((("x87", i.mnemonic), PRE + b + POST, "ebx", {("b", "esi"), ("b", "edi")}, i.mnemonic + " " + i.op_str))
    print("%d x87 tests x %d trials" % (len(tests), trials))
    # the snippet is longer than a slot's default: give each 64 bytes (PRE 33 + insn 3 + POST 13 + pushf/pop/ret 3)
    os.makedirs(F.OUT, exist_ok=True)
    code = bytearray()
    for _, b, spare, _, _ in tests:
        snip = b + b"\x9c" + F.POP[spare] + b"\xc3"
        assert len(snip) <= F.SLOT, len(snip)
        code += snip + b"\xcc" * (F.SLOT - len(snip))
    addrs = [F.CODE_BASE + F.SLOT * k for k in range(len(tests))]
    ftr = F.FakeTR(F.FakePE(code), md, addrs)
    F.R.TR = ftr
    bodies = []
    for a in addrs:
        try: bodies.append(F.R.FuncGen(ftr, a).gen())
        except Exception as ex: bodies.append('void F_%x(CPU *c) { bad_insn(c, 0x%xu, "translator error"); }' % (a, a))
    with open(os.path.join(F.OUT, "arm_code.c"), "w") as f:
        f.write('#include "cpu32.h"\n#pragma clang diagnostic ignored "-Wunused-label"\n')
        f.write("".join("void F_%x(CPU *c);\n" % a for a in addrs))
        f.write("\n\n".join(bodies))
        f.write("\nconst gfn fuzz_fns[] = {%s};\nconst int fuzz_n = %d;\n" % (",".join("F_%x" % a for a in addrs), len(addrs)))
    with open(os.path.join(F.OUT, "code.bin"), "wb") as f: f.write(code)
    rnd = random.Random(99)
    def dval():
        r = rnd.random()
        if r < 0.15: return rnd.choice([0.0, -0.0, 1.0, -1.0, 0.5, 2.0, 3.0, -2.5, 100.0, 1e-3])
        if r < 0.6: return rnd.uniform(-100, 100)
        return float(rnd.randint(-50, 50))
    with open(os.path.join(F.OUT, "inputs.bin"), "wb") as f:
        f.write(struct.pack("<III", len(tests), trials, F.SLOT))
        for key, b, spare, _, text in tests:
            for _ in range(trials):
                g = [rnd.getrandbits(32) for _ in range(16)]
                g[F.GPRS.index("esi")] = F.BUF_MID - 0x100
                g[F.GPRS.index("edi")] = F.BUF_MID + 0x100
                g[4] = 0
                x = b"".join(struct.pack("<2d", dval(), dval()) for _ in range(16))
                # memory operands of the integer forms read [esi+0x18] as int16/int32: make them small integers
                if text.startswith("fi"): x = x[:48] + struct.pack("<ii", rnd.randint(-40, 40), 0) + x[56:]
                f.write(struct.pack("<16Q", *g) + x + struct.pack("<I", rnd.getrandbits(32)))
    harness = os.path.join(HERE, "w32_fuzz_harness.c")
    def run(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode: print(" ".join(cmd)); print(r.stdout[-3000:], r.stderr[-3000:]); sys.exit(1)
    run(["clang", "-O1", "-arch", "x86_64", "-DX86", "-Wl,-pagezero_size,0x1000", "-Wl,-image_base,0x100000000",
         harness, os.path.join(F.FW, "tests", "fuzz_x86.S"), "-o", os.path.join(F.OUT, "x86h")])
    run(["clang", "-O1", "-arch", "arm64", "-I" + os.path.join(F.W32, "runtime"), "-w", harness, os.path.join(F.OUT, "arm_code.c"), "-o", os.path.join(F.OUT, "armh")])
    for side in ("x86h", "armh"):
        with open(os.path.join(F.OUT, side + ".out"), "wb") as o:
            r = subprocess.run(["arch", "-x86_64" if side == "x86h" else "-arm64", os.path.join(F.OUT, side), F.OUT], stdout=o, stderr=subprocess.PIPE)
            if r.returncode: print(side, "failed:", r.stderr.decode()[-2000:]); sys.exit(1)
    rec = 16 * 8 + 16 * 16 + 8 + 4 + 64 * 5
    a, bb = open(os.path.join(F.OUT, "x86h.out"), "rb").read(), open(os.path.join(F.OUT, "armh.out"), "rb").read()
    WIN = 64 << 10
    EDI = (F.BUF_MID + 0x100) - (F.BUF_MID - WIN // 2)        # edi's offset in the harness's compared window
    def fill(seed):                                           # the harness's xorshift fill of the window
        s_ = (seed | 1) & 0xFFFFFFFF; out = bytearray(WIN)
        for i in range(WIN):
            s_ ^= (s_ << 13) & 0xFFFFFFFF; s_ ^= s_ >> 17; s_ ^= (s_ << 5) & 0xFFFFFFFF; out[i] = s_ & 0xFF
        return out
    # seeds, in input order
    inp = open(os.path.join(F.OUT, "inputs.bin"), "rb").read()[12:]
    recin = 16 * 8 + 256 + 4
    def depth(m):   # values left on the stack after the instruction (3 loaded)
        if m in ("fcompp", "fucompp"): return 1
        if m.endswith("p") or m.endswith("pi") or m in ("fstp",): return 2
        return 3
    def stored(r, seed, n):
        w = fill(seed)
        cnt = struct.unpack_from("<I", r, 392)[0]
        for k in range(min(cnt, 64)):
            off, v = struct.unpack_from("<IB", r, 396 + 5 * k)
            if off < WIN: w[off] = v
        return [struct.unpack_from("<d", w, EDI + 8 * j)[0] for j in range(n)]
    def close(x, y):
        if x != x and y != y: return True
        return x == y or abs(x - y) <= 1e-9 * max(abs(x), abs(y), 1e-300)
    bad = collections.OrderedDict()
    for t, (key, _, _, _, text) in enumerate(tests):
        n = depth(key[1])
        for k in range(trials):
            o = (t * trials + k) * rec
            ra, rb = a[o:o + rec], bb[o:o + rec]
            if struct.unpack_from("<I", ra, 392)[0] == 0xFFFFFFFF: continue
            seed = struct.unpack_from("<I", inp, (t * trials + k) * recin + 128 + 256)[0]
            # C0 C2 C3 only matter after compares; TOP always
            cmpinsn = "com" in key[1] or key[1] in ("ftst", "fxam")
            mask = 0x4500 if cmpinsn else 0   # C0 C2 C3 (Rosetta reports an unreliable TOP)
            sa, sb = struct.unpack_from("<Q", ra, 0)[0] & mask, struct.unpack_from("<Q", rb, 0)[0] & mask
            va, vb = stored(ra, seed, n), stored(rb, seed, n)
            if sa != sb or not all(close(x, y) for x, y in zip(va, vb)):
                x = struct.unpack_from("<4d", inp, (t * trials + k) * recin + 128)
                bad.setdefault(text, []).append("in st0..2=%g,%g,%g m=%g | fsw x86=%04x arm=%04x | out x86=%s arm=%s" % (
                    x[0], x[2], x[3] if False else struct.unpack_from("<d", inp, (t * trials + k) * recin + 128 + 32)[0],
                    struct.unpack_from("<d", inp, (t * trials + k) * recin + 128 + 48)[0], sa, sb,
                    ",".join("%g" % v for v in va), ",".join("%g" % v for v in vb)))
    print("%d of %d x87 tests differ" % (len(bad), len(tests)))
    for text, d in bad.items(): print("  %-28s %2d/%d  %s" % (text, len(d), trials, d[0][:170]))

if __name__ == "__main__":
    main()
