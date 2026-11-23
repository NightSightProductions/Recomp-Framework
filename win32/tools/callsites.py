#!/usr/bin/env python3
"""Map a COM call-site histogram (RT_COM_CALLSITES=1 writes <data dir>/com_callsites.txt: "count retaddr Class::Method")
to the guest functions making the calls, using the /*@addr*/ tags of the generated C.

usage: callsites.py com_callsites.txt GEN_DIR [--by-method]
  default:    per calling function, the methods it calls (sorted by total calls)
  --by-method per method, the functions that call it
"""
import os, re, sys, collections

def main():
    hist, gen = sys.argv[1], sys.argv[2]
    rows = []
    for ln in open(hist):
        p = ln.split()
        if len(p) == 3: rows.append((int(p[0]), int(p[1], 16), p[2]))
    # the call instruction ends at the return address: find the function whose body holds the instruction before it,
    # i.e. the one with a tag for an address < ret that is followed by a tag >= ret (or the call's own tag)
    want = {r for _, r, _ in rows}
    owner = {}
    fre, tre = re.compile(r"^void F_([0-9a-f]+)\(CPU \*c\) \{"), re.compile(r"/\*@([0-9a-f]+)\*/")
    for fn in sorted(os.listdir(gen)):
        if not fn.endswith(".c"): continue
        cur, prev = None, None
        for ln in open(os.path.join(gen, fn)):
            m = fre.match(ln)
            if m: cur, prev = int(m.group(1), 16), None; continue
            if cur is None: continue
            for t in tre.findall(ln):
                a = int(t, 16)
                if a in want and prev is not None and prev < a: owner.setdefault(a, set()).add(cur)
                prev = a
    by_func = collections.defaultdict(collections.Counter)
    by_meth = collections.defaultdict(collections.Counter)
    for n, r, m in rows:
        fs = owner.get(r) or {None}
        f = min(fs, key=lambda x: (x is None, x))
        by_func[f][m] += n
        by_meth[m][(f, r)] += n
    if "--by-method" in sys.argv:
        for m, c in sorted(by_meth.items(), key=lambda kv: -sum(kv[1].values())):
            print("%10d  %s" % (sum(c.values()), m))
            for (f, r), n in c.most_common():
                print("            %10d  %s  (ret %08x)" % (n, "F_%x" % f if f else "?", r))
    else:
        for f, c in sorted(by_func.items(), key=lambda kv: -sum(kv[1].values())):
            print("%10d  %s" % (sum(c.values()), "F_%x" % f if f else "?"))
            for m, n in c.most_common(): print("            %10d  %s" % (n, m))

if __name__ == "__main__":
    main()
