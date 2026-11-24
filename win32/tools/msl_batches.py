#!/usr/bin/env python3
"""Packs the Metal shaders tools/sm3msl writes (one [vp]s_*.metal per shader) into a few large sources, for builds
without Apple's offline Metal compiler (the Metal Toolchain comes with Xcode, not the Command Line Tools).

Each shader goes into a namespace of its own (bN::<name>), since every converted shader defines the same helper
types; the shared headers and the alpha-test function constant are declared once per batch. The runtime
(mtl_render.m, mtlr_load_shaders given the folder) compiles the batches with macOS's own compiler at startup: macOS
compiles source one library at a time, and a batch of a few hundred shaders costs far less than as many libraries.

usage: msl_batches.py SHADER_DIR OUT_DIR [shaders per batch, default 200]
"""
import os, re, sys

HEADER = ('#pragma clang diagnostic ignored "-Wmissing-prototypes"\n'
          '#include <metal_stdlib>\n#include <simd/simd.h>\nusing namespace metal;\n'
          'constant bool rn_alpha_test_fc [[function_constant(0)]];\n')
DROP = re.compile(r'^\s*(#pragma clang diagnostic ignored "-Wmissing-prototypes"|#include <metal_stdlib>|'
                  r'#include <simd/simd\.h>|using namespace metal;|constant bool rn_alpha_test_fc \[\[function_constant\(0\)\]\];)\s*$')

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    src, out = sys.argv[1], sys.argv[2]
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    names = sorted(f for f in os.listdir(src) if re.match(r'[vp]s_[0-9a-f]+\.metal$', f))
    if not names:
        sys.exit("msl_batches: no shaders in %s" % src)
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        if f.startswith("batch_") and f.endswith(".metal"):
            os.remove(os.path.join(out, f))
    nb = 0
    for b in range(0, len(names), per):
        parts = [HEADER]
        for i, name in enumerate(names[b:b + per]):
            body = "\n".join(l for l in open(os.path.join(src, name)).read().split("\n") if not DROP.match(l))
            parts.append("namespace b%d {\n%s\n}\n" % (b + i, body))
        open(os.path.join(out, "batch_%03d.metal" % nb), "w").write("".join(parts))
        nb += 1
    print("%d shaders -> %d batches in %s" % (len(names), nb, out))

if __name__ == "__main__":
    main()
