// sm3msl: offline converter from D3D9 Shader Model 1-3 bytecode to Metal Shading Language, for recomps that replace
// a D3D9 renderer with a native Metal one. Nothing here runs in the game: the game's shaders are converted at build
// time (dxbc-spirv's sm3 frontend -> SPIR-V -> SPIRV-Cross -> MSL) into project-owned Metal shaders, and a C table
// describes each one so the renderer can bind it.
//
// usage: sm3msl OUT_DIR SHADER.bin...
//   SHADER.bin  raw token stream (version token .. end token), named {vs,ps}_<fnv1a32 of the bytes>.bin
//   writes OUT_DIR/<name>.metal (entry point <name>) and OUT_DIR/sm3_shaders.inc (an Sm3ShaderInfo initializer list)
//
// Fixed binding model (sm3msl.h has the buffer layouts):
//   buffer(0..15)   vertex streams (vertex stage only; the renderer's vertex descriptor)
//   buffer(16 + k)  constant buffers, k = SM3_CBV_*: float constants, int, bool, alpha test, fog, clip planes,
//                   point args, sampler state, texture stage
//   texture(s), sampler(s)  sampler register s
//   vertex attribute(r)     input register v<r> (its usage/index are in the table)
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "ir/ir.h"
#include "ir/ir_builder.h"
#include "ir/ir_legalize.h"
#include "ir/passes/ir_pass_lower_io.h"
#include "sm3/sm3_converter.h"
#include "spirv/spirv_builder.h"
#include "spirv/spirv_mapping.h"
#include "util/util_byte_stream.h"

#include "spirv_msl.hpp"

#include "sm3msl.h"

using namespace dxbc_spv;

namespace {

struct FixedMapping : spirv::ResourceMapping {
    spirv::DescriptorBinding mapDescriptor(ir::ScalarType type, uint32_t space, uint32_t index) override {
        spirv::DescriptorBinding b;
        b.set = 0;
        b.binding = type == ir::ScalarType::eCbv ? SM3_BUFFER_BASE + index : index;
        return b;
    }
    uint32_t mapPushData(ir::ShaderStageMask) override { return 0; }
};

struct Decl { uint32_t reg, usage, index; };
struct Info {
    std::string name;
    uint32_t hash = 0, stage = 0, major = 0, minor = 0;
    std::vector<Decl> inputs, outputs;
    uint32_t sampler_types[16] = {0};
    uint32_t cbv_mask = 0;
};

// the parts of the token stream the renderer needs: input/output declarations and sampler types
void scan_tokens(const std::vector<uint32_t> &t, Info &info) {
    info.stage = (t[0] >> 16) == 0xFFFE ? SM3_STAGE_VERTEX : SM3_STAGE_PIXEL;
    info.major = (t[0] >> 8) & 0xFF; info.minor = t[0] & 0xFF;
    for (size_t i = 1; i < t.size() && t[i] != 0x0000FFFFu;) {
        uint32_t op = t[i] & 0xFFFF;
        size_t len = op == 0xFFFE ? (t[i] >> 16) : ((t[i] >> 24) & 0xF);
        if (op == 0x1F && i + 2 < t.size()) {                  // dcl
            uint32_t d = t[i + 1], r = t[i + 2];
            uint32_t type = ((r >> 28) & 7) | ((r >> 8) & 0x18), num = r & 0x7FF;
            if (type == 10) { if (num < 16) info.sampler_types[num] = (d >> 27) & 0xF; }   // sampler: 2 2d, 3 cube, 4 volume
            else if (type == 1) info.inputs.push_back({num, d & 0x1F, (d >> 16) & 0xF});  // input v#
            else if (type == 6) info.outputs.push_back({num, d & 0x1F, (d >> 16) & 0xF}); // SM3 output o#
        }
        i += 1 + len;
    }
}

bool convert(const std::vector<uint32_t> &tokens, Info &info, std::string &msl, std::string &err) {
    ir::Builder builder;
    util::ByteReader reader(tokens.data(), tokens.size() * 4);
    sm3::Converter::Options o = {};
    o.name = info.name.c_str();
    o.includeDebugNames = true;
    sm3::Converter converter(reader, o);
    if (!converter.convertShader(builder)) { err = "sm3 conversion failed"; return false; }

    ir::CompileOptions co = {};
    co.cseOptions.relocateDescriptorLoad = true;
    co.descriptorIndexing.optimizeDescriptorIndexing = true;
    ir::legalizeIr(builder, co);

    {
        ir::LowerIoPass pass(builder);
        pass.lowerSampleCountToSpecConstant(0u);
        static const ir::BuiltIn order[SM3_CBV_COUNT] = {
            ir::BuiltIn::eLegacyConstFloat, ir::BuiltIn::eLegacyConstInt, ir::BuiltIn::eLegacyConstBool,
            ir::BuiltIn::eLegacyAlphaTest, ir::BuiltIn::eLegacyFog, ir::BuiltIn::eLegacyClipPlanes,
            ir::BuiltIn::eLegacyPointArgs, ir::BuiltIn::eLegacySamplerState, ir::BuiltIn::eLegacyTextureStage,
        };
        for (uint32_t k = 0; k < SM3_CBV_COUNT; k++) pass.lowerLegacyBuiltInToCbv(order[k], 0u, k);
    }

    FixedMapping mapping;
    spirv::SpirvBuilder::Options so = {};
    so.includeDebugNames = true;
    so.floatControls2 = false;
    so.supportedRoundModesF16 = so.supportedRoundModesF32 = so.supportedRoundModesF64 = ir::RoundMode::eNearestEven | ir::RoundMode::eZero;
    so.supportedDenormModesF16 = so.supportedDenormModesF32 = so.supportedDenormModesF64 = ir::DenormMode::eFlush | ir::DenormMode::ePreserve;
    spirv::SpirvBuilder sb(builder, mapping, so);
    sb.buildSpirvBinary();
    size_t size = 0;
    sb.getSpirvBinary(size, nullptr);
    std::vector<uint32_t> spv(size / 4);
    sb.getSpirvBinary(size, spv.data());

    try {
        spirv_cross::CompilerMSL msl_c(std::move(spv));
        auto opts = msl_c.get_msl_options();
        opts.platform = spirv_cross::CompilerMSL::Options::macOS;
        opts.msl_version = spirv_cross::CompilerMSL::Options::make_msl_version(2, 3);
        opts.enable_decoration_binding = true;
        msl_c.set_msl_options(opts);
        auto eps = msl_c.get_entry_points_and_stages();
        if (eps.size() != 1) { err = "expected one entry point"; return false; }
        msl_c.rename_entry_point(eps[0].name, info.name, eps[0].execution_model);
        msl = msl_c.compile();
        auto res = msl_c.get_shader_resources();
        for (auto &ub : res.uniform_buffers) {
            uint32_t b = msl_c.get_decoration(ub.id, spv::DecorationBinding);
            if (b >= SM3_BUFFER_BASE && b < SM3_BUFFER_BASE + SM3_CBV_COUNT) info.cbv_mask |= 1u << (b - SM3_BUFFER_BASE);
        }
    } catch (const std::exception &e) { err = std::string("spirv-cross: ") + e.what(); return false; }
    return true;
}

// D3D9 converts integer vertex formats (UBYTE4, SHORT2/4) to float shader inputs without normalizing; Metal
// can't. The runtime binds them as the normalized formats and every float input is scaled back by
// rn_attr_scale[attribute] (buffer(SM3_ATTR_SCALE_BUFFER), 1 for other formats).
std::string scale_inputs(const std::string &msl, const std::string &name) {
    size_t st = msl.find("struct " + name + "_in\n{");
    if (st == std::string::npos) return msl;
    size_t se = msl.find("};", st);
    std::string body = msl.substr(st, se - st), lines;
    std::regex field(R"(\n\s*(float[234]?) (\w+) \[\[attribute\((\d+)\)\]\];)");
    for (std::sregex_iterator it(body.begin(), body.end(), field), end; it != end; ++it)
        lines += "    in." + (*it)[2].str() + " *= rn_attr_scale[" + (*it)[3].str() + "];\n";
    if (lines.empty()) return msl;
    std::string out = msl;
    size_t ep = out.find("vertex " + name + "_out " + name + "(");
    if (ep == std::string::npos) return msl;
    size_t close = out.find(")\n{", ep);
    out.insert(close, ", constant float* rn_attr_scale [[buffer(" + std::to_string(SM3_ATTR_SCALE_BUFFER) + ")]]");
    size_t brace = out.find("{\n", ep) + 2;
    out.insert(brace, lines);
    return out;
}

// D3D9's alpha test lives in every pixel shader (dxbc-spirv: `if (!alphaTest(...)) discard_fragment();`). Guard it
// with function constant SM3_FC_ALPHA_TEST so the renderer can specialize a variant without it: no discard at all,
// which keeps Apple GPUs' hidden surface removal and early depth working on the (most common) draws without alpha
// test. Unspecialized, the constant is true and the shader behaves as converted.
std::string alpha_test_variant(const std::string &msl) {
    if (msl.find("if (!alphaTest(") == std::string::npos) return msl;
    std::string out = msl;
    size_t ns = out.find("using namespace metal;\n");
    if (ns == std::string::npos) return msl;
    out.insert(ns + 24, "\nconstant bool rn_alpha_test_fc [[function_constant(" + std::to_string(SM3_FC_ALPHA_TEST) + ")]];\n"
                        "constant bool rn_alpha_test = is_function_constant_defined(rn_alpha_test_fc) ? rn_alpha_test_fc : true;\n");
    for (size_t p = 0; (p = out.find("if (!alphaTest(", p)) != std::string::npos; p += 20)
        out.replace(p, 15, "if (rn_alpha_test && !alphaTest(");
    return out;
}

}  // namespace

// ---- library entry (runtime conversion of shaders that were not converted at build time) ----
extern "C" char *sm3msl_convert(const uint32_t *tokens, uint32_t ntokens, Sm3ShaderInfo *out, char *err, size_t errlen) {
    std::vector<uint32_t> t(tokens, tokens + ntokens);
    Info info;
    info.hash = sm3_hash(tokens, ntokens);
    scan_tokens(t, info);
    char nm[32]; snprintf(nm, sizeof nm, "%s_%08x", info.stage == SM3_STAGE_VERTEX ? "vs" : "ps", info.hash);
    info.name = nm;
    std::string msl, e;
    if (!convert(t, info, msl, e)) { if (err) snprintf(err, errlen, "%s", e.c_str()); return nullptr; }
    if (info.stage == SM3_STAGE_VERTEX) msl = scale_inputs(msl, info.name);
    else msl = alpha_test_variant(msl);
    memset(out, 0, sizeof *out);
    out->hash = info.hash; out->stage = (uint8_t)info.stage; out->major = (uint8_t)info.major;
    out->function = strdup(nm); out->cbv_mask = info.cbv_mask;
    for (int k = 0; k < 16; k++) out->sampler_type[k] = (uint8_t)info.sampler_types[k];
    out->ninputs = (uint8_t)std::min<size_t>(info.inputs.size(), SM3_MAX_IO);
    for (int k = 0; k < out->ninputs; k++) out->inputs[k] = {(uint8_t)info.inputs[k].reg, (uint8_t)info.inputs[k].usage, (uint8_t)info.inputs[k].index};
    out->noutputs = (uint8_t)std::min<size_t>(info.outputs.size(), SM3_MAX_IO);
    for (int k = 0; k < out->noutputs; k++) out->outputs[k] = {(uint8_t)info.outputs[k].reg, (uint8_t)info.outputs[k].usage, (uint8_t)info.outputs[k].index};
    return strdup(msl.c_str());
}

#ifndef SM3MSL_LIB
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: sm3msl OUT_DIR SHADER.bin...\n"); return 2; }
    std::string out = argv[1];
    std::ostringstream table;
    int ok = 0, bad = 0;
    for (int a = 2; a < argc; a++) {
        std::ifstream f(argv[a], std::ios::binary);
        std::vector<char> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (bytes.size() < 8 || bytes.size() % 4) { fprintf(stderr, "%s: not a shader\n", argv[a]); bad++; continue; }
        std::vector<uint32_t> tokens(bytes.size() / 4);
        memcpy(tokens.data(), bytes.data(), bytes.size());
        Info info;
        uint32_t h = 2166136261u;
        for (char c : bytes) h = (h ^ (uint8_t)c) * 16777619u;
        info.hash = h;
        scan_tokens(tokens, info);
        char nm[32]; snprintf(nm, sizeof nm, "%s_%08x", info.stage == SM3_STAGE_VERTEX ? "vs" : "ps", h);
        info.name = nm;
        std::string msl, err;
        if (!convert(tokens, info, msl, err)) { fprintf(stderr, "%s: %s\n", argv[a], err.c_str()); bad++; continue; }
        if (info.stage == SM3_STAGE_VERTEX) msl = scale_inputs(msl, info.name);
        else msl = alpha_test_variant(msl);
        std::ofstream(out + "/" + info.name + ".metal") << msl;
        table << "{0x" << std::hex << info.hash << std::dec << "u, " << info.stage << ", " << info.major << ", \"" << info.name
              << "\", 0x" << std::hex << info.cbv_mask << std::dec << "u, {";
        for (int s = 0; s < 16; s++) table << (s ? "," : "") << info.sampler_types[s];
        table << "}, " << info.inputs.size() << ", {";
        for (size_t i = 0; i < info.inputs.size() && i < SM3_MAX_IO; i++)
            table << (i ? "," : "") << "{" << info.inputs[i].reg << "," << info.inputs[i].usage << "," << info.inputs[i].index << "}";
        table << "}, " << info.outputs.size() << ", {";
        for (size_t i = 0; i < info.outputs.size() && i < SM3_MAX_IO; i++)
            table << (i ? "," : "") << "{" << info.outputs[i].reg << "," << info.outputs[i].usage << "," << info.outputs[i].index << "}";
        table << "}},\n";
        ok++;
    }
    std::ofstream(out + "/sm3_shaders.inc") << table.str();
    fprintf(stderr, "sm3msl: %d converted, %d failed\n", ok, bad);
    return bad ? 1 : 0;
}
#endif
