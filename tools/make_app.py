#!/usr/bin/env python3
"""Package the recompiled game as a macOS app bundle.

usage: make_app.py BINARY GAME_EXE OUT.app [--name NAME] [--display-name NAME] [--bundle-id ID] [--category UTI]
                   [--version V]
                   [--resource FILE[=NAME]]... [--lib DYLIB]... [--icon IMAGE] [--no-vulkan]
  BINARY    the linked runtime + recompiled game (build/boot)
  GAME_EXE  the original Windows executable, used only for its icon
  --name    executable name (default: OUT.app's name)
  --display-name  the name shown in the menu bar, Dock and app switcher (default: --name); may contain characters a
                  file name can't, e.g. a colon, while OUT.app keeps a plain file name
  --resource  copy FILE (or a folder) into Contents/Resources (as NAME), e.g. the image named by rt_game.image
  --lib       copy DYLIB into Contents/Frameworks (signed), e.g. a d3d9 backend the runtime dlopens
  --icon      the app icon from IMAGE (any format sips reads; center-cropped to a square) instead of the exe's,
              for games whose exe icon is tiny
  --no-vulkan an OpenGL game: no Vulkan driver in the bundle
The app finds the game folder itself on launch (see runtime/boot.c), so no game data goes in the bundle.
"""
import os, plistlib, shutil, subprocess, sys, tempfile

args = sys.argv[1:]
def opt(flag, default):
    if flag in args:
        i = args.index(flag); v = args[i + 1]; del args[i:i + 2]; return v
    return default
app_name = opt("--name", None)
display_name = opt("--display-name", None)
bundle_id = opt("--bundle-id", None)
category = opt("--category", "public.app-category.games")
version = opt("--version", "0.1")
resources = []
while "--resource" in args:
    resources.append(opt("--resource", None))
libs = []
while "--lib" in args:
    libs.append(opt("--lib", None))
icon_image = opt("--icon", None)
no_vulkan = "--no-vulkan" in args
if no_vulkan: args.remove("--no-vulkan")
binary, game_exe, app = args[0], args[1], args[2]
app_name = app_name or os.path.splitext(os.path.basename(app.rstrip("/")))[0]
display_name = display_name or app_name
bundle_id = bundle_id or "com.example." + "".join(ch for ch in app_name.lower() if ch.isalnum()) + "-recomp"
here = os.path.dirname(os.path.abspath(__file__))
contents = os.path.join(app, "Contents")
macos, res = os.path.join(contents, "MacOS"), os.path.join(contents, "Resources")
if os.path.exists(app):
    shutil.rmtree(app)
os.makedirs(macos); os.makedirs(res)

shutil.copy2(binary, os.path.join(macos, app_name))

# the KosmicKrisp Vulkan driver built from Mesa source (make kosmickrisp): driver, ICD json, loader, driconf XML
# code goes in Frameworks/kosmickrisp, data (ICD json, drirc.d, VERSION) in Resources/kosmickrisp (codesign
# rejects non-code files among the frameworks); the json points at the driver relative to itself
kk = os.path.join(os.path.dirname(binary), "kosmickrisp")
for r in resources:   # files or folders
    src, _, name = r.partition("=")
    dst = os.path.join(res, name or os.path.basename(src.rstrip("/")))
    if os.path.isdir(src):
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)
for lib in libs:
    os.makedirs(os.path.join(contents, "Frameworks"), exist_ok=True)
    shutil.copy2(lib, os.path.join(contents, "Frameworks", os.path.basename(lib)))
if no_vulkan:
    pass
elif os.path.isdir(kk):
    fw_dir, res_dir = os.path.join(contents, "Frameworks", "kosmickrisp"), os.path.join(res, "kosmickrisp")
    os.makedirs(fw_dir); os.makedirs(res_dir)
    for f in os.listdir(kk):
        src = os.path.join(kk, f)
        if f.endswith(".dylib"): shutil.copy2(src, fw_dir)
        elif os.path.isdir(src): shutil.copytree(src, os.path.join(res_dir, f))
        elif f != "kosmickrisp_icd.json": shutil.copy2(src, res_dir)
    import json
    with open(os.path.join(res_dir, "kosmickrisp_icd.json"), "w") as f:
        json.dump({"file_format_version": "1.0.1", "ICD": {"library_path": "../../Frameworks/kosmickrisp/libvulkan_kosmickrisp.dylib",
                                                           "api_version": "1.4.0"}}, f, indent=4)
    print("bundled", open(os.path.join(kk, "VERSION")).read().strip())
else:
    print("note: no build/kosmickrisp (run `make kosmickrisp`); the app will use a system KosmicKrisp")

with open(os.path.join(contents, "Info.plist"), "wb") as f:
    plistlib.dump({
        "CFBundleName": display_name,
        "CFBundleDisplayName": display_name,
        "CFBundleExecutable": app_name,
        "CFBundleIdentifier": bundle_id,
        "CFBundleIconFile": app_name,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": "1",
        "LSMinimumSystemVersion": "26.0",
        "LSApplicationCategoryType": category,
        "NSHighResolutionCapable": True,
        # online services of older games often use plain http://
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "NSSupportsAutomaticGraphicsSwitching": True,
    }, f)

# icon: the exe's own application icon -> .iconset -> .icns
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, "icon.png")
    if icon_image:
        subprocess.run(["sips", "-s", "format", "png", icon_image, "--out", png], check=True, capture_output=True)
        dims = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", png], check=True, capture_output=True, text=True).stdout.split()
        side = min(int(dims[dims.index("pixelWidth:") + 1]), int(dims[dims.index("pixelHeight:") + 1]))
        subprocess.run(["sips", "--cropToHeightWidth", str(side), str(side), png], check=True, capture_output=True)
    else:
        subprocess.run([sys.executable, os.path.join(here, "app_icon.py"), game_exe, png], check=True)
    iconset = os.path.join(tmp, app_name + ".iconset")
    os.makedirs(iconset)
    for size in (16, 32, 64, 128, 256, 512):
        for scale in (1, 2):
            px = size * scale
            name = "icon_%dx%d%s.png" % (size, size, "@2x" if scale == 2 else "")
            subprocess.run(["sips", "-z", str(px), str(px), png, "--out", os.path.join(iconset, name)], check=True, capture_output=True)
    subprocess.run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(res, app_name + ".icns")], check=True)
    shutil.copy2(png, os.path.join(res, app_name + ".png"))   # e.g. for a Steam library shortcut

# ad-hoc signatures: the bundled dylibs first, then the whole bundle (arm64 code must be signed to run)
for lib in libs:
    subprocess.run(["codesign", "--force", "--sign", "-", os.path.join(contents, "Frameworks", os.path.basename(lib))], check=True, capture_output=True)
fw = os.path.join(contents, "Frameworks", "kosmickrisp")
if os.path.isdir(fw):
    for f in sorted(os.listdir(fw)):
        if f.endswith(".dylib"):
            subprocess.run(["codesign", "--force", "--sign", "-", os.path.join(fw, f)], check=True, capture_output=True)
subprocess.run(["codesign", "--force", "--sign", "-", app], check=True, capture_output=True)
print("built", app)
