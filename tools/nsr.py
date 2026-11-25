#!/usr/bin/env python3
"""NightSight Recomp (NSR): one Steam Play compatibility tool for every native Mac port built on Recomp-Framework.

Steam for Mac has the same compatibility-tool support as Steam on Linux, switched off; NotProton
(github.com/NotProtonNot/NotProton) switches it on. NSR registers a single tool, "NightSight Recomp (NSR)", in
~/Library/Application Support/Steam/compatibilitytools.d/nsr_proton. Choose it for a game (the game > Properties >
Compatibility > Force the use of a specific Steam Play compatibility tool) and Play on the game's own library entry
starts its native app on the Windows release Steam installed, with playtime, presence and the Steam overlay.

The tool's ID contains "proton" on purpose: Steam for Mac maps a game's Steam Auto-Cloud rules for Windows paths
(Saved Games, Documents, AppData...) into the tool's prefix, steamapps/compatdata/<appid>/pfx/drive_c/users/steamuser,
only for a tool whose name contains "proton"; for any other tool it skips every rule, so saves that the Windows
release syncs with Auto-Cloud never sync on the Mac. A port saves into that prefix to share them with Windows.
`install` moves games registered with the tool's earlier ID, "nsr", over to it (see cmd_install).

Steam calls the tool's `run` launcher with the game's Windows exe and SteamAppId in the environment. The launcher
looks the app ID up in games.conf (next to it) and starts that game's .app. Adding a game is a config edit.

NotProton plugins work too: a plugin in ~/Library/Application Support/notproton/plugins/*.conf that is switched on
for the game (NOTPROTON_<ID>=1 in the game's environment) is applied the way NotProton's own launcher applies it:
`inject` loads its dylib into the game, its `env` lines are set, and NOTPROTON_ENV_<NAME>=value sets <NAME>.
`depends`, `requires` and `tools` are honoured.

A game's environment (plugin switches, runtime settings) goes in games.conf with `set-env`, not in Steam's launch
options: Steam for Mac starts a game with launch options as `env VAR=value <tool>`, which fails ("OS Error 260")
for compatibility tools other than NotProton's own.

The overlay and plugin libraries are inserted with DYLD_INSERT_LIBRARIES, which macOS strips when it starts a system
binary such as /bin/sh, so `run` is a small compiled launcher that execs the app directly. `install` needs clang
(Apple's Command Line Tools). Only Python's standard library is used.

usage:
  nsr.py install [--display "NightSight Recomp (NSR)"]
  nsr.py add --appid 201810 --app /Applications/Game.app [--exe 'game*.exe'] [--pass-paths [--force-exe Game.exe]]
             [--name "Game"]
  nsr.py set-env --appid 201810 [NAME=value ...]   (no values: clear)
  nsr.py remove --appid 201810
  nsr.py list
  nsr.py uninstall
  (every command takes --id <tool id>, default "nsr_proton"; keep "proton" in it, see above)

  --exe          glob (case-insensitive) for the Windows exe Steam starts as the game; anything else Steam runs first
                 (redistributable installers, helpers) finishes at once. If left out, the game's exe is found in its
                 Steam folder, provided there is exactly one (not counting crash handlers and installers).
  --pass-paths   start the app as `app <exe path> <game folder> [args]`, for ports that load the original game's
                 files from the Steam folder (Recomp-Framework apps). Without it the app only gets the game's own
                 arguments (self-contained ports).
  --force-exe    with --pass-paths: always pass this exe from the game folder, whichever launch option Steam picked
                 (for a game that ships several exes where the port supports one)

games.conf has one game per line, tab separated: appid, app executable, exe glob, force exe, pass-paths (yes/no),
name, and optionally environment (space-separated NAME=value). The launcher writes what each launch did to ~/Library/Logs/<tool id>.log.
Set NSR_TOOLS_DIR / NSR_STEAM_ROOT to use another compatibilitytools.d / Steam folder (for testing).
Based on a community contributor's multi-game version of the earlier one-tool-per-game Steam Play script, which
NSR replaces.
"""
import os, plistlib, shutil, subprocess, sys, tempfile

TOOLS = os.environ.get("NSR_TOOLS_DIR") or os.path.expanduser("~/Library/Application Support/Steam/compatibilitytools.d")
DEFAULT_ID, DEFAULT_DISPLAY = "nsr_proton", "NightSight Recomp (NSR)"
LEGACY_ID = "nsr"   # the tool's ID before it had to contain "proton" (Auto-Cloud); `install` migrates it

DECLARATION = '''"compatibilitytools"
{
  "compat_tools"
  {
    "%(id)s"
    {
      "install_path" "."
      "display_name" "%(display)s"
      "from_oslist" "windows"
      "to_oslist" "macos"
    }
  }
}
'''
MANIFEST = '''"manifest"
{
  "version" "2"
  "commandline" "/run %verb%"
}
'''

# Steam runs:  run <verb> <Windows executable> [arguments]   (SteamAppId in the environment)
LAUNCHER = r'''#include <ctype.h>
#include <dirent.h>
#include <fnmatch.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

extern char **environ;
#define TOOL_ID "@ID@"

static FILE *logf;
static void lg(const char *fmt, ...) {
    if (!logf) return;
    va_list ap; va_start(ap, fmt); vfprintf(logf, fmt, ap); va_end(ap);
    fputc('\n', logf); fflush(logf);
}
static void alert(const char *msg) {
    char script[2048];
    snprintf(script, sizeof script, "display alert \"NightSight Recomp\" message \"%s\"", msg);
    execl("/usr/bin/osascript", "osascript", "-e", script, (char *)NULL);
}

/* ---------------- games.conf ---------------- */
static int lookup(const char *conf, const char *appid, char *bin, char *glob, char *force, char *mode, char *name, char *envs) {
    FILE *f = fopen(conf, "r");
    if (!f) return 0;
    char line[PATH_MAX * 3];
    int found = 0;
    while (!found && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!*line || *line == '#') continue;
        char *fld[7] = { 0 }; int n = 0; char *p = line;
        while (n < 7) { fld[n++] = p; char *t = strchr(p, '\t'); if (!t) break; *t = 0; p = t + 1; }
        if (n < 5 || strcmp(fld[0], appid)) continue;
        snprintf(bin, PATH_MAX, "%s", fld[1]); snprintf(glob, PATH_MAX, "%s", fld[2]);
        snprintf(force, PATH_MAX, "%s", fld[3]); snprintf(mode, 16, "%s", fld[4]);
        snprintf(name, 256, "%s", n > 5 && fld[5] ? fld[5] : "");
        snprintf(envs, PATH_MAX, "%s", n > 6 && fld[6] ? fld[6] : "");
        found = 1;
    }
    fclose(f);
    return found;
}

/* ---------------- NotProton plugins ----------------
   ~/Library/Application Support/notproton/plugins/*.conf, read in byte order: "[ID]" starts a section, then
   "key = value" lines; a key may repeat (env, requires, tools). Applied as NotProton's launcher does. */
#define MAXF 4096
typedef struct { char *id, *key, *val; } Field;
static Field fields[MAXF]; static int nfields;
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s); while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}
static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static void read_plugins(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    char *names[256]; int nn = 0; struct dirent *e;
    while ((e = readdir(d)) && nn < 256) {
        size_t l = strlen(e->d_name);
        if (l > 5 && !strcmp(e->d_name + l - 5, ".conf") && !strpbrk(e->d_name, "\t\n")) names[nn++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, nn, sizeof *names, cmpstr);
    for (int i = 0; i < nn; i++) {
        char path[PATH_MAX]; snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        FILE *f = fopen(path, "r"); if (!f) continue;
        lg("plugins: reading %s", path);
        char line[4096], *sect = NULL;
        while (fgets(line, sizeof line, f)) {
            line[strcspn(line, "\r\n")] = 0;
            char *s = trim(line);
            if (!*s || *s == '#' || *s == ';') continue;
            if (*s == '[') { char *z = strchr(s, ']'); if (z) { *z = 0; sect = strdup(trim(s + 1)); } continue; }
            char *eq = strchr(s, '='); if (!eq || !sect || nfields >= MAXF) continue;
            *eq = 0;
            fields[nfields].id = sect; fields[nfields].key = strdup(trim(s)); fields[nfields].val = strdup(trim(eq + 1));
            nfields++;
        }
        fclose(f);
    }
}
static const char *first(const char *id, const char *key) {
    for (int i = 0; i < nfields; i++) if (!strcmp(fields[i].id, id) && !strcmp(fields[i].key, key)) return fields[i].val;
    return NULL;
}
static int has_section(const char *id) { for (int i = 0; i < nfields; i++) if (!strcmp(fields[i].id, id)) return 1; return 0; }
static void home_path(const char *p, char *out) {   /* relative paths hang off $HOME */
    const char *home = getenv("HOME"); if (!home) home = "";
    if (p[0] == '/') snprintf(out, PATH_MAX, "%s", p);
    else if (p[0] == '~' && p[1] == '/') snprintf(out, PATH_MAX, "%s/%s", home, p + 2);
    else snprintf(out, PATH_MAX, "%s/%s", home, p);
}
static int requires_file(const char *id, char *out) {   /* the first required file that is there */
    for (int i = 0; i < nfields; i++)
        if (!strcmp(fields[i].id, id) && !strcmp(fields[i].key, "requires")) {
            home_path(fields[i].val, out);
            if (access(out, R_OK) == 0) return 1;
        }
    return 0;
}
static int installed(const char *id) { char p[PATH_MAX]; return !first(id, "requires") || requires_file(id, p); }
static int switched(const char *id) {
    const char *v = getenv(id);
    if (first(id, "type")) return v && *v;
    const char *on = first(id, "on");
    return v && !strcmp(v, on && *on ? on : "1");
}
static int for_tool(const char *id) {   /* "tools" names the tools a plugin is for; none means all */
    int any = 0;
    for (int i = 0; i < nfields; i++)
        if (!strcmp(fields[i].id, id) && !strcmp(fields[i].key, "tools") && *fields[i].val) {
            any = 1;
            /* also the tool's earlier ID, "nsr", for plugins written before the rename */
            if (fnmatch(fields[i].val, TOOL_ID, 0) == 0 || fnmatch(fields[i].val, "nsr", 0) == 0) return 1;
        }
    return !any;
}
static int active(const char *id, int depth) {
    if (depth > 32 || !has_section(id) || !for_tool(id) || !switched(id) || !installed(id)) return 0;
    const char *dep = first(id, "depends");
    return !dep || !*dep || active(dep, depth + 1);
}
static int reserved(const char *name) {   /* what the launch sets itself: no plugin or option may replace it */
    static const char *const pre[] = { "DYLD_", "STEAM_COMPAT_", "NOTPROTON_", "WINE", "CX_", NULL };
    static const char *const exact[] = { "PATH", "HOME", "STEAM_DYLD_INSERT_LIBRARIES", "SteamAppId", "UID", "EUID",
                                         "PPID", "SHELLOPTS", "BASHOPTS", NULL };
    for (int i = 0; pre[i]; i++) if (!strncmp(name, pre[i], strlen(pre[i]))) return 1;
    for (int i = 0; exact[i]; i++) if (!strcmp(name, exact[i])) return 1;
    return 0;
}
static int valid_name(const char *n, size_t l) {
    if (!l || !(isupper((unsigned char)n[0]) || n[0] == '_')) return 0;
    for (size_t i = 0; i < l; i++) if (!(isupper((unsigned char)n[i]) || isdigit((unsigned char)n[i]) || n[i] == '_')) return 0;
    return 1;
}
static void set_plugin_env(const char *id, const char *line) {   /* NAME=value, with ~/ and $HOME expanded */
    const char *eq = strchr(line, '=');
    if (!eq) { lg("plugins: %s skips env line %s (no =)", id, line); return; }
    char name[256]; size_t l = (size_t)(eq - line);
    if (l >= sizeof name || !valid_name(line, l)) { lg("plugins: %s skips env %.*s (not a valid name)", id, (int)l, line); return; }
    memcpy(name, line, l); name[l] = 0;
    if (reserved(name)) { lg("plugins: %s skips env %s (set by the launch)", id, name); return; }
    const char *home = getenv("HOME"); if (!home) home = "";
    char val[PATH_MAX * 2] = ""; const char *v = eq + 1;
    if (v[0] == '~' && v[1] == '/') { snprintf(val, sizeof val, "%s/", home); v += 2; }
    while (*v) {
        const char *h = strstr(v, "$HOME");
        size_t k = h ? (size_t)(h - v) : strlen(v);
        strncat(val, v, k); v += k;
        if (h) { strncat(val, home, sizeof val - strlen(val) - 1); v += 5; }
    }
    setenv(name, val, 1);
    lg("plugins: %s sets %s=%s", id, name, val);
}
/* plugin dylibs to insert (colon list) */
static void apply_plugins(char *dylibs, size_t n) {
    const char *home = getenv("HOME"); if (!home) home = "";
    char dir[PATH_MAX]; snprintf(dir, sizeof dir, "%s/Library/Application Support/notproton/plugins", home);
    read_plugins(dir);
    dylibs[0] = 0;
    for (int i = 0; i < nfields; i++) {
        const char *id = fields[i].id;
        int seen = 0; for (int j = 0; j < i; j++) if (!strcmp(fields[j].id, id)) { seen = 1; break; }
        if (seen) continue;
        if (!installed(id)) { if (switched(id)) lg("plugins: %s is on but its required files are missing", id); continue; }
        if (!active(id, 0)) continue;
        lg("plugins: %s is on", id);
        const char *inj = first(id, "inject");
        if (inj && !strcmp(inj, "1")) {
            char lib[PATH_MAX];
            if (!requires_file(id, lib)) lg("plugins: %s asks to load a dylib but names none that exists", id);
            else if (strchr(lib, ':')) lg("plugins: %s skipped: %s has a colon in it", id, lib);
            else if (!strstr(dylibs, lib)) {
                if (*dylibs) strncat(dylibs, ":", n - strlen(dylibs) - 1);
                strncat(dylibs, lib, n - strlen(dylibs) - 1);
                lg("plugins: %s loads %s", id, lib);
            }
        }
        for (int j = 0; j < nfields; j++)
            if (!strcmp(fields[j].id, id) && !strcmp(fields[j].key, "env")) set_plugin_env(id, fields[j].val);
    }
    /* NOTPROTON_ENV_<NAME>=value launch options set <NAME> */
    for (char **e = environ; *e; e++) {
        if (strncmp(*e, "NOTPROTON_ENV_", 14)) continue;
        const char *eq = strchr(*e, '='); if (!eq) continue;
        char key[256], name[256]; size_t l = (size_t)(eq - *e);
        if (l >= sizeof key) continue;
        memcpy(key, *e, l); key[l] = 0;
        snprintf(name, sizeof name, "%s", key + 14);
        if (!valid_name(name, strlen(name)) && !isalpha((unsigned char)name[0])) continue;
        if (has_section(key) && !for_tool(key)) { lg("plugins: %s is not for " TOOL_ID ", ignored", key); continue; }
        if (reserved(name)) { lg("plugins: %s would replace a setting the launch sets, ignored", key); continue; }
        setenv(name, eq + 1, 1);
        lg("plugins: %s sets %s", key, name);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    const char *verb = argv[1];
    const char *appid = getenv("SteamAppId");
    if (!appid || !*appid) appid = getenv("STEAM_COMPAT_APP_ID");
    if (!appid) appid = "";
    int launch = !strcmp(verb, "run") || !strcmp(verb, "waitforexitandrun") || !strcmp(verb, "waitforexit");
    {   /* ~/Library/Logs/<tool>.log: what Steam asked for and what the launch did (latest launch) */
        char lp[PATH_MAX]; const char *home = getenv("HOME");
        snprintf(lp, sizeof lp, "%s/Library/Logs/" TOOL_ID ".log", home ? home : "/tmp");
        logf = fopen(lp, launch ? "w" : "a");
        for (int i = 0; i < argc; i++) lg("argv[%d] = %s", i, argv[i]);
        for (char **e = environ; *e; e++)
            if (!strncmp(*e, "DYLD_", 5) || !strncasecmp(*e, "steam", 5) || !strncmp(*e, "NOTPROTON_", 10)) lg("%s", *e);
    }
    if (!strcmp(verb, "getcompatpath") || !strcmp(verb, "getnativepath")) {
        if (argc > 2) printf("%s\n", argv[2]);
        return 0;
    }
    if (!launch || argc < 3) return 0;

    char self[PATH_MAX], conf[PATH_MAX];
    snprintf(self, sizeof self, "%s", argv[0]);
    snprintf(conf, sizeof conf, "%s/games.conf", dirname(self));
    char bin[PATH_MAX], glob[PATH_MAX], force[PATH_MAX], mode[16], name[256], envs[PATH_MAX];
    if (!lookup(conf, appid, bin, glob, force, mode, name, envs)) {
        lg("no games.conf entry for app %s (%s)", appid, conf);
        alert("This game is not set up in NightSight Recomp. Choose another compatibility tool for it in Steam, or add it with nsr.py add.");
        return 1;
    }
    char path[PATH_MAX], dir[PATH_MAX], base[PATH_MAX], exe[PATH_MAX];
    snprintf(path, sizeof path, "%s", argv[2]); snprintf(dir, sizeof dir, "%s", dirname(path));
    snprintf(path, sizeof path, "%s", argv[2]); snprintf(base, sizeof base, "%s", basename(path));
    if (fnmatch(glob, base, FNM_CASEFOLD) != 0) { lg("%s is not the game (%s): nothing to do", base, glob); return 0; }
    if (*force) snprintf(exe, sizeof exe, "%s/%s", dir, force);
    else snprintf(exe, sizeof exe, "%s", argv[2]);
    if (access(bin, X_OK) != 0) {
        lg("app missing: %s", bin);
        alert("The native app is missing. Build or install it again, or choose another compatibility tool for this game in Steam.");
        return 1;
    }
    char *args[argc + 3]; int n = 0;
    args[n++] = bin;
    if (!strcmp(mode, "yes")) { args[n++] = exe; args[n++] = dir; }
    for (int i = 3; i < argc; i++) args[n++] = argv[i];
    args[n] = NULL;

    /* the game's environment from games.conf (plugin switches, settings): before the plugins are evaluated */
    for (char *t = strtok(envs, " "); t; t = strtok(NULL, " ")) {
        char *eq = strchr(t, '=');
        if (!eq || eq == t) continue;
        *eq = 0;
        if (!strncmp(t, "DYLD_", 5)) { lg("games.conf: %s refused (libraries come from the overlay and plugins)", t); continue; }
        setenv(t, eq + 1, 1);
        lg("games.conf: %s=%s", t, eq + 1);
    }
    /* libraries for the game: what was already there, Steam's overlay, then switched-on NotProton plugins */
    char plugs[8192]; apply_plugins(plugs, sizeof plugs);
    char ins[16384] = "";
    const char *parts[3] = { getenv("DYLD_INSERT_LIBRARIES"), getenv("STEAM_DYLD_INSERT_LIBRARIES"), plugs };
    for (int i = 0; i < 3; i++) {
        if (!parts[i] || !*parts[i] || strstr(ins, parts[i])) continue;
        if (*ins) strncat(ins, ":", sizeof ins - strlen(ins) - 1);
        strncat(ins, parts[i], sizeof ins - strlen(ins) - 1);
    }
    if (*ins) setenv("DYLD_INSERT_LIBRARIES", ins, 1);
    lg("starting %s (%s) %s, DYLD_INSERT_LIBRARIES=%s", name, appid, bin, *ins ? ins : "(none)");
    if (logf) { fclose(logf); logf = NULL; }
    execv(bin, args);
    perror("execv");
    return 1;
}
'''


def die(msg):
    sys.exit("nsr: " + msg)


def opt(a, name, default=None):
    return a[a.index(name) + 1] if name in a and a.index(name) + 1 < len(a) else default


def tool_dir(a):
    tid = opt(a, "--id", DEFAULT_ID)
    if not tid.replace("_", "").isalnum():
        die("--id: letters, digits and _ only")
    return tid, os.path.join(TOOLS, tid)


def app_binary(app):
    """The app's executable, from CFBundleExecutable."""
    app = os.path.abspath(app)
    plist = os.path.join(app, "Contents", "Info.plist")
    if not os.path.isfile(plist):
        die("not an app bundle (no Contents/Info.plist): %s" % app)
    with open(plist, "rb") as f:
        name = plistlib.load(f).get("CFBundleExecutable")
    binary = os.path.join(app, "Contents", "MacOS", name or "")
    if not name or not os.access(binary, os.X_OK):
        die("executable not found: %s" % binary)
    return binary


def read_conf(conf):
    rows = []
    if os.path.isfile(conf):
        for line in open(conf, encoding="utf-8"):
            line = line.rstrip("\r\n")
            if line and not line.startswith("#"):
                rows.append((line.split("\t") + [""] * 7)[:7])
    return rows


def write_conf(conf, rows):
    with open(conf, "w", encoding="utf-8") as f:
        f.write("# appid\tapp executable\texe glob\tforce exe\tpass-paths\tname\tenvironment\n")
        for r in sorted(rows, key=lambda r: int(r[0]) if r[0].isdigit() else 0):
            f.write("\t".join(r).rstrip("\t") + "\n")


def cmd_install(a):
    tid, tool = tool_dir(a)
    display = opt(a, "--display", DEFAULT_DISPLAY)
    if '"' in display:
        die("--display: no quotes")
    os.makedirs(tool, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        c, out = os.path.join(tmp, "run.c"), os.path.join(tmp, "run")
        open(c, "w").write(LAUNCHER.replace("@ID@", tid))
        r = subprocess.run(["clang", "-O2", "-Wall", "-o", out, c], capture_output=True, text=True)
        if r.returncode:
            die("clang failed:\n" + r.stderr)
        shutil.copy2(out, os.path.join(tool, "run"))
    open(os.path.join(tool, "compatibilitytool.vdf"), "w").write(DECLARATION % {"id": tid, "display": display})
    open(os.path.join(tool, "toolmanifest.vdf"), "w").write(MANIFEST)
    conf = os.path.join(tool, "games.conf")
    write_conf(conf, read_conf(conf))   # creates it, or keeps the games already there
    print("installed %s (%s)" % (tool, display))
    if tid == DEFAULT_ID:
        migrate_legacy(tool)
    print("restart Steam if it is running, then add games with `add`")


def steam_running():
    return subprocess.run(["pgrep", "-x", "steam_osx"], capture_output=True).returncode == 0


def remap_steam(old, new):
    """Point every per-game tool choice in Steam (config.vdf, CompatToolMapping) that names the old tool ID at the new
    one: that tool no longer exists, so Steam could not start those games. Steam rewrites
    config.vdf while it runs, so this only happens with Steam closed. Returns the app IDs changed, or None."""
    if steam_running():
        return None
    vdf = os.path.join(os.environ.get("NSR_STEAM_ROOT") or os.path.dirname(TOOLS), "config", "config.vdf")
    if not os.path.isfile(vdf):
        return []
    lines = open(vdf, encoding="utf-8").read().split("\n")
    done, depth, in_map, app = [], 0, False, None
    for i, line in enumerate(lines):
        t = line.strip()
        if t == '"CompatToolMapping"':
            in_map, depth = True, 0
            continue
        if not in_map:
            continue
        if t == "{":
            depth += 1
        elif t == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1 and t.startswith('"') and t.endswith('"') and t.count('"') == 2:
            app = t.strip('"')
        elif depth == 2 and app and t.split() == ['"name"', '"%s"' % old]:
            lines[i] = line.replace('"%s"' % old, '"%s"' % new)
            done.append(app)
    if done:
        shutil.copy2(vdf, vdf + ".nsr-backup")
        open(vdf, "w", encoding="utf-8").write("\n".join(lines))
    return done


def migrate_legacy(tool):
    """Move games from the tool's earlier ID ("nsr") into this one, point Steam's choices of it at this one, and remove
    the old tool. The new tool shows the same name, so nothing changes for the player apart from cloud saves.
    Safe to run again: with Steam running, the old tool is kept until a later run can switch Steam's choices."""
    old = os.path.join(TOOLS, LEGACY_ID)
    if os.path.isdir(old):
        conf = os.path.join(tool, "games.conf")
        rows = read_conf(conf)
        have = {r[0] for r in rows}
        moved = [r for r in read_conf(os.path.join(old, "games.conf")) if r[0] not in have]
        write_conf(conf, rows + moved)
        if moved:
            print("copied %d game(s) from the earlier tool ID \"%s\"" % (len(moved), LEGACY_ID))
    remapped = remap_steam(LEGACY_ID, DEFAULT_ID)
    if remapped is None:
        if os.path.isdir(old):   # Steam's choices may still name the old tool: keep it working until they are switched
            print("Steam is running, so the old tool \"%s\" is kept for now: quit Steam and run `install` again to finish"
                  " (or choose NightSight Recomp (NSR) again for each game)" % LEGACY_ID)
        return
    if remapped:
        print("Steam's compatibility choice switched to the new tool for app(s) %s" % ", ".join(sorted(remapped)))
    if os.path.isdir(old):
        shutil.rmtree(old, ignore_errors=True)
        print("removed the old tool %s" % old)


HELPER_EXES = ("unitycrashhandler", "vcredist", "vc_redist", "dxsetup", "dotnet", "unins", "setup", "install",
               "crashreport", "crashpad", "launcher_helper")


def steam_libraries():
    """steamapps folders of every Steam library (libraryfolders.vdf)."""
    root = os.environ.get("NSR_STEAM_ROOT") or os.path.dirname(TOOLS)
    libs = [os.path.join(root, "steamapps")]
    vdf = os.path.join(root, "steamapps", "libraryfolders.vdf")
    if os.path.isfile(vdf):
        for line in open(vdf, encoding="utf-8", errors="replace"):
            parts = line.split('"')
            if len(parts) >= 4 and parts[1] == "path":
                libs.append(os.path.join(parts[3].replace("\\\\", "\\"), "steamapps"))
    return libs


def detect_exe(appid):
    """The one game exe in the app's Steam folder, or exit with a clear message."""
    folder = None
    for lib in steam_libraries():
        acf = os.path.join(lib, "appmanifest_%s.acf" % appid)
        if os.path.isfile(acf):
            for line in open(acf, encoding="utf-8", errors="replace"):
                parts = line.split('"')
                if len(parts) >= 4 and parts[1] == "installdir":
                    folder = os.path.join(lib, "common", parts[3])
            break
    if not folder or not os.path.isdir(folder):
        die("--exe not given and app %s is not installed in a Steam library: pass --exe" % appid)
    exes = [n for n in os.listdir(folder) if n.lower().endswith(".exe") and not any(h in n.lower() for h in HELPER_EXES)]
    if len(exes) != 1:
        die("--exe not given and %s has %s: pass --exe" % (folder, "no exe" if not exes else "several exes (%s)" % ", ".join(sorted(exes))))
    print("using exe %s (from %s)" % (exes[0], folder))
    return exes[0]


def cmd_add(a):
    tid, tool = tool_dir(a)
    conf = os.path.join(tool, "games.conf")
    if not os.path.isdir(tool):
        die("not installed: run `install` first")
    appid, app, exe = opt(a, "--appid"), opt(a, "--app"), opt(a, "--exe")
    if not (appid and appid.isdigit() and app):
        die("--appid (a number) and --app are required")
    mode = "yes" if "--pass-paths" in a else "no"
    force = opt(a, "--force-exe", "")
    if force and mode == "no":
        die("--force-exe only applies with --pass-paths")
    binary = app_binary(app)
    exe = exe or detect_exe(appid)
    name = opt(a, "--name", os.path.splitext(os.path.basename(os.path.abspath(app)))[0])
    for v in (binary, exe, force, name):
        if "\t" in v or "\n" in v:
            die("tabs and newlines are not allowed in values")
    old = [r for r in read_conf(conf) if r[0] == appid]
    envs = old[0][6] if old else ""   # re-adding a game keeps its environment
    rows = [r for r in read_conf(conf) if r[0] != appid] + [[appid, binary, exe, force, mode, name, envs]]
    write_conf(conf, rows)
    print("%s (%s) -> %s, %s" % (name, appid, binary, "with the exe path and game folder" if mode == "yes" else "with the game's arguments"))
    print("in Steam: %s > Properties > Compatibility > Force the use of a specific Steam Play compatibility tool > %s"
          % (name, open(os.path.join(tool, "compatibilitytool.vdf")).read().split('"display_name" "')[1].split('"')[0]))


def cmd_set_env(a):
    tid, tool = tool_dir(a)
    conf = os.path.join(tool, "games.conf")
    appid = opt(a, "--appid")
    vals = [v for v in a if "=" in v and not v.startswith("-")]
    for v in vals:
        n = v.split("=", 1)[0]
        if not n or not (n[0].isalpha() or n[0] == "_") or not n.replace("_", "").isalnum():
            die("not a NAME=value setting: %s" % v)
        if n.startswith("DYLD_"):
            die("%s: libraries come from Steam's overlay and NotProton plugins" % n)
        if " " in v or "\t" in v:
            die("no spaces or tabs in values: %s" % v)
    rows = read_conf(conf)
    hit = [r for r in rows if r[0] == appid]
    if not hit:
        die("app %s is not registered" % appid)
    hit[0][6] = " ".join(vals)
    write_conf(conf, rows)
    print("%s (%s): %s" % (hit[0][5], appid, hit[0][6] or "no environment"))


def cmd_remove(a):
    tid, tool = tool_dir(a)
    conf = os.path.join(tool, "games.conf")
    appid = opt(a, "--appid")
    rows = read_conf(conf)
    keep = [r for r in rows if r[0] != appid]
    if len(keep) == len(rows):
        die("app %s is not registered" % appid)
    write_conf(conf, keep)
    print("removed", appid)


def cmd_list(a):
    tid, tool = tool_dir(a)
    for r in read_conf(os.path.join(tool, "games.conf")):
        print("%-8s %-28s %-11s exe=%s  force=%s%s\n         %s" % (r[0], r[5], "pass-paths" if r[4] == "yes" else "-", r[2], r[3] or "-",
                                                         "  env=" + r[6] if r[6] else "", r[1]))


def cmd_uninstall(a):
    tid, tool = tool_dir(a)
    shutil.rmtree(tool, ignore_errors=True)
    print("removed", tool)


COMMANDS = {"install": cmd_install, "add": cmd_add, "set-env": cmd_set_env, "remove": cmd_remove, "list": cmd_list,
            "uninstall": cmd_uninstall}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(2)
    COMMANDS[sys.argv[1]](sys.argv[2:])
