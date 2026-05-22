/*
 * Parser.c — Binary deserialization for the POSIX Demon agent.
 *
 * Mirrors the teamserver's pkg/common/parser/parser.go interface.
 * All integers are little-endian, strings are [uint32 len][bytes NUL].
 */

#include "DemonPosix.h"
#include <stdlib.h>
#include <string.h>

/* ── Internal helper ─────────────────────────────────────────────────── */

static inline uint32_t read_u32_le(const uint8_t *b)
{
    return (uint32_t)b[0]
         | ((uint32_t)b[1] << 8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
}

static inline uint64_t read_u64_le(const uint8_t *b)
{
    return (uint64_t)read_u32_le(b) | ((uint64_t)read_u32_le(b+4) << 32);
}

/* ── Public API ─────────────────────────────────────────────────────── */

PARSER *ParserNew(const uint8_t *data, size_t len)
{
    PARSER *p = (PARSER *)malloc(sizeof(PARSER));
    if (!p) return NULL;

    p->Original = (uint8_t *)malloc(len);
    if (!p->Original) { free(p); return NULL; }
    memcpy(p->Original, data, len);

    p->Buffer = p->Original;
    p->Length = len;
    return p;
}

void ParserFree(PARSER *p)
{
    if (!p) return;
    if (p->Original) free(p->Original);
    free(p);
}

int32_t ParserReadInt32(PARSER *p)
{
    if (!p || p->Length < 4) return 0;
    int32_t v = (int32_t)read_u32_le(p->Buffer);
    p->Buffer += 4;
    p->Length -= 4;
    return v;
}

int64_t ParserReadInt64(PARSER *p)
{
    if (!p || p->Length < 8) return 0;
    int64_t v = (int64_t)read_u64_le(p->Buffer);
    p->Buffer += 8;
    p->Length -= 8;
    return v;
}

/*
 * ParserReadBytes — reads [uint32 size][bytes].
 * Returns a pointer into the internal buffer (do NOT free).
 * Sets *out_len to the number of bytes.
 */
uint8_t *ParserReadBytes(PARSER *p, uint32_t *out_len)
{
    if (!p || !out_len || p->Length < 4) return NULL;
    uint32_t sz = read_u32_le(p->Buffer);
    p->Buffer += 4;
    p->Length -= 4;
    if (p->Length < sz) return NULL;
    uint8_t *ptr = p->Buffer;
    p->Buffer += sz;
    p->Length -= sz;
    *out_len = sz;
    return ptr;
}

/*
 * ParserReadString — reads [uint32 size][NUL-terminated string].
 * Returns a pointer into the internal buffer (do NOT free independently).
 * The returned pointer is NUL-terminated.
 */
char *ParserReadString(PARSER *p)
{
    uint32_t sz = 0;
    char *ptr = (char *)ParserReadBytes(p, &sz);
    return ptr; /* already NUL-terminated since Demon adds '\0' */
}

/*
 * ParserDecrypt — AES-256 CBC decrypt the current buffer in-place.
 * Replaces p->Buffer / p->Length with the decrypted (unpadded) content.
 * Returns true on success.
 */
bool ParserDecrypt(PARSER *p, const uint8_t *key, const uint8_t *iv)
{
    if (!p || !key || !iv || p->Length == 0) return false;

    uint8_t *out = (uint8_t *)malloc(p->Length);
    if (!out) return false;

    size_t out_len = 0;
    if (AES256_Decrypt(p->Buffer, p->Length, out, &out_len, key, iv) != 0) {
        free(out);
        return false;
    }

    /* Replace the buffer content */
    memcpy(p->Buffer, out, out_len);
    p->Length = out_len;
    free(out);
    return true;
}
