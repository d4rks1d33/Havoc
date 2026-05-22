/*
 * Package.c — Binary serialization (packer) for the POSIX Demon agent.
 *
 * The wire format is identical to the Windows Demon so the teamserver's
 * existing BuildPayloadMessage / ParseHeader code handles both agents
 * without modification.
 *
 * Frame layout (little-endian):
 *   [4] SIZE         total frame size (not including this field)
 *   [4] MAGIC VALUE  0xDEADBEEF
 *   [4] AGENT ID
 *   [4] COMMAND ID
 *   [4] REQUEST ID
 *   [4] DATA SIZE    size of the (encrypted) data blob
 *   [N] DATA         AES-256 CBC encrypted payload
 */

#include "DemonPosix.h"
#include <stdlib.h>
#include <string.h>

/* ── Internal helpers ────────────────────────────────────────────────── */

static inline void put_u32_le(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)(v);
    buf[1] = (uint8_t)(v >> 8);
    buf[2] = (uint8_t)(v >> 16);
    buf[3] = (uint8_t)(v >> 24);
}

static inline void put_u64_le(uint8_t *buf, uint64_t v)
{
    put_u32_le(buf,   (uint32_t)(v));
    put_u32_le(buf+4, (uint32_t)(v >> 32));
}

static void pkg_ensure(PKG_BUFFER *pkg, size_t extra)
{
    if (pkg->Length + extra <= pkg->Capacity) return;
    size_t new_cap = pkg->Capacity + extra + 4096;
    pkg->Buffer    = (uint8_t *)realloc(pkg->Buffer, new_cap);
    pkg->Capacity  = new_cap;
}

/* ── Public API ─────────────────────────────────────────────────────── */

PKG_BUFFER *PkgCreate(uint32_t commandID, uint32_t requestID)
{
    PKG_BUFFER *pkg = (PKG_BUFFER *)calloc(1, sizeof(PKG_BUFFER));
    if (!pkg) return NULL;

    /* Pre-allocate a reasonable buffer */
    pkg->Capacity = 256;
    pkg->Buffer   = (uint8_t *)malloc(pkg->Capacity);
    pkg->Length   = 0;

    /* Write command ID and request ID at the start of the payload section */
    pkg_ensure(pkg, 8);
    put_u32_le(pkg->Buffer + pkg->Length,     commandID);
    pkg->Length += 4;
    put_u32_le(pkg->Buffer + pkg->Length,     requestID);
    pkg->Length += 4;

    return pkg;
}

void PkgAddInt32(PKG_BUFFER *pkg, int32_t val)
{
    pkg_ensure(pkg, 4);
    put_u32_le(pkg->Buffer + pkg->Length, (uint32_t)val);
    pkg->Length += 4;
}

void PkgAddInt64(PKG_BUFFER *pkg, int64_t val)
{
    pkg_ensure(pkg, 8);
    put_u64_le(pkg->Buffer + pkg->Length, (uint64_t)val);
    pkg->Length += 8;
}

void PkgAddBytes(PKG_BUFFER *pkg, const uint8_t *data, uint32_t len)
{
    pkg_ensure(pkg, 4 + len);
    put_u32_le(pkg->Buffer + pkg->Length, len);
    pkg->Length += 4;
    if (len > 0) {
        memcpy(pkg->Buffer + pkg->Length, data, len);
        pkg->Length += len;
    }
}

void PkgAddString(PKG_BUFFER *pkg, const char *str)
{
    uint32_t len = (uint32_t)(str ? strlen(str) : 0) + 1; /* include NUL */
    pkg_ensure(pkg, 4 + len);
    put_u32_le(pkg->Buffer + pkg->Length, len);
    pkg->Length += 4;
    if (str) memcpy(pkg->Buffer + pkg->Length, str, len);
    else     pkg->Buffer[pkg->Length] = 0;
    pkg->Length += len;
}

void PkgFree(PKG_BUFFER *pkg)
{
    if (!pkg) return;
    if (pkg->Buffer) free(pkg->Buffer);
    free(pkg);
}

/*
 * PkgBuildMessage — wrap the payload in the full C2 frame and AES-encrypt
 * the data section.
 *
 * Frame layout written to the returned buffer:
 *   [4] total_size  (SIZE field = everything after this uint32)
 *   [4] 0xDEADBEEF
 *   [4] AgentID
 *   [4] DATA_SIZE   (size of AES-encrypted blob)
 *   [N] encrypted payload
 *
 * Caller must free() the returned buffer.
 */
uint8_t *PkgBuildMessage(PKG_BUFFER *pkg, const uint8_t *aes_key,
                         const uint8_t *aes_iv, size_t *out_len)
{
    if (!pkg || !aes_key || !aes_iv || !DemonInstance) return NULL;

    /* Encrypt the payload section */
    size_t   enc_len   = pkg->Length + AES_BLOCK_SIZE; /* worst case */
    uint8_t *enc_buf   = (uint8_t *)malloc(enc_len);
    if (!enc_buf) return NULL;

    size_t actual_enc = 0;
    if (AES256_Encrypt(pkg->Buffer, pkg->Length,
                       enc_buf, &actual_enc,
                       aes_key, aes_iv) != 0) {
        free(enc_buf);
        return NULL;
    }

    /*
     * Full frame:
     *   4  SIZE
     *   4  MAGIC
     *   4  AGENTID
     *   4  ENC_DATA_SIZE
     *   N  encrypted data
     */
    size_t frame_body = 4 + 4 + 4 + actual_enc;  /* MAGIC + ID + ENC_SIZE + data */
    size_t total      = 4 + frame_body;            /* SIZE field + body */

    uint8_t *frame = (uint8_t *)malloc(total);
    if (!frame) { free(enc_buf); return NULL; }

    size_t off = 0;
    put_u32_le(frame + off, (uint32_t)frame_body);  off += 4; /* SIZE */
    put_u32_le(frame + off, DEMON_MAGIC_VALUE);      off += 4; /* MAGIC */
    put_u32_le(frame + off, DemonInstance->Session.AgentID); off += 4; /* ID */
    put_u32_le(frame + off, (uint32_t)actual_enc);  off += 4; /* ENC SIZE */
    memcpy(frame + off, enc_buf, actual_enc);        off += actual_enc;

    free(enc_buf);

    *out_len = total;
    return frame;
}
