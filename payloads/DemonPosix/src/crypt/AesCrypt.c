/*
 * AesCrypt.c — AES-256 CTR encryption for the POSIX Demon agent.
 *
 * The Havoc teamserver uses AES-256 CTR mode (Go's crypto/cipher.NewCTR).
 * CTR is a stream cipher: encrypt == decrypt, no padding needed.
 * Output length always equals input length.
 *
 * This is a pure-C implementation with no external dependencies.
 */

#include "DemonPosix.h"

/* ── AES S-box ───────────────────────────────────────────────────────── */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t Rcon[11] = {
    0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

typedef struct { uint8_t RoundKey[240]; } AES256_CTX;

static void AES256_KeyExpansion(AES256_CTX *ctx, const uint8_t *key)
{
    int i, j;
    uint8_t tmp[4];
    for (i = 0; i < 8; i++) {
        ctx->RoundKey[i*4+0] = key[i*4+0];
        ctx->RoundKey[i*4+1] = key[i*4+1];
        ctx->RoundKey[i*4+2] = key[i*4+2];
        ctx->RoundKey[i*4+3] = key[i*4+3];
    }
    for (; i < 60; i++) {
        int k = (i-1)*4;
        tmp[0] = ctx->RoundKey[k+0];
        tmp[1] = ctx->RoundKey[k+1];
        tmp[2] = ctx->RoundKey[k+2];
        tmp[3] = ctx->RoundKey[k+3];
        if (i % 8 == 0) {
            uint8_t u = tmp[0];
            tmp[0] = sbox[tmp[1]] ^ Rcon[i/8];
            tmp[1] = sbox[tmp[2]];
            tmp[2] = sbox[tmp[3]];
            tmp[3] = sbox[u];
        } else if (i % 8 == 4) {
            tmp[0] = sbox[tmp[0]]; tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]]; tmp[3] = sbox[tmp[3]];
        }
        j = i*4; k = (i-8)*4;
        ctx->RoundKey[j+0] = ctx->RoundKey[k+0] ^ tmp[0];
        ctx->RoundKey[j+1] = ctx->RoundKey[k+1] ^ tmp[1];
        ctx->RoundKey[j+2] = ctx->RoundKey[k+2] ^ tmp[2];
        ctx->RoundKey[j+3] = ctx->RoundKey[k+3] ^ tmp[3];
    }
}

typedef uint8_t state_t[4][4];

static void SubBytes(state_t *s)   { for(int i=0;i<4;i++) for(int j=0;j<4;j++) (*s)[i][j]=sbox[(*s)[i][j]]; }
static void ShiftRows(state_t *s)  {
    uint8_t t;
    t=(*s)[0][1];(*s)[0][1]=(*s)[1][1];(*s)[1][1]=(*s)[2][1];(*s)[2][1]=(*s)[3][1];(*s)[3][1]=t;
    t=(*s)[0][2];(*s)[0][2]=(*s)[2][2];(*s)[2][2]=t;t=(*s)[1][2];(*s)[1][2]=(*s)[3][2];(*s)[3][2]=t;
    t=(*s)[3][3];(*s)[3][3]=(*s)[2][3];(*s)[2][3]=(*s)[1][3];(*s)[1][3]=(*s)[0][3];(*s)[0][3]=t;
}
static uint8_t xtime(uint8_t x) { return (x<<1)^(((x>>7)&1)*0x1b); }
static void MixColumns(state_t *s) {
    for(int i=0;i<4;i++){uint8_t t=(*s)[i][0],tmp=(*s)[i][0]^(*s)[i][1]^(*s)[i][2]^(*s)[i][3];
        (*s)[i][0]^=xtime((*s)[i][0]^(*s)[i][1])^tmp;(*s)[i][1]^=xtime((*s)[i][1]^(*s)[i][2])^tmp;
        (*s)[i][2]^=xtime((*s)[i][2]^(*s)[i][3])^tmp;(*s)[i][3]^=xtime((*s)[i][3]^t)^tmp;}
}
static void AddRoundKey(uint8_t round, state_t *s, const uint8_t *rk) {
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) (*s)[i][j]^=rk[round*16+i*4+j];
}
static void buf2state(state_t *s, const uint8_t *b) { for(int i=0;i<4;i++)for(int j=0;j<4;j++)(*s)[i][j]=b[i*4+j]; }
static void state2buf(uint8_t *b, const state_t *s)  { for(int i=0;i<4;i++)for(int j=0;j<4;j++)b[i*4+j]=(*s)[i][j]; }

/* Encrypt one 16-byte block in-place */
static void AES256_EncryptBlock(const AES256_CTX *ctx, uint8_t *block)
{
    state_t s;
    buf2state(&s, block);
    AddRoundKey(0, &s, ctx->RoundKey);
    for (int r = 1; r < 14; r++) {
        SubBytes(&s); ShiftRows(&s); MixColumns(&s); AddRoundKey(r, &s, ctx->RoundKey);
    }
    SubBytes(&s); ShiftRows(&s); AddRoundKey(14, &s, ctx->RoundKey);
    state2buf(block, &s);
}

/* ── Increment a 16-byte big-endian counter (CTR mode) ──────────────── */
static void ctr_inc(uint8_t *ctr)
{
    for (int i = 15; i >= 0; i--) {
        if (++ctr[i]) break;
    }
}

/* ── Public API: AES-256 CTR (matches Go's crypto/cipher.NewCTR) ──────
 *
 * CTR is symmetric: AES256_Encrypt == AES256_Decrypt.
 * out may equal in (in-place).
 * Returns 0 on success, -1 on error.
 */
int AES256_Encrypt(const uint8_t *in,  size_t in_len,
                   uint8_t       *out, size_t *out_len,
                   const uint8_t *key, const uint8_t *iv)
{
    if (!in || !out || !out_len || !key || !iv) return -1;

    AES256_CTX ctx;
    AES256_KeyExpansion(&ctx, key);

    uint8_t ctr[16];
    memcpy(ctr, iv, 16);   /* IV is the initial counter value */

    uint8_t keystream[16];
    size_t  offset = 0;

    while (offset < in_len) {
        /* Generate one keystream block by encrypting the counter */
        memcpy(keystream, ctr, 16);
        AES256_EncryptBlock(&ctx, keystream);
        ctr_inc(ctr);

        size_t chunk = in_len - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }

    *out_len = in_len;   /* CTR: no padding, output == input length */
    return 0;
}

/* CTR decrypt == CTR encrypt */
int AES256_Decrypt(const uint8_t *in,  size_t in_len,
                   uint8_t       *out, size_t *out_len,
                   const uint8_t *key, const uint8_t *iv)
{
    return AES256_Encrypt(in, in_len, out, out_len, key, iv);
}
