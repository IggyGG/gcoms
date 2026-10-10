package boo.gcoms.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import boo.gcoms.sdk.GComs
import boo.gcoms.sdk.KeystoreUnlockProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

/**
 * M2 agent foreground service.
 *
 * Loads a deployment config from `filesDir/agent-config.json` (never
 * committed; pushed or embedded at install time), opens the GComs client
 * profile, enrolls with the installation invitation when present, and polls
 * the durable inbox. Fails closed when the config is missing.
 */
class AgentService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var sdk: GComs? = null
    private var runJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, notification("starting"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (runJob?.isActive != true) {
            runJob = scope.launch { run() }
        } else {
            Log.i(TAG, "Agent run already active")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun run() {
        Log.i(TAG, "DS-MIN core ABI=${DropshipNative.abiVersion()} ready=${DropshipNative.ready()}")
        // Rig path (no Bluetooth): if a dropship config is present, run the
        // in-process installer + drone on start. The virtual rig uses this
        // (the iOS simulator and Android emulator have no usable BLE).
        val rigAsset = try {
            assets.open("dropship-config.json").use { true }
        } catch (_: Exception) {
            false
        }
        if (File(filesDir, "dropship-config.json").isFile || rigAsset) {
            updateNotification("dropship run")
            val rc = DropshipRunner.runInProcess(this, ByteArray(0))
            Log.i(TAG, "rig dropship run rc=$rc")
        }
        val raw = loadConfig()
        if (raw == null) {
            Log.w(TAG, "no agent-config.json (filesDir or asset); failing closed")
            updateNotification("no config")
            return
        }
        // Over-the-air dropship: if the config pins a BLE attempt id, receive the
        // DS-MIN artifacts from the Pico before enrolling. The verified artifact
        // is handed to the in-process runner (the drone), never exec'd.
        raw.optJSONObject("ble")?.optString("attempt")?.takeIf { it.isNotEmpty() }?.let { attempt ->
            updateNotification("BLE receive $attempt")
            val receiver = BleReceiver(
                context = this,
                attemptId = attempt,
                onArtifact = { role, bytes ->
                    File(filesDir, "dropship-$role.bin").writeBytes(bytes)
                    Log.i(TAG, "received $role ${bytes.size}B")
                    if (role == "ARTIFACT") DropshipRunner.runInProcess(this, bytes) else 0
                },
                onFinished = { ok, detail -> Log.i(TAG, "BLE receive done ok=$ok ($detail)") },
            )
            receiver.start()
        }
        try {
            val application = raw.optString("application", "pico-mobile-agent")
            val profile = File(noBackupFilesDir, "profile").absolutePath
            val unlock = KeystoreUnlockProvider(this, "agent")
            val secret = String(unlock.unlock())
            val config = JSONObject()
                .put("application", application)
                .put("profile", profile)
                .put("secret", secret)
            raw.optJSONArray("relay")?.let { config.put("relay", it) }

            val session = GComs().also { sdk = it }
            session.open(config)
            raw.optString("invitation").takeIf { it.isNotEmpty() }?.let { link ->
                val started = session.startEnrollment(link, Build.MODEL) as JSONObject
                Log.i(TAG, "enrollment started: $started")
            }
            val identity = session.identity()
            File(filesDir, "agent-identity.json").writeText(identity.toString())
            updateNotification("running ${identity.optString("safety_number")}")
            Log.i(TAG, "agent running")

            var cursor = 0L
            while (scope.isActive) {
                val inbox = session.inbox(cursor)
                val messages = inbox.optJSONArray("messages")
                if (messages != null && messages.length() > 0) {
                    cursor = inbox.optLong("next_after", cursor)
                    File(filesDir, "agent-inbox.json").writeText(messages.toString())
                    Log.i(TAG, "inbox ${messages.length()} at $cursor")
                }
                delay(5000)
            }
        } catch (error: Throwable) {
            Log.e(TAG, "agent failed: $error")
            updateNotification("failed")
        }
    }

    private fun loadConfig(): JSONObject? {
        val file = File(filesDir, "agent-config.json")
        if (file.isFile) return JSONObject(file.readText())
        return try {
            val text = assets.open("agent-config.json").bufferedReader().use { it.readText() }
            JSONObject(text)
        } catch (_: Exception) {
            null
        }
    }

    private fun notification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "Agent", NotificationManager.IMPORTANCE_LOW))
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL).setContentTitle("GComs Agent")
                .setContentText(text).setSmallIcon(android.R.drawable.stat_notify_sync).build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this).setContentTitle("GComs Agent")
                .setContentText(text).setSmallIcon(android.R.drawable.stat_notify_sync).build()
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        private const val TAG = "GComsAgent"
        private const val CHANNEL = "agent"
        private const val NOTIFICATION_ID = 1
        fun start(context: Context) {
            context.startForegroundService(Intent(context, AgentService::class.java))
        }
    }
}
