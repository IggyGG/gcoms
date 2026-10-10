package boo.gcoms.agent

import android.content.Context
import android.util.Log
import java.io.File

/** Fetch, verify and launch the authorized worker in this application process. */
object DropshipRunner {
    private const val TAG = "GComsDropship"

    /** Zero requires the downloaded worker's real runtime-ready signal. */
    fun runInProcess(context: Context, artifact: ByteArray): Int {
        if (!DropshipNative.ready()) return 1
        val deploymentFile = File(context.filesDir, "deployment-request.json")
        val deployment = if (deploymentFile.exists()) try {
            if (deploymentFile.length() > 2048) return 1
            org.json.JSONObject(deploymentFile.readText()).also { request ->
                for (key in listOf("release_id", "apk_sha256", "worker_sha256")) {
                    if (!request.getString(key).matches(Regex("[0-9a-f]{64}"))) return 1
                }
            }
        } catch (_: Exception) { return 1 } else null
        // A retained success from a previous process cannot qualify this run.
        val readyFile = File(context.filesDir, "deployment-ready.json")
        if (readyFile.exists() && !readyFile.delete()) return 1
        // Retain the separately verified BLE delivery; it is never treated as
        // an executable or substituted for the signed GC/2 worker artifact.
        File(context.filesDir, "dropship-artifact.bin").writeBytes(artifact)
        val profileFile = File(context.filesDir, "dropship-config.json")
        val profile = if (profileFile.isFile) profileFile.readBytes() else try {
            context.assets.open("dropship-config.json").use { it.readBytes() }
        } catch (_: Exception) { null }
        if (profile == null) {
            Log.e(TAG, "No authenticated Dropship configuration")
            return 1
        }
        val state = File(context.filesDir, "d")
        // Native code creates and validates a private 0700 state directory.
        val rc = DropshipNative.installerRun(profile, state.absolutePath)
        if (rc != 0 || DropshipNative.workerStatus() != 1) {
            Log.e(TAG, "Downloaded worker not ready: installer=$rc status=${DropshipNative.workerStatus()}")
            return 1
        }
        val receipt = try { org.json.JSONObject(File(state, "payload-evidence.json").readText()) }
            catch (_: Exception) { return 1 }
        if (receipt.optString("outcome") != "launched" ||
            receipt.optString("executionMode") != "in-process-library" ||
            !receipt.optBoolean("payloadVerified") || !receipt.optBoolean("admissionVerified")) return 1
        if (deployment != null) {
            if (receipt.optString("artifactSha256") != deployment.getString("worker_sha256") ||
                receipt.optLong("processId") != android.os.Process.myPid().toLong()) return 1
            deployment.put("process_id", android.os.Process.myPid())
                .put("full_download_verified", true)
                .put("admission_verified", true)
                .put("loaded_worker_ready", true)
            // MODE_PRIVATE keeps this observation within the installed app.
            // Host verification also checks the installed APK hash and live PID.
            context.openFileOutput("deployment-ready.json", Context.MODE_PRIVATE).use {
                it.write(deployment.toString().toByteArray(Charsets.UTF_8))
            }
        }
        Log.i(TAG, "Verified downloaded worker launched in-process; runtime ready")
        return 0
    }

    fun stop(): Int = DropshipNative.workerStop()
}
