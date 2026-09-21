package boo.gcoms.push

import boo.gcoms.sdk.GComs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** Application-owned HTTPS endpoint; app authentication issues tickets separately. */
class PushGateway(origin: String, private val storage: PushStorage) {
    private val base = URL(origin)
    private val mutex = Mutex()
    init {
        require(base.protocol == "https" && base.host.isNotEmpty() && base.userInfo == null &&
            base.query == null && base.ref == null && base.path in listOf("", "/"))
    }
    private suspend fun post(path: String, body: JSONObject): JSONObject = withContext(Dispatchers.IO) {
        val bytes = body.toString().toByteArray(Charsets.UTF_8)
        require(bytes.size <= 8192)
        val connection = URL(base, path).openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(bytes.size)
            connection.outputStream.use { it.write(bytes) }
            check(connection.responseCode in 200..299) { "Push gateway rejected request" }
            connection.inputStream.use {
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(1024)
                while (true) {
                    val count = it.read(buffer)
                    if (count < 0) break
                    check(output.size() + count <= 8192) { "Push gateway response is too large" }
                    output.write(buffer, 0, count)
                }
                val reply = output.toByteArray()
                JSONObject(reply.toString(Charsets.UTF_8))
            }
        } finally { bytes.fill(0); connection.disconnect() }
    }
    /** Token rotation needs a fresh one-use ticket from the app's authenticated server. */
    suspend fun register(ticket: String, deviceToken: String) = mutex.withLock {
        require(ticket.length <= 4096 && deviceToken.length in 1..4096)
        val reply = post("/v1/register", JSONObject().put("ticket", ticket)
            .put("platform", "fcm").put("token", deviceToken))
        val reference = reply.getString("reference")
        val management = reply.getString("management_token")
        require(reference.matches(Regex("[0-9a-f]{64}")) && management.matches(Regex("[0-9a-f]{64}")))
        val state = storage.load()
        state.put("reference", reference).put("management_token", management).put("expires", reply.getLong("expires"))
        storage.save(state)
    }
    /** Persist a revision before binding; call after reopen and before suspension. */
    suspend fun bind(sdk: GComs) = mutex.withLock {
        val state = storage.load()
        val reference = state.optString("reference", "0".repeat(64))
        val revision = Math.addExact(state.optLong("revision", 0), 1)
        val now = System.currentTimeMillis() / 1000
        val expiry = if (reference == "0".repeat(64)) now + 3600 else minOf(now + 23 * 3600, state.getLong("expires"))
        require(expiry > now) { "Refresh expired push registration first" }
        state.put("revision", revision)
        storage.save(state)
        val bytes = JSONArray((0 until 32).map { reference.substring(it * 2, it * 2 + 2).toInt(16) })
        sdk.request(JSONObject().put("op", "bind_push").put("reference", bytes)
            .put("revision", revision).put("expires", expiry))
    }
    /** Provider opt-out first. Call bind afterwards to remove current relay bindings. */
    suspend fun unregister() = mutex.withLock {
        val state = storage.load()
        if (state.has("reference")) post("/v1/unregister", JSONObject()
            .put("reference", state.getString("reference")).put("management_token", state.getString("management_token")))
        storage.save(JSONObject().put("revision", state.optLong("revision", 0)))
    }
}
