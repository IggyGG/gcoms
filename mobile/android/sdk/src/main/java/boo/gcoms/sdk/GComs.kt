package boo.gcoms.sdk

import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

internal object Native {
    init { System.loadLibrary("gcoms_mobile") }
    @JvmStatic external fun create(): Long
    @JvmStatic external fun role(): Int
    @JvmStatic external fun submit(session: Long, request: ByteArray): Long
    @JvmStatic external fun take(session: Long, ticket: Long): ByteArray?
    @JvmStatic external fun cancel(session: Long, ticket: Long): Int
    @JvmStatic external fun destroy(session: Long): Int
}

/** Exactly one SDK role per app. Suspend before the OS suspends network execution. */
class GComs {
    private val handle: AtomicLong
    init {
        check(Native.role() == BuildConfig.NATIVE_ROLE) { "Mixed client and relay libraries" }
        handle = AtomicLong(Native.create().also { check(it != 0L) { "Native session limit reached" } })
    }

    /** Cancellation releases the ticket; a running durable mutation may still complete. */
    suspend fun request(command: JSONObject): Any? = withContext(Dispatchers.IO) {
        val session = handle.get()
        check(session != 0L) { "GComs is closed" }
        val bytes = command.toString().toByteArray(Charsets.UTF_8)
        val ticket = try { Native.submit(session, bytes) } finally { bytes.fill(0) }
        check(ticket != 0L) { "Native queue full or request too large" }
        try {
            while (true) {
                ensureActive()
                val response = Native.take(session, ticket)
                if (response != null) {
                    val value = try { JSONObject(response.toString(Charsets.UTF_8)) } finally { response.fill(0) }
                    if (value.has("error")) throw GComsException(value.getString("error"))
                    return@withContext value.opt("ok").takeUnless { it === JSONObject.NULL }
                }
                delay(10)
            }
            @Suppress("UNREACHABLE_CODE") null
        } finally { Native.cancel(session, ticket) }
    }

    suspend fun open(config: JSONObject) = request(JSONObject().put("op", "open").put("config", config))
    suspend fun suspendProfile() = request(JSONObject().put("op", "suspend"))
    suspend fun close() = withContext(Dispatchers.IO + NonCancellable) {
        val session = handle.getAndSet(0)
        if (session != 0L) check(Native.destroy(session) == 0) { "Native shutdown failed" }
    }
    suspend fun identity() = request(JSONObject().put("op", "identity")) as JSONObject
    suspend fun channels() = request(JSONObject().put("op", "channels")) as JSONArray
    suspend fun events() = request(JSONObject().put("op", "events")) as JSONArray
    suspend fun inbox(after: Long = 0, limit: Int = 16) =
        request(JSONObject().put("op", "inbox").put("after", after).put("limit", limit)) as JSONObject
    suspend fun acknowledge(sequence: Long, digest: JSONArray) =
        request(JSONObject().put("op", "acknowledge").put("sequence", sequence).put("digest", digest))
    suspend fun files(value: Any) = request(JSONObject().put("op", "files").put("request", value))

    /** Streams may be ContentResolver streams. They remain owned by the caller. */
    suspend fun importFile(scope: JSONObject, name: String, size: Long, source: InputStream): JSONArray =
        withContext(Dispatchers.IO) {
            require(size in 0..10L * 1024 * 1024 * 1024)
            val id = ByteArray(16).also { SecureRandom().nextBytes(it) }.json()
            files(JSONObject().put("Prepare", JSONObject().put("id", id).put("scope", scope).put("name", name).put("size_bytes", size)))
            try {
                var remaining = size
                var piece = 0
                val buffer = ByteArray(256 * 1024)
                try {
                    while (remaining > 0) {
                        val count = minOf(remaining, buffer.size.toLong()).toInt()
                        var offset = 0
                        while (offset < count) {
                            ensureActive()
                            val read = source.read(buffer, offset, count - offset)
                            check(read > 0) { "Source ended before declared length" }
                            offset += read
                        }
                        val bytes = JSONArray()
                        for (index in 0 until count) bytes.put(buffer[index].toInt() and 255)
                        files(JSONObject().put("WritePiece", JSONObject().put("id", id).put("piece", piece++).put("bytes", bytes)))
                        remaining -= count
                    }
                    check(source.read() == -1) { "Source exceeds declared length" }
                } finally { buffer.fill(0) }
                files(JSONObject().put("Commit", JSONObject().put("id", id)))
                id
            } catch (error: Throwable) {
                withContext(NonCancellable) { runCatching { files(JSONObject().put("Cancel", JSONObject().put("id", id))) } }
                throw error
            }
        }

    suspend fun exportFile(id: JSONArray, destination: OutputStream) = withContext(Dispatchers.IO) {
        val snapshot = (files("List") as JSONObject).getJSONObject("Snapshot").getJSONArray("files")
        val info = (0 until snapshot.length()).map { snapshot.getJSONObject(it) }
            .first { it.getJSONArray("id").toString() == id.toString() }
        check(info.getString("status") == "Complete") { "File is not complete" }
        var remaining = info.getLong("size_bytes")
        var piece = 0
        while (remaining > 0) {
            val reply = files(JSONObject().put("ReadPiece", JSONObject().put("id", id).put("piece", piece++))) as JSONObject
            val data = reply.getJSONArray("Piece")
            val count = minOf(remaining, 256L * 1024).toInt()
            check(data.length() == count) { "Invalid piece length" }
            val bytes = ByteArray(count) { data.getInt(it).toByte() }
            try { destination.write(bytes) } finally { bytes.fill(0) }
            remaining -= count
        }
        destination.flush()
    }
}
class GComsException(message: String) : Exception(message)
internal fun ByteArray.json() = JSONArray().also { array -> for (byte in this) array.put(byte.toInt() and 255) }
