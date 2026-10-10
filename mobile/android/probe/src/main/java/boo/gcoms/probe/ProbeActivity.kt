package boo.gcoms.probe

import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import android.app.Activity
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * M1 install-chain probe. Proves that the Pico's blind stock-Android flow
 * (launcher search -> Chrome -> APK URL -> unknown sources -> package
 * installer -> Install/Open) reached execution, and reports the device
 * identity the Pico could not fingerprint.
 *
 * Optional extras:
 *   --es report_url https://...   POST a JSON marker to a canary endpoint
 *   --es marker PICO-PROBE-XYZ    marker text (default: build timestamp)
 */
class ProbeActivity : Activity() {
    private val stamp: String
        get() = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val marker = intent.getStringExtra("marker") ?: "PICO-PROBE ${Build.MODEL}"
        val reportUrl = intent.getStringExtra("report_url")
        val record = buildString {
            append("marker=").append(marker).append('\n')
            append("model=").append(Build.MODEL).append('\n')
            append("manufacturer=").append(Build.MANUFACTURER).append('\n')
            append("android=").append(Build.VERSION.RELEASE)
            append(" sdk=").append(Build.VERSION.SDK_INT).append('\n')
            append("time=").append(stamp).append('\n')
        }
        // Durable on-device proof independent of any network.
        File(filesDir, "probe.txt").writeText(record)
        Log.i("PicoProbe", record)
        val view = TextView(this).apply {
            text = "Pico probe OK\n\n$record"
            textSize = 16f
            setPadding(48, 96, 48, 48)
        }
        setContentView(view)
        if (!reportUrl.isNullOrBlank()) {
            thread {
                runCatching { post(reportUrl, record) }
                    .onFailure { Log.w("PicoProbe", "report failed: $it") }
            }
        }
    }

    private fun post(url: String, body: String) {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 8000
            readTimeout = 8000
            setRequestProperty("Content-Type", "text/plain")
        }
        conn.outputStream.use { it.write(body.toByteArray()) }
        Log.i("PicoProbe", "report status=${conn.responseCode}")
        conn.disconnect()
    }
}