package boo.gcoms.sample
import android.app.Activity
import android.os.Bundle
import android.widget.TextView
class MainActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val label = TextView(this).apply { text = "Loading GComs preview"; textSize = 18f; setPadding(24, 48, 24, 24) }
        setContentView(label)
        kotlin.concurrent.thread {
            val result = Preview.text()
            runOnUiThread { if (!isDestroyed) label.text = result }
        }
    }
}
