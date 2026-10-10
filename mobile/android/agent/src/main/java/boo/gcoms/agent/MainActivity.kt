package boo.gcoms.agent

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/** Minimal control surface: start the agent and show its state. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AgentService.start(this)
        val view = TextView(this).apply {
            text = "GComs Agent\n\nThe foreground service is starting.\n" +
                "Place the deployment config at files/agent-config.json " +
                "(profile + signed network + installation invitation)."
            textSize = 16f
            setPadding(48, 96, 48, 48)
        }
        setContentView(view)
    }
}