package boo.gcoms.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Re-arm the agent after reboot (M2 persistence). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            AgentService.start(context)
        }
    }
}