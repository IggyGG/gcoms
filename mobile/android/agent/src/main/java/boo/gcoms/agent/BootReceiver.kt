package boo.gcoms.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/** Re-arm where boot-time data sync is permitted; otherwise wait for the activity. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        // Android 15+ forbids a dataSync foreground service from BOOT_COMPLETED
        // for apps targeting 35+. This broadcast can also arrive on the first
        // activity launch after a force-stop; it must not kill that activity.
        if (Build.VERSION.SDK_INT >= 35 && context.applicationInfo.targetSdkVersion >= 35) {
            Log.i("GComsAgent", "Boot data sync deferred until the agent is opened")
            return
        }
        try {
            AgentService.start(context)
        } catch (error: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException derives from this
            // platform-independent type (the agent also supports API 26-30).
            Log.w("GComsAgent", "Boot service start deferred by Android", error)
        }
    }
}
