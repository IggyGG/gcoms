package boo.gcoms.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

object PushHints {
    fun reference(data: Map<String, String>): String? {
        if (data.keys != setOf("gcoms_activity", "gcoms_reference") || data["gcoms_activity"] != "message") return null
        return data["gcoms_reference"]?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
    }
}

/** Declare the application's concrete subclass in its manifest.
 * Callbacks enqueue app-owned, bounded reconciliation/registration work.
 * No GComs profile is opened and no message content is accepted here.
 */
abstract class GComsFirebaseService : FirebaseMessagingService() {
    final override fun onNewToken(token: String) { enqueueTokenRegistration(token) }
    final override fun onMessageReceived(message: RemoteMessage) {
        PushHints.reference(message.data)?.let { enqueueInboxReconciliation(it) }
    }
    abstract fun enqueueTokenRegistration(token: String)
    abstract fun enqueueInboxReconciliation(reference: String)
}
