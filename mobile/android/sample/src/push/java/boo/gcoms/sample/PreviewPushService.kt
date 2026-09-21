package boo.gcoms.sample
import boo.gcoms.push.GComsFirebaseService

/** Provider-free size/packaging fixture. A real application queues its own work. */
class PreviewPushService : GComsFirebaseService() {
    override fun enqueueTokenRegistration(token: String) {}
    override fun enqueueInboxReconciliation(reference: String) {}
}
