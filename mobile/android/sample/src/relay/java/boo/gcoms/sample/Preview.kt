package boo.gcoms.sample
import boo.gcoms.sdk.GComs
import kotlinx.coroutines.runBlocking
object Preview {
    fun text(): String {
        val sdk = GComs()
        runBlocking { sdk.close() }
        return "GComs relay preview\nNative interface loaded. Configure your signed network and invitation in the host app."
    }
}
