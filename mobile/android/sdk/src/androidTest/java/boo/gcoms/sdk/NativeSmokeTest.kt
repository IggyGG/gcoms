package boo.gcoms.sdk

import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File

class NativeSmokeTest {
    @Test fun loadsRoleAndOwnsNativeResults() = runBlocking {
        val sdk = GComs()
        try {
            try { sdk.identity(); fail("suspended profile accepted identity") }
            catch (_: GComsException) { }
            sdk.suspendProfile()
        } finally { sdk.close() }
        sdk.close()
    }

    @Test fun relayProfileChannelsFilesAndLifecycle() = runBlocking {
        assumeTrue(BuildConfig.NATIVE_ROLE == 2)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.noBackupFilesDir, "smoke-" + System.nanoTime()).apply { mkdir() }
        val sdk = GComs()
        val config = JSONObject().put("application", "mobile-smoke")
            .put("profile", File(directory, "profile").absolutePath)
            .put("secret", "disposable-emulator-secret").put("fixture", true)
        try {
            val first = sdk.open(config) as JSONObject
            val channel = sdk.request(JSONObject().put("op", "create_channel").put("channel", "smoke")
                .put("display", "owner").put("capacity", 8).put("visibility", "Private")) as JSONArray
            val invitation = sdk.request(JSONObject().put("op", "create_invitation")
                .put("channel", "smoke").put("lifetime_secs", 3600)) as JSONObject
            assertTrue(invitation.getString("link").isNotEmpty())
            val bytes = ByteArray(256 * 1024 + 17) { (it % 251).toByte() }
            val id = sdk.importFile(JSONObject().put("channel", channel).put("participants", JSONArray()),
                "smoke.bin", bytes.size.toLong(), ByteArrayInputStream(bytes))
            sdk.suspendProfile()
            val second = sdk.open(config) as JSONObject
            assertEquals(first.getString("safety_number"), second.getString("safety_number"))
            val output = ByteArrayOutputStream()
            sdk.exportFile(id, output)
            assertArrayEquals(bytes, output.toByteArray())
        } finally {
            sdk.close()
            directory.deleteRecursively()
        }
    }
}
