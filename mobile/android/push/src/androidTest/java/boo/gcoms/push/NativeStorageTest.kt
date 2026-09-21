package boo.gcoms.push

import androidx.datastore.core.MultiProcessDataStoreFactory
import androidx.datastore.core.Serializer
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

class NativeStorageTest {
    @Test fun nativeSharedCounterSupportsTheQualificationEmulator() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val file = context.noBackupFilesDir.resolve("counter-${UUID.randomUUID()}")
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            val store = MultiProcessDataStoreFactory.create(
                serializer = object : Serializer<Int> {
                    override val defaultValue = 0
                    override suspend fun readFrom(input: InputStream) = input.read().coerceAtLeast(0)
                    override suspend fun writeTo(t: Int, output: OutputStream) = output.write(t)
                },
                scope = scope,
                produceFile = { file },
            )
            withTimeout(10_000) {
                assertEquals(1, store.updateData { it + 1 })
                assertEquals(1, store.data.first())
            }
        } finally {
            scope.cancel()
        }
    }
}
