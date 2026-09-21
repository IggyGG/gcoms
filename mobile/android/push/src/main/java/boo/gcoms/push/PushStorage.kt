package boo.gcoms.push

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** One instance per profile. Replace with an equivalent app-owned durable secure store. */
interface PushStorage {
    suspend fun load(): JSONObject
    suspend fun save(state: JSONObject)
}

class KeystorePushStorage(context: Context, name: String) : PushStorage {
    private val alias = "gcoms.push.$name"
    private val file = AtomicFile(File(context.noBackupFilesDir, "$name.push"))
    init { require(name.matches(Regex("[A-Za-z0-9_-]{1,64}"))) }
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (store.containsAlias(alias)) return store.getKey(alias, null) as SecretKey
        check(!file.baseFile.exists()) { "Push storage key is unavailable" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    override suspend fun load(): JSONObject = withContext(Dispatchers.IO) {
        synchronized(KeystorePushStorage::class.java) {
            if (!file.baseFile.exists()) return@synchronized JSONObject()
            val sealed = file.readFully()
            check(sealed.size in 28..8220)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
            val plain = cipher.doFinal(sealed, 12, sealed.size - 12)
            try { JSONObject(plain.toString(Charsets.UTF_8)) } finally { plain.fill(0) }
        }
    }
    override suspend fun save(state: JSONObject) = withContext(Dispatchers.IO) {
        synchronized(KeystorePushStorage::class.java) {
            val plain = state.toString().toByteArray(Charsets.UTF_8)
            require(plain.size <= 8192)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key())
                val output = file.startWrite()
                try { output.write(cipher.iv + cipher.doFinal(plain)); file.finishWrite(output) }
                catch (error: Throwable) { file.failWrite(output); throw error }
            } finally { plain.fill(0) }
        }
    }
}
