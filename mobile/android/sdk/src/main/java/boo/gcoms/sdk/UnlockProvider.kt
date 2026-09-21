package boo.gcoms.sdk

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

fun interface UnlockProvider { suspend fun unlock(): CharArray }

/** App-private, non-backup storage plus Android Keystore. Reinstall requires recovery. */
class KeystoreUnlockProvider(context: Context, private val name: String) : UnlockProvider {
    private val root = context.noBackupFilesDir
    init { require(name.matches(Regex("[A-Za-z0-9_-]{1,64}"))) }
    override suspend fun unlock(): CharArray = withContext(Dispatchers.IO) {
        synchronized(KeystoreUnlockProvider::class.java) {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "gcoms.$name"
            val file = AtomicFile(File(root, "$name.unlock"))
            val key = if (store.containsAlias(alias)) store.getKey(alias, null) as SecretKey else {
                check(!file.baseFile.exists()) { "Unlock key is unavailable; use account recovery" }
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                    init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
                }.generateKey()
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val secret: ByteArray
            if (file.baseFile.exists()) {
                val sealed = file.readFully()
                check(sealed.size == 12 + 32 + 16) { "Invalid unlock storage" }
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
                secret = cipher.doFinal(sealed, 12, sealed.size - 12)
            } else {
                secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val stream = file.startWrite()
                try { stream.write(cipher.iv + cipher.doFinal(secret)); file.finishWrite(stream) }
                catch (error: Throwable) { file.failWrite(stream); secret.fill(0); throw error }
            }
            try { Base64.encodeToString(secret, Base64.NO_WRAP).toCharArray() } finally { secret.fill(0) }
        }
    }
}
