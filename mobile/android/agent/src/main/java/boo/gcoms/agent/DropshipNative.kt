package boo.gcoms.agent

/**
 * In-process DS-MIN core binding.
 *
 * Loads the native bridge built from `libdsminimal-android-<abi>.a` (the
 * dropship DS-MIN staticlib). The app refuses to run a dropship if the linked
 * core ABI does not match [EXPECTED_ABI]. There is no fork/exec on Android: the
 * core runs in this process, and the BLE receiver's verified artifact is handed
 * to it through [BleReceiver]'s onArtifact callback.
 */
object DropshipNative {
    const val EXPECTED_ABI = 1
    private var loaded = false

    fun load(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("dsminimal_jni")
            loaded = true
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    /** DS-MIN core ABI revision, or -1 when the library is absent. */
    fun abiVersion(): Int = if (load()) abiVersionNative() else -1

    /** True when the core is linked and matches the ABI this app was built for. */
    fun ready(): Boolean = abiVersion() == EXPECTED_ABI

    fun workerStatus(): Int = if (load()) workerStatusNative() else -1
    fun workerStop(): Int = if (load()) workerStopNative() else -1

    /** Zero means a verified downloaded worker reached actual runtime readiness. */
    fun installerRun(config: ByteArray, stateDir: String): Int =
        if (load()) installerRunNative(config, stateDir) else 3

    private external fun abiVersionNative(): Int
    private external fun workerStatusNative(): Int
    private external fun workerStopNative(): Int
    private external fun installerRunNative(config: ByteArray, stateDir: String): Int
}
