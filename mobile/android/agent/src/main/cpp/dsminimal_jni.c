/* The JNI bridge links only DS-MIN. The signed worker is downloaded and loaded
 * from the exact verified descriptor by its native mobile launch backend. */
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
extern uint32_t ds_minimal_abi_version(void);
extern uint32_t ds_minimal_loaded_worker_status(void);
extern int ds_minimal_loaded_worker_stop(void);
extern int ds_minimal_install_config(const uint8_t *, size_t, const char *);
JNIEXPORT jint JNICALL Java_boo_gcoms_agent_DropshipNative_abiVersionNative(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz; return (jint)ds_minimal_abi_version();
}
JNIEXPORT jint JNICALL Java_boo_gcoms_agent_DropshipNative_workerStatusNative(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz; return (jint)ds_minimal_loaded_worker_status();
}
JNIEXPORT jint JNICALL Java_boo_gcoms_agent_DropshipNative_workerStopNative(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz; return (jint)ds_minimal_loaded_worker_stop();
}

/* Run the DS-MIN installer in-process from a profile document + state dir.
 * Returns the installer result code (0 = receipt produced). */
JNIEXPORT jint JNICALL
Java_boo_gcoms_agent_DropshipNative_installerRunNative(JNIEnv *env, jclass clazz,
                                                 jbyteArray config, jstring stateDir) {
    (void)clazz;
    if (config == NULL || stateDir == NULL) return 3;
    jsize len = (*env)->GetArrayLength(env, config);
    if (len <= 0) return 3;
    jbyte *bytes = (*env)->GetByteArrayElements(env, config, NULL);
    if (bytes == NULL) return 3;
    const char *path = (*env)->GetStringUTFChars(env, stateDir, NULL);
    if (path == NULL) {
        (*env)->ReleaseByteArrayElements(env, config, bytes, JNI_ABORT);
        return 3;
    }
    int rc = ds_minimal_install_config((const uint8_t *)bytes, (size_t)len, path);
    (*env)->ReleaseStringUTFChars(env, stateDir, path);
    (*env)->ReleaseByteArrayElements(env, config, bytes, JNI_ABORT);
    return (jint)rc;
}
