//! JNI copies into Java-owned byte arrays; platform code never sees Rust pointers.
use super::*;
use jni::{
    objects::{JByteArray, JClass},
    sys::{jbyteArray, jint, jlong},
    JNIEnv,
};

#[no_mangle]
pub extern "system" fn Java_boo_gcoms_sdk_Native_create(_: JNIEnv, _: JClass) -> jlong {
    gcoms_mobile_create() as jlong
}
#[no_mangle]
pub extern "system" fn Java_boo_gcoms_sdk_Native_role(_: JNIEnv, _: JClass) -> jint {
    gcoms_mobile_role() as jint
}
#[no_mangle]
pub extern "system" fn Java_boo_gcoms_sdk_Native_submit(
    mut env: JNIEnv,
    _: JClass,
    session: jlong,
    request: JByteArray,
) -> jlong {
    boundary(0, || {
        if !env
            .get_array_length(&request)
            .is_ok_and(|n| n > 0 && n as usize <= MAX_REQUEST)
        {
            return 0;
        }
        match env.convert_byte_array(&request) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                // SAFETY: slice remains alive through the copying call.
                unsafe { gcoms_mobile_submit(session as u64, bytes.as_ptr(), bytes.len()) as jlong }
            }
            Err(_) => {
                let _ = env.throw_new(
                    "java/lang/IllegalStateException",
                    "Cannot copy native request",
                );
                0
            }
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_boo_gcoms_sdk_Native_take(
    mut env: JNIEnv,
    _: JClass,
    session: jlong,
    ticket: jlong,
) -> jbyteArray {
    boundary(std::ptr::null_mut(), || {
        // SAFETY: null output is the supported non-consuming length query.
        let length =
            unsafe { gcoms_mobile_take(session as u64, ticket as u64, std::ptr::null_mut(), 0) };
        if length == 0 {
            return std::ptr::null_mut();
        }
        if length < 0 || length as usize > MAX_RESPONSE {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "Native ticket is unavailable",
            );
            return std::ptr::null_mut();
        }
        let mut bytes = Zeroizing::new(vec![0; length as usize]);
        // SAFETY: buffer has exactly the requested capacity.
        let copied = unsafe {
            gcoms_mobile_take(
                session as u64,
                ticket as u64,
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        if copied != length {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "Native ticket was consumed concurrently",
            );
            return std::ptr::null_mut();
        }
        match env.byte_array_from_slice(&bytes) {
            Ok(array) => array.into_raw(),
            Err(_) => {
                let _ = env.throw_new("java/lang/OutOfMemoryError", "Cannot copy native result");
                std::ptr::null_mut()
            }
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_boo_gcoms_sdk_Native_cancel(
    _: JNIEnv,
    _: JClass,
    session: jlong,
    ticket: jlong,
) -> jint {
    gcoms_mobile_cancel(session as u64, ticket as u64)
}
#[no_mangle]
pub extern "system" fn Java_boo_gcoms_sdk_Native_destroy(
    _: JNIEnv,
    _: JClass,
    session: jlong,
) -> jint {
    gcoms_mobile_destroy(session as u64)
}
