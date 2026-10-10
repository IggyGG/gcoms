cmake_minimum_required(VERSION 3.22)
project(dsminimal_jni C)

# The DS-MIN core static library is built by dropship/build/build-android.sh and
# its directory is supplied by the build (DSMINIMAL_LIB_DIR). The app ABI names
# differ from the dropship ones only for arm64; the Rust triple differs for both.
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(DS_ABI arm64)
    set(DS_TRIPLE aarch64-linux-android)
else()
    set(DS_ABI ${ANDROID_ABI})
    set(DS_TRIPLE x86_64-linux-android)
endif()
set(DS_LIB "${DSMINIMAL_LIB_DIR}/libdsminimal-android-${DS_ABI}.a")
if(NOT EXISTS "${DS_LIB}")
    message(FATAL_ERROR "DS-MIN library not found: ${DS_LIB} (set DSMINIMAL_LIB_DIR)")
endif()

add_library(dsminimal STATIC IMPORTED)
set_target_properties(dsminimal PROPERTIES IMPORTED_LOCATION "${DS_LIB}")

# The worker is fetched and verified at runtime; never prelink a substitute.
add_library(dsminimal_jni SHARED dsminimal_jni.c)
target_link_libraries(dsminimal_jni dsminimal log dl)
