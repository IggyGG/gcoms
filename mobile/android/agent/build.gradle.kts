plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// M2 agent: the real mobile client, built on the GComs SDK client role. It
// loads a deployment config (profile + signed network + installation
// invitation), enrolls over GC/2 and receives files. Opt-in via
// -PgcomsAgent=true; the private config is never committed.
android {
    namespace = "boo.gcoms.agent"
    compileSdk = 36
    // Pin the installed 16 KiB-capable JNI toolchain; never download an
    // unrelated AGP default NDK during a routine offline deployment.
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = "boo.gcoms.agent"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-agent"
    }
    flavorDimensions += "role"
    productFlavors {
        create("client") { dimension = "role" }
        create("relay") { dimension = "role" }
    }
    buildTypes {
        release {
            // Disposable lab agent; self-signed release like the sample.
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
kotlin {
    jvmToolchain(21)
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

// Optional in-process DS-MIN core: -PdsminimalLibDir=<dir> (or DSMINIMAL_LIB_DIR)
// links libdsminimal-android-<abi>.a (dropship/build/build-android.sh) and
// builds the JNI bridge. Without it the agent still runs on the GComs SDK alone.
val dsminimalLibDir = (findProperty("dsminimalLibDir") as String?)
    ?: System.getenv("DSMINIMAL_LIB_DIR")
val droneLibDir = (findProperty("droneLibDir") as String?) ?: System.getenv("DRONE_LIB_DIR")
if (dsminimalLibDir != null) {
    android.defaultConfig.ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    android.defaultConfig.externalNativeBuild.cmake {
        arguments += "-DDSMINIMAL_LIB_DIR=$dsminimalLibDir"
        if (droneLibDir != null) arguments += "-DDSDRONE_LIB_DIR=$droneLibDir"
    }
    android.externalNativeBuild.cmake {
        path = file("src/main/cpp/CMakeLists.txt")
        version = "3.22.1"
    }
}
dependencies {
    "clientImplementation"(project(":sdk"))
    "clientImplementation"("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}

// Optional embedded deployment config: -PgcomsAgentConfig=<path> copies the
// private config (profile + signed network + invitation) into
// assets/agent-config.json. The file is never committed; the service reads it
// when no filesDir copy is present.
providers.gradleProperty("gcomsAgentConfig").orNull?.let { configPath ->
    val configDir = layout.buildDirectory.dir("generated/agentConfig")
    val copyConfig = tasks.register<Copy>("copyAgentConfig") {
        from(configPath)
        into(configDir)
        rename { "agent-config.json" }
    }
    android.sourceSets.getByName("main").assets.srcDir(configDir)
    tasks.named("preBuild") { dependsOn(copyConfig) }
}

// Optional embedded DS-MIN profile document: -PgcomsDropshipConfig=<path> copies
// it to assets/dropship-config.json so the rig path can run the in-process
// installer without a Bluetooth transfer. Never committed.
providers.gradleProperty("gcomsDropshipConfig").orNull?.let { configPath ->
    val configDir = layout.buildDirectory.dir("generated/dropshipConfig")
    val copyConfig = tasks.register<Copy>("copyDropshipConfig") {
        from(configPath)
        into(configDir)
        rename { "dropship-config.json" }
    }
    android.sourceSets.getByName("main").assets.srcDir(configDir)
    tasks.named("preBuild") { dependsOn(copyConfig) }
}
