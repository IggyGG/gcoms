plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The probe is the M1 install-chain canary: the Pico drives the stock-Android
// "unknown sources + package installer" flow to install this APK, then the
// probe proves execution by writing a marker and reporting its identity.
// It is NOT the agent (that is the client-role SDK app). It is included only
// when -PgcomsProbe=true so the default SDK CI matrix is unchanged.
android {
    namespace = "boo.gcoms.probe"
    compileSdk = 36
    defaultConfig {
        applicationId = "boo.gcoms.probe"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-probe"
    }
    buildTypes {
        release {
            // Disposable lab probe; self-signed release like the sample.
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