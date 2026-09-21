plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "boo.gcoms.sample"
    compileSdk = 36
    defaultConfig {
        applicationId = "boo.gcoms.sample"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-preview"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    flavorDimensions += "role"
    productFlavors {
        create("client") { dimension = "role"; applicationIdSuffix = ".client" }
        create("relay") { dimension = "role"; applicationIdSuffix = ".relay" }
        create("baseline") { dimension = "role"; applicationIdSuffix = ".baseline" }
    }
    buildTypes {
        release {
            // Disposable qualification application; shipped SDK AARs have no app signing key.
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
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
dependencies {
    "clientImplementation"(project(":sdk"))
    "relayImplementation"(project(":sdk"))
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    "clientImplementation"("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    "relayImplementation"("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
