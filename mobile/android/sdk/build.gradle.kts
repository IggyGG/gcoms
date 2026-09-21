plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}
android {
    namespace = "boo.gcoms.sdk"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    flavorDimensions += "role"
    productFlavors {
        create("client") { dimension = "role"; buildConfigField("int", "NATIVE_ROLE", "1") }
        create("relay") { dimension = "role"; buildConfigField("int", "NATIVE_ROLE", "2") }
    }
    buildFeatures { buildConfig = true }
    sourceSets {
        getByName("client").jniLibs.srcDir("../../../target/mobile/android/client")
        getByName("relay").jniLibs.srcDir("../../../target/mobile/android/relay")
    }
    buildTypes { release { isMinifyEnabled = false } }
    publishing { singleVariant("clientRelease"); singleVariant("relayRelease") }
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
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
afterEvaluate {
    publishing.publications {
        create<MavenPublication>("client") {
            groupId = "boo.gcoms"; artifactId = "gcoms-client"; version = "0.1.0-preview"
            from(components["clientRelease"])
        }
        create<MavenPublication>("relay") {
            groupId = "boo.gcoms"; artifactId = "gcoms-relay"; version = "0.1.0-preview"
            from(components["relayRelease"])
        }
    }
}
