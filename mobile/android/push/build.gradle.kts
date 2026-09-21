plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}
val publicationRole = providers.gradleProperty("gcomsPublishRole").orElse("client").get()
    .also { require(it in listOf("client", "relay")) { "gcomsPublishRole must be client or relay" } }
android {
    namespace = "boo.gcoms.push"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    flavorDimensions += "role"
    productFlavors {
        create("client") { dimension = "role" }
        create("relay") { dimension = "role" }
    }
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
    api(project(":sdk"))
    api("com.google.firebase:firebase-messaging:25.1.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    testImplementation("junit:junit:4.13.2")
}
afterEvaluate {
    publishing.publications {
        create<MavenPublication>(publicationRole) {
            groupId = "boo.gcoms"; artifactId = "gcoms-$publicationRole-fcm"; version = "0.1.0-preview"
            from(components[publicationRole + "Release"])
        }
    }
}
