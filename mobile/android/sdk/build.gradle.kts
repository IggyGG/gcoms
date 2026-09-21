plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}
val nativeRoot = providers.gradleProperty("gcomsNativeRoot")
    .orElse(rootProject.layout.projectDirectory.dir("../../target/mobile/android").asFile.absolutePath).get()
val pushEnabled = providers.gradleProperty("gcomsPush").orNull == "true"
val publicationRole = providers.gradleProperty("gcomsPublishRole").orElse("client").get()
    .also { require(it in listOf("client", "relay")) { "gcomsPublishRole must be client or relay" } }
android {
    namespace = "boo.gcoms.sdk"
    compileSdk = 36
    ndkVersion = "27.3.13750724"
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
        getByName("client").jniLibs.srcDir("$nativeRoot/client")
        getByName("relay").jniLibs.srcDir("$nativeRoot/relay")
        providers.gradleProperty("gcomsFixtureAssets").orNull?.let {
            getByName("androidTest").assets.srcDir(it)
        }
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
    for (role in listOf("client", "relay")) {
        val title = role.replaceFirstChar { it.uppercase() }
        val verify = tasks.register("verify${title}ReleaseNative") {
            doLast {
                val metadata = groovy.json.JsonSlurper().parse(file("$nativeRoot/$role/build.json")) as Map<*, *>
                check(metadata["role"] == role && metadata["fixtures"] == false) {
                    "Release SDKs require native libraries built without fixture support"
                }
                check((metadata["push"] == true) == pushEnabled) { "Native push feature differs from the selected distribution" }
            }
        }
        tasks.named("pre${title}ReleaseBuild").configure { dependsOn(verify) }
    }
    publishing.publications {
        create<MavenPublication>(publicationRole) {
            groupId = "boo.gcoms"; artifactId = "gcoms-$publicationRole" + (if (pushEnabled) "-push" else ""); version = "0.1.0-preview"
            from(components[publicationRole + "Release"])
        }
    }
}
