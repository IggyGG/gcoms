pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "gcoms-mobile"
include(":sdk", ":sample")
if (providers.gradleProperty("gcomsPush").orNull == "true") include(":push")
// The install-chain probe is a lab APK, not part of the SDK matrix; opt in.
if (providers.gradleProperty("gcomsProbe").orNull == "true") include(":probe")
// The M2 agent links the SDK client role; opt in separately.
if (providers.gradleProperty("gcomsAgent").orNull == "true") include(":agent")
