plugins {
    kotlin("jvm") version "2.0.0"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("com.github.ben-manes.versions") version "0.51.0" //Gradle -> Help -> dependencyUpdates
}

group = "com.nickcoblentz.montoya"
version = "0.0.2"

repositories {
    mavenLocal()
    mavenCentral()
    maven(url="https://jitpack.io") {
        content {
            includeGroup("com.github.milchreis")
            includeGroup("com.github.ncoblentz")
        }
    }
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("net.portswigger.burp.extensions:montoya-api:2024.7")
    implementation("com.nickcoblentz.montoya:MontoyaLibrary:0.1.20")
    //implementation("com.github.ncoblentz:BurpMontoyaLibrary:0.1.14")
    implementation("com.github.milchreis:uibooster:1.21.1")
    implementation("org.json:json:20240303")

}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(21)
}