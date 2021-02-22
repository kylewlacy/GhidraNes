import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.time.LocalDate
import java.time.format.DateTimeFormatter.BASIC_ISO_DATE
import java.util.Properties

plugins {
    java
    kotlin("jvm") version "1.4.30"
    id("org.jlleitschuh.gradle.ktlint") version "9.4.1"
}

repositories {
    jcenter()
}

val ghidraDir = System.getenv("GHIDRA_INSTALL_DIR")
    ?: (project.findProperty("ghidra.dir") as? String)
    ?: throw IllegalStateException("Can't find Ghidra installation")

val ghidraProps = Properties().apply { file("$ghidraDir/Ghidra/application.properties").inputStream().use { load(it) } }
val ghidraVersion = ghidraProps.getProperty("application.version")!!
val ghidraRelease = ghidraProps.getProperty("application.release.name")!!

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        jvmTarget = "11"
        freeCompilerArgs += "-Xopt-in=kotlin.ExperimentalUnsignedTypes"
    }
}

val ghidra: Configuration by configurations.creating

dependencies {
    ghidra(fileTree("$ghidraDir/Ghidra/Framework") { include("**/*.jar") })
    ghidra(fileTree("$ghidraDir/Ghidra/Features") { include("**/*.jar") })

    compileOnly(ghidra)

    testImplementation(ghidra)
    testImplementation(kotlin("stdlib-jdk8"))
    testImplementation(platform("org.junit:junit-bom:5.7.0"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
}

val generateExtensionProps by tasks.registering() {
    val output = file("$buildDir/generated/extension.properties")
    outputs.file(output)
    doLast {
        output.outputStream().use {
            val props = Properties()
            props.load(project.file("extension.properties").inputStream())
            props += mapOf(
                ("name" to project.name),
                ("createdOn" to LocalDate.now().toString()),
                ("version" to ghidraVersion)
            )
            props.store(it, null)
        }
    }
}

val compileSleigh by tasks.registering(JavaExec::class) {
    val slaspecFile = file("data/languages/sm83.slaspec")
    val slaFile = file("data/languages/sm83.sla")

    inputs.files(fileTree("data/languages").include("*.slaspec", "*.sinc"))
        .withPropertyName("sourceFiles")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.files(slaFile)
        .withPropertyName("outputFile")

    classpath = configurations["ghidra"]
    main = "ghidra.pcodeCPort.slgh_compile.SleighCompile"
    args = listOf("-u", "-l", "-n", "-t", "-e", "-c", "-f", slaspecFile.absolutePath)
}

val zip by tasks.registering(Zip::class) {
    archiveFileName.set("ghidra_${ghidraVersion}_${ghidraRelease}_${LocalDate.now().format(BASIC_ISO_DATE)}_${project.name}.zip")

    into("${project.name}/")
    from(tasks.named("jar")) {
        into("lib/")
    }
    from(tasks.named("sourcesJar")) {
        into("lib/")
        rename { "${project.name}-src.zip" }
    }
    from(configurations.runtimeClasspath.get()) {
        into("lib/")
    }

    from(generateExtensionProps)
    from("data") {
        into("data/")
        include("**/*.cspec", "**/*.ldefs", "**/*.pspec", "**/*.sinc", "**/*.slaspec", "**/sleighArgs.txt")
    }
    from("README.markdown", "LICENSE", "Module.manifest")
}

tasks.named("assemble") {
    dependsOn("zip")
}

tasks.named<Test>("test") {
    dependsOn("compileSleigh")
    useJUnitPlatform()

    systemProperty("ghidra.dir", ghidraDir)
    systemProperty("SystemUtilities.isTesting", true)
}

defaultTasks("clean", "assemble")
