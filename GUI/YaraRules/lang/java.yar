// severity: safe
rule Lang_Java {
    meta:
        description = "Java binary — JAR/class launcher with JVM references"
    strings:
        $cafebabe  = { CA FE BA BE }
        $jvm       = "jvm.dll" ascii nocase
        $jni       = "JNI_CreateJavaVM" ascii
        $jnienv    = "JNIEnv" ascii
        $jar       = ".jar" ascii
        $mainclass = "Main-Class:" ascii
        $hotspot   = "HotSpot" ascii
    condition:
        $cafebabe or 2 of ($jvm, $jni, $jnienv, $jar, $mainclass, $hotspot)
}

// severity: safe
rule Lang_Kotlin {
    meta:
        description = "Kotlin — Kotlin runtime or coroutine symbols"
    strings:
        $kotlin    = "kotlin" ascii nocase
        $coroutine = "kotlinx.coroutines" ascii
        $stdlib    = "kotlin.stdlib" ascii
        $meta      = "kotlin.Metadata" ascii
    condition:
        2 of them
}

// severity: safe
rule Lang_Scala {
    meta:
        description = "Scala — Scala library or runtime symbols"
    strings:
        $scala    = "scala" ascii nocase
        $scalalib = "scala.collection" ascii
        $scalarun = "scala.runtime" ascii
    condition:
        2 of them
}
