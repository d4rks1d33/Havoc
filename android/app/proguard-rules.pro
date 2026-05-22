# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# Kotlinx Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** { kotlinx.serialization.KSerializer serializer(...); }
-keep,includedescriptorclasses class com.havoc.client.**$$serializer { *; }
-keepclassmembers class com.havoc.client.** {
    *** Companion;
}
-keepclasseswithmembers class com.havoc.client.** {
    kotlinx.serialization.KSerializer serializer(...);
}
