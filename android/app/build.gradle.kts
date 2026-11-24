plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.jose00735.fortitatake"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.jose00735.fortitatake"
        minSdk = 29
        targetSdk = 34
        versionCode = 10
        versionName = "0.6.2"
    }

    // A fixed key so every build can update the installed app (sideloaded, personal use).
    signingConfigs {
        create("ft") {
            storeFile = file("../keystore/fortitatake-sideload.jks")
            storePassword = "fortitatake"
            keyAlias = "fortitatake"
            keyPassword = "fortitatake"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("ft")
        }
        debug {
            signingConfig = signingConfigs.getByName("ft")
        }
    }

    // The Go engine ships as lib/<abi>/libfortitatake.so and is executed, so it must be
    // extracted to disk on install.
    packaging {
        jniLibs { useLegacyPackaging = true }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }
}

dependencies {
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
