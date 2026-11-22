#!/usr/bin/env bash
# Builds the Android APK: the Go engine for each ABI, then the Kotlin shell.
# Needs Go 1.24+, JDK 17+, and the Android SDK (ANDROID_HOME) with platform 35.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/build_content.py
JNI=android/app/src/main/jniLibs
rm -rf "$JNI" && mkdir -p "$JNI"/{arm64-v8a,armeabi-v7a,x86_64}
FLAGS=(-trimpath -ldflags "-s -w")
# arm64: Go's native android target. Others: static linux builds, which Android runs fine.
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$JNI/arm64-v8a/libfortitatake.so" .
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$JNI/armeabi-v7a/libfortitatake.so" .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$JNI/x86_64/libfortitatake.so" .
cd android
if [ -x ./gradlew ]; then G=./gradlew; else G=gradle; fi
$G --no-daemon -q assembleRelease
VER=$(grep -o 'versionName = "[^"]*"' app/build.gradle.kts | cut -d'"' -f2)
mkdir -p ../dist
cp app/build/outputs/apk/release/app-release.apk "../dist/fortitatake-v$VER.apk"
echo "built dist/fortitatake-v$VER.apk"
