#!/usr/bin/env bash
# Builds the Android APK: the Go engine for each ABI, then the Kotlin shell.
# Needs Go 1.24+, JDK 17+, and the Android SDK (ANDROID_HOME) with platform 35.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/build_content.py
python3 tools/build_labs.py
if command -v node >/dev/null; then node tools/test_labs.mjs >/dev/null || { echo 'lab tests failed: run node tools/test_labs.mjs'; exit 1; }; fi
JNI=android/app/src/main/jniLibs
rm -rf "$JNI" && mkdir -p "$JNI"/{arm64-v8a,armeabi-v7a,x86_64}
FLAGS=(-trimpath -ldflags "-s -w")
# arm64: Go's native android target. Others: static linux builds, which Android runs fine.
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$JNI/arm64-v8a/libfortitatake.so" .
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$JNI/armeabi-v7a/libfortitatake.so" .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$JNI/x86_64/libfortitatake.so" .
# QEMU for the phone (tools/build_qemu_android.sh): a static aarch64 binary shipped as a native library
if [ -f dist/qemu-android/libqemu.so ]; then cp dist/qemu-android/libqemu.so "$JNI/arm64-v8a/libqemu.so"; else echo "note: dist/qemu-android/libqemu.so missing: the APK won't run FortiTatake OS"; fi
cd android
if [ -x ./gradlew ]; then G=./gradlew; else G=gradle; fi
$G --no-daemon -q assembleRelease
VER=$(grep -o 'versionName = "[^"]*"' app/build.gradle.kts | cut -d'"' -f2)
mkdir -p ../dist
cp app/build/outputs/apk/release/app-release.apk "../dist/fortitatake-v$VER.apk"
echo "built dist/fortitatake-v$VER.apk"
