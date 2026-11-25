#!/bin/bash
# QEMU for Android: a static aarch64 Linux binary (musl, built with zig cc) that the APK ships
# as jniLibs/arm64-v8a/libqemu.so. Android runs static Linux binaries from the app's native
# library folder, the same way it runs the Go engine. Only the aarch64 "virt" machine, TCG,
# no graphics. Sources: zlib and libffi (Buildroot's download cache or the web), pcre2 and
# glib from the Ubuntu archive, QEMU from download.qemu.org.
set -euo pipefail
W=${W:-/home/claude/aq}
QV=11.1.3
P=$W/sysroot
mkdir -p "$W/bin" "$P" "$W/src"
cd "$W"
ZIG=${ZIG:-$W/zig/ziglang/zig}
T=aarch64-linux-musl
for t in gcc cc; do printf '#!/bin/sh\n# zig defines NDEBUG with optimisation; QEMU refuses to build with it\nexec %s cc -target %s "$@" -UNDEBUG\n' "$ZIG" $T > bin/$T-$t; done
printf '#!/bin/sh\nexec %s c++ -target %s "$@"\n' "$ZIG" $T > bin/$T-g++
printf '#!/bin/sh\nexec %s ar "$@"\n' "$ZIG" > bin/$T-ar
printf '#!/bin/sh\nexec %s ranlib "$@"\n' "$ZIG" > bin/$T-ranlib
printf '#!/bin/sh\nexec llvm-strip "$@"\n' > bin/$T-strip
printf '#!/bin/sh\nexec llvm-nm "$@"\n' > bin/$T-nm
printf '#!/bin/sh\nexec llvm-objcopy "$@"\n' > bin/$T-objcopy
printf '#!/bin/sh\nPKG_CONFIG_LIBDIR=%s/lib/pkgconfig PKG_CONFIG_PATH= exec pkg-config --static "$@"\n' "$P" > bin/$T-pkg-config
chmod +x bin/*
export PATH=$W/bin:$PATH
export PKG_CONFIG_LIBDIR=$P/lib/pkgconfig PKG_CONFIG_PATH=
cat > cross.ini <<EOC
[binaries]
c = '$W/bin/$T-gcc'
cpp = '$W/bin/$T-g++'
ar = '$W/bin/$T-ar'
strip = '$W/bin/$T-strip'
pkg-config = 'pkg-config'
[properties]
pkg_config_libdir = '$P/lib/pkgconfig'
[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
EOC
MESON=${MESON:-$W/venv/bin/meson}
J=$(nproc)

if [ ! -f $P/lib/libz.a ]; then
  rm -rf src/zlib && mkdir src/zlib && tar -xf zlib-1.3.2.tar.xz -C src/zlib --strip-components=1
  (cd src/zlib && CC=$T-gcc AR=$T-ar RANLIB=$T-ranlib CFLAGS=-Os ./configure --static --prefix=$P && make -j$J && make install) >/dev/null
fi
if [ ! -f $P/lib/libffi.a ]; then
  rm -rf src/ffi && mkdir src/ffi && tar -xf libffi-3.4.8.tar.gz -C src/ffi --strip-components=1
  (cd src/ffi && CC=$T-gcc AR=$T-ar RANLIB=$T-ranlib CFLAGS=-Os ./configure --host=aarch64-linux-musl --prefix=$P --disable-shared --enable-static --disable-docs --disable-multi-os-directory && make -j$J && make install) >/dev/null
fi
if [ ! -f $P/lib/libpcre2-8.a ]; then
  rm -rf src/pcre2 && mkdir src/pcre2 && tar -xf pcre2_10.45.orig.tar.gz -C src/pcre2 --strip-components=1
  (cd src/pcre2 && CC=$T-gcc AR=$T-ar RANLIB=$T-ranlib CFLAGS=-Os ./configure --host=aarch64-linux-musl --prefix=$P --disable-shared --enable-static && make -j$J && make install) >/dev/null
fi
if [ ! -f $P/lib/libglib-2.0.a ]; then
  rm -rf src/glib && mkdir src/glib && tar -xf glib2.0_2.84.1.orig.tar.xz -C src/glib --strip-components=1
  (cd src/glib && $MESON setup b --cross-file "$W/cross.ini" --prefix=$P --libdir=lib --default-library=static --buildtype=minsize \
     -Dtests=false -Dintrospection=disabled -Dnls=disabled -Dlibmount=disabled -Dselinux=disabled -Dxattr=false \
     -Dman-pages=disabled -Dsysprof=disabled -Dglib_debug=disabled -Ddocumentation=false -Dlibelf=disabled -Dbsymbolic_functions=false \
     && ninja -C b -j$J && ninja -C b install) >/dev/null
fi

[ -f qemu-$QV.tar.xz ] || curl -sfLO https://download.qemu.org/qemu-$QV.tar.xz
[ -d qemu-$QV ] || tar -xf qemu-$QV.tar.xz
# libfdt (the aarch64 virt machine needs it): QEMU's wrap fetches it from gitlab; use Ubuntu's dtc source instead
if [ ! -f qemu-$QV/subprojects/dtc/meson.build ]; then
  [ -f device-tree-compiler_1.7.2.orig.tar.xz ] || curl -sfO http://archive.ubuntu.com/ubuntu/pool/main/d/device-tree-compiler/device-tree-compiler_1.7.2.orig.tar.xz
  rm -rf qemu-$QV/subprojects/dtc && mkdir -p qemu-$QV/subprojects/dtc && tar -xf device-tree-compiler_1.7.2.orig.tar.xz -C qemu-$QV/subprojects/dtc --strip-components=1
  # its tests need the tools QEMU doesn't build
  sed -i "s/^if get_option('tests')$/if get_option('tests') and get_option('tools')/" qemu-$QV/subprojects/dtc/meson.build
  # QEMU links libfdt statically
  sed -i "s/^if static_build$/if true/" qemu-$QV/subprojects/dtc/libfdt/meson.build
fi
# QEMU's newer kernel headers first (zig's musl ships older ones); missing files fall through
mkdir -p lh && ln -sfn "$W/qemu-$QV/linux-headers/linux" lh/linux && ln -sfn "$W/qemu-$QV/linux-headers/asm-arm64" lh/asm && ln -sfn "$W/qemu-$QV/linux-headers/asm-generic" lh/asm-generic
# --gcc-toolchain: keep clang from adding the host's aarch64 *glibc* GCC libraries (libatomic, libm) to the link
printf '#!/bin/sh\nexec %s cc -target %s --gcc-toolchain=/nonexistent -I%s/lh "$@" -UNDEBUG\n' "$ZIG" $T "$W" > "$W/bin/$T-gcc"
mkdir -p qemu-$QV/build-android
cd qemu-$QV/build-android
if [ ! -f build.ninja ]; then
  rm -rf ./*
  ../configure --cross-prefix=$T- --target-list=aarch64-softmmu --static \
    --without-default-features --enable-tcg --disable-pixman --enable-fdt=internal \
    --disable-docs --disable-tools --disable-guest-agent --disable-werror --disable-debug-info \
    --extra-cflags="-Os -I$P/include" --extra-ldflags="-L$P/lib"
fi
# meson finds the host's aarch64 *glibc* libm/libutil through the compiler's search dirs; musl has its own
sed -i 's# /usr/aarch64-linux-gnu/lib/lib[a-z]*\.\(a\|so\)##g' build.ninja
ninja -j$J qemu-system-aarch64
llvm-strip -o "$W/libqemu.so" qemu-system-aarch64
mkdir -p "$W/share" && cp ../pc-bios/edk2-aarch64-code.fd.bz2 "$W/share/" 2>/dev/null || true
ls -la "$W/libqemu.so"
