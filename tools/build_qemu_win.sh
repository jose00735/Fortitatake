#!/usr/bin/env bash
# Cross-compiles the stripped Windows QEMU that runs FortiTatake OS: x86_64 machine only,
# Windows Hypervisor Platform (WHPX) plus TCG, no graphics, no tools. Output: dist/qemu-win.
# Needs: gcc-mingw-w64-x86-64, meson, ninja, pkg-config, python3-venv, zstd, curl,
#        binutils-mingw-w64-x86-64. Libraries come prebuilt from MSYS2's mingw64 repo.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
QV=11.1.3
W=${FTK_QEMU_WORK:-$HOME/qw}
REPO=https://repo.msys2.org/mingw/mingw64
PKGS="glib2-2.90.1-1 zlib-1.4-2 libffi-3.8.1-1 gettext-runtime-1.0-1 libiconv-1.19.1-1 pcre2-10.49-2"
mkdir -p "$W/pkgs" "$W/sysroot"
for p in $PKGS; do
  f=mingw-w64-x86_64-$p-any.pkg.tar.zst
  [ -f "$W/pkgs/$f" ] || curl -sfL -o "$W/pkgs/$f" "$REPO/$f"
  tar --zstd -xf "$W/pkgs/$f" -C "$W/sysroot" 2>/dev/null
done
# Ubuntu's MinGW headers predate the WHPX VMX capability codes QEMU 11 uses.
HDR=mingw-w64-x86_64-headers-git-13.0.0.r91.gfc0b67305-1-any.pkg.tar.zst
[ -f "$W/pkgs/$HDR" ] || curl -sfL -o "$W/pkgs/$HDR" "$REPO/$HDR"
mkdir -p "$W/hdr" && tar --zstd -xf "$W/pkgs/$HDR" -C "$W/hdr" --wildcards '*winhv*'
printf '#!/bin/sh\nPKG_CONFIG_LIBDIR=%s/sysroot/mingw64/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR=%s/sysroot exec pkg-config "$@"\n' "$W" "$W" > "$W/x86_64-w64-mingw32-pkg-config"
chmod +x "$W/x86_64-w64-mingw32-pkg-config"
export PATH="$W:$PATH"
[ -d "$W/qemu-$QV" ] || curl -sfL "https://download.qemu.org/qemu-$QV.tar.xz" | tar xJ -C "$W"
cd "$W/qemu-$QV"
if [ ! -f build/build.ninja ]; then
  rm -rf build && mkdir build && cd build
  ../configure --cross-prefix=x86_64-w64-mingw32- --target-list=x86_64-softmmu --without-default-features \
    --enable-whpx --enable-tcg --disable-docs --disable-tools --disable-guest-agent --disable-werror \
    --disable-pixman --disable-fdt --enable-strip --extra-cflags="-Os -I$W/hdr/mingw64/include"
  cd ..
fi
make -C build -j"$(nproc)" qemu-system-x86_64.exe
OUT="$ROOT/dist/qemu-win"
rm -rf "$OUT" && mkdir -p "$OUT/share"
cp build/qemu-system-x86_64.exe "$OUT/"
x86_64-w64-mingw32-strip "$OUT/qemu-system-x86_64.exe"
for fw in bios-256k.bin linuxboot_dma.bin kvmvapic.bin; do cp "pc-bios/$fw" "$OUT/share/"; done
cp COPYING "$OUT/QEMU-COPYING.txt"
# DLLs: follow imports through the MSYS2 libraries and the MinGW runtime.
SEARCH="$W/sysroot/mingw64/bin $(ls -d /usr/lib/gcc/x86_64-w64-mingw32/*-posix 2>/dev/null | tail -1) /usr/x86_64-w64-mingw32/lib"
todo=("$OUT/qemu-system-x86_64.exe")
while [ ${#todo[@]} -gt 0 ]; do
  f=${todo[0]}; todo=("${todo[@]:1}")
  for dll in $(x86_64-w64-mingw32-objdump -p "$f" | sed -n 's/.*DLL Name: //p'); do
    [ -f "$OUT/$dll" ] && continue
    for d in $SEARCH; do
      if [ -f "$d/$dll" ]; then cp "$d/$dll" "$OUT/"; todo+=("$OUT/$dll"); break; fi
    done
  done
done
du -sh "$OUT"; ls "$OUT"
