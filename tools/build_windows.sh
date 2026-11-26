#!/usr/bin/env bash
# Builds the Windows release: dist/fortitatake.exe, the NSIS installer, and a zip that
# contains the installer (the standard way FortiTatake is delivered for Windows).
# Needs Go 1.24+, Python 3 with PyYAML, NSIS 3 (makensis) and zip.
set -euo pipefail
cd "$(dirname "$0")/.."
VER=$(grep -o 'var version = "v[^"]*"' main.go | sed 's/.*"v\(.*\)"/\1/')
python3 tools/build_content.py >/dev/null
python3 tools/build_labs.py
python3 tools/build_threats.py
if command -v node >/dev/null; then node tools/test_labs.mjs >/dev/null || { echo 'lab tests failed: run node tools/test_labs.mjs'; exit 1; }; fi
mkdir -p dist ftkos/bin
# FortiTatake OS: the lab agent (embedded, copied into each OS build) and the QEMU runner.
for a in amd64:x86_64 arm64:aarch64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=${a%%:*} go build -trimpath -ldflags "-s -w" -o "ftkos/bin/ftk-agent-${a##*:}" ./ftkos/agent
done
[ -f dist/qemu-win/qemu-system-x86_64.exe ] || bash tools/build_qemu_win.sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-H windowsgui -s -w" -o dist/fortitatake.exe .
(cd installer && makensis -V2 -DVERSION="$VER" -DDIST=../dist fortitatake.nsi)
SETUP="FortiTatake-Setup-v$VER.exe"
ZIP="dist/fortitatake-v$VER-windows-setup.zip"
rm -f "$ZIP"
cat > dist/INSTALL.txt <<TXT
FortiTatake v$VER for Windows

1. Unzip this file.
2. Double-click $SETUP and follow the steps. No administrator rights are needed.
   Windows SmartScreen may say "Windows protected your PC" because the installer
   isn't code-signed: click "More info", then "Run anyway".
3. Open FortiTatake from the Start menu (or the desktop shortcut).

Updating: run the new installer over the old one. Your progress in
%APPDATA%\FortiTatake is kept.
Uninstalling: Settings > Apps > FortiTatake, or "Uninstall FortiTatake" in the Start menu.
TXT
(cd dist && zip -q "$(basename "$ZIP")" "$SETUP" INSTALL.txt)
echo "built $ZIP"
