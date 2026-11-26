#!/bin/sh
# Runs after packages are installed. $1 = target directory.
set -e
T="$1"
# Services start on first use, from the agent: drop every init script but ours.
n=0
for s in "$T"/etc/init.d/S*; do
  [ -e "$s" ] || continue
  case "$(basename "$s")" in S99ftkagent) ;; *) rm -f "$s"; n=$((n + 1)) ;; esac
done
# the build screen reports it (BASE_DIR is Buildroot's output directory)
# (an incremental build only reinstalls some packages: keep the larger count)
if [ -n "$BASE_DIR" ]; then
  p=$(cat "$BASE_DIR/ftk-init-removed" 2>/dev/null || echo 0)
  [ "$n" -gt "$p" ] 2>/dev/null && echo "$n" > "$BASE_DIR/ftk-init-removed"
fi
# Per-namespace /etc files (ip netns exec binds /etc/netns/NAME/*) live in RAM.
rm -rf "$T/etc/netns"; ln -s /run/etc-netns "$T/etc/netns"
# The agent binary is prebuilt by FortiTatake and handed in by the builder.
if [ -n "$FTK_AGENT_BIN" ] && [ -f "$FTK_AGENT_BIN" ]; then
  install -D -m 0755 "$FTK_AGENT_BIN" "$T/usr/bin/ftk-agent"
fi
[ -x "$T/usr/bin/ftk-agent" ] || { echo "post-build: ftk-agent missing (set FTK_AGENT_BIN)"; exit 1; }
# Build stamp read by the agent's hello.
echo "${FTK_BUILD_ID:-dev}" > "$T/etc/ftkos-build"
