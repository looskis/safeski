#!/bin/sh
# Remove safeski binaries installed by scripts/install.sh / make install, and the per-user
# LaunchAgent. Keys, secrets, policy and the audit log in ~/.safeski are kept unless --purge.
#
#   scripts/uninstall.sh [--prefix DIR] [--purge]
#
# The root broker (if installed) must be removed with sudo; `safeski broker uninstall`
# prints the commands. This script never runs sudo.
set -eu

prefix="${PREFIX:-$HOME/.local}"
purge=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --prefix=*) prefix="${1#--prefix=}"; shift ;;
    --purge) purge=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

bin="$prefix/bin/safeski"
if [ -x "$bin" ]; then
  "$bin" agent uninstall 2>/dev/null || true
elif command -v safeski >/dev/null 2>&1; then
  safeski agent uninstall 2>/dev/null || true
else
  launchctl bootout "gui/$(id -u)/dev.safeski.agent" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/dev.safeski.agent.plist"
fi

rm -f "$bin" "$prefix/lib/libsafeski-pkcs11.dylib"
rm -rf "$prefix/libexec/safeski"
echo "removed $bin"

if [ -f /Library/LaunchDaemons/dev.safeski.broker.plist ]; then
  echo "the root broker is installed; remove it with:"
  echo "  sudo launchctl bootout system/dev.safeski.broker && sudo rm -f /Library/LaunchDaemons/dev.safeski.broker.plist && sudo rm -rf /var/run/safeski"
fi

home="${SAFESKI_HOME:-$HOME/.safeski}"
if [ "$purge" = 1 ]; then
  rm -rf "$home"
  echo "purged $home (keys, secrets, policy, audit log)"
else
  echo "kept $home (pass --purge to delete keys, secrets, policy and the audit log)"
fi
