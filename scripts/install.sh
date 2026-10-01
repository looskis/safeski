#!/bin/sh
# Build safeski from source and install it. Default prefix: ~/.local (no sudo needed).
#
#   scripts/install.sh [--prefix DIR] [--no-agent] [--no-build]
#
# After installing, the per-user LaunchAgent is installed with `safeski agent install`
# unless --no-agent is given. The root broker (cross-user access) is never installed by
# this script: run `safeski broker install` and follow the printed sudo commands.
set -eu

prefix="${PREFIX:-$HOME/.local}"
agent=1
build=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --prefix=*) prefix="${1#--prefix=}"; shift ;;
    --no-agent) agent=0; shift ;;
    --no-build) build=0; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if ! command -v swift >/dev/null 2>&1; then
  echo "install.sh: swift not found. Install the Xcode Command Line Tools: xcode-select --install" >&2
  exit 1
fi

if [ -d "$root/.build/release" ] && [ -x "$root/.build/release/safeski" ] && [ "$build" = 0 ]; then
  echo "using existing release build"
else
  echo "building (release)..."
  make -s build
fi

make -s install PREFIX="$prefix"

bin="$prefix/bin/safeski"
case ":$PATH:" in
  *":$prefix/bin:"*) ;;
  *) echo "note: $prefix/bin is not on your PATH; add:  export PATH=\"$prefix/bin:\$PATH\"" ;;
esac

if [ "$agent" = 1 ]; then
  if [ ! -f "${SAFESKI_HOME:-$HOME/.safeski}/device.json" ]; then
    echo "initializing ${SAFESKI_HOME:-$HOME/.safeski}..."
    "$bin" init
  fi
  "$bin" agent install
  echo 'add to your shell profile:  eval "$(safeski agent env)"'
else
  echo "skipped agent install (--no-agent). Later: $bin init && $bin agent install"
fi
echo "done: $bin"
