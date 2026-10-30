#!/usr/bin/env bash
# Save a standalone pazuzu executable. Quicklisp is required here and is
# not required to run the executable. Native libraries are loaded from
# PAZUZU_DEPS while the image is saved, and from $ORIGIN/../lib/pazuzu
# (or LD_LIBRARY_PATH) when the executable runs.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
DEPS="${PAZUZU_DEPS:-/opt/pazuzu}"
export LD_LIBRARY_PATH="${DEPS}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="${DEPS}/bin:${PATH}"

QL="${QUICKLISP:-}"
if [[ -z "$QL" ]]; then
  if [[ -f "${HOME}/quicklisp/setup.lisp" ]]; then
    QL="${HOME}/quicklisp/setup.lisp"
  elif [[ -f /root/quicklisp/setup.lisp ]]; then
    QL=/root/quicklisp/setup.lisp
  else
    echo "Quicklisp setup.lisp not found; set QUICKLISP" >&2
    exit 1
  fi
fi

mkdir -p build
sbcl --dynamic-space-size 4096 --noinform --disable-debugger \
  --load "$QL" \
  --load "$ROOT/script/build-image.lisp"
test -x build/pazuzu
echo "built $ROOT/build/pazuzu"
