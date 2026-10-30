#!/usr/bin/env bash
# Idempotent install: native libraries, the pazuzu binary, a system user,
# and the default config. Re-running replaces the binary and libraries
# and leaves an existing /etc/pazuzu/config.lisp alone.
#
#   sudo ./install.sh
#   sudo PREFIX=/usr/local ./install.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"
PREFIX="${PREFIX:-/usr/local}"
DEPS="${PAZUZU_DEPS:-/opt/pazuzu}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "re-run as root: sudo $0" >&2
  exit 1
fi

export PAZUZU_DEPS="$DEPS"
PREFIX="$DEPS" ./script/build-deps.sh
export PATH="${DEPS}/bin:${PATH}"
export LD_LIBRARY_PATH="${DEPS}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./script/build-binary.sh
make install PREFIX="$PREFIX" PAZUZU_DEPS="$DEPS"

if ! id pazuzu >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/pazuzu \
    --shell /usr/sbin/nologin pazuzu
fi
install -d -o pazuzu -g pazuzu /var/lib/pazuzu/www /var/log/pazuzu
if [[ ! -f /etc/pazuzu/config.lisp ]]; then
  install -m 0644 packaging/config.lisp /etc/pazuzu/config.lisp
fi
echo "pazuzu is installed at ${PREFIX}/bin/pazuzu"
echo "enable the sockets with: systemctl enable --now pazuzu.socket"
