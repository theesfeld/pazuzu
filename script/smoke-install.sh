#!/usr/bin/env bash
# Install into DESTDIR and serve one static file over HTTP/1.1, HTTP/2,
# and HTTP/3, then stop on SIGTERM.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
DEPS="${PAZUZU_DEPS:-/opt/pazuzu}"
DEST="${DESTDIR:-/tmp/pazuzu-destdir}"
PREFIX="${PREFIX:-/usr/local}"
PORT="${PORT:-18081}"
rm -rf "$DEST"
make install DESTDIR="$DEST" PREFIX="$PREFIX" PAZUZU_DEPS="$DEPS"

BIN="$DEST$PREFIX/bin/pazuzu"
"$BIN" --version
test -x "$BIN"
test -f "$DEST/etc/pazuzu/config.lisp"
test -f "$DEST/etc/systemd/system/pazuzu.service"
test -e "$DEST$PREFIX/lib/pazuzu/libnghttp2.so"
test -e "$DEST$PREFIX/lib/pazuzu/libngtcp2_crypto_ossl.so"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/www"
printf 'smoke-ok' > "$WORK/www/index.html"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 \
  -subj /CN=127.0.0.1 \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
cat > "$WORK/config.lisp" <<EOF
(:address "127.0.0.1"
 :port ${PORT}
 :workers 1
 :certificate "$WORK/cert.pem"
 :private-key "$WORK/key.pem"
 :root "$WORK/www"
 :directories ((:prefix "/" :root ".")))
EOF
"$BIN" --check-config "$WORK/config.lisp" | grep -q "configuration ok"

# The wrapper sets LD_LIBRARY_PATH to the installed private lib directory.
# Drop the build prefix so a leaked /opt/pazuzu path cannot satisfy dlopen.
env -u LD_LIBRARY_PATH "$BIN" --config "$WORK/config.lisp" >"$WORK/out" 2>"$WORK/err" &
pid=$!
cleanup() {
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
ready=0
for _ in $(seq 1 100); do
  if curl -skf --http1.1 --max-time 1 "https://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "server exited early" >&2
    cat "$WORK/err" >&2
    exit 1
  fi
  sleep 0.2
done
test "$ready" = 1

h1=$(curl -skf --http1.1 --max-time 5 -o "$WORK/h1" -w '%{http_version}' "https://127.0.0.1:${PORT}/")
test "$h1" = "1.1"
test "$(cat "$WORK/h1")" = "smoke-ok"
h2=$(curl -skf --http2 --max-time 5 -o "$WORK/h2" -w '%{http_version}' "https://127.0.0.1:${PORT}/")
test "$h2" = "2"
test "$(cat "$WORK/h2")" = "smoke-ok"
h3=$(curl -skf --http3-only --max-time 8 -o "$WORK/h3" -w '%{http_version}' "https://127.0.0.1:${PORT}/")
test "$h3" = "3"
test "$(cat "$WORK/h3")" = "smoke-ok"

kill -TERM "$pid"
status=0
wait "$pid" || status=$?
# SIGTERM is a clean shutdown. The process exits 0.
if [[ "$status" -ne 0 ]]; then
  echo "exit status $status" >&2
  cat "$WORK/err" >&2
  exit 1
fi
grep -q "draining connections" "$WORK/err"
trap - EXIT
rm -rf "$WORK"
echo "smoke ok"
