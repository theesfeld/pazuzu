#!/bin/bash
# Keep-alive HTTP/3 requests on one connection.
#
# One curl process is given the URL COUNT times. curl reuses the QUIC
# connection, so this is not one process per request. Prints:
#   h3load connects=N ok=N fail=N seconds=N rps=N
#
# Usage: script/h3load.sh URL [COUNT]
set -euo pipefail
url="${1:?usage: h3load.sh URL [COUNT]}"
count="${2:-50}"
case "$count" in
  ''|*[!0-9]*) echo "COUNT must be a positive integer" >&2; exit 2 ;;
esac
if [ "$count" -lt 1 ]; then
  echo "COUNT must be a positive integer" >&2
  exit 2
fi
if [ -x /opt/pazuzu/bin/curl ]; then
  curl=/opt/pazuzu/bin/curl
elif command -v curl >/dev/null 2>&1; then
  curl=$(command -v curl)
else
  echo "curl was not found" >&2
  exit 2
fi
if ! "$curl" --version | grep -q HTTP3; then
  echo "curl at $curl has no HTTP/3" >&2
  exit 2
fi
args=()
i=0
while [ "$i" -lt "$count" ]; do
  # One -o per URL. A single -o applies only to the first URL.
  args+=(-o /dev/null "$url")
  i=$((i + 1))
done
write=$(mktemp)
trap 'rm -f "$write"' EXIT
# -w is emitted after each URL. num_connects is cumulative for the process,
# so the last line is how many QUIC handshakes were opened.
start=$(date +%s.%N)
"$curl" --http3-only -k -sS -o /dev/null --max-time 60 \
  -w '%{num_connects} %{http_code}\n' \
  "${args[@]}" >"$write"
end=$(date +%s.%N)
connects=$(awk 'END { print $1 }' "$write")
ok=$(awk '$2 == 200 { n++ } END { print n + 0 }' "$write")
fail=$((count - ok))
rps=$(awk -v n="$ok" -v a="$start" -v b="$end" 'BEGIN { d = b - a; if (d <= 0) print "0"; else printf "%.2f", n / d }')
seconds=$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.3f", b - a }')
printf 'h3load connects=%s ok=%s fail=%s seconds=%s rps=%s\n' \
  "$connects" "$ok" "$fail" "$seconds" "$rps"
# curl 8.23 reports QUIC handshakes as num_connects 0. A TCP-style client
# that reconnects per request reports num_connects equal to COUNT.
[ "$fail" -eq 0 ] && [ "$connects" != "$count" ]
