#!/bin/bash
# Move the listening sockets named by PAZUZU_FDS onto descriptors 3, 4, ...
# and exec the server. LISTEN_PID is this process, which stays the same
# across exec. The parent waits until "ready" is written to
# PAZUZU_HANDOFF_STATUS.
set -euo pipefail
status="${PAZUZU_HANDOFF_STATUS:?}"
IFS=',' read -r -a fds <<< "${PAZUZU_FDS:?}"
count="${#fds[@]}"
base=200
i=0
for fd in "${fds[@]}"; do
  eval "exec $((base + i))<&${fd}"
  i=$((i + 1))
done
i=0
while [ "$i" -lt "$count" ]; do
  eval "exec $((3 + i))<&$((base + i))"
  eval "exec $((base + i))<&-"
  i=$((i + 1))
done
export LISTEN_FDS="$count"
export LISTEN_FDNAMES="${PAZUZU_FDNAMES:-}"
export LISTEN_PID="$$"
printf 'ready\n' >&"${status}"
eval "exec ${status}<&-"
exec "$@"
