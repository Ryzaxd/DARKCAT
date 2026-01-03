#!/bin/bash
set -euo pipefail

echo "Starting Tor..."
tor &

echo "Waiting for Tor SOCKS to become ready..."
MAX_WAIT=60
WAITED=0

until curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; do
  sleep 2
  WAITED=$((WAITED + 2))
  echo "  ... ${WAITED}s"
  if [ $WAITED -ge $MAX_WAIT ]; then
    echo "Tor not ready after ${MAX_WAIT}s (continuing anyway)."
    break
  fi
done

echo "Running DARKCAT with args: $*"
exec /usr/local/bin/darkcat "$@"
