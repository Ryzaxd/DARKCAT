#!/bin/bash
set -e

echo "Starting Tor service..."
tor &
TOR_PID=$!

echo "Waiting for Tor to bootstrap..."
MAX_WAIT=60
WAITED=0

while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip > /dev/null 2>&1; then
        echo "Tor is ready!"
        break
    fi

    if [ $WAITED -eq 0 ]; then
        echo -n "Bootstrapping"
    else
        echo -n "."
    fi

    sleep 2
    WAITED=$((WAITED + 2))
done

echo ""

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "Warning: Tor may not be fully ready, but continuing anyway..."
fi

echo "Running forensics tool..."
/usr/local/bin/darkweb-forensics "$@"

# Keep Tor running
wait $TOR_PID
