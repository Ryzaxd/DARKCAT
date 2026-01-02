#!/bin/bash
set -e

echo "Starting Tor service..."
tor &

sleep 10

echo "Running forensics tool..."
/usr/local/bin/darkweb-forensics "$@"
