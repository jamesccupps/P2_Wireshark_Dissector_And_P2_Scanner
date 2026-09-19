#!/usr/bin/env bash
# Launch the P2-BACnet Bridge configurator GUI on Linux / macOS.
set -e
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

exec "$PY" p2_bridge_launcher.py "$@"
