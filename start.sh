#!/usr/bin/env sh
# ARACHNE OSINT launcher (Linux / macOS)
cd "$(dirname "$0")" || exit 1
exec python3 server.py "$@"
