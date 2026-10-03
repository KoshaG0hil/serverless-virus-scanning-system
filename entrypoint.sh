#!/bin/bash
set -e

echo "[*] Initializing ClamAV service in Google Cloud Run..."
mkdir -p /var/run/clamav && chown -R clamav:clamav /var/run/clamav /var/lib/clamav

# Start clamd service in background if available
if command -v clamd >/dev/null 2>&1; then
    echo "[*] Starting ClamAV daemon (clamd)..."
    clamd &
fi

# Run background freshclam signature updater every 2 hours
freshclam -d &

echo "[*] Starting Gunicorn application server on port ${PORT:-8080}..."
exec gunicorn --bind "0.0.0.0:${PORT:-8080}" --workers 2 --threads 4 --timeout 300 "src.app:app"
