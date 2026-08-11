#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "================================================================"
echo "   VULNFORGE ULTIMATE v3.3 - Production Security Suite         "
echo "   [Safe Scope Guard • Adaptive Rate Limiter • State Machine]  "
echo "================================================================"

if ! python3 -c "import fastapi, uvicorn, httpx, reportlab" 2>/dev/null; then
    echo "[*] Installing dependencies..."
    python3 -m pip install -r requirements.txt
fi

if [ ! -f "vulnforge.db" ]; then
    echo "[*] Initializing SQLite database..."
    python3 seed.py
fi

if [ "$#" -gt 0 ]; then
    exec python3 cli.py "$@"
fi

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "[+] Starting Interactive Dashboard on http://$HOST:$PORT"
echo "[+] Usage: ./run.sh -u https://authorized-target.com --rate-limit 5.0"
echo ""

exec python3 server.py
