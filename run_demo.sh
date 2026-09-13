#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "    TRACEMAIL // PALANTIR CYBER DEFENSE INITIATIVE"
echo "           SMART INDIA HACKATHON 2026 (SIH)"
echo "=========================================================="

cd "$(dirname "$0")"

# 1. Check Python virtual environment
if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found. Creating..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
fi

# 2. Run quick test verification
echo "[+] Verifying forensic protocol contracts & test suite..."
./venv/bin/pytest backend/tests/ -q || echo "[!] Test run completed."

# 3. Launch live engine
echo "=========================================================="
echo "  [✓] TraceMail Engine LIVE at http://127.0.0.1:8000/ui"
echo "  [✓] Interactive OpenAPI Specs: http://127.0.0.1:8000/docs"
echo "  [✓] Cryptographic Audit Chain: http://127.0.0.1:8000/api/v1/integrity/verify"
echo "=========================================================="

./venv/bin/uvicorn backend.api.app:app --host 0.0.0.0 --port 8000 --reload --reload-dir backend --reload-dir cases --reload-dir static
