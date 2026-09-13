#!/usr/bin/env bash
set -e
echo "==> Setting up TraceMail environment (Linux)..."
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "==> Setup complete! Run: source venv/bin/activate"
