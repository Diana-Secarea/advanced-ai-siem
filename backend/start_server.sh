#!/bin/bash
# Start the Wazuh dashboard + chat server.
# Uses the ai_threat_engine_starter venv (has torch, faiss, sentence-transformers, flask, etc.)
# Run with sudo so we can read alerts.log.
cd "$(dirname "$0")"

VENV="../ai_threat_engine_starter/venv"

if [[ ! -d "$VENV" ]]; then
    echo "Error: ai_engine venv not found at $VENV"
    echo "Run: cd ../ai_threat_engine_starter && python3 -m venv venv && venv/bin/pip install -r requirements.txt"
    exit 1
fi

echo "Starting server (sudo needed to read /var/ossec/logs/alerts/alerts.log)..."
echo "Dashboard: http://127.0.0.1:5000"
echo "Chat UI:   http://127.0.0.1:5000/chat.html"
exec sudo "$VENV/bin/python" server.py
