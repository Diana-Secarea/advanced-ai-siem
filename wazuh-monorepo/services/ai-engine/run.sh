#!/bin/bash
# Helper script to run AI Threat Engine with virtual environment

cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Run the monitor
python3 monitor_alerts.py
