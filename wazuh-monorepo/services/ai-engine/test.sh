#!/bin/bash
# Helper script to test AI Threat Engine with virtual environment

cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Run the test
python3 test_engine.py
