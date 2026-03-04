#!/bin/bash
#
# Start Wazuh with RAG Core Integration
# This script initializes RAG Core and starts monitoring Wazuh alerts
#
# Usage:
#   ./start_wazuh_rag.sh           # Local demo (data/ in project)
#   ./start_wazuh_rag.sh --wazuh   # With real Wazuh (/var/ossec/...)
#   RUN_WITH_WAZUH=1 ./start_wazuh_rag.sh   # Same as --wazuh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PROJECT_ROOT="$SCRIPT_DIR"

# Wazuh mode: use real Wazuh paths and require manager
RUN_WITH_WAZUH=0
[[ "$1" == "--wazuh" ]] && RUN_WITH_WAZUH=1
[[ -n "$RUN_WITH_WAZUH" && "$RUN_WITH_WAZUH" != "0" ]] && RUN_WITH_WAZUH=1

if [[ "$RUN_WITH_WAZUH" -eq 1 ]]; then
    MODEL_PATH="${MODEL_PATH:-/var/ossec/ai_models}"
    VECTOR_DB_PATH="${VECTOR_DB_PATH:-/var/ossec/ai_models/vector_db}"
    ALERTS_FILE="${ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}"
    ENHANCED_ALERTS_FILE="${ENHANCED_ALERTS_FILE:-/var/ossec/logs/alerts/ai_enhanced_alerts.json}"
    echo "🔧 Mode: Wazuh (using /var/ossec/...)"
else
    MODEL_PATH="${MODEL_PATH:-$SCRIPT_DIR/data/ai_models}"
    VECTOR_DB_PATH="${VECTOR_DB_PATH:-$SCRIPT_DIR/data/ai_models/vector_db}"
    ALERTS_FILE="${ALERTS_FILE:-$SCRIPT_DIR/data/alerts.json}"
    ENHANCED_ALERTS_FILE="${ENHANCED_ALERTS_FILE:-$SCRIPT_DIR/data/ai_enhanced_alerts.json}"
    echo "🔧 Mode: Local demo (using project data/)"
fi
export MODEL_PATH VECTOR_DB_PATH ALERTS_FILE ENHANCED_ALERTS_FILE

echo "=========================================="
echo "Wazuh + RAG Core Integration"
echo "=========================================="
echo ""

# Create directories
echo "📁 Creating directories..."
if ! mkdir -p "$MODEL_PATH" "$VECTOR_DB_PATH" 2>/dev/null; then
    if [[ "$RUN_WITH_WAZUH" -eq 1 ]]; then
        echo ""
        echo "   Run these commands in your terminal (one-time setup, then start Wazuh separately):"
        echo ""
        echo "   sudo mkdir -p $MODEL_PATH $VECTOR_DB_PATH"
        echo "   sudo chown -R \$(whoami) $MODEL_PATH"
        echo "   sudo systemctl start wazuh-manager"
        echo "   sudo systemctl start wazuh-agent"
        echo ""
        echo "   Then run again: ./start_wazuh_rag.sh --wazuh"
        echo ""
        exit 1
    fi
    exit 1
fi
mkdir -p "$(dirname "$ALERTS_FILE")"
mkdir -p "$(dirname "$ENHANCED_ALERTS_FILE")"
echo "   Model: $MODEL_PATH"
echo "   Vector DB: $VECTOR_DB_PATH"
echo "   Alerts: $ALERTS_FILE"
echo "✅ Directories ready"
echo ""

# Check if Wazuh Manager and Agent are running (strict when --wazuh)
echo "🔍 Checking Wazuh status..."
MANAGER_RUNNING=0
AGENT_RUNNING=0
if systemctl is-active --quiet wazuh-manager 2>/dev/null || pgrep -f "wazuh-manager" >/dev/null 2>&1; then
    MANAGER_RUNNING=1
    echo "✅ Wazuh Manager is running"
fi
if systemctl is-active --quiet wazuh-agent 2>/dev/null || pgrep -f "wazuh-agent" >/dev/null 2>&1; then
    AGENT_RUNNING=1
    echo "✅ Wazuh Agent is running"
fi
if [[ "$MANAGER_RUNNING" -eq 0 ]]; then
    echo "⚠️  Wazuh Manager is not running"
    echo "   Start manager: sudo systemctl start wazuh-manager"
    echo "   Start agent:   sudo systemctl start wazuh-agent"
    if [[ "$RUN_WITH_WAZUH" -eq 1 ]]; then
        echo ""
        echo "   You started with --wazuh. Start Manager and Agent first, then run this script again."
        exit 1
    fi
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi
if [[ "$AGENT_RUNNING" -eq 0 ]] && [[ "$RUN_WITH_WAZUH" -eq 1 ]]; then
    echo "⚠️  Wazuh Agent is not running (Manager needs Agent to receive events)"
    echo "   Start agent:   sudo systemctl start wazuh-agent"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi
echo ""

# Check if alerts file exists
if [ ! -f "$ALERTS_FILE" ]; then
    echo "⚠️  Alerts file not found: $ALERTS_FILE"
    echo "   Waiting for Wazuh to create it..."
    echo "   (This is normal if Wazuh just started)"
    echo ""
fi

# Use venv Python if present
PYTHON="python3"
if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python3"
    echo "Using venv: $PYTHON"
fi

# Initialize RAG Core (if needed)
echo "🤖 Initializing RAG Core..."
$PYTHON << EOF
import sys
import os
from pathlib import Path

# Add project and rag_core to path (rag_core uses "from ingestion.*" etc.)
project_root = Path(os.environ.get("PROJECT_ROOT", "."))
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "rag_core"))
os.chdir(project_root)

try:
    from rag_core.rag_core_system import RAGCoreSystem
    from ai_engine import AIThreatEngine
    
    # Initialize RAG Core
    print("  Initializing RAG Core System...")
    rag_system = RAGCoreSystem(base_path="$VECTOR_DB_PATH")
    
    # Check if we have episodes indexed
    if not rag_system.episodes:
        print("  ⚠️  No episodes found. Ingesting threat intelligence...")
        print("  (This may take a few minutes on first run)")
        
        # Ingest threat intelligence
        results = rag_system.ingest_threat_intelligence()
        
        # Build episodes from threat intelligence
        print("  Building episodes...")
        # Episodes will be built from events, not from threat intel directly
        # So we'll wait for events to come in
        
        print("  ✅ Threat intelligence ingested")
    else:
        print(f"  ✅ Found {len(rag_system.episodes)} existing episodes")
    
    # Test AI Engine
    print("  Testing AI Engine...")
    engine = AIThreatEngine(
        model_path="$MODEL_PATH",
        vector_db_path="$VECTOR_DB_PATH"
    )
    print("  ✅ AI Engine initialized successfully")
    
except Exception as e:
    print(f"  ❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    echo "❌ Failed to initialize RAG Core"
    exit 1
fi

echo "✅ RAG Core initialized"
echo ""

# Start monitor
echo "🚀 Starting Wazuh Alert Monitor..."
echo "   Monitoring: $ALERTS_FILE"
echo "   Press Ctrl+C to stop"
echo ""
echo "=========================================="
echo ""

# Run monitor (from project dir so imports work; env vars already exported)
cd "$SCRIPT_DIR"
PYTHONPATH="$SCRIPT_DIR" $PYTHON monitor_alerts.py
