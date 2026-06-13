#!/usr/bin/env python3
"""
AI Threat Engine - Alert Monitor
Monitors Wazuh alert logs and processes them with AI
"""

import json
import time
import os
import sys
from pathlib import Path
from ai_engine import AIThreatEngine

# Ensemble detector (IF + Autoencoder)
sys.path.insert(0, str(Path(__file__).parent))
try:
    from autoencoders_approach.ensemble_detector import load_ensemble as _load_ensemble
    _ENSEMBLE_AVAILABLE = True
except ImportError:
    _ENSEMBLE_AVAILABLE = False

# Wazuh paths (override with env for local demo)
ALERTS_FILE = os.environ.get("ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
ENHANCED_ALERTS_FILE = os.environ.get("ENHANCED_ALERTS_FILE", "/var/ossec/logs/alerts/ai_enhanced_alerts.json")
MODEL_PATH = os.environ.get("MODEL_PATH", "/var/ossec/ai_models")
VECTOR_DB_PATH = os.environ.get("VECTOR_DB_PATH", "/var/ossec/ai_models/vector_db")

def ensure_directories():
    """Create necessary directories"""
    os.makedirs(MODEL_PATH, exist_ok=True)
    os.makedirs(VECTOR_DB_PATH, exist_ok=True)
    os.makedirs(os.path.dirname(ENHANCED_ALERTS_FILE), exist_ok=True)

def read_last_position():
    """Read last processed position"""
    pos_file = "/tmp/wazuh_ai_last_position.txt"
    if os.path.exists(pos_file):
        with open(pos_file, 'r') as f:
            return int(f.read().strip())
    return 0

def save_last_position(position):
    """Save last processed position"""
    pos_file = "/tmp/wazuh_ai_last_position.txt"
    with open(pos_file, 'w') as f:
        f.write(str(position))

def process_new_alerts(engine, ensemble=None):
    """Process new alerts from the alerts file"""
    if not os.path.exists(ALERTS_FILE):
        print(f"Alert file not found: {ALERTS_FILE}")
        return

    last_position = read_last_position()

    try:
        with open(ALERTS_FILE, 'r') as f:
            f.seek(last_position)
            new_content = f.read()
            current_position = f.tell()

        if not new_content.strip():
            return

        enhanced_alerts = []
        for line in new_content.strip().split('\n'):
            if not line.strip():
                continue

            try:
                alert = json.loads(line)

                # ── Step 1: RAG + Pattern Analyzer (existing pipeline) ──
                ai_result = engine.analyze_event(json.dumps(alert))

                # ── Step 2: Ensemble scoring (IF + Autoencoder) ──
                ensemble_result = None
                if ensemble is not None:
                    try:
                        ens = ensemble.score(alert)
                        ensemble_result = {
                            'anomaly_label': ens['anomaly_label'],
                            'combined_score': ens['combined_score'],
                            'if_score':       ens['if_score'],
                            'ae_score':       ens['ae_score'],
                            'is_anomaly':     ens['is_anomaly'],
                        }
                    except Exception as e:
                        print(f"  [ensemble] Scoring error: {e}")

                # ── Step 3: Build enhanced alert ──
                enhanced_alert = {
                    "original_alert": alert,
                    "ai_analysis":    ai_result,
                    "ensemble":       ensemble_result,
                    "timestamp":      time.time(),
                }
                enhanced_alerts.append(enhanced_alert)

                # ── Step 4: Console output ──
                anomaly_label = ensemble_result['anomaly_label'] if ensemble_result else None
                combined      = ensemble_result['combined_score'] if ensemble_result else None
                if_score      = ensemble_result['if_score']   if ensemble_result else ai_result.get('anomaly_score', 0)
                ae_score      = ensemble_result['ae_score']   if ensemble_result else None
                is_anomaly    = ensemble_result['is_anomaly'] if ensemble_result else ai_result.get('is_anomaly', False)

                if is_anomaly:
                    rule_desc = alert.get('rule', {}).get('description', 'unknown')[:60]
                    ae_str    = f"  AE score:   {ae_score}/100" if ae_score is not None else ""
                    print(f"\n[{anomaly_label or 'ANOMALY'}] {rule_desc}")
                    print(f"  IF score:   {if_score}/100")
                    if ae_str:
                        print(ae_str)
                    if combined is not None:
                        print(f"  Combined:   {combined}/100")
                    print(f"  Threat Lvl: {ai_result.get('threat_level', 'UNKNOWN')}")
                    if ai_result.get('recommendations'):
                        print(f"  Action:     {ai_result['recommendations'][0]}")

            except json.JSONDecodeError as e:
                print(f"Error parsing alert: {e}")
                continue
            except Exception as e:
                print(f"Error processing alert: {e}")
                continue

        if enhanced_alerts:
            with open(ENHANCED_ALERTS_FILE, 'a') as f:
                for alert in enhanced_alerts:
                    f.write(json.dumps(alert) + '\n')

        save_last_position(current_position)

    except Exception as e:
        print(f"Error reading alerts file: {e}")

def main():
    """Main monitoring loop"""
    print("AI Threat Engine - Starting...")
    print(f"Monitoring: {ALERTS_FILE}")
    print(f"Output: {ENHANCED_ALERTS_FILE}")
    print()

    ensure_directories()

    # Initialize existing AI engine (RAG + Pattern Analyzer)
    try:
        engine = AIThreatEngine(
            model_path=MODEL_PATH,
            vector_db_path=VECTOR_DB_PATH
        )
        print("AI Engine initialized successfully")
    except Exception as e:
        print(f"Error initializing AI engine: {e}")
        sys.exit(1)

    # Load ensemble (IF + Autoencoder) — optional, degrades gracefully
    ensemble = None
    if _ENSEMBLE_AVAILABLE:
        try:
            ensemble = _load_ensemble()
            ae_status = "IF + Autoencoder" if ensemble.ae_det is not None else "IF only"
            print(f"Ensemble detector loaded: {ae_status}")
        except Exception as e:
            print(f"Ensemble load failed (continuing without it): {e}")
    else:
        print("Ensemble not available — install autoencoders_approach package")

    print()
    print("Monitoring alerts... (Press Ctrl+C to stop)")
    print()

    try:
        while True:
            process_new_alerts(engine, ensemble)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping AI Threat Engine...")
        sys.exit(0)

if __name__ == "__main__":
    main()
