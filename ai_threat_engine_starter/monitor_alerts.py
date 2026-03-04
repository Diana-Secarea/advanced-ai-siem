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

def process_new_alerts(engine):
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
        
        # Process each line (JSONL format)
        enhanced_alerts = []
        for line in new_content.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                alert = json.loads(line)
                
                # Analyze with AI engine
                ai_result = engine.analyze_event(json.dumps(alert))
                
                # Create enhanced alert
                enhanced_alert = {
                    "original_alert": alert,
                    "ai_analysis": ai_result,
                    "timestamp": time.time()
                }
                
                enhanced_alerts.append(enhanced_alert)
                
                # Print if anomaly detected
                if ai_result.get('is_anomaly'):
                    print(f"[ANOMALY DETECTED] Score: {ai_result.get('anomaly_score', 0)}")
                    print(f"  Threat Level: {ai_result.get('threat_level', 'UNKNOWN')}")
                    print(f"  Confidence: {ai_result.get('confidence', 0)}%")
                    if ai_result.get('recommendations'):
                        print(f"  Recommendations: {ai_result['recommendations'][0]}")
                    print()
                
            except json.JSONDecodeError as e:
                print(f"Error parsing alert: {e}")
                continue
            except Exception as e:
                print(f"Error processing alert: {e}")
                continue
        
        # Write enhanced alerts
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
    
    # Initialize AI engine
    try:
        engine = AIThreatEngine(
            model_path=MODEL_PATH,
            vector_db_path=VECTOR_DB_PATH
        )
        print("AI Engine initialized successfully")
    except Exception as e:
        print(f"Error initializing AI engine: {e}")
        sys.exit(1)
    
    print("Monitoring alerts... (Press Ctrl+C to stop)")
    print()
    
    try:
        while True:
            process_new_alerts(engine)
            time.sleep(5)  # Check every 5 seconds
    except KeyboardInterrupt:
        print("\nStopping AI Threat Engine...")
        sys.exit(0)

if __name__ == "__main__":
    main()
