# AI-SIEM Threat Engine

An AI-powered threat detection and intelligence engine built on top of [Wazuh](https://wazuh.com). It extends traditional SIEM capabilities with machine learning anomaly detection and a RAG-based threat intelligence chat system, enabling automated identification of sophisticated attacks that rule-based systems miss.

## Architecture

The AI-SIEM Threat Engine consists of three core components that layer on top of a running Wazuh Manager:

1. **Anomaly Detection Engine** — An Isolation Forest model trained on clean baseline data to detect deviations in alert behavior
2. **Real-Time Alert Monitor** — Continuously processes incoming Wazuh alerts and scores them for anomalous activity
3. **RAG Threat Intelligence Chat** — A retrieval-augmented generation system that queries MITRE ATT&CK, YARA rules, and vendor advisories using a local LLM

## Capabilities

**ML-Based Anomaly Detection**

Uses an Isolation Forest algorithm trained exclusively on clean (baseline) data to learn normal alert patterns. Incoming alerts are scored on a 0–100 scale, with scores above the calibrated threshold flagged as anomalous. The model extracts 13 features from each alert including rule severity, MITRE technique count, suspicious group indicators, and temporal patterns.

**Real-Time Alert Scoring**

The monitor daemon watches for new Wazuh alerts and runs each one through the anomaly detection pipeline in real time. Alerts that exceed the anomaly threshold trigger elevated notifications, allowing security teams to focus on genuinely suspicious events rather than sifting through noise.

**Threat Intelligence Chat (RAG)**

A chat interface backed by a FAISS + BM25 hybrid retrieval index over 1,300+ threat intelligence episodes sourced from MITRE ATT&CK, YARA rule descriptions, and vendor security advisories. Users can ask natural-language questions about attack techniques, indicators of compromise, or detection strategies and receive contextual answers with source attribution.

**Automated Training Data Collection**

A daily collection pipeline gathers Wazuh alerts, deduplicates them, and builds a clean training dataset. This supports continuous model retraining as the environment evolves, keeping detection baselines current.

**Attack Simulation Coverage**

The engine has been validated against 14 categories of simulated attacks:

- SSH brute force & credential stuffing
- Privilege escalation (su/sudo abuse, SUID manipulation)
- File integrity violations (critical system file modifications)
- Malware simulation (reverse shells, base64 payloads, SUID shells)
- Network reconnaissance (port scans, lateral movement, DNS recon)
- Account manipulation (UID-0 backdoors, hidden users)
- Reverse shell & C2 (Python/NC/Bash/Perl, HTTP beaconing, DNS tunneling)
- Log tampering (wtmp clearing, fake injection, history wiping)
- Persistence mechanisms (malicious cron jobs, systemd backdoor services)
- Web attacks (SQL injection, XSS, directory traversal)
- Rootkit simulation (hidden files, kernel module abuse)
- Cryptomining simulation (download attempts, process spoofing)
- Data exfiltration (DNS exfil, HTTP exfil, file staging)
- Firewall manipulation (iptables flush, suspicious port opens)

## Model Performance

| Metric | Value |
|---|---|
| Score separation (attack vs clean) | 44.1 points |
| Anomaly threshold | 62/100 (90th percentile of clean) |
| Real attack detection rate | ~95–100% across all attack categories |
| False positive rate | 11.2% |

## Feature Extraction

The model extracts 13 features from each Wazuh alert:

| # | Feature | Description |
|---|---|---|
| 0 | `word_count` | Number of words in the alert message |
| 1 | `event_size` | Total size of the alert event |
| 2 | `failed_count` | Count of failure-related keywords in `full_log` |
| 3 | `hour` | Hour of day the alert was generated |
| 4 | `off_hours` | Whether the alert occurred outside business hours |
| 5 | `ip_count` | Number of unique IPs referenced |
| 6 | `port_count` | Number of ports referenced |
| 7 | `process_count` | Number of processes referenced |
| 8 | `rule_level` | Wazuh rule severity level |
| 9 | `rule_id` | Numeric Wazuh rule ID |
| 10 | `mitre_count` | Number of MITRE ATT&CK techniques tagged |
| 11 | `suspicious_group_count` | Count of suspicious group indicators |
| 12 | `data_field_count` | Number of populated data fields |

## Project Structure

```
ai_threat_engine_starter/
├── ai_engine/
│   └── anomaly_detector.py          # Isolation Forest detector (scoring & prediction)
├── backend/
│   └── start_server.sh              # Flask API server launcher
├── frontend/
│   └── chat.html                    # RAG chat web interface
├── rag_core/
│   └── indexing/
│       └── threat_intel_indexer.py   # FAISS + BM25 index builder
├── train_isolation_forest.py        # Model training script
├── evaluate_isolation_forest.py     # Evaluation & metrics report
├── collect_training_data.py         # Daily alert collection pipeline
├── collect_daily.sh                 # Cron wrapper for scheduled collection
├── monitor_alerts.py                # Real-time alert processing daemon
├── data/
│   ├── training/                    # Training datasets
│   │   ├── daily_logs/              # Per-day alert snapshots
│   │   └── combined/                # Merged training data
│   ├── ai_models/                   # Trained model artifacts (.pkl)
│   └── threat_intel_index/          # FAISS + BM25 index files
└── venv/                            # Python virtual environment
```

## Getting Started

### Prerequisites

- Wazuh Manager (v4.x) installed and running
- Python 3.10+
- Ollama with a local LLM model (e.g., `llama3.2`) for the RAG chat system

### Setup

```bash
# Create and activate virtual environment
cd ai_threat_engine_starter
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install scikit-learn numpy joblib flask faiss-cpu rank_bm25

# Collect baseline training data
python collect_training_data.py

# Train the anomaly detection model
python train_isolation_forest.py

# Build the threat intelligence index
python -m rag_core.indexing.threat_intel_indexer

# Start the API server (includes chat endpoint)
bash backend/start_server.sh
```

### Usage

```bash
# Run the real-time alert monitor
python monitor_alerts.py

# Evaluate model performance
python evaluate_isolation_forest.py

# Chat API (once server is running)
curl -X POST http://localhost:5000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What MITRE techniques relate to SSH brute force?"}'
```

## Tech Stack

| Component | Technology |
|---|---|
| SIEM Platform | Wazuh v4.x |
| Anomaly Detection | scikit-learn (Isolation Forest) |
| Threat Intel Index | FAISS + BM25 |
| Local LLM | Ollama (llama3.2) |
| API Server | Flask |
| Chat Frontend | HTML/JS (dark theme) |
| Model Serialization | joblib |

## Authors

Wazuh Copyright (C) 2015-2023 Wazuh Inc. (License GPLv2)

Based on the OSSEC project started by Daniel Cid.

AI-SIEM Threat Engine built on top of Wazuh by the project maintainer.
