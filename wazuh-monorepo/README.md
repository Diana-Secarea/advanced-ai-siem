# wazuh-monorepo

All of **Selene** (the AI Threat Engine built on top of this Wazuh fork)
lives here, organized as a monorepo. The surrounding repository root is the
upstream Wazuh source tree — untouched.

```
wazuh-monorepo/
├── apps/
│   ├── backend/          Flask API :5000 — alerts, ensemble scoring, RAG chat,
│   │                     auth (users.db), tickets, reactor, CVE-agent endpoints, /metrics
│   ├── frontend/         Selene UI (served at /) — dashboard, ML engine,
│   │                     reactor panel, CVE agent, vector DB, profile, login
│   └── frontend-legacy/  previous UI (served at /legacy/)
├── services/
│   ├── ai-engine/        ML + RAG core: detectors (IF / AE / UEBA / stacking),
│   │                     training + eval scripts, rag_core (Qdrant/Ollama),
│   │                     scheduled_agent (CVE ingestion), venv, data/
│   └── threat_intel/     raw threat-intel corpus (MITRE, sigma, IoC, vendor, KEV)
└── infra/                MLOps: Jenkins pipelines (retrain / rag-eval / promote),
                          Prometheus + Grafana + Pushgateway compose stack,
                          dev/staging/production environments + model registries
```

## Compatibility symlinks

The old top-level paths still work — they are symlinks into the monorepo, so
external references (ossec.conf, cron entries, shell history, docs) don't break:

```
backend                  → wazuh-monorepo/apps/backend
improved_UI              → wazuh-monorepo/apps/frontend
frontend                 → wazuh-monorepo/apps/frontend-legacy
ai_threat_engine_starter → wazuh-monorepo/services/ai-engine
threat_intel             → wazuh-monorepo/services/threat_intel
wazuh-ai-infra           → wazuh-monorepo/infra
```

## Quick start

```bash
# run the backend (dev)
cd wazuh-monorepo/apps/backend
sudo ../../services/ai-engine/venv/bin/python server.py

# retrain everything + evaluate + push metrics
bash wazuh-monorepo/infra/scripts/run_ml_pipeline.sh

# monitoring stack (Jenkins / Prometheus / Grafana)
cd wazuh-monorepo/infra && docker compose up -d

# environments
set -a; source wazuh-monorepo/infra/environments/staging.env; set +a
```

See `infra/README.md` for the full MLOps setup (Jenkins jobs, promotion flow,
dashboards) and `services/ai-engine/scheduled_agent/README.md` for the CVE agent.
