# Selenne — AI Threat Engine for Wazuh

**[selenne.app](https://selenne.app/)** · **[LinkedIn](https://www.linkedin.com/company/selenne)**

Selenne turns a Wazuh SIEM into an AI analyst: every alert is scored by an
unsupervised ML ensemble, explained in plain language by a **local** LLM
grounded in a threat-intelligence corpus, and optionally acted on by a headless
reactor. Nothing leaves the host — no cloud LLM, no telemetry.

This monorepo sits inside a Wazuh source fork; the surrounding tree is upstream
Wazuh and is not modified.

```
Wazuh manager ──► alerts.json / archives.json
                        │
                        ▼
     ┌─────────────── Flask backend (:5000) ───────────────┐
     │  ensemble scoring   IF + Autoencoder + UEBA         │
     │                     → LogReg stacker → verdict      │
     │  raw-log scoring    novelty + content model         │
     │  agentic RAG        Qdrant + Ollama (llama3.2)      │
     │  reactor            webhook / Wazuh active response │
     │  CVE agent          NVD + CISA-KEV → Postgres+Qdrant│
     └──────────────────────┬──────────────────────────────┘
                            ▼
                Selenne UI (static HTML, served at /)
```

---

## 1. Repository layout

```
wazuh-monorepo/
├── apps/
│   ├── backend/           Flask API :5000 — the whole server-side product
│   │   ├── server.py        routes, scoring, SSE streams, reactor, auth gate
│   │   ├── wsgi.py          production entry point (waitress)
│   │   ├── auth.py          users.db, cookie sessions, lockout, admin roles
│   │   ├── agent_core.py    bounded ReAct loop + read-only tools
│   │   ├── agentic_rag.py   query gate, multi-query rewrite, CRAG grading
│   │   ├── tenancy.py       maps endpoints/alerts to the owning account
│   │   ├── reactor_actions.py, tickets.py, doc_extract.py, guardrails.py
│   │   └── start_server.sh / stop_server.sh
│   ├── frontend/          production UI (served at /) — index, alerts, chat,
│   │                      ml, cve-agent, vectordb, reactor, admin, profile,
│   │                      login, landing
│   └── frontend-legacy/   previous UI (served at /legacy/)
├── services/
│   ├── ai-engine/         ML + RAG core (and the venv everything runs from)
│   │   ├── ai_engine/       anomaly_detector, ueba_detector, pattern_analyzer
│   │   ├── rag_core/        ingestion → indexing → retrieval → evaluation
│   │   ├── scheduled_agent/ autonomous CVE ingestion agent
│   │   ├── adversary/       attacker-in-the-loop self-training
│   │   ├── train_*.py, log_*.py, evaluate_*.py, retrain_all.sh
│   │   └── data/ai_models/  trained .pkl artefacts (tracked in git)
│   └── threat_intel/      raw corpus: MITRE, sigma, IoC, vendor, KEV
└── infra/
    ├── deploy/            DEPLOYMENT.md, systemd unit, nginx sample,
    │                      preflight.sh, endpoint collector installers
    ├── jenkins/           retrain / rag-eval / promote pipelines
    ├── grafana/, prometheus/   monitoring stack (infra/docker-compose.yml)
    ├── scripts/           run_ml_pipeline.sh, tune_hyperparams.py, metrics
    └── environments/      dev / staging / production .env profiles
```

**Compatibility symlinks** at the repo root make old paths in `ossec.conf`,
cron entries and notes keep working. They are local-only and gitignored — a
fresh clone has just `wazuh-monorepo/`, and you recreate them if you want them
(`ln -s wazuh-monorepo/apps/backend backend`):

| Old path | Now |
|---|---|
| `backend` | `wazuh-monorepo/apps/backend` |
| `improved_UI` | `wazuh-monorepo/apps/frontend` |
| `frontend` | `wazuh-monorepo/apps/frontend-legacy` |
| `ai_threat_engine_starter` | `wazuh-monorepo/services/ai-engine` |
| `threat_intel` | `wazuh-monorepo/services/threat_intel` |
| `wazuh-ai-infra` | `wazuh-monorepo/infra` |

---

## 2. Prerequisites

| Need | Why | Check |
|---|---|---|
| Linux / WSL2 | everything runs here | `uname -a` |
| Wazuh manager 4.x at `/var/ossec` | produces the alerts Selenne reads | `sudo /var/ossec/bin/wazuh-control status` |
| Docker + compose | Qdrant (vectors) + Postgres (ledger) | `docker ps` |
| Ollama | local LLM — no cloud inference | `curl -s localhost:11434/api/tags` |
| Python 3.13 | the venv | `services/ai-engine/venv/bin/python --version` |
| `sudo` | the backend reads `/var/ossec/logs/…` | — |

GPU is optional; without one, `llama3.2` still answers, just slower.

---

## 3. First-time setup

```bash
cd ~/wazuh/wazuh-monorepo

# 1. Python environment (one venv for backend + ML + RAG + agents)
python3 -m venv services/ai-engine/venv
services/ai-engine/venv/bin/pip install -r services/ai-engine/requirements.txt
services/ai-engine/venv/bin/pip install -r apps/backend/requirements.txt
#   CPU-only host: install the CPU torch build FIRST, or pip pulls ~4 GB of
#   unused CUDA wheels — see infra/deploy/DEPLOYMENT.md.

# 2. Secrets
cp apps/backend/.env.example apps/backend/.env
python3 -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32))"
#   paste that in, set PG_PASSWORD, leave BIND_HOST=127.0.0.1

# 3. Data services (Qdrant :6333, Postgres :5432 — both bound to localhost)
docker compose -f services/ai-engine/docker-compose.yml up -d

# 4. Local models
ollama pull llama3.2      # chat + analysis
ollama pull llava:7b      # optional — image attachments in chat

# 5. Threat-intel index (only once; the Qdrant volume persists across restarts)
cd services/ai-engine
venv/bin/python -m rag_core.ingestion.ingest_all          # fetch/refresh corpus
venv/bin/python -m rag_core.indexing.qdrant_indexer --wipe # build the vectors
```

Trained models (`data/ai_models/*.pkl`) are committed, so detection works
immediately after a clone — no training run needed to get started.

> `apps/backend/venv/` is a leftover second environment (Flask only, 44 MB).
> Nothing starts from it — `start_server.sh` uses `services/ai-engine/venv`.

---

## 4. Daily run

Order matters: the manager writes the log files the backend reads.

```bash
# 1. Wazuh manager (and the local agent, if this host is also monitored)
sudo /var/ossec/bin/wazuh-control start

# 2. Backend — brings up Docker + Ollama itself, then serves the UI
cd ~/wazuh/wazuh-monorepo/apps/backend
./start_server.sh                 # waitress (production)
DEV_SERVER=1 ./start_server.sh    # Flask dev server instead

# stop everything
./stop_server.sh
```

Open **http://127.0.0.1:5000** (from Windows, use the WSL IP — `hostname -I`).

Verify:

```bash
curl -s localhost:5000/health          # {"status":"ok"}
curl -s localhost:5000/ready           # models + Qdrant + Ollama reachable
curl -s localhost:5000/metrics | head  # Prometheus exposition
```

> **The backend does not auto-reload.** After editing anything under
> `apps/backend/`, restart it — otherwise new routes 404 with an HTML page.
> `stop_server.sh` only kills the dev server; for waitress use
> `sudo pkill -f "python wsgi.py"`.

---

## 5. Enrolling endpoints (collectors)

Signed-in users download a per-account package from the UI (hero buttons on the
landing page, or the cards on the overview page):

| Platform | Package | Install |
|---|---|---|
| Windows | `selenne-collector-windows.zip` | unzip → double-click `install-selenne-agent.cmd` (self-elevates via UAC) |
| Linux | `selenne-collector-linux.zip` | `sudo bash install-selenne-collector.sh` |
| macOS | `selenne-collector-macos.zip` | `sudo bash install-selenne-collector-macos.sh` |

Each zip carries the installer, the Selenne logo (`selenne.ico` becomes the
Windows Start Menu icon) and a README. Bare scripts remain at
`/download/install-selenne-agent.cmd` (`.ps1` alias for policy-restricted
environments) and `/download/install-selenne-collector*.sh`.

The routes **503 until enrolment is configured** — the manager needs password
enrolment on, and the backend needs the same password:

```bash
openssl rand -hex 16 | sudo tee /var/ossec/etc/authd.pass
sudo chown root:wazuh /var/ossec/etc/authd.pass && sudo chmod 640 /var/ossec/etc/authd.pass
sudo sed -i 's|<use_password>no</use_password>|<use_password>yes</use_password>|' /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-control restart

printf 'WAZUH_REG_PASSWORD=%s\n' \
  "$(sudo cat /var/ossec/etc/authd.pass)" >> apps/backend/.env
# restart the backend afterwards
```

Then pin the two hosts, which must be different records:

```bash
SELENNE_MANAGER_HOST=agents.selenne.app    # DNS-only (grey cloud) → origin
SELENNE_DASHBOARD_HOST=selenne.app         # the proxied name customers open
```

`agent-auth` (1515) and the agent's `<address>` (1514) are raw TCP, and
Cloudflare's proxy forwards 80/443 only — point `SELENNE_MANAGER_HOST` at a
proxied name and the dashboard keeps working while every enrolment times out.
Unset, both fall back to the request's `Host` header, which the caller controls.

Enrolled agents are named `<account>__<machine>`, which is how `tenancy.py`
attributes each endpoint's alerts to the right account.

---

## 6. Configuration

All of it lives in `apps/backend/.env` (gitignored; template in
`.env.example`). The ones that actually change behaviour:

| Variable | Default | Effect |
|---|---|---|
| `FLASK_SECRET_KEY` | — | **required**; session signing |
| `BIND_HOST` / `BIND_PORT` | `127.0.0.1` / `5000` | keep on loopback unless behind nginx |
| `AUTH_ENABLED` | `1` | `0` disables the whole auth gate (local dev only) |
| `AUTH_COOKIE_SECURE` | `0` | set `1` behind HTTPS |
| `TRUST_PROXY` | `0` | `1` behind a reverse proxy (honours X-Forwarded-For) |
| `ALLOWED_ORIGINS` | — | CORS allowlist |
| `OLLAMA_MODEL` / `VISION_MODEL` | `llama3.2` / `llava:7b` | local inference models |
| `OLLAMA_KEEP_ALIVE` | `24h` | how long weights stay in memory after a query — `-1` never unloads, `30m` frees them when idle |
| `ALERTS_DIR`, `ALERTS_LOG`, `ARCHIVES_JSON` | `/var/ossec/logs/…` | what the backend tails |
| `WAZUH_REG_PASSWORD` | — | enrolment password; must match the manager's `authd.pass` (§5) |
| `SELENNE_MANAGER_HOST` | request `Host` | agent transport host — DNS-only, never proxied (§5) |
| `SELENNE_DASHBOARD_HOST` | request `Host` | branded https host in installer text and shortcuts (§5) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | — | verification mail; without it no self-registered account can finish signup |
| `SELENNE_PUBLIC_URL` | — | base URL for verification links (never the request `Host`) |
| `REACTOR_ENABLED` | `0` | arm the reactive daemon (§9) |
| `CVE_AGENT_AUTOSTART` | `0` | run the CVE agent on boot |
| `STRIPE_SECRET_KEY`, `STRIPE_PRICE_*` | — | landing-page checkout; 503 until set |

`infra/environments/{dev,staging,production}.env` hold per-environment
profiles: `set -a; source infra/environments/staging.env; set +a`.

---

## 7. ML engine

```bash
cd services/ai-engine
./retrain_all.sh                    # collect → IF → AE → UEBA → stacker → log model
venv/bin/python evaluate_isolation_forest.py --plot
venv/bin/python monitor_model_health.py        # PSI drift check
bash ../../infra/scripts/run_ml_pipeline.sh    # retrain + eval + push metrics
```

Detectors are one-class (trained on clean data only); the LogReg stacker learns
the blend weights and is the only supervised piece. Artefacts land in
`data/ai_models/` — undated files are live, dated ones are archives for
rollback. **Restart the backend after retraining**: it holds the old models in
memory.

---

## 8. RAG & chat

```bash
cd services/ai-engine
venv/bin/python -m rag_core.indexing.qdrant_indexer --search "ssh brute force"
venv/bin/python rag_core/evaluation/run_eval2.py        # retrieval metrics
bash ../../infra/scripts/run_rag_eval.sh
```

Retrieval is `all-MiniLM-L6-v2` over Qdrant; generation is Ollama, pinned in
VRAM for 24 h at startup so the first token arrives in ~2.5 s. The agentic path
(query gate → multi-query rewrite → CRAG grading → corrective retry) fails open:
if grading breaks, plain retrieval still answers.

---

## 9. Agents & reactor

| Component | Where | Default | Notes |
|---|---|---|---|
| CVE ingestion agent | `services/ai-engine/scheduled_agent/` | manual | NVD + CISA-KEV → score → Postgres ledger + Qdrant; ≥7 auto-indexed, 4–6 queued for review |
| Reactor | `apps/backend/server.py` + `reactor_actions.py` | **off** | tails alerts, reacts at/above `REACTOR_MIN_LABEL` |
| Wazuh active response | reactor | **off + dry-run** | `REACTOR_WAZUH_AR=1` arms it, `REACTOR_WAZUH_AR_DRYRUN=0` makes blocks real; private ranges never blocked |
| Adversary self-training | `services/ai-engine/adversary/` | manual | mines ensemble false negatives, harvests into the corpus |

Arming anything destructive is deliberate and reversible — read
`infra/deploy/DEPLOYMENT.md` §"Reactor arming" first.

---

## 10. Ports

| Port | Service |
|---|---|
| 5000 | Flask backend + UI |
| 6333 / 6334 | Qdrant REST / gRPC (localhost-bound) |
| 5432 | Postgres (localhost-bound) |
| 11434 | Ollama |
| 1514 / 1515 | Wazuh agent comms / enrolment |
| 8080, 3000, 9090, 9091 | Jenkins, Grafana, Prometheus, Pushgateway (`infra/docker-compose.yml`) |

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| New `/api/…` route returns an HTML 404 | backend not restarted | restart it — there is no auto-reload |
| Alert stream frozen / stale timestamps | manager stopped; the backend only reads files | `sudo /var/ossec/bin/wazuh-control start` |
| Collector download returns 503 | `WAZUH_REG_PASSWORD` unset | §5 |
| Collector installs, then "Enrolment failed" / hangs on 1515 | `SELENNE_MANAGER_HOST` is a Cloudflare-proxied name, or 1514/1515 are firewalled | §5 |
| Collector download returns 401 | not signed in — the routes are behind auth | sign in first |
| `wazuh_qdrant` shows `(unhealthy)` but Qdrant works | container still running the old curl-based healthcheck (the image has no curl) | `docker compose -f services/ai-engine/docker-compose.yml up -d --force-recreate qdrant` |
| Chat hangs or 503s | Ollama not running / model not pulled | dev: `ollama serve &` then `ollama pull llama3.2` · server: `systemctl status ollama` (see DEPLOYMENT.md "Keeping Ollama up") |
| Chat is slow on the first message only | model cold-loading into memory | expected; it then stays resident for `OLLAMA_KEEP_ALIVE` |
| Scores unchanged after retraining | old models still in memory | restart the backend |
| Evaluation looks better than reality | eval reading a stale copy of the model | confirm the `.pkl` in `data/ai_models/` is the one just written |
| Windows installer opens "choose an app" | a `.ps1` was downloaded, not the `.cmd` | use the zip package — Windows never executes `.ps1` on double-click |

---

## 12. Further reading

| Doc | Covers |
|---|---|
| `infra/deploy/DEPLOYMENT.md` | production host, systemd, nginx + TLS, pre-flight, admin panel |
| `infra/README.md` | Jenkins pipelines, promotion flow, Grafana dashboards |
| `apps/frontend/README.md` | every page and the APIs it calls |
| `services/ai-engine/scheduled_agent/README.md` | CVE agent internals |
| `services/ai-engine/adversary/README.md` | adversarial self-training loop |

## 13. Links

- Product site — <https://selenne.app/>
- LinkedIn — <https://www.linkedin.com/company/selenne>

Production runs on the `selenne.app` host behind nginx + TLS; the update and
rollback procedure for that box is in `infra/deploy/DEPLOYMENT.md`
("Updating the live selenne.app host").
