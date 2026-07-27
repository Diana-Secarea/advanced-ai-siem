# Deployment guide — Wazuh AI Threat Engine

Single-node deployment (the thesis/PoC target). The backend runs under
**waitress** (production WSGI), fronted by a reverse proxy for TLS.

## Architecture at deploy time

```
             ┌────────── nginx (TLS :443) ──────────┐
Internet ───▶│  /  → backend :5000 (waitress)        │
             │  proxy_buffering off  (for SSE chat)  │
             └───────────────────────────────────────┘
                              │
   backend (root, loopback :5000) ── reads /var/ossec/logs/alerts
        │        │          │
     Qdrant   Postgres    Ollama          (docker + host service)
     :6333     :5432       :11434
        │
   infra/ : Jenkins :8080 · Prometheus :9090 · Grafana :3000  (docker compose)
```

## Pre-flight checklist

Run the automated gate first — it verifies everything below and exits non-zero
if any blocking item fails:

```bash
ENV_FILE=/etc/wazuh-ai/backend.env infra/deploy/preflight.sh
```

It checks: secrets filled in (no `CHANGE_ME`), `AUTH_ENABLED`, CORS/HTTPS flags,
no key literals in source, the pinned venv + core imports, all four trained
models, Qdrant/Postgres containers, Ollama + the pulled model, and `/health` +
`/ready`. Green everywhere ⇒ safe to expose.

### Blocking — do before exposing the app
- [ ] **Secrets set** — `FLASK_SECRET_KEY`, `ADMIN_PASSWORD`, `PG_PASSWORD` are
      real values in `/etc/wazuh-ai/backend.env` (never committed). No secret
      is hardcoded in source (verified).
- [ ] **Production server** — start via `wsgi.py` (waitress), not `server.py`
      (Flask dev server). `start_server.sh` now defaults to waitress.
- [ ] **TLS + reverse proxy** — the app binds loopback only and every mutating
      endpoint is authenticated, but the reactor's active-response and uploads
      mean you want TLS + a proxy in front. Set `AUTH_COOKIE_SECURE=1` once
      HTTPS is live. Nginx must set `proxy_buffering off` on the chat route so
      SSE streams token-by-token.
- [ ] **CORS** — `ALLOWED_ORIGINS` set to your real domain (no wildcard).
- [ ] **Dependencies pinned** — install from `services/ai-engine/requirements.lock`
      (exact versions) for a reproducible environment.

### Recommended
- [ ] **Rate-limit storage** — the limiter uses `memory://` (resets on restart,
      per-process). For multi-instance, point it at Redis
      (`storage_uri="redis://…"`). Fine for single-node.
- [ ] **Log shipping** — logs go to `apps/backend/logs/{backend,reactor}.log`
      (rotating, 10 MB × 5) and stdout/journald. Point your shipper at either.
      `reactor.log` is the security-action audit trail — retain it.
- [ ] **Backups** — `apps/backend/users.db` (accounts + tickets),
      `incidents.jsonl` (reactor ledger), the Postgres `wazuh_ai` DB (CVE
      ledger), and the Qdrant `wazuh_qdrant_storage` volume.
- [ ] **Model provenance** — production loads models from `/var/ossec/ai_models`;
      only promote via the Jenkins `promote` job (dev → staging → prod).

## Steps

```bash
# 1. Dependencies (reproducible)
cd wazuh-monorepo/services/ai-engine
python3 -m venv venv
# GPU-less host: install the CPU torch build FIRST — the plain torch pin pulls
# the CUDA wheels (~4 GB of nvidia-* libs this host will never use).
venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch==2.9.1
venv/bin/pip install -r requirements.lock

# 2. Data services
cd ../../infra && docker compose up -d          # (or just Qdrant+Postgres compose)
#    Ollama:  ollama serve &   +   ollama pull llama3.2

# 3. Secrets + service
sudo mkdir -p /etc/wazuh-ai
sudo cp infra/deploy/wazuh-ai-backend.env /etc/wazuh-ai/backend.env
sudoedit /etc/wazuh-ai/backend.env               # fill FLASK_SECRET_KEY, ADMIN_PASSWORD, PG_PASSWORD
sudo cp infra/deploy/wazuh-ai-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-ai-backend

# 4. Verify
curl http://127.0.0.1:5000/health      # {"status":"ok"}
curl http://127.0.0.1:5000/ready       # {"status":"ready","checks":{...}}
journalctl -u wazuh-ai-backend -f
```

## Health & monitoring

| Probe | Meaning |
|---|---|
| `GET /health` | liveness — process up (use for systemd/LB liveness) |
| `GET /ready` | readiness — ensemble + Qdrant + Ollama + Postgres reachable (503 if core down) |
| `GET /metrics` | Prometheus scrape — alerts, chat latency (5s target), injection flags, reactor actions, CVE agent state |

Grafana dashboards (auto-provisioned): **ML Engine**, **AI Engine**
(chat latency + injection panels), **Reactor** (staleness alarm, active blocks,
actions taken). Prometheus already scrapes the backend `/metrics` — for that to
work across the docker boundary set `BIND_HOST=0.0.0.0` (safe: auth is on,
`/metrics` and `/health` are the only exempt read-only endpoints).

## Public pages & billing

- `/landing.html` is the only public page (plus `/login.html`); anonymous
  visitors hitting `/` are redirected there, deep links go to sign-in.
  Logout also returns to the landing page.
- Stripe Checkout powers the pricing buttons: set `STRIPE_SECRET_KEY`,
  `STRIPE_PRICE_ANALYST`, `STRIPE_PRICE_TEAM` in `backend.env` (see sample).
  Until set, `/api/billing/checkout` returns a clean 503 and the landing page
  shows a "not configured" note — safe to deploy without billing.

## Model lifecycle (retraining + drift)

- **Retrain**: `services/ai-engine/retrain_all.sh` runs the whole chain
  (collect → IF → AE → UEBA → stacker → eval → drift reference). Monthly cron:
  `0 3 1 * * cd .../services/ai-engine && ./retrain_all.sh >> data/eval/retrain.log 2>&1`
  Restart the backend afterwards — models are loaded at startup.
- **Drift**: `monitor_model_health.py` compares the live ensemble score
  distribution against the reference saved at training time (PSI). PSI > 0.25
  → run retrain_all.sh. Temporal validation (temporal_validation.py) showed
  ranking survives time shifts (AUC 0.999); drift mostly moves the score
  calibration, so retraining is recalibration — cheap and safe.
- **Provenance**: canonical metrics live in `data/eval/ml_metrics.json`
  (written by `infra/scripts/ml_eval_metrics.py`, scraped into Grafana).

## Reactor arming (deliberate)

Everything defaults OFF or dry-run. Arm from the Reactor page or env:
`REACTOR_BLOCK_IP_DRYRUN=0` (real firewall drops), `REACTOR_SCAN_DRYRUN=0`
(real Wazuh scans). Blocks target public IPs only, never LAN/loopback, and
auto-expire on TTL. Every action is written to `reactor.log`.

## Not for this PoC (documented scope)
- Horizontal scaling / multiple backend instances (would need Redis-backed rate
  limiting + sessions, and the reactor/CVE-agent singletons moved to one leader).
- OCR for scanned PDFs (image-only PDFs are rejected with a clear message).
- The Flask dev server (`DEV_SERVER=1`) — local development only.
