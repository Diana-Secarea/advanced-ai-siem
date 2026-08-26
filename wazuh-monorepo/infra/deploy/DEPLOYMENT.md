# Deployment guide — Wazuh AI Threat Engine

Single-node deployment (the thesis/PoC target). The backend runs under
**waitress** (production WSGI), fronted by a reverse proxy for TLS.

## Architecture at deploy time

```
Internet ──▶ Cloudflare (DNS + TLS edge for selenne.app)
                              │
             ┌────────── nginx (TLS :443) ──────────┐
             │  /  → backend :5000 (waitress)        │
             │  proxy_buffering off  (for SSE chat)  │
             │  CF-Connecting-IP → X-Forwarded-For   │
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
- [ ] **CORS** — `ALLOWED_ORIGINS=https://selenne.app` (no wildcard).
- [ ] **Real client IPs** — two halves, and neither works alone:
      1. `sudo ./cloudflare-realip.sh` — generates
         `/etc/nginx/conf.d/cloudflare-realip.conf` so nginx *writes* the
         visitor IP from `CF-Connecting-IP`.
      2. `TRUST_PROXY=1` in `backend.env` so the backend *reads* it.

      Do them in that order and confirm a real address shows up in
      `/var/log/nginx/access.log` before flipping `TRUST_PROXY`. Without both,
      every request looks like `127.0.0.1`: the per-(user, IP) login lockout
      and the rate limiter collapse into one shared counter, so a single
      attacker can lock out every account. With `TRUST_PROXY=1` but nothing
      rewriting the header, the opposite hole opens — clients spoof their own
      IP. `preflight.sh` now checks both halves; it only checked the backend
      one until 2026-08-26, which is how the live host drifted unnoticed.
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
#    Ollama: install as a SERVICE, never `ollama serve &` — see "Keeping Ollama up"
curl -fsSL https://ollama.com/install.sh | sh   # creates + enables ollama.service
sudo systemctl edit ollama                      # add the drop-in from that section
sudo ollama pull llama3.2

# 3. Secrets + service
sudo mkdir -p /etc/wazuh-ai
sudo cp infra/deploy/wazuh-ai-backend.env /etc/wazuh-ai/backend.env
sudoedit /etc/wazuh-ai/backend.env               # fill FLASK_SECRET_KEY, ADMIN_PASSWORD, PG_PASSWORD
sudo cp infra/deploy/wazuh-ai-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-ai-backend

# 4. Reverse proxy + TLS
sudo cp infra/deploy/nginx.conf.sample /etc/nginx/sites-available/selenne
sudo ln -s /etc/nginx/sites-available/selenne /etc/nginx/sites-enabled/
sudo certbot --nginx -d selenne.app -d www.selenne.app
sudo nginx -t && sudo systemctl reload nginx

# 5. Verify
curl http://127.0.0.1:5000/health      # {"status":"ok"}
curl http://127.0.0.1:5000/ready       # {"status":"ready","checks":{...}}
curl -sI https://selenne.app/          # 302 → /landing.html
journalctl -u wazuh-ai-backend -f
```

## Updating the live selenne.app host

Facts about the running deployment (verified 2026-08-20), because several of
them differ from the generic install above:

| | |
|---|---|
| host | Hetzner CPX32 `selenne-prod`, 4 vCPU / 8 GB |
| ssh | `selenne@<origin IP>` — **not** `selenne.app`, which resolves to Cloudflare |
| repo | `/home/selenne/advanced-ai-siem` |
| **systemd unit** | **`selenne-backend.service`** — *not* `wazuh-ai-backend` |
| env file | `/etc/wazuh-ai/backend.env` (root-only) |
| nginx site | `/etc/nginx/sites-enabled/selenne` |
| sudo | password-protected — the restart cannot be automated over BatchMode ssh |

The frontend is served straight off the working tree, so shipping a page is a
pull; anything that touches `apps/backend/*.py` needs the service restarted —
routes are registered at import time and waitress does not auto-reload. Pull
and restart belong together: in between, a new page is live against an API
that still 404s.

```bash
ssh selenne@<origin IP>
cd ~/advanced-ai-siem
git pull

ENV_FILE=/etc/wazuh-ai/backend.env wazuh-monorepo/infra/deploy/preflight.sh
sudo systemctl restart selenne-backend     # required for new/changed API routes
curl -sf http://127.0.0.1:5000/health && echo up
```

Sanity-check the release from outside, signed in as an admin and as a
non-admin — the second call is the one that proves the boundary holds:

```bash
curl -sI https://selenne.app/admin.html                    # 302 → /login.html when signed out
curl -s -b admin.cookie  -o /dev/null -w '%{http_code}\n' \
     https://selenne.app/api/admin/accounts                # 200
curl -s -b analyst.cookie -o /dev/null -w '%{http_code}\n' \
     https://selenne.app/api/admin/accounts                # 403
```

Rollback is `git checkout <previous-sha> && sudo systemctl restart
selenne-backend`; `users.db` is untouched by either direction, though the new
`last_login` column only starts filling in from the first sign-in after the
upgrade (existing accounts read "never signed in" until then).

## Keeping Ollama up (Hetzner)

Two separate things, often confused:

| | What it costs idle | What it buys |
|---|---|---|
| **The daemon** (`ollama.service`) — must always run | ~50–100 MB RSS, no CPU | a RAG query has something to talk to; without it chat 503s |
| **The model in memory** (`OLLAMA_KEEP_ALIVE`) | ~2 GB for `llama3.2` | no cold load on the next query |

Customers never download a model. One Ollama on the Selenne host answers for
every account; the endpoint package only ships logs. So the daemon stays up
permanently (it is nearly free), and `OLLAMA_KEEP_ALIVE` decides whether the
weights are held while nobody is asking — that is the "activate on RAG query"
knob. `30m` means the first question after a quiet spell loads the model and
everything for the next half hour is instant.

`ollama serve &` is a shell job: it dies with the SSH session and never comes
back after a reboot. Run it under systemd instead — the official installer
already ships a unit with `Restart=always` and a dedicated `ollama` user.

```bash
# 1. Install (creates + enables /etc/systemd/system/ollama.service)
curl -fsSL https://ollama.com/install.sh | sh

# 2. Selenne's settings as a drop-in — survives Ollama upgrades
sudo systemctl edit ollama
```
```ini
[Service]
Environment="OLLAMA_KEEP_ALIVE=30m"         # load on query, free when idle (-1 = never unload)
Environment="OLLAMA_HOST=127.0.0.1:11434"   # loopback only — 11434 is unauthenticated
Environment="OLLAMA_MAX_LOADED_MODELS=1"    # RAM is the budget on a CPU box
Environment="OLLAMA_NUM_PARALLEL=1"         # raise to 2–4 once several accounts query at once
OOMScoreAdjust=-100
Restart=always
RestartSec=3
```
```bash
sudo systemctl restart ollama
sudo ollama pull llama3.2
```

Set the same value in `/etc/wazuh-ai/backend.env` — the app re-pins after every
chat call, because the `/v1` API resets the timer to 5 minutes:

```bash
echo 'OLLAMA_KEEP_ALIVE=30m' | sudo tee -a /etc/wazuh-ai/backend.env
sudo systemctl restart wazuh-ai-backend
```

**Optional — preload at boot.** Only if you chose `-1` and want the very first
query of the day to be fast too. Skip it on a memory-tight host: it defeats the
point of an idle timeout.

```bash
sudo cp infra/deploy/ollama-warmup.sh /usr/local/bin/selenne-ollama-warmup.sh
sudo chmod 755 /usr/local/bin/selenne-ollama-warmup.sh
sudo cp infra/deploy/ollama-warmup.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ollama-warmup
```

Verify, including across a reboot:

```bash
systemctl is-enabled ollama                   # enabled
curl -s localhost:11434/api/ps                # loaded models + their expiry
sudo reboot   # then: curl -s https://selenne.app/ready
```

`infra/deploy/ollama.service` is a complete unit for hosts where Ollama was
installed some other way (manual binary, arm64 tarball) — don't copy it over a
unit the installer created; use the drop-in above.

**Sizing.** Hetzner Cloud has no GPU instances — CPU only. Verify the current
lineup before buying, but the shape of the decision:

| Host | Fits | Reality |
|---|---|---|
| CPX41 / CCX23 (8 vCPU, 16–32 GB) | `llama3.2` (3B, ~2 GB resident) | works; token generation is fine, but **prompt** processing is the slow part — a long RAG context can take 10–30 s before the first token |
| Dedicated GEX-series (RTX Ada GPU) | 3B–13B comfortably | the only way to keep the ~2.5 s first-token experience; setup fee + higher monthly |

If you stay on CPU: keep `OLLAMA_MAX_LOADED_MODELS=1`, skip `llava:7b` (vision
attachments would evict the chat model on every image), keep the swap file from
`bootstrap-server.sh` but leave `vm.swappiness=10` — a swapped-out model is
worse than a cold load. Trimming retrieved context (`k`, chunk size) buys more
first-token latency on CPU than any Ollama flag.

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

## What selenne.app serves

| URL | Who can reach it |
|---|---|
| `https://selenne.app/` | anonymous → redirected to `/landing.html` |
| `/landing.html`, `/login.html` | public (marketing, pricing, sign-in) |
| `/index.html`, `/alerts.html`, `/chat.html`, … | any signed-in account |
| **`/admin.html`** | **signed-in admins only** — user accounts + signups |
| `/api/admin/accounts` | admin role only (403 otherwise), 60 req/min |
| `/health`, `/ready`, `/metrics` | public read-only probes |

### Admin panel

`/admin.html` is the cross-tenant view: every account, when it was created,
when it last signed in, whether it holds a live session, and how many
endpoints it owns — plus a signups-per-day chart over 7/30/90/365 days.

Three layers keep it admin-only, and the outer two are the ones that matter
because they run server-side:

1. the global auth gate redirects anonymous visitors to `/login.html`;
2. `GET /api/admin/accounts` returns **403** unless the session's role is
   `admin` — this is the real boundary;
3. the nav entry and the page body only render for admins, so nobody else is
   shown a door they cannot open.

Nothing extra is needed in nginx — it is an ordinary page behind `location /`.
Grant the role with
`sqlite3 apps/backend/users.db "UPDATE users SET role='admin' WHERE username='…'"`.
It takes effect on the next request — sessions store only the username, and the
role is re-read from `users` on every call — so a reload is enough, no re-login
and no restart.

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
