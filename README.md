# ◈ Selenne

**See the attack before it lands.**

Selenne is a security platform built on Wazuh. It scores every alert with a
machine-learning ensemble, explains it with a local LLM grounded in threat
intelligence, and can act on it automatically. Its second product,
**Selenne Agents**, applies the same idea to AI agents and chatbots: every
prompt, tool call and model call, traced and checked for risky behaviour.

**[selenne.app](https://selenne.app/)** · **[AI Agents console](https://selenne.app/agents/)** ·
**[LinkedIn](https://www.linkedin.com/company/selenne)**

---

## Contents

- [Two products, one account](#two-products-one-account)
- [Why Selenne](#why-selenne)
- [Architecture](#architecture)
- [SIEM features](#siem-features)
- [Selenne Agents](#selenne-agents)
- [Detection results](#detection-results)
- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Documentation map](#documentation-map)
- [Security model](#security-model)
- [Tech stack](#tech-stack)
- [Author & license](#author--license)

---

## Two products, one account

| | **Selenne SIEM** | **Selenne Agents** |
|---|---|---|
| Watches | servers, laptops, networks (via Wazuh) | AI agents and chatbots (via OpenTelemetry) |
| Console | [selenne.app](https://selenne.app/) | [selenne.app/agents/](https://selenne.app/agents/) |
| Data in | Wazuh collectors on each endpoint | traces sent to `ingest.selenne.app` with an ingestion key |
| Finds | anomalous alerts, known CVEs on your stack, attacker behaviour | secret access, prompt injection, dangerous shell, exfiltration |
| Code | this repository | [advanced-selenne-agents](https://github.com/Diana-Secarea/advanced-selenne-agents) |

Both share one sign-in, one look, and a **SIEM ⇄ AI Agents** switch in the
navigation bar.

---

## Why Selenne

- **Local AI.** The SIEM's models and its LLM run on your own hardware. No
  cloud LLM, no telemetry, no third-party inference API. That's a design rule,
  not a setting: it makes Selenne usable where security data can't go to a
  vendor.
- **Learns normal, not a list of attacks.** The detectors are one-class: they
  learn what your clean traffic looks like, so a new attack still stands out.
- **Explains itself.** Every verdict comes with a plain-language explanation,
  grounded in MITRE ATT&CK, Sigma, YARA, CISA-KEV and vendor advisories rather
  than the model's memory.
- **Safe by default.** The reactor ships disarmed, active response ships in
  dry-run, and private IP ranges are never blocked.

---

## Architecture

```
                         ┌──────────── selenne.app (Cloudflare → nginx + TLS) ────────────┐
                         │                                                                 │
 endpoints ─► Wazuh manager ─► alerts.json        browser ─► /  ─────────► Flask backend :5000
  (1514/1515)                     │                         ─► /agents/ ─► Agents console :4319
                                  ▼                                              │
        ┌────────────── Flask backend (:5000) ──────────────┐                    │ session check
        │  ensemble scoring   IF + Autoencoder + UEBA        │◄───────────────────┘ /api/auth/me
        │                     → LogReg stacker → verdict     │
        │  raw-log scoring    novelty + content model        │◄── key check ──┐
        │  agentic RAG        Qdrant + Ollama (llama3.2)     │  /internal/     │
        │  reactor            webhook / Wazuh active response│  keys/verify    │
        │  CVE agent          NVD + CISA-KEV → Postgres+Qdrant│                │
        │  accounts           users, sessions, ingestion keys │                │
        └────────────────────────────────────────────────────┘                │
                                                                               │
 AI agents ─ OTLP/HTTP, OTLP/gRPC, JSON ─► ingest.selenne.app ─► Agents ingest :4317/4318
                                                                   └─► Postgres (spans, alerts)
```

The SIEM backend owns accounts. Selenne Agents runs as its own Docker stack
next to it and asks the backend who is signed in and whether a key is valid.
It never reads the SIEM's database or feeds the SIEM's alert pipeline.

---

## SIEM features

| | |
|---|---|
| **Anomaly detection** | Three one-class detectors (Isolation Forest, Autoencoder, UEBA), blended by a logistic-regression stacker that *learns* the weights instead of assuming them. |
| **Raw-log scoring** | Scores every collected log, not just Wazuh alerts. A novelty model asks "is this new?" and a separately trained content model asks "is this hostile?", so an unfamiliar but harmless log is labelled `NEW`, not `THREAT`. |
| **AI analyst chat** | Agentic RAG: query gate → multi-query rewrite → CRAG grading → corrective retry, over a Qdrant corpus of threat intelligence. If grading breaks, plain retrieval still answers. |
| **Reactor** | Headless daemon that tails alerts, scores them and reacts: ledger, webhook, or Wazuh active response. Arming anything destructive is deliberate and reversible. |
| **CVE agent** | Scheduled workflow: fetch NVD + CISA-KEV → dedup → boost by local evidence → LLM-score for relevance to *this* deployment → index, queue for review, or drop with an audit trail. |
| **Endpoint collectors** | Per-account installers for Windows, Linux and macOS, downloaded from the UI, that enrol a machine in one step. |
| **Accounts & admin** | Email-verified sign-up, cookie sessions with lockout, admin roles, tickets by email, per-account tenancy of endpoints and alerts. |

---

## Selenne Agents

Monitoring and security for AI agents, in three steps:

1. **Create an ingestion key.** Go to **Profile → AI agent ingestion keys** and
   create one key per agent or environment. The key is shown once. The page
   gives you ready-to-paste snippets (curl, OpenTelemetry, Python, Node,
   `.env` / Docker), a **Download .env** button, and a **Send test event**
   button that confirms the key works without a terminal.
2. **Connect.** Already on OpenTelemetry? No code change needed:

   ```bash
   export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.selenne.app/v1/traces
   export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer sk_sel_…"
   export OTEL_SERVICE_NAME=my-agent
   ```

   Not on OpenTelemetry? POST JSON spans to `https://ingest.selenne.app/v1/events`.
   OTLP/gRPC works on the same host.
3. **Watch.** Each agent run appears in the
   [AI Agents console](https://selenne.app/agents/) as a timeline of model
   and tool calls. Detection rules flag credential access, secrets in agent
   data, prompt injection, dangerous shell commands and exfiltration, tagged
   with OWASP Top 10 for LLM Applications and MITRE ATLAS.

Revoke a key any time; traffic using it stops within a minute. Ingestion API,
rules and self-hosting are documented in the
[Selenne Agents README](https://github.com/Diana-Secarea/advanced-selenne-agents#readme).

---

## Detection results

Latest recorded evaluation (`services/ai-engine/data/eval/ml_metrics.json`,
run 2026-07-18) on a held-out set of **182 alerts containing 11 attacks**:

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Isolation Forest | 1.000 | 0.727 | 0.842 | 0.000 |
| Autoencoder | 0.526 | 0.909 | 0.667 | 0.053 |
| UEBA | 1.000 | 0.818 | 0.900 | 0.000 |
| **Stacked ensemble** | **1.000** | **1.000** | **1.000** | **0.000** |

> Read that honestly: 11 attacks is a small positive class, and a perfect score
> on it is evidence the blend works, not proof of a solved problem. The
> individual detectors are the informative rows. Each misses cases the others
> catch, which is why the stacker earns its place. Reproduce with
> `venv/bin/python evaluate_isolation_forest.py --plot` and
> `bash infra/scripts/run_ml_pipeline.sh`.

---

## Quick start

You need Linux or WSL2, a Wazuh 4.x manager at `/var/ossec`, Docker, Ollama,
and Python 3.10+. A GPU is optional.

```bash
git clone git@github.com:Diana-Secarea/advanced-ai-siem.git ~/wazuh
cd ~/wazuh/wazuh-monorepo

# Python environment (one venv for backend + ML + RAG + agents)
python3 -m venv services/ai-engine/venv
services/ai-engine/venv/bin/pip install -r services/ai-engine/requirements.txt
services/ai-engine/venv/bin/pip install -r apps/backend/requirements.txt

# Secrets: set FLASK_SECRET_KEY and PG_PASSWORD
cp apps/backend/.env.example apps/backend/.env

# Qdrant + Postgres (localhost only), then the local model
docker compose -f services/ai-engine/docker-compose.yml up -d
ollama pull llama3.2

# Run
sudo /var/ossec/bin/wazuh-control start
apps/backend/start_server.sh
curl -s localhost:5000/health        # {"status":"ok"}
```

Open **http://127.0.0.1:5000**. Trained models are committed, so detection
works straight after a clone. Building the threat-intel index, enrolling
endpoints and every setting are in the
**[monorepo README](wazuh-monorepo/README.md)**.

> The backend does not auto-reload. After changing anything under
> `apps/backend/`, restart it, or new routes return an HTML 404.

---

## Repository layout

```
wazuh/                     ← this repo: a Wazuh source fork
├── src/ framework/ api/ ruleset/ …      upstream Wazuh, unmodified
└── wazuh-monorepo/        ← everything Selenne
    ├── apps/backend/          Flask API, auth, ingestion keys, reactor, agents
    ├── apps/frontend/         the Selenne UI (landing, consoles, profile, admin)
    ├── apps/frontend-legacy/  superseded UI, served at /legacy/
    ├── services/ai-engine/    detectors, training, RAG, CVE agent
    ├── services/threat_intel/ drop-in corpora
    └── infra/                 Docker, deploy units, nginx, Jenkins, Grafana
```

Upstream Wazuh is left as it is; everything Selenne adds lives in
[`wazuh-monorepo/`](wazuh-monorepo/).

---

## Documentation map

| I want to… | Read |
|---|---|
| set up a dev box, run it daily, configure it | [`wazuh-monorepo/README.md`](wazuh-monorepo/README.md) |
| deploy or update the live server | [`infra/deploy/DEPLOYMENT.md`](wazuh-monorepo/infra/deploy/DEPLOYMENT.md) |
| enrol endpoints | [monorepo README §5](wazuh-monorepo/README.md) |
| understand each UI page and its API | [`apps/frontend/README.md`](wazuh-monorepo/apps/frontend/README.md) |
| run the pipelines and dashboards | [`infra/README.md`](wazuh-monorepo/infra/README.md) |
| work on the CVE agent | [`scheduled_agent/README.md`](wazuh-monorepo/services/ai-engine/scheduled_agent/README.md) |
| work on Selenne Agents | [advanced-selenne-agents](https://github.com/Diana-Secarea/advanced-selenne-agents#readme) |

---

## Security model

- **Loopback by default.** The backend, Qdrant, Postgres, Ollama and the Agents
  stack all bind to `127.0.0.1`. Web traffic reaches them only through nginx,
  behind Cloudflare. Wazuh agents connect directly on 1514/1515.
- **Secrets stay out of git.** They live in `/etc/wazuh-ai/backend.env` on the
  server and in gitignored `.env` files locally.
- **Ingestion keys are stored hashed.** The raw key is shown once. Keys die
  when revoked or when their account is deleted.
- **Internal endpoints are private.** nginx answers `/internal/` with 404, and
  the backend also refuses anything that arrived through a proxy, on top of the
  shared secret.
- **Agents data stays separate.** AI-agent traces never feed the SIEM's
  Wazuh-collected logs or alert pipeline.

Found a vulnerability in Selenne? Please report it privately through
[GitHub security advisories](https://github.com/Diana-Secarea/advanced-ai-siem/security/advisories/new)
rather than a public issue. (`SECURITY.md` is upstream Wazuh's policy and
covers Wazuh itself.)

---

## Tech stack

| Component | Technology |
|---|---|
| SIEM platform | Wazuh 4.x |
| Anomaly detection | scikit-learn: Isolation Forest, Autoencoder, UEBA, LogReg stacker |
| Vector store | Qdrant (hybrid dense + BM25 sparse, RRF) |
| Relational store | PostgreSQL 17 |
| Embeddings | `all-MiniLM-L6-v2` (dense) + `Qdrant/bm25` (sparse) |
| Local LLM | Ollama: `llama3.2`, `llava:7b` for images |
| Threat intel | NVD, CISA-KEV, MITRE ATT&CK / Groups / Software / D3FEND, Sigma, YARA, CIS, OTX |
| Agent telemetry | OpenTelemetry (OTLP/HTTP + OTLP/gRPC), native JSON |
| API server | Flask + waitress, behind nginx and Cloudflare |
| Observability | Prometheus + Grafana, Jenkins pipelines |
| Payments | Stripe |

---

## Author & license

**Diana Maria Secarea** is the author and developer of Selenne. It started as
her bachelor thesis application and her third production freelance project,
and now runs as a live deployment at [selenne.app](https://selenne.app/).

Built on top of Wazuh. Wazuh Copyright (C) 2015-2023 Wazuh Inc. (GPLv2), based
on the OSSEC project started by Daniel Cid.
