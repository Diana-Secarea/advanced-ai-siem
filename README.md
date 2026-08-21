# Selenne — AI Threat Engine for Wazuh

**[selenne.app](https://selenne.app/)** · **[LinkedIn](https://www.linkedin.com/company/selenne)**

Selenne turns a Wazuh SIEM into an AI analyst. Every alert is scored by an
unsupervised ML ensemble, explained in plain language by a **local** LLM
grounded in a threat-intelligence corpus, and optionally acted on by a headless
reactor.

**Nothing leaves the host.** No cloud LLM, no telemetry, no third-party
inference API. The models run on your hardware, against your logs. That is a
design constraint, not a configuration option — it is what makes the system
deployable somewhere that cannot send security telemetry to a vendor.

This repository is a **fork of the [Wazuh](https://wazuh.com) source**. The
surrounding tree (`src/`, `framework/`, `api/`, `ruleset/`, …) is upstream Wazuh
and is left unmodified. Everything Selenne adds lives in
**[`wazuh-monorepo/`](wazuh-monorepo/)**.

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

## What it does

| | |
|---|---|
| **Anomaly detection** | Three one-class detectors — Isolation Forest, Autoencoder, UEBA — blended by a logistic-regression stacker that *learns* the weights instead of assuming them. |
| **Raw-log scoring** | Scores every collected log, not just Wazuh alerts. A novelty model asks "is this new?", a separately trained content model asks "is this hostile?" — so an unfamiliar but benign log is labelled `NEW`, not `THREAT`. |
| **Agentic RAG chat** | Query gate → multi-query rewrite → CRAG grading → corrective retry, over a Qdrant corpus of MITRE ATT&CK, Sigma, YARA, CISA-KEV, CIS and vendor advisories. Fails open: if grading breaks, plain retrieval still answers. |
| **Reactor** | Headless daemon that tails alerts, scores them, and reacts — ledger, webhook, or Wazuh active response. Ships disarmed; arming anything destructive is deliberate and reversible. |
| **CVE agent** | Scheduled workflow: fetch NVD + CISA-KEV → dedup → boost by local evidence → LLM-score for relevance to *this* deployment → index, queue for review, or drop with an audit trail. |
| **Endpoint collectors** | One-command installers for Windows, Linux and macOS that enrol a machine against the manager. |

---

## Detection approach

The detectors are **one-class**: trained on clean traffic only, so they describe
what normal looks like rather than memorising a fixed catalogue of attacks. The
stacker is the only supervised component, and it learns how much to trust each
detector rather than using hand-tuned weights.

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
> individual detectors are the informative rows — each misses cases the others
> catch, which is precisely why the stacker earns its place. Reproduce with
> `venv/bin/python evaluate_isolation_forest.py --plot` and
> `bash infra/scripts/run_ml_pipeline.sh`.

---

## Repository layout

```
wazuh/                     ← this repo: a Wazuh source fork
├── src/ framework/ api/ ruleset/ …      upstream Wazuh, unmodified
└── wazuh-monorepo/        ← everything Selenne
    ├── apps/backend/          Flask API + reactor + agents
    ├── apps/frontend/         the Selenne UI
    ├── apps/frontend-legacy/  superseded UI, served at /legacy/
    ├── services/ai-engine/    detectors, training, RAG, CVE agent
    ├── services/threat_intel/ drop-in corpora
    └── infra/                 Docker, deploy units, Jenkins, Grafana
```

Full breakdown, including the compatibility symlinks that let pre-monorepo
paths keep resolving on a dev box, is in
**[`wazuh-monorepo/README.md` §1](wazuh-monorepo/README.md)**.

---

## Getting started

Setup, daily operation, configuration, ports and troubleshooting all live in the
monorepo README — kept there so there is one copy to keep correct:

- **[Prerequisites & first-time setup](wazuh-monorepo/README.md)** — §2–§3
- **[Daily run](wazuh-monorepo/README.md)** — §4
- **[Enrolling endpoints](wazuh-monorepo/README.md)** — §5
- **[Configuration reference](wazuh-monorepo/README.md)** — §6
- **[Production deployment](wazuh-monorepo/infra/deploy/DEPLOYMENT.md)** — nginx, TLS, systemd, hardening checklist

Requires a running Wazuh manager, Python 3.10+, Docker (Qdrant + PostgreSQL),
and Ollama with a local model.

---

## Tech stack

| Component | Technology |
|---|---|
| SIEM platform | Wazuh v4.x |
| Anomaly detection | scikit-learn — Isolation Forest, Autoencoder, UEBA, LogReg stacker |
| Vector store | Qdrant (hybrid dense + BM25 sparse, RRF) |
| Relational store | PostgreSQL 17 — CVE decision ledger, threat-intel records |
| Embeddings | `all-MiniLM-L6-v2` (dense) + `Qdrant/bm25` (sparse) |
| Local LLM | Ollama — `llama3.2`, `llava:7b` for vision |
| Threat intel | NVD, CISA-KEV, MITRE ATT&CK / Groups / Software / D3FEND, Sigma, YARA, CIS, OTX |
| API server | Flask + waitress, behind nginx |
| Observability | Prometheus + Grafana, Jenkins pipelines |

---

## Author & license

**Diana Maria Secarea** — author and developer of Selenne. Built as her bachelor
thesis application and her third production freelance project; now running as a
live deployment at [selenne.app](https://selenne.app/).

Built on top of Wazuh. Wazuh Copyright (C) 2015-2023 Wazuh Inc. (GPLv2); based
on the OSSEC project started by Daniel Cid.
