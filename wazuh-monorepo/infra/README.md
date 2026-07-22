# wazuh-ai-infra — MLOps for the Wazuh AI Threat Engine

CI/CD + monitoring for both engines:

| Concern | Tool | Where |
|---|---|---|
| Automatic ML retraining + testing | Jenkins pipeline | `jenkins/Jenkinsfile.ml-retrain` |
| RAG retrieval evaluation (nightly) | Jenkins pipeline | `jenkins/Jenkinsfile.rag-eval` |
| Metrics storage | Prometheus + Pushgateway | `prometheus/` |
| Dashboards (ML engine + AI engine) | Grafana | `grafana/dashboards/` |
| Hyperparameter tuning (optional stage) | `scripts/tune_hyperparams.py` | Jenkins param `TUNE_HYPERPARAMS` |

## 1. Start the stack

```bash
cd wazuh-ai-infra
docker compose up -d
```

| Service | URL | Login |
|---|---|---|
| Jenkins | http://localhost:8080 | setup wizard on first boot (`docker logs wazuh-ai-jenkins` for the initial password) |
| Grafana | http://localhost:3000 | admin / shield-admin (override with `GRAFANA_ADMIN_PASSWORD`) |
| Prometheus | http://localhost:9090 | — |
| Pushgateway | http://localhost:9091 | — |

Grafana auto-provisions the **ML Engine** and **AI Engine** dashboards from
`grafana/dashboards/` — no clicking needed.

## 2. Connect the WSL host as the build agent (one time)

The pipelines run **on the host**, not inside the Jenkins container — they need
the project venv, the GPU (Ollama), Qdrant and `/var/ossec`.

1. Jenkins → *Manage Jenkins → Nodes → New Node* → name `wazuh-host`,
   type *Permanent*, **label `wazuh-host`**, remote root `/home/sek/jenkins-agent`,
   launch method *"Launch agent by connecting it to the controller"*.
2. Open the node page — Jenkins shows the `curl … agent.jar` + `java -jar agent.jar …` command.
3. Run that command on the host (needs a JRE: `sudo apt install openjdk-17-jre-headless`).
   Keep it alive with `nohup … &` or a systemd user unit.

## 3. Create the three pipeline jobs (one time)

Create each as *New Item → Pipeline* → Definition: **Pipeline script from SCM** →
SCM: Git → repo URL (local path `/home/sek/wazuh` works) → Script Path as below.
**The job NAMES matter for chaining** — use exactly these:

| Job name (New Item) | Script Path |
|---|---|
| `wazuh-ml-retrain` | `wazuh-monorepo/infra/jenkins/Jenkinsfile.ml-retrain` |
| `wazuh-rag-eval`   | `wazuh-monorepo/infra/jenkins/Jenkinsfile.rag-eval` |
| `wazuh-ml-promote` | `wazuh-monorepo/infra/jenkins/Jenkinsfile.promote` |

First build of each must be started manually once — after that the `cron` /
`pollSCM` triggers registered in the Jenkinsfiles take over:

- **ml-retrain** — weekly (Sun ~03:00) + on every push that changes training code.
  Stages: sanity → *(optional)* hyperparameter tuning → train IF → AE → UEBA →
  stacking → evaluate on held-out test → **quality gate** (fails the build if
  ensemble F1 < 0.60 or FPR > 15%, dated `.pkl` archives remain for rollback) →
  push metrics.
- **rag-eval** — nightly ~02:00. 82-query hybrid retrieval benchmark →
  quality gate (hit rate ≥ 70%) → push metrics.

### How the jobs chain

The chain is **defined in the Jenkinsfiles (version-controlled), not clicked in
the UI** — so it travels with the repo:

```
wazuh-ml-retrain ──success──▶ wazuh-ml-promote (TARGET=staging)
  (train+eval+gate)             dev→staging → validate → [MANUAL APPROVAL] → production

wazuh-rag-eval  (independent, nightly)
```

- `Jenkinsfile.ml-retrain` has a `post { success { build job: params.DOWNSTREAM_JOB, ... } }`
  block that fires `wazuh-ml-promote` with `TARGET=staging` after a green retrain.
  Controlled by params **CHAIN_PROMOTE** (default true) and **DOWNSTREAM_JOB**
  (default `wazuh-ml-promote`). `wait:false` so retrain doesn't block; `propagate:false`
  so a promote hiccup doesn't red-flag a good retrain.
- `Jenkinsfile.promote` chains its own stages internally: evaluate dev → gate →
  promote dev→staging → re-validate from staging → **`input` approval step** →
  promote staging→production. Nothing reaches prod without a human clicking approve.

**Alternative (UI-driven) chaining** if you ever want it: a job's *Configure →
Build Triggers → "Build after other projects are built"* does the same upstream/
downstream link by clicking. Prefer the in-Jenkinsfile `build job:` step — it's
in git, reviewable, and survives a Jenkins rebuild.

## 4. Environments: dev → staging → production

Three environments = three **model registries** + three env configs
(`environments/*.env`). Models only move forward via the promote pipeline.

| Env | Models | Port | Auth | Reactor | Config |
|---|---|---|---|---|---|
| dev | `data/ai_models/` (training output) | 5001 | off | off | `environments/dev.env` |
| staging | `wazuh-monorepo/infra/registry/staging/` | 5002 | on | on (never real AR) | `environments/staging.env` |
| production | `/var/ossec/ai_models/` | 5000 | on | on | `environments/production.env` |

Run an instance against an environment:

```bash
set -a; source wazuh-monorepo/infra/environments/staging.env; set +a
wazuh-monorepo/services/ai-engine/venv/bin/python backend/server.py
```

**Jenkins job 3 — `Jenkinsfile.promote`** (Pipeline from SCM, like the others):
evaluates the dev candidates → quality gate → `promote_models.sh dev staging` →
re-evaluates *from the staging registry* → **manual approval step** →
`promote_models.sh staging production`. Every promotion archives the replaced
`.pkl`s as dated `.bak` files for instant rollback and writes `PROMOTION.json`
provenance. Run with `TARGET=staging` for candidate soak, `TARGET=production`
for a full release.

## 5. Metrics flow

```
train/eval scripts ──JSON──▶ data/eval/*.json ──push_metrics.py──▶ Pushgateway ─┐
                                                                                ├─▶ Prometheus ─▶ Grafana
Flask backend /metrics (live: alerts, chat, CVE agent, uptime) ◀────scrape──────┘
```

For Prometheus to scrape the Flask backend from Docker, start the backend with
`BIND_HOST=0.0.0.0` — this is safe now that authentication is enabled
(`/metrics` itself is auth-exempt but contains only counters, no alert content).

## 6. Manual runs (no Jenkins needed)

```bash
bash wazuh-monorepo/infra/scripts/run_ml_pipeline.sh        # full retrain + eval + push
SKIP_TRAIN=1 bash wazuh-monorepo/infra/scripts/run_ml_pipeline.sh   # eval only
bash wazuh-monorepo/infra/scripts/run_rag_eval.sh           # RAG benchmark + push
wazuh-monorepo/services/ai-engine/venv/bin/python3 wazuh-monorepo/infra/scripts/tune_hyperparams.py
```

## Design notes

- **Why the host agent?** The RAG stack (torch, sentence-transformers) and GPU
  access make containerized builds pointlessly heavy; Jenkins orchestrates and
  records, the host executes. This mirrors a common on-prem MLOps pattern.
- **Why Pushgateway?** Training/eval are batch jobs — they'd be gone before
  Prometheus's next scrape. Jobs push once at the end; the gateway holds the
  last value.
- **Quality gates** make Jenkins an actual gatekeeper, not just a scheduler:
  a regression (bad data batch, broken feature) fails the build loudly instead
  of silently shipping a worse model.
