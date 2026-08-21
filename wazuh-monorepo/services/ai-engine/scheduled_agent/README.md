# Scheduled CVE Ingestion Agent

A scheduled agentic workflow that continuously enriches the RAG knowledge base
with newly published CVEs relevant to *this* deployment — closing the threat
intelligence lifecycle (detect anomalies in real time **and** keep learning
about new, environment-relevant threats without manual curation).

## Pipeline

```
fetch  ->  dedup  ->  boost  ->  score  ->  act  ->  log
```

For each source (NVD, CISA-KEV):

1. **fetch** — `fetch_nvd_cves(since=cursor)`, `fetch_cisa_kev()`. The cursor is
   the timestamp of the last successful run, read from `ingestion_log`.
2. **dedup** — skip CVEs already in `threat_intel` (exact CVE-id match).
3. **boost** — read-only environment evidence raises a new CVE's relevance:
   - `check_wazuh_rules` — a Wazuh detection rule references the CVE / its software → `+3`
   - `check_alert_history` — the environment fired alerts touching that software → `+2`
4. **score** — local LLM (Ollama `llama3.2`) scores 0–10 against the deployment
   profile (`config.ENV_CONTEXT`). `final = min(base + boost, 10)`.
5. **act** on the band:
   | final score | decision  | effect |
   |-------------|-----------|--------|
   | **≥ 7**     | `indexed` | written to `threat_intel` **and** Qdrant (queryable in RAG chat) |
   | **4–6**     | `queued`  | quarantined in Postgres, **withheld from RAG** until human review |
   | **< 4**     | `dropped` | audit-logged with the model's reasoning, never indexed |
6. **log** — close the `ingestion_log` run row with the rollup counts.

The only LLM decision point is step 4 (a bounded 0–10 judgment); control flow is
fixed code. This is an **agentic scheduled workflow**, chosen over a dynamic
agent for reproducibility and auditability.

## How PostgreSQL is used (the audit/analytics backbone)

Postgres is the system-of-record and control plane for the whole agent. Qdrant
only ever *receives* approved survivors; the flat alert log contributes a single
read-only boost signal.

| Concern | Store | Object |
|---|---|---|
| Where to resume fetching | Postgres | `ingestion_log` (MAX started_at = cursor) |
| Skip already-known CVEs | Postgres | `threat_intel` |
| Every decision + reasoning | Postgres | **`cve_decisions`** (the ledger) |
| Kept CVEs (score ≥ 7) | Postgres + Qdrant | `threat_intel` + `wazuh_threat_intel` |
| Review queue (4–6) | Postgres | `pending_review` view |
| Run rollups / status | Postgres | `ingestion_log` (evaluated/indexed/queued/dropped) |

The `cve_decisions.run_id → ingestion_log.id` foreign key is the relational join
that Qdrant fundamentally cannot do — every CVE decision is traceable to the run
that made it.

## Alert-history boost: prototype vs. production

`check_alert_history` uses a **pluggable backend** (`config.ALERT_HISTORY_BACKEND`):

- **`flatfile`** (default, this prototype) — scans `/var/ossec/logs/alerts/alerts.json`.
  This single-node dev box runs the Wazuh **Manager only** (no Indexer), so the
  flat log is the only alert store. Note: the live file is rotated, so "last 90
  days" is bounded by what's still in it.
- **`opensearch`** (production) — queries the Wazuh Indexer `_search` API on
  `:9200`. Same `count_recent(keywords, days)` interface; enabling it is a
  one-line config change once the indexer stack is deployed.

## Setup & run

```bash
cd wazuh-monorepo/services/ai-engine
# containers (Postgres + Qdrant) and Ollama must be running
docker compose up -d

# schema is applied automatically on first run, or manually:
./venv/bin/python3 -c "from scheduled_agent import store; store.ensure_schema()"

# run the agent
./venv/bin/python3 -m scheduled_agent.agent --source all
./venv/bin/python3 -m scheduled_agent.agent --dry-run     # score+print, no writes
```

Schedule daily at 02:00:

```cron
0 2 * * * /home/sek/wazuh/wazuh-monorepo/services/ai-engine/scheduled_agent/run_agent.sh >> .../agent.log 2>&1
```

Optional: set `NVD_API_KEY` to raise the NVD rate limit.

## Human review queue

```bash
./venv/bin/python3 -m scheduled_agent.review list
./venv/bin/python3 -m scheduled_agent.review approve CVE-2024-12345   # -> indexed
./venv/bin/python3 -m scheduled_agent.review reject  CVE-2024-12345   # -> dropped
```

## Audit & analytics queries

```bash
./venv/bin/python3 -m scheduled_agent.queries last-runs           # when/how many per source
./venv/bin/python3 -m scheduled_agent.queries decision-breakdown  # indexed/queued/dropped
./venv/bin/python3 -m scheduled_agent.queries queue               # pending review
./venv/bin/python3 -m scheduled_agent.queries drops               # drop audit log + reasons
./venv/bin/python3 -m scheduled_agent.queries boosted             # feedback loop in action
./venv/bin/python3 -m scheduled_agent.queries indexed-over-time   # growth (JOIN ledger->run)
./venv/bin/python3 -m scheduled_agent.queries cve CVE-2024-12345  # one CVE's full trail
```

## Files

| File | Role |
|---|---|
| `config.py` | env context, thresholds, boost weights, source URLs |
| `normalize.py` | NVD/KEV → common CVE shape; CPE parsing; episode builder |
| `fetchers.py` | `fetch_nvd_cves`, `fetch_cisa_kev` (graceful on outage) |
| `dedup.py` | exact CVE-id dedup against `threat_intel` |
| `boosts.py` | rule + alert-history boosts (pluggable backend) |
| `scorer.py` | LLM relevance scoring (Ollama, JSON, robust parse) |
| `store.py` | Postgres backbone: schema, cursor, run log, ledger, indexing |
| `agent.py` | pipeline orchestrator (`python -m scheduled_agent.agent`) |
| `review.py` | human review-queue approve/reject |
| `queries.py` | audit/analytics SQL CLI |
| `schema_additions.sql` | idempotent schema (ledger + run columns + view) |
| `run_agent.sh` | cron wrapper |
```
