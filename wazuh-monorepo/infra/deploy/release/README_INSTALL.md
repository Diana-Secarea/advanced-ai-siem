# Selenne — Linux install

AI threat-detection engine with a live dashboard, ML anomaly + novelty scoring,
a retrieval-grounded AI analyst, and an autonomous CVE agent.

## Quick start

```bash
tar -xzf selenne-linux.tar.gz
cd selenne-linux
./install.sh      # one-time setup (Python env + optional Docker/Ollama)
./run.sh          # start it
```

Then open **http://127.0.0.1:5000**.

## Requirements

| Component | Needed for | If missing |
|-----------|------------|------------|
| **Python 3.10+** | the app itself | **required** |
| **Docker** (+ compose) | vector search (Qdrant) + CVE ledger (Postgres) | those features are limited; core dashboard + ML scoring still work |
| **Ollama** (`ollama.com`) | the AI analyst chat + local LLM | chat is unavailable; everything else works |
| **Wazuh manager** | *live* SIEM alerts & system-log feed | the app runs standalone as a demo — the alert feed is simply empty until a Wazuh manager writes to `/var/ossec/logs/…` |

Selenne is the AI layer that sits **on top of** a Wazuh deployment. Without Wazuh
it runs fine for exploring the UI, the ML scoring lab, the RAG chat and the CVE
agent; connect it to a Wazuh manager to get live alerts and full log scoring.

## Notes

- Binds to `127.0.0.1:5000` by default (loopback only). Set `BIND_HOST` /
  `BIND_PORT` to change. **Do not** expose it on `0.0.0.0` without the auth
  gateway / reverse proxy — mutating endpoints are unauthenticated by default.
- Config lives in `app/apps/backend/.env` (copied from `.env.example` on first
  install). Add Stripe / SMTP keys there only if you need billing / email.
- Trained ML models ship in `app/services/ai-engine/data/ai_models/`. Retrain
  anytime with `app/services/ai-engine/retrain_all.sh`.
- To stop: `Ctrl+C`. To stop the Docker services too:
  `docker compose -f app/services/ai-engine/docker-compose.yml down`.
