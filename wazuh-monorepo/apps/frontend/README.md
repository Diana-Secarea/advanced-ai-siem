# Selenne — production frontend

The production UI for the Wazuh AI Threat Engine, served by Flask at
**http://localhost:5000** (`backend/server.py`). Fully wired to the live
backend — every page reads and writes the real APIs. The previous frontend
remains reachable at **/legacy/** as a fallback.

Every page shows an **"owned by Diana Secarea"** byline above the nav.

## Pages & the APIs they use

| Page | Feature | Backend |
|------|---------|---------|
| `index.html` | hero live stats (total / critical-high / possible / normal / avg) | `/api/alerts/scored` |
| `alerts.html` | scored alert stream, report strip, 4 click-to-filter charts, filter toolbar, expandable cards | `/api/alerts/scored` (30 s poll) |
| | attack-origin map (real `data.srcip` geolocation, 24 h cache) | ip-api.com batch |
| | **Populate Map** → runs `backend/populate_map.py` server-side | `POST /api/populate-map` |
| | **Test the Shield** → streams `attack_simulation/simulate_attack_for_wazuh.sh` | `GET /api/test-shield` (SSE) |
| | benign rule exceptions + suspicious groups (chips, modals, suggested lists) | `/api/benign-rules`, `/api/suspicious-groups`, `/api/suggested-*` |
| | 🤖 Investigate side panel — real RAG analysis of the clicked alert | `POST /api/chat/stream` (SSE) |
| `chat.html` | streaming RAG chat with clickable source chips | `POST /api/chat/stream`, `DELETE /api/chat/sessions` |
| | source viewer modal (exact passage + Qdrant deep link) | `GET /api/source?id=` |
| | document upload dropzone + My Documents panel with delete | `/api/knowledge/upload`, `/api/knowledge/documents` |
| `ml.html` | Live Scoring Walkthrough — real 16-feature extraction + IF/AE/ensemble scores; score curated samples or any live alert | `POST /api/score-alert`, `/api/alerts/scored?raw=1` |
| `cve-agent.html` | KPIs + recent decisions from the Postgres ledger | `/api/cve-agent/status` |
| | Run Agent + live console (polls the real subprocess log) | `POST /api/cve-agent/run`, `/api/cve-agent/run-status` |
| | review queue with approve / reject + CVE detail modal | `/api/cve-agent/queue`, `/cve/<id>`, `/approve`, `/reject` |
| `vectordb.html` | KPIs, collection monitor, source breakdown bars, system health, galaxy weighted by the real source mix | `/api/vectordb/stats` (30 s poll) |

The **Benign** and **Suspicious** nav-bar managers (on every page, from
`assets/app.js`) persist straight to the backend JSON stores — changes apply
to the scoring engine instantly, no retraining.

## Reactor — the reactive service

Beyond the dashboard, the backend runs a **headless reactor**: a daemon that
tails the Wazuh alert stream, scores each new alert with the ensemble, and
*acts* on high-severity verdicts with no browser open —

- **incident ledger** → append-only `backend/incidents.jsonl` (always)
- **webhook** → Slack-compatible `{text, incident}` POST (if `REACTOR_WEBHOOK_URL` set)
- **active response** → optional, IP-validated command (off by default)

De-duplicates repeats by `rule+srcip+label` within a cooldown window. Enable via
`REACTOR_ENABLED=1` (see `backend/.env.example`) or at runtime from the **⚡ Reactor**
card on the Alerts page. API: `GET /api/reactor/status`, `GET /api/reactor/incidents`,
`POST /api/reactor/config`, `POST /api/reactor/test`. This is what makes the project
a *service that runs and reacts*, not just a dashboard.

## Run it

```bash
cd backend && ./start_server.sh     # Flask serves this UI at :5000
```

Needs the Docker stack (Qdrant, Postgres) and Ollama for the RAG/chat and
CVE-agent features; the alerts dashboard and ML lab work with just Flask.

## Tech

Pure HTML/CSS/vanilla JS — no build step. External CDNs: Google Fonts,
Leaflet 1.9.4 (map), Chart.js 4.4.2 (charts), ip-api.com (geolocation).
Shared code in `assets/style.css` + `assets/app.js` (`NX` helper: modals,
toasts, counters, particles, transitions, benign/suspicious managers).
