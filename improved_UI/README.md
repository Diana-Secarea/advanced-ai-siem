# Diana's Shield — showcase UI (alternative frontend)

A standalone, animation-heavy concept UI for the Wazuh AI Threat Engine, with
**full feature parity** to the production `frontend/`. It is **not wired into the
live backend** — the existing `frontend/` is untouched and still what Flask serves.
This one runs on realistic mock data so you can preview the look and every interaction.

Every page shows an **"owned by Diana Secarea"** byline above the nav.

## Run it

```bash
cd improved_UI
python3 -m http.server 8081
# open http://localhost:8081
```

(Or open `index.html` directly; only Google Fonts + the Leaflet/Chart.js CDNs need internet.)

## Pages & feature parity with the production frontend

| Page | Production feature | Showcase implementation |
|------|--------------------|--------------------------|
| `index.html` | dashboard hub | hero live stats, 5 module cards, ticker, pipeline, particle bg |
| `alerts.html` | Alert Dashboard | **report strip** (Total/Critical-High/Possible/Normal/Benign/Avg w/ sub-stats), **4 charts** (timeline, anomaly donut, top-10 rules, level distribution — all click-to-filter), **filter toolbar** (search · period · anomaly · min level · agent · sort · clear), **exception chip bar** (benign rules + suspicious groups always visible), expandable alert cards, **inline AI analysis** side-panel, Leaflet **attack-origin map** |
| `chat.html` | RAG Threat Intel Chat | typewriter answers, **clickable source chips → source-viewer modal** (shows the exact quoted passage + full doc), **document upload** (dropzone), **My Documents** slide-out panel with delete, the real suggested prompts |
| `cve-agent.html` | CVE Ingestion Agent | KPIs (46 indexed / 29 review / 285 dropped / last run), **Run Agent** + source selector, **idle** console until run, animated pipeline, **review queue** with approve/reject, CVE detail modal |
| `vectordb.html` | Vector DB Dashboard | KPIs (7,251 docs / 7,252 embeddings / 2 collections / 5 sources / v1.17.0), **Open Qdrant UI** + Refresh, Collection Monitor cards, Document-Sources breakdown, System Health grid, orbiting **vector galaxy** (hover to link points) |

## Modern UI treatment (client ask: "10× better, super futuristic")

- **Page-to-page transitions** — fade-out on nav click, fade-in on load
- **Objects grow on click, shrink on scroll** — alert cards expand to 1.02× on click; nav shrinks on scroll
- **Chatbot opens any alert** → click an alert's "Analyze with AI" → side panel explains it with the ensemble verdict + citations
- Particle constellation background (mouse-reactive), aurora blobs, animated gradient headlines
- 3D-tilt glassmorphism cards with cursor glow, animated counters, score bars, toasts, marquee ticker
- Live Leaflet map with pulsing geo-markers; Chart.js charts with click-to-filter

## Tech

Pure HTML/CSS/vanilla JS — no build step. External CDNs: Google Fonts,
Leaflet 1.9.4 (map), Chart.js 4.4.2 (charts). Shared code in `assets/style.css`
+ `assets/app.js` (`NX` helper: modals, toasts, counters, particles, transitions).

## Wiring it to the real backend later

Each page footer notes the real API it would read (`/api/alerts/scored`,
`/api/chat`, `/api/knowledge/upload` + `/documents`, `/api/cve-agent/status` +
`/queue` + `/run`, `/api/vectordb/stats`). Swap the mock `POOL` / `SOURCES` /
`QUEUE` arrays for `fetch()` calls and keep the rendering + animations.
