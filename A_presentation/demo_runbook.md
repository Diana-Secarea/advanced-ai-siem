# AI Threat Engine — 10-Minute Live Demo Runbook

**Goal:** in 10 minutes, show the whole loop working end-to-end — detection → explanation → knowledge maintenance — ordered so that if you run out of time, you've already shown the most important, highest-impact things.

**Golden rule of a live demo:** *show the thing that is hardest to fake first.* Real attack → real detection → real grounded explanation is the money shot. Do it early.

**Before you start (off the clock):**
- Server running (`backend/start_server.sh`), Qdrant + Postgres + Ollama up.
- **Pre-warm Ollama**: send one throwaway chat message so the model is loaded (avoids a cold-start pause on stage).
- Alerts dashboard, Chat, ML Engine, and CVE Agent tabs already open in the browser.
- The attack-simulation timing is already reduced (~7s), so "Test the Shield" returns quickly.

---

## The order (most important live → least important)

| # | Time | What | Why it's ranked here |
|---|------|------|----------------------|
| 1 | 0:00–0:40 | **Hook + architecture** (1 slide) | Frame the loop before the demo so every click has meaning. |
| 2 | 0:40–3:10 | **Run a real attack → live detection + map** | The hardest-to-fake, highest-impact proof. Do it first. |
| 3 | 3:10–5:10 | **Grounded RAG explanation of that attack** | Turns raw detection into analyst value; shows citations + sources. |
| 4 | 5:10–7:00 | **ML Engine page — how the score was made** | Makes the "intrinsic" ML visible; academic depth. |
| 5 | 7:00–9:00 | **CVE Agent — autonomous knowledge maintenance** | Closes the loop; shows the agentic contribution. |
| 6 | 9:00–10:00 | **Results + honest limitations + close** (slides) | Land the numbers and credibility. |

> If you're behind: cut #5 to 45s (just show the KPIs + one console run), and skip the "continue the conversation" part of #3.

---

## 1 · Hook + architecture — 40s (Slide 18: full architecture)
> "Wazuh tells you *what* rule fired. It can't tell you *how anomalous* it is, *why* it matters, or keep its own knowledge current. My engine adds three AI layers that do exactly that — and they reinforce each other in a loop. Let me show you the loop running live."

Point once at the four bands (data → AI core → storage → interfaces) and move on. **Don't linger on slides — the demo is the star.**

---

## 2 · Real attack → live detection + map — 2m30s  ⭐ THE MONEY SHOT
On the **Alerts dashboard**:

1. **"Populate Map"** first (it's instant and visual): synthetic geo-located attacks appear as pulsing pins across the world map. → *"These are real public attacker IPs, geolocated. The dashboard reacts live."*
2. **"Test the Shield"**: → *"Now a real attack. This runs 14 attack families as actual commands on the host — SSH brute force, reverse shells, rootkit, SQL injection — through the real Wazuh pipeline."*
   - Narrate the streaming log as families fire.
3. As alerts land, point at the **report strip updating** (Total / Critical / Possible / Normal) and the **anomaly donut**.
4. Click one CRITICAL alert (e.g. SSH brute force, rule 5503) → the card shows **score 99/100, rule, agent, IP, raw log, IF/AE sub-scores**. → *"Scored in ~12 milliseconds, before a human looked."*

**One-liner to land it:** *"Nothing here is staged — real commands, real Wazuh detection, real ensemble scores."*

---

## 3 · Grounded RAG explanation — 2m  (this is your "ask a RAG question")
Click **"🤖 Investigate"** on that same alert (or open the Chat tab).

1. Ask: **"What attacks were detected on my system?"** or use the alert's Investigate button so the alert context is pre-loaded.
2. While it streams, say: → *"The LLM runs locally — llama3.2 via Ollama. Nothing leaves the machine. And it can only answer from retrieved evidence."*
3. When the answer lands, **click a source citation chip** → the viewer shows the exact quoted MITRE/Sigma/CVE passage, with an **"Open in Qdrant UI"** link. → *"Every claim is traceable to a specific indexed chunk — 98.3% citation precision in my evaluation."*
4. **Continue the conversation once** (shows it's a real analyst, not a canned reply): ask *"How do I contain it?"* → grounded, actionable steps.
5. Mention the anti-hallucination guard: → *"If I ask about something not in the knowledge base, it refuses instead of inventing — that was 0 hallucinations on my unanswerable-query set."*

---

## 4 · ML Engine page — how the score was made — 1m50s  (the ML made visible)
Open the **ML Engine** tab. *This is how you show the "intrinsic" ML without hand-waving.*

1. → *"That 99/100 wasn't magic. Here's the exact pipeline for one alert."*
2. Pick **"SSH brute force"** in the selector, press **"Score this alert"**. Watch the 4 animated steps:
   - **16 features** light up — the red ones (failed_count, off_hours, external IP, unknown user) are what drive it.
   - **Isolation Forest** score counts up → flagged anomalous.
   - **Autoencoder** reconstruction error → flagged anomalous.
   - **Fusion**: `0.45·IF + 0.55·AE` → **CRITICAL** ("both models flag").
3. Then pick **"New UID-0 user"** and score it → show a **HIGH** case where *only the autoencoder* catches it → *"This is why I use two models: they fail in opposite ways. An attacker can't evade both at once."*
4. Scroll down to the **75-point score separation histogram** and **confusion matrix**: → *"Precision 83%, recall 96%, F1 89 — reproducible, on 2,171 alerts."*
5. One sentence on training: → *"And it's fully unsupervised — Isolation Forest with contamination='auto', autoencoder with iterative trimming. No human labels anywhere. It learns 'normal' on any network by itself."*

---

## 5 · CVE Agent — autonomous knowledge maintenance — 2m
Open the **CVE Agent** tab.

1. Point at the KPIs: **46 indexed · 29 awaiting review · 285 dropped**. → *"The knowledge base must not go stale, so this agent maintains it on a daily schedule."*
2. Press **"Run Agent"** → narrate the streaming console: *fetch (NVD/CISA-KEV) → dedup → boost by environment → LLM scores relevance 0–10 → act.*
3. Explain the three bands: **≥7 auto-index · 4–6 human review · <4 drop (audited)**. → *"Agentic doesn't mean unbounded — one bounded LLM decision, every outcome logged to Postgres, fully reversible."*
4. **Duplicates:** → *"Re-fetched CVEs are skipped, never re-inserted — a unique DB constraint plus deterministic IDs guarantee no duplicates."* (only if asked / time allows)
5. Note it runs server-side: → *"If I close the tab mid-run, it keeps going and re-attaches when I come back."*

---

## 6 · Results + limitations + close — 1m  (Slides 19–20)
1. Results at a glance: recall 95.9, F1 89.2, RAG hit rate 82.9, citation precision 98.3, 14/14 attack families, all local.
2. **Show one limitation openly** (examiners love this): → *"Single failed PAM logins are only 45% — they're informationally identical to a typo. The fix is temporal window features, which is in future work."*
3. Close: → *"A SIEM that detects without labels, explains with citations, and updates its own knowledge — local, auditable, reproducible end-to-end. Thank you."*

---

## Contingencies (say these calmly if something breaks)
- **Ollama is slow / cold**: *"It's doing local inference on CPU — in production this runs on GPU with the model kept warm."* (Keep talking; it will catch up.)
- **A run stalls**: switch to the **ML Engine** page (fully client-side, never fails) and talk through the scoring while the backend recovers.
- **No network for NVD**: the CVE Agent console still shows the pipeline; say the fetch is cached/offline for the demo.
- **Projector too small to read**: the ML Engine + alert cards were redesigned to be low-density and high-contrast for exactly this.

## Why this order (defensible rationale)
The riskiest, most impressive claim is *"real attack → real detection → real grounded answer."* Front-loading it means the examiners see the core contribution even if a later step hiccups. Detection (what) → explanation (why) → ML (how) → agent (stay current) also mirrors the thesis chapter order, so the narrative is consistent with the document.
