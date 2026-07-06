# GATA — Defense Presentation Script (Slides + Live Demo)

**Deck:** `GATA_Defense_Presentation.pptx` — **15 slides** (14 content + 1 references appendix)
**Companion:** `../demo_runbook.md` (click-by-click for the live demo)
**Two timings in one script:** the **10-minute** path is the core; the **[+15]** blocks are what you *add* if you have 15 minutes. Cut markers (✂) show what to drop first if you fall behind.

**Slide map (memorise this — the back half moved):**
`1` title · `2` problem · `3` architecture · `4` stack · `5` ensemble · `6` ablation · `7` training · `8` detection results · `9` RAG pipeline · `10` two databases · `11` retrieval results · `12` generation results · `13` CVE agent · `14` conclusions · `15` references.

---

## The single most important rule

> **Show the thing that is hardest to fake, early.** A real attack → real detection → real grounded explanation, running live on your own machine, is the money shot. The slides frame it; the demo proves it.

**Structure of the talk:** you do *not* present all 14 content slides then demo. You **weave** them: a few framing slides → jump to the live app for the proof → return to slides for the depth and the numbers. The flow below is the exact order.

**Your one-sentence thesis, repeated as a refrain:** *score every alert, explain every score, keep the knowledge fresh — entirely local, fully audited.* Say a version of it at the open, at the pivot into the demo, and at the close. It is the spine an examiner will remember.

---

## Before you walk up (off the clock)

- [ ] `backend/start_server.sh` running — Qdrant + Postgres + Ollama + Flask all up.
- [ ] **Pre-warm Ollama**: send one throwaway chat message so the model is hot (the keep-alive pin holds it for 24h; still verify). Avoids a cold pause on stage.
- [ ] Four browser tabs open and logged in: **Alerts**, **ML Engine**, **Chat**, **CVE Agent**.
- [ ] Deck open in presenter view on the other screen; slide 1 showing.
- [ ] A terminal visible (for the CVE agent run), font size bumped up.
- [ ] Water. Breathe. You built this — you know it better than anyone in the room.

---

# ═══════════  10-MINUTE FLOW  ═══════════

| Phase | Time | Medium | Slides |
|-------|------|--------|--------|
| A. Frame the problem | 0:00–1:30 | Slides | 1 → 2 → 3 |
| B. **Live: attack → detection** ⭐ | 1:30–4:00 | **App** | (Alerts tab) |
| C. **Live: grounded explanation** ⭐ | 4:00–5:30 | **App** | (Chat / Investigate) |
| D. How the score is made | 5:30–6:30 | Slide + App | 5 (+ ML Engine tab) |
| E. Why detection is trustworthy | 6:30–7:30 | Slides | 7 → 8 |
| F. Why the copilot is trustworthy | 7:30–8:30 | Slides | 11 → 12 |
| G. Autonomous knowledge | 8:30–9:00 | App or Slide | 13 (+ CVE tab) |
| H. Conclusions (stays up for Q&A) | 9:00–10:00 | Slide | 14 |

*Slides **4** (stack), **6** (ablation), **9** (RAG pipeline internals) and **10** (two databases) are **spoken over or skipped** in the 10-min path — they carry the full depth for the 15-min path and for Q&A.*

---

## A · Frame the problem — 1:30  (Slides 1 → 2 → 3)

**Slide 1 (title) — 15s.**
> "Good morning. My thesis builds a SIEM that does something today's tools can't: it integrates two AI paradigms into Wazuh — unsupervised anomaly detection, and a knowledge-grounded language model. Everything I'll show is implemented, deployed, and evaluated on real data — and I'll prove it with a live demo on my own machine, not a slide."

**Slide 2 (the problem) — 40s.**
> "Rule-based SIEMs put analysts in an impossible position. Four structural failures. One — alert fatigue is not a tuning problem, it's structural: a SOC averages around 4,490 alerts a day and roughly 67% are never investigated at all. Two — rules only match the known, so a zero-day or a custom tool generates events no rule ID covers; detection is reactive by design. Three — static thresholds misfire: 'eight failed logins in two minutes' fits no real environment and floods you with false positives. Four — even when an alert is right, it arrives context-free: 'possible kernel rootkit, rule 521' still sends an analyst off to research the technique, the indicators, the fix."
> "So my research question, on the right, is deliberately concrete: can unsupervised anomaly scoring plus retrieval-grounded reasoning cut triage time and *earn analyst trust* — on a real, running Wazuh deployment, not a benchmark. My answer is: score every alert, and explain every score."

**Slide 3 (architecture) — 35s.**
> "Here's how. The endpoint and manager layers — the left — are standard Wazuh. Everything above them is my contribution: an AI Threat-Hunting Engine that extends Wazuh end-to-end and does three things. One, an anomaly *ensemble* scores every alert zero to a hundred and fuses that into confidence tiers. Two, a RAG copilot *explains* each score with a local LLM grounded in MITRE ATT&CK, YARA, Sigma and CVEs — with citations, in the dashboard. Three, a scheduled CVE agent keeps the knowledge *fresh*, with PostgreSQL as the audit ledger. Score, explain, stay current — and let me show you that loop running live."

→ **Alt-tab to the browser. This is the pivot into the demo.**

---

## B · Live: real attack → live detection — 2:30  ⭐ THE MONEY SHOT  (Alerts tab)

*(Full click-by-click in `demo_runbook.md §2`.)*

1. **"Populate Map"** — instant, visual: pulsing geolocated attacker pins appear on the world map.
   > "Real public attacker IPs, geolocated. The dashboard reacts live."
2. **"Test the Shield"** — runs 14 attack families as *actual commands* on the host through the real Wazuh pipeline.
   > "This is not a recording and not a replay. Real SSH brute force, reverse shells, rootkit behaviour, SQL injection — firing right now, through the real Wazuh manager."
   - Narrate the streaming log as families fire.
3. Point at the **report strip** (Total / Critical / Possible / Normal) and the **anomaly donut** updating.
4. Click one **CRITICAL** alert (SSH brute force, rule 5503) → card shows **score 99/100, rule, agent, IP, raw log, IF + AE sub-scores**.
   > "Scored in about 12 milliseconds — before any human looked at it. And the tier isn't cosmetic: CRITICAL means *both* independent models agreed this is anomalous."

**Land it:** *"Nothing here is staged — real commands, real Wazuh detection, real ensemble scores, on my laptop."*

✂ *If behind:* skip Populate Map, go straight to Test the Shield.

---

## C · Live: grounded explanation — 1:30  ⭐  (Investigate / Chat tab)

*(Full detail in `demo_runbook.md §3`.)*

1. Click **"🤖 Investigate"** on that same CRITICAL alert (pre-loads the alert context), or ask in Chat: **"What attacks were detected on my system?"**
2. While it streams:
   > "The LLM is llama3.2, running *locally* through Ollama — nothing leaves this machine, no cloud API, no per-token cost. And it is constrained to answer *only* from retrieved evidence — it is not free to improvise."
3. When the answer lands, **click a source citation chip** → viewer shows the exact quoted MITRE / Sigma / CVE passage + "Open in Qdrant UI" link.
   > "Every claim traces to a specific indexed chunk you can open and read. This is the difference between a chatbot and an auditable analyst — and I measured it: 98.3% citation precision, which I'll come back to."
4. One anti-hallucination line:
   > "And if I ask about something *not* in the knowledge base, it refuses instead of inventing an answer — zero fabricated threats on my purpose-built unanswerable-query set."

✂ *If behind:* skip the follow-up question; one grounded answer + one source-chip click is enough.

→ **Alt-tab back to slides.**

---

## D · How the score is made — 1:00  (Slide 5, optionally ML Engine tab)

**Slide 5 (ensemble) — 60s.**
> "So how is that score actually made? One alert becomes 16 numerical features, z-scaled. Two unsupervised models judge it — and the whole design rests on the fact that they fail *differently*. Isolation Forest isolates extreme single features with random cuts. The Autoencoder learns to reconstruct a normal alert, so it catches unusual *combinations* even when no single feature stands out. They fuse — 0.45 Isolation Forest, 0.55 Autoencoder — into calibrated tiers."
> "Two things I want you to take from this slide. First, the tiers *mean* something: agreement between both models is 'act now'; a single-model flag is 'review when you can' — and 91.3% of the attacks we detect land in the CRITICAL tier, so the ranking is doing real work. Second, the adversarial argument I'm proud of: you cannot evade both at once. Blending into the crowd to fool Isolation Forest makes you statistically average — which is exactly what the Autoencoder reconstructs perfectly. The two evasion strategies contradict each other."

**[+15] Jump to the ML Engine tab (Scoring Lab):** pick the live SSH alert, hit *Score* → watch the 16 features extract, IF and AE score, fusion, tier — the *real* ensemble, live. *(This is the strongest 15-min-only addition — it makes the intrinsic ML visible and turns a slide into a demonstration.)*

---

## E · Why detection is trustworthy — 1:00  (Slides 7 → 8)

**Slide 7 (training) — 35s.** *(the methodological heart — say it slowly)*
> "A production deployment's logs are never guaranteed clean, so I refuse to assume a labelling capability that doesn't exist in the real world. I train with *zero labels* on contaminated data — about 30% attacks mixed in. Iterative trimming: train the autoencoder on all 2,171 alerts, drop the worst-reconstructed 25% — because that tail is exactly where attacks hide — retrain, drop another 15%, then final fit and calibrate. The model bootstraps its own clean set. The table is the honest trade: versus a clean-only baseline I give up about five points of recall, but I *lower* false positives from 8.8% to 6.2%, *raise* precision, and need no labelling — which is the only version of this that actually ships to a SOC."

**Slide 8 (detection results) — 35s.**
> "Results on 2,171 real alerts — months of live Wazuh telemetry plus a WordPress site that was attacked in the wild for two months. The exhibit is the ensemble confusion matrix, and the number that matters for a security tool is missed attacks: the ensemble misses 41, versus 62 for Isolation Forest alone and 208 for the Autoencoder alone. Fewest misses wins — because in a SOC a miss costs far more than a second look. Precision 82%, recall 94%; Isolation Forest is the workhorse at 0.94 AUC, the Autoencoder is the second opinion that trims false alarms. I optimised for the fewest missed attacks, not the prettiest F1 — and I say so explicitly."

✂ *If behind:* present slide 8 only; fold slide 7's headline ("zero labels, lower false positives") into one sentence.

---

## F · Why the copilot is trustworthy — 1:00  (Slides 11 → 12)

*These two slides are the RAG equivalent of E: retrieval finds the right evidence, generation uses it honestly.*

**Slide 11 (retrieval results) — 30s.**
> "For the copilot I hold retrieval to the same standard. Over 82 hand-annotated queries: Hit-Rate 82.9%, MRR 0.695 at k=5 — the correct source is usually ranked at or near the top. And I report where it's weak, not just where it's strong: CVEs and APT profiles retrieve near-perfectly because their vocabulary is distinctive; MITRE techniques are the weak spot at 46%, because one query maps to many overlapping sub-techniques. I also tried a cross-encoder re-ranker — it *hurt* domain queries, so I removed it. Reporting a negative result is part of doing this honestly."

**Slide 12 (generation results) — 30s.**
> "And generation is verifiably grounded. 98.3% citation precision — 117 of 119 inline citations point at a chunk that genuinely supports the claim. When I probed it with a *fake* CVE and an *invented* APT group, it refused all six fabricated-intelligence questions instead of making threat intel up. And it never over-refuses — zero of 82 answerable questions were wrongly declined. It is calibrated, not just cautious. That combination — grounded, honest about what it doesn't know, and still useful — is what earns an analyst's trust."

✂ *If behind:* present slide 12 only; mention slide 11's Hit-Rate in one sentence as the base it rests on.

---

## G · Autonomous knowledge maintenance — 0:30  (Slide 13 or CVE tab)

**Slide 13 (CVE agent) — 30s.**
> "Last piece: the knowledge base maintains itself. A scheduled agent fetches new CVEs from NVD and CISA-KEV since its last cursor, deduplicates against the ledger, *boosts* by evidence from this specific deployment — my local rules, my alert history — then scores each CVE's relevance zero to ten with the LLM and routes it: seven or above auto-indexes into RAG, four to six goes to a human review queue held *out* of RAG, below four is dropped and logged. Every single decision lands in a PostgreSQL audit ledger — reversible, never silent. The retrieval pipeline never changes; the corpus just stays current on its own."

**[+15] Jump to the CVE Agent tab / terminal:** trigger one run, show a CVE getting scored and a KPI strip updating, and the `pending_review` queue. *(Closes the agentic loop visibly.)*

---

## H · Conclusions — 1:00  (Slide 14 — stays on screen for Q&A)

**Slide 14 (conclusions).**
> "To conclude — three claims, each one I've now shown you evidence for. One: unsupervised detection *works* on real telemetry — the ensemble reaches 94% recall with the fewest missed attacks, trained with zero labels on contaminated data. Two: grounded explanation is measurable, not aspirational — 98.3% citation precision, refusal of fabricated threats, zero over-refusals. Three: the knowledge base maintains itself, with humans in the loop only where confidence is medium."
> "And I was honest about the limits — about 2,200 training alerts, per-alert scoring without entity analytics yet, and local-LLM latency — each of which I've turned into concrete future work: entity-level behaviour analytics, a supervised comparison baseline, a domain-tuned re-ranker. The full system is public on GitHub. This isn't a prototype that only works in the slides — it's running right now on the machine in front of you. I'll stop here, and I'd welcome your questions."

**Leave slide 14 up.** Do **not** advance to a "Thank You" or blank slide — the conclusions, the GitHub link and your contact stay visible through Q&A.

---

# ═══════════  15-MINUTE FLOW  ═══════════

Same spine, with the depth restored. Add these **[+15]** blocks:

1. **Slide 4 (stack) — +45s**, after slide 3: walk the three columns — scikit-learn IF + MLP autoencoder + custom 16-feature extractor / Qdrant HNSW + MiniLM 384-d + BM25 + RRF + Ollama llama3.2 / Wazuh 4.14.1 + Flask + PostgreSQL 17 + Docker. Land the punchline: **"fully local, open-source — security data never leaves the machine, and there is no per-token cost."**
2. **Slide 6 (feature ablation) — +50s**, after slide 5: every feature is retrained-from-scratch, not approximated (<5s per variant). Privilege-change is the strongest signal — remove it and new-user / promiscuous-mode attacks drop to 0% detection. Then the credibility moment: `mitre_count` *looked* sensible but added +8.9% false positives from train/production drift — so I removed it. Showing a feature you *cut* is more convincing than any you kept.
3. **ML Engine Scoring Lab (live) — +60s**, inside phase D: score the live alert through the real ensemble on screen.
4. **Slide 9 (RAG pipeline) — +45s**, before phase F: the retrieval stack is ablated end-to-end — 512-token chunks with 25% overlap beat 128/256/1024; k=5 fits llama3.2's 8K window without lost-in-the-middle dilution; RRF instead of a learned re-ranker. Every knob was measured, not assumed.
5. **Slide 10 (two databases) — +45s**, inside phase F: Qdrant answers *"what is similar?"*, PostgreSQL answers *"what is true?"* — and `cve_decisions.qdrant_id` is a foreign key that bridges the two paradigms. Medium-confidence CVEs are quarantined in Postgres, never allowed into RAG. This is the architecture-maturity slide.
6. **CVE Agent live run — +60s**, inside phase G: trigger a run, show scoring + the review queue + the Postgres ledger.
7. **Breathe in the demo:** in phase B, open a second alert type (e.g. reverse shell) to show tier variety; in phase C, ask the follow-up "How do I contain it?" to prove it's a real conversation.

**15-min timing target:** finish at ~13:30 spoken, leaving buffer. Rehearse to *under* time — going over at a defense is the one avoidable mistake.

---

## Anticipated Q&A → which slide/appendix to jump to

| Question | Where to go | One-line answer |
|----------|-------------|-----------------|
| "Why not a supervised classifier?" | Slide 7 | "Production has no clean labels; I measured the trade — supervised inflates recall via a shortcut that doesn't exist in the wild." |
| "Why two models, not one?" | Slide 5 | "Complementary failure modes; evading both is contradictory. The ensemble misses 41 vs 62 / 208 alone." |
| "How do you know the LLM isn't hallucinating?" | **Slide 12** | "98.3% citation precision, and it refused all 6 fabricated-intelligence probes — it declines instead of inventing." |
| "Why PostgreSQL *and* a vector DB?" | **Slide 10** | "Qdrant answers 'what's similar'; Postgres answers 'what exactly happened' and is the audit ledger. Different questions, one foreign key between them." |
| "Isn't 2,200 alerts small?" | **Slide 14** (limits) | "Yes — stated as a limitation; retraining is <5s so it scales with data, and trimming self-corrects on drift." |
| "Why not fine-tune the LLM?" | **Slide 9 / 13** | "RAG updates in seconds with no retraining, gives citations, and keeps data local — fine-tuning gives none of those." |
| "How does it handle concept drift?" | Slide 7 | "Iterative trimming re-estimates the clean distribution from scratch each retrain — no manual relabelling." |
| "Feature choice justification?" | Slide 6 | "Every feature ablation-tested; I even removed one (mitre_count) that looked useful but hurt due to train/prod drift." |
| "Retrieval isn't perfect — MITRE at 46%?" | **Slide 11** | "Correct, and I report it openly; distinctive vocab (CVEs/APTs) retrieves near-perfectly, overlapping sub-techniques are the known weak spot and future work." |

---

## Recovery lines (if the live demo misbehaves)

- **Ollama cold / slow:** "It's loading the model locally — which is exactly the privacy trade-off I chose over a cloud API. While it warms up…" → narrate the architecture.
- **Attack sim stalls:** don't wait — "The pipeline's mid-run; here's a scored alert from moments ago," → click an existing CRITICAL alert. The ML Engine Scoring Lab is your fully-offline fallback (it re-scores with the real models, or cached values if the backend is down).
- **Network/browser dies entirely:** the deck alone carries the full argument (ghost-deck test passes) — slides **5, 7, 8, 11, 12** have every number you need.

---

*Rehearse aloud, to time, at least three times. Target finishing 1–2 minutes under. You've got this.*
