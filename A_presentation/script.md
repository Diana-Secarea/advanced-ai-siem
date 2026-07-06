# AI Threat Engine — Presentation Script
**30 slides · target 18–20 minutes · ~45–60 s per slide**
(The authoritative per-slide narration is embedded in the PPTX speaker notes — open the deck in Notes view.)

> **Deck structure (updated 2026-07-05):** the deck opens with a proper thesis
> **title slide** and an **Agenda/roadmap**, uses three **section-divider slides**
> (01 Machine Learning · 02 RAG · 03 Agentic Ingestion) to structure the talk,
> and includes a **Live Demo** slide before the Results. Every content slide has a
> footer with name + slide number, and **all slides use a smooth fade transition**.
> Because of the inserted slides, the "Slide N" headings below are the *original*
> order — use the embedded speaker notes for exact per-slide text, and
> `demo_runbook.md` for the 10-minute live walkthrough.

---

## Slide 1 — Title (30 s)
Good morning. Today I present the **AI Threat Engine** — a system that upgrades the open-source Wazuh SIEM with three AI layers: an **unsupervised anomaly-detection ensemble**, a **retrieval-augmented LLM analyst**, and an **autonomous CVE-ingestion agent**. Everything runs locally — no cloud APIs, no data ever leaves the machine. Headline numbers: **F1 89.2%**, attack recall **95.9%**, and **98.3% citation precision** for the AI analyst.

## Slide 2 — Motivation (60 s)
Why does a SIEM need AI? Four problems. **Alert fatigue** — a single monitored host produces thousands of alerts a day and analysts triage a fraction. **Rules only catch what they name** — signatures miss novel behavior. **Severity is not maliciousness** — a level-5 alert can be routine or the start of a brute force; context decides. And **knowledge is scattered** across MITRE, Sigma, CVE feeds and internal runbooks. My corpus: 2,171 real alerts, 640 of them from 14 simulated attack families — and, crucially, **zero labels needed for training**.

## Slide 3 — Integration with Wazuh (55 s)
Integration is deliberately **non-invasive** — Wazuh itself is never modified. The engine tails `alerts.json` read-only, scores every new alert in about **12 milliseconds**, and attaches the verdict. A daily collector snapshots data for retraining. A Flask API layer exposes scored alerts, chat and document upload. And Wazuh's own parsing works *for* the ML: rule level, rule ID and groups become model features. If Wazuh breaks tomorrow, nothing I built caused it — and if my engine stops, Wazuh keeps running.

## Slide 4 — Technologies (50 s)
The stack, in four columns. **ML**: scikit-learn for both models, with a custom feature extractor. **RAG & LLM**: Ollama serving llama3.2 locally, Qdrant as the vector database, dense sentence-transformers plus sparse BM25 embeddings. **Data & backend**: PostgreSQL for the audit ledger, Flask with server-sent-event streaming, Docker Compose. **Security base**: Wazuh 4.14 and the standard intel corpora. The key property: **zero cloud dependencies** — air-gap deployable, no per-token cost, GDPR-safe by construction.

## Slide 5 — Unsupervised training pipeline (75 s)
The training strategy is **fully unsupervised** — this is the methodological core. Raw alerts, *including the attacks hiding in them*, flow through feature extraction and standard scaling into two branches. The **Isolation Forest** trains with `contamination=0.3` — it expects up to 30% anomalies in its own training data and isolates them natively; that is *genuinely* unsupervised. The **autoencoder** uses **iterative trimming**: train, discard the worst-reconstructed 25% of samples, retrain, discard 15%, three rounds — bootstrapping a clean model of "normal" without a single label. The literature calls this *self-supervised one-class classification*. Operationally it means: deploy on a network you have never seen, and it learns that network's normal by itself.

## Slide 6 — Feature engineering (65 s)
Every alert becomes a **16-dimensional vector** across five groups: content (failed-login counts, event size), temporal (hour, off-hours), network (IP and port counts, external-source-IP with **CDN awareness** — Cloudflare ranges excluded), identity (unknown users, privileged account changes), and Wazuh metadata. This set was refined **14 times** against live attack simulations. One lesson worth sharing: I **removed** the MITRE-tag-count feature after discovering Wazuh attaches MITRE tags to benign SSH logins — the feature poisoned training. Feature engineering is empirical, not guesswork.

## Slide 7 — Isolation Forest (60 s)
First ensemble member. The intuition: anomalies are **few and different**, so random feature splits isolate them in short paths — short path, high anomaly score. Raw scores are calibrated to 0–100 and the threshold sits at the **90th percentile of clean scores**, which is 50. Why this algorithm? No labels, microsecond scoring, robust to irrelevant features. Its known weakness — axis-parallel splits miss correlated anomalies — is exactly what the second model covers. On the right: the score distributions — attacks average **92.4**, normal traffic **17.3** — a **75-point separation**.

## Slide 8 — Autoencoder (60 s)
Second member: a bottleneck network, **16→8→4→8→16**, trained to reconstruct its own input. Because it only learns from (trimmed) normal data, normal alerts reconstruct well and attacks reconstruct badly — **reconstruction error is the anomaly score**. The 4-neuron bottleneck is the point: it forces compression, so the network must learn *correlations between features* — precisely what the forest cannot see. Two models, two different failure geometries. That is the entire argument for the ensemble.

## Slide 9 — Ensemble & labels (70 s)
Fusion: **combined = 0.45 × IF + 0.55 × AE**. Label logic: both flag → **CRITICAL**; only the autoencoder → **HIGH** (it is the higher-precision model); only the forest → **POSSIBLE**, dampened ×0.65; neither → **NORMAL**. `is_anomaly` is true for the top three. Two important design facts: the ensemble is a **fixed, deterministic layer — not trained** — which keeps it fully explainable; and the security argument: an evasion must fool **tree isolation and a neural manifold simultaneously**, two fundamentally different geometries.

## Slide 10 — Score injection (60 s)
How verdicts reach the rest of the system — three paths. **Dashboard**: every streamed alert carries score + label, sorted worst-first; analyst-defined benign rules zero scores live, no retrain. **Chat grounding**: the LLM literally reads "rule 5720 · level 10 · Anomaly HIGH (94/100)" next to each matched alert — detection and explanation cannot contradict each other. **Retrieval gating**: if all matched alerts are level < 5, threat-intel retrieval is *skipped* and the LLM is instructed not to map routine events to ATT&CK — an anti-hallucination guard born from a real failure I observed.

## Slide 11 — Detection evaluation (60 s)
On 2,171 alerts: **precision 83.4%, recall 95.9%, F1 89.2%, FP rate 8%**. The confusion matrix: 614 attacks caught, 26 missed, 122 false alarms on 1,531 clean alerts. Whole attack families sit at **100%**: brute force, SQL injection, XSS, C2 beaconing, DNS exfiltration, reverse shells, rootkits, account manipulation. I am equally transparent about the hard case: **single failed PAM logins — 45%** — because one failed login is informationally identical to a typo. The fix is temporal context, and it is in future work.

## Slide 12 — RAG: why it explains (55 s)
Detection says *what* is anomalous; RAG explains *why* and *what to do*. A bare LLM **hallucinates** — it will invent CVE numbers with total confidence. RAG retrieves verified knowledge first and forces the model to answer *from it*, with numbered citations. Two grounding sources: the 1,333-point intel base and the live alert stream with ML verdicts attached. Uploaded runbooks are **quoted verbatim with the document title** — institutional knowledge becomes part of every answer. Sessions are multi-turn, so analysts can drill down naturally.

## Slide 13 — Vector database (65 s)
How the knowledge base is built. Every item — MITRE technique, Sigma rule, KEV entry, document chunk — becomes an **episode** with summary, tags and entities. Each episode is embedded **twice**: a 384-dim dense vector for meaning, a sparse BM25 vector for exact terms. At query time both retrievers pull 40 candidates and **Reciprocal Rank Fusion** merges them — score = Σ 1/(60+rank), normalized to [0,1]. Why hybrid? Security queries are bimodal: "CVE-2021-44228" demands exact match; "is someone stealing data?" demands semantics. RRF gives both, with no weights to tune.

## Slide 14 — PostgreSQL (55 s)
Why a relational DB next to a vector DB? Different questions: Qdrant answers *"what is similar?"* — Postgres answers *"what happened, when, and why?"*. Four structures: `threat_intel`, the relational mirror of every indexed item; `cve_decisions`, one row per CVE the agent ever judged, including the LLM's reasoning; `ingestion_log`, per-run traceability; and the `pending_review` view — the human-in-the-loop surface. Design principle: **Qdrant is disposable and re-indexable; Postgres is the source of truth.** Every automated decision is auditable and reversible.

## Slide 15 — Grounded answer generation (60 s)
The prompt is assembled in layers. A **system prompt** sets the analyst persona, citation rules, and two anti-hallucination guards — never map routine events to techniques; quote user documents verbatim with citations. Then the **intel context**, numbered [1]–[5]; then **matched alerts with their ensemble verdicts**; finally the question. llama3.2 answers, streamed token-by-token over SSE. Every reply returns its **sources**, rendered as evidence chips. And refusal is a feature: no evidence → the model says so rather than inventing.

## Slide 16 — RAG evaluation (65 s)
Two stages, because retrieval and generation fail differently. **Retrieval**, 82 queries: hit rate 82.9%, MRR 0.695, recall@5 48.4%. **Generation**, 35 queries with an LLM judge: faithfulness 0.71, **citation precision 98.3%** — when the answer cites source [3], source [3] really supports the claim — and citation coverage 88.6%. I report negative results too: cross-encoder **reranking hurt** domain retrieval and was removed; the over-refusal regex flagged 8/35 answers but **manual verification showed zero true refusals**. Metrics need human validation — that is itself a finding.

## Slide 17 — Agentic CVE workflow (70 s)
The knowledge base must not go stale, so an agent maintains it. Daily pipeline: **fetch** new CVEs from NVD and CISA-KEV since the last cursor; **dedup** against the ledger; **boost** by environment evidence — does the CVE touch software we run, does it match our alert history; then **one bounded LLM call** scores relevance 0–10. Three bands: **≥7 auto-indexes** into RAG; **4–6 quarantines** for human review, held *out* of RAG; **<4 drops** with the reasoning logged. Philosophy: *agentic does not mean unbounded* — fixed control flow, a single LLM decision, every outcome auditable. If the LLM is down, CVEs route to review — fail-safe, never silent.

## Slide 18 — Full architecture (60 s)
Everything together, four layers: data sources on top, the AI core, storage, interfaces. Watch where the arrows meet: ML verdicts flow into RAG context; agent decisions flow into the knowledge base; user documents join the same index; and every automated action lands in the audit ledger. Detection, explanation and knowledge maintenance **reinforce each other** — that closed loop is the thesis contribution, not any single component.

## Slide 19 — Results (45 s)
At a glance: recall 95.9, F1 89.2, FP 8%, 75-point separation, RAG hit rate 82.9, citation precision 98.3, 12-millisecond scoring, 14 of 14 attack families. Every number is **reproducible** — the evaluation harness, datasets and charts ship with the code. Limitations stated openly: PAM single logins at 45%, faithfulness judged by a same-family LLM, FP headroom remains.

## Slide 20 — Future work & close (45 s)
Next: **temporal window features** for the last hard case; **learned ensemble weights** via validation-split search; an **independent judge model**; **query expansion** for weak retrieval categories; and the already-designed **cloud deployment** with an authenticated API gateway. To conclude: a SIEM that **detects without labels, explains with citations, and updates its own knowledge** — local, auditable, reproducible end-to-end. Thank you — I welcome your questions.

---

## Appended slides 21–25 (from the thesis PDF — reorder into the deck as noted)

### Slide 21 — Training data: two sources (75 s) · *goes after slide 5*
Training data comes from two complementary sources. **Source one**: a daily collector run by cron reads the live alerts file, filters by date, deduplicates with a fingerprint of timestamp + rule + agent + message, and merges daily snapshots — this teaches the model what THIS deployment's normal looks like. **Source two**: a WordPress security plugin on a live website under real attack for two weeks — brute force, SQL injection, XSS, scanning — giving genuine malicious patterns the local host rarely produces. Combined: **2,171 alerts** (1,534 benign, 637 attack) for training, plus a held-out test set of **182**. The union is the point: local data defines normal, external data supplies real attacks.

### Slide 22 — Why these two algorithms (60 s) · *goes after slide 8*
Why Isolation Forest and the autoencoder specifically? I evaluated the leading unsupervised methods against four SIEM constraints: linear-time scoring, a persistable model that scores new points without retraining, no distribution assumptions, and a native anomaly score. **One-Class SVM** fails on scalability — cubic training. **Local Outlier Factor** has no persistable model. **Gaussian Mixture** assumes Gaussian data, which security data isn't. **DBSCAN** produces no score at all. Only IF and the autoencoder satisfy every constraint — and they fail in *opposite* ways, which is what makes them a genuine ensemble rather than two copies of one idea.

### Slide 23 — Feature ablation (65 s) · *goes after slide 6*
To prove the feature set is earned, not guessed, I ran an ablation — removing or adding one feature at a time and fully retraining, which takes under five seconds. Three features carry most of the power: **privileged_account_change** (−6.3 F1 when removed — new-user and promiscuous-mode attacks drop to zero detection without it), **failed_count** (−5.7, the credential-attack signal), and **rule_level** (−4.1, a severity prior). The instructive negative result: adding a semantically obvious feature — **MITRE technique count** — made things *worse*, +8.9% false positives, because Wazuh tags benign SSH logins with MITRE IDs, so the feature's distribution differs between training and production. Plausible is not the same as useful.

### Slide 24 — Attack testing & map population (70 s) · *goes after slide 11* — **the requested slide**
This is how the whole pipeline is validated. The attack-simulation framework — `simulate_attack_for_wazuh.sh` — executes 14 attack families as **real commands** on the host: trojanized-file signatures on `/bin/passwd`, kernel-rootkit hidden files in `/tmp`, PAM and SU authentication failures, listening-port changes, and MITRE-tagged events like T1548 sudo caching, T1078 valid accounts, T1110 password guessing, T1014 rootkit. Real Wazuh detects them and the ensemble scores the *authentic* alerts — no synthetic feature vectors. Separately, `populate_map.py` injects alerts carrying real public source IPs, which the dashboard geolocates and plots on a dark Leaflet world map so an analyst sees where attacks originate. Two validation paths, both converging on the dashboard.

### Slide 25 — RAG design choices (60 s) · *goes after slide 12*
Four design choices worth defending. **RAG over fine-tuning**: knowledge updates in seconds not days, answers are traceable and cited, documents stay local — decisive for confidential security data. **Embedding model** all-MiniLM-L6-v2, 384-dim, ~8 ms on CPU — 5× faster than mpnet while keeping 90%+ of the quality; SOTA models are impractical on CPU. **Chunk size** 512 tokens with 25% overlap won a systematic sweep on Recall@5 — 128 fragments a concept, 1024 dilutes the embedding. **RRF instead of a cross-encoder**: the ms-marco reranker actually hurt domain retrieval because it doesn't know rule 5710 relates to SSH; RRF makes no learned judgment, it just trusts rank position. And k=5 maximizes hit rate within llama's 8K context before "lost in the middle" sets in.

---

## Live demo walkthrough — the EXISTING production frontend (`frontend/`)
*If you demo the real app after the slides, follow this order. Everything below is what the shipped `frontend/` actually does today (not the improved_UI concept).*

**1. Dashboard hub (`index.html`).** Landing page shows the live hero stats — Total Alerts, CRITICAL/HIGH, POSSIBLE, Normal, Avg Score — plus five module cards: Alert Dashboard, RAG Threat Intel Chat, Inline Alert Analysis, Benign Exceptions, Suspicious Groups. "This is the operator's home; every number is pulled live from `/api/alerts/scored`."

**2. Alert Dashboard (`alerts.html`).** The heart of the demo. Point out, in order:
- The **report strip** at the top: 67 total (1 agent), 33 CRITICAL/HIGH (49%), 15 POSSIBLE (22%), 4 Normal (6%), 15 Benign (22%), Avg Score 55 (17 unique rules).
- **Four charts**: Alert Timeline (last 24 h, click a bar to filter that hour), Anomaly Distribution donut (click to filter), Top 10 Rules by Frequency (click a bar to filter), Alert Level Distribution.
- The **filter toolbar**: free-text search over rule/description/log content; Period (all · 1h · 6h · 24h · 7d · custom); Anomaly (all · critical · high · possible · normal · benign); Min level; Agent selector (scroll between machines); Sort by score / time / level; and Clear.
- **Benign Exceptions** and **Suspicious Groups** managers — "these let an analyst tune scoring live, with no retraining: a benign rule is zero-scored, a suspicious group is boosted."
- The **attack-origin map** (Leaflet, geolocated source IPs) — tie this back to slide 24's `populate_map.py`.
- **Inline analysis**: click an alert → the side chat panel opens pre-loaded with that alert's context (`openChatWith`), and the LLM explains it with the ensemble verdict already in the prompt.

**3. RAG Threat Intel Chat (`chat.html`).** Header reads "SIEM AI Threat Intel Chat — Ask questions about MITRE ATT&CK techniques, YARA rules, and security advisories." Use the four canned prompts: *What attacks were detected on my system? · Show me SSH brute force attempts · Explain T1055 process injection · What rootkit alerts were triggered?* Then show:
- **Source attribution**: each answer renders **source-tag chips** (color-coded by type — MITRE / YARA / vendor / Wazuh alert) with the chunk summary on hover.
- **Document upload**: the Upload modal takes `.txt/.md/.json`, chunks + embeds into Qdrant and Postgres; the **"My Documents"** panel lists uploaded docs with chunk counts and a delete action.

**4. CVE Agent (`cve-agent.html`).** KPI bar — 46 indexed into RAG, 29 awaiting review, 285 dropped (audited), last run 2h ago. The **Run Agent** button (with the "All sources / NVD / CISA-KEV" selector) triggers a run; the **Run Console** streams the fetch→dedup→boost→score→act log (it sits *idle* until you press Run or the 02:00 schedule fires). The **review queue** is the human-in-the-loop surface for the 4–6 band.

**5. Vector DB Dashboard (`vectordb.html`).** KPIs — 7,251 total documents, 7,252 embeddings, 2 collections, 5 data sources, Qdrant 1.17.0 — plus **Open Qdrant UI** and Refresh buttons. Collection Monitor cards (`wazuh_threat_intel` 7,251 docs / `wazuh_alert_episodes` 0), the Document-Sources breakdown (Sigma 3,005 · CISA KEV 1,566 · MITRE ATT&CK 823 · CIS 361 · D3FEND 6), and System Health (Optimal, 16 segments, 384-dim MiniLM, 5 active sources, 0 user uploads).

*Note for the "can I see the document it quoted?" question: in the current shipped frontend the chat shows source chips with a hover-tooltip preview and a separate "My Documents" manager, but there is not yet a click-through from a specific citation to the exact quoted chunk. That click-to-view source viewer is built into the improved_UI concept and is a natural next step for the production frontend.*

---

## Likely Q&A (prepare these)

- **"Why not deep learning end-to-end?"** → 2,171 samples; deep models overfit tiny data. The 16 engineered features + shallow models are the right capacity, and explainability is a SOC requirement.
- **"Why llama3.2 (small model)?"** → RAG shifts the burden from *knowing* to *reading*: grounding text does the knowledge work; 98.3% citation precision proves the small model follows evidence. Local + free + private beats bigger + cloud.
- **"Isn't contamination=0.3 too high?"** → It's an upper bound, not a target; the eval corpus is ~30% attacks by construction. Sensitivity analysis is straightforward future work.
- **"How do you know the training attacks are realistic?"** → 14 families executed as real commands on a real system through the real Wazuh pipeline — not synthetic feature vectors.
- **"What if the LLM hallucinates anyway?"** → Layered guards: retrieval gating, refusal instruction, citations verified in eval (98.3%), and the analyst always sees raw sources next to the answer.
- **"Why both Qdrant and Postgres?"** → Similarity vs truth. Vectors are disposable/re-indexable; the relational ledger is permanent and auditable. Different query patterns, different guarantees.
