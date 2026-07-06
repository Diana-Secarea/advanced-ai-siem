● Done. The full review is at A_presentation/CODE_REVIEW.md — every finding verified against actual source with file:line
  references, nothing generic. What's in it:

  What I reviewed

  All of ai_threat_engine_starter/ (ai_engine, autoencoders_approach, both trainers, attack_labels, collectors, monitor, rag_core's
  7 subpackages, scheduled_agent's 11 modules, docker-compose, shell scripts) plus backend/server.py and both frontends where the
  engine is actually exercised. A coverage table states honestly what was read in full vs skimmed.

  Headline findings

  3 Critical (security):
  - C1 — no auth + root Flask + GET /api/test-shield is CSRF-triggerable: any webpage you visit can launch the attack sim as root
  via an <img> tag
  - C2 — two real XSS paths: renderMarkdown() injects unescaped LLM output into innerHTML (and the LLM quotes attacker-controlled
  log lines), plus stored XSS via upload tags
  - C3 — attacker IPs go to ip-api.com over plain HTTP + CDN tiles — contradicts the "fully local" slide claim

  11 High (correctness/ML validity), including several nobody had caught before:
  - RAGCoreSystem.index_episodes() doesn't exist but is called from 2 modules; self.llm_copilot is used but never constructed
  - The pattern analyzer regexes threat-intel text (which by definition contains "malware/exploit/rootkit") → analyze_event
  escalates nearly everything to CRITICAL by construction
  - Label leakage: attack_labels.py uses level >= 8 as ground truth while rule_level is feature 8 — your eval numbers are an upper
  bound and must be disclosed
  - Chat truncates retrieved chunks to 500 of 1500 chars — your tuned retrieval is decapitated at prompt time
  - Log rotation silently kills both alert tailers at midnight (byte-offset seek past EOF)
  - The CVE scorer's parse fallback can grab "9" from "CVSS 9.8" → auto-index garbage into RAG

  19 Medium (dead feature 10 — suspicious_groups.json is {} so the deployed model trained with a constant-zero feature; races;
  unbounded session dict; contamination='auto' vs the "0.3" narrative; HIGH tier ignores the 0.45/0.55 fusion...), 12 Low, and —
  equally important — a "what's genuinely excellent" section (the three-store design, the CVE agent's conservative failure routing,
  the MITRE-exclusion insight, keep-alive pin discovery).

  Plus: module grades table, ML-methodology and RAG assessments, an 11-item prioritized fix plan (fix #1 is a one-line change with
  the biggest payoff), and a defense-day disclosure cheat-sheet with exact answers for the questions this review would provoke.

  The highest-leverage move before your defense: fixes #1–#4 are ~70 lines total and close the truncation, XSS, auth, and rotation
  holes. Want me to apply them?

# AI Threat Engine — Full Code Review

**Scope:** the entire `ai_threat_engine_starter/` tree, plus its two serving surfaces (`backend/`, `frontend/`) where the engine's code is actually exercised.
**Date:** 2026-07-06 · **Reviewer:** Claude Code (Opus 4.8) · **Method:** full read of every core module; every finding below was verified against the actual source (file:line), not assumed. Items I only skimmed are listed in the Coverage table and are *not* the basis of any finding.

---

## Verdict

**This is a genuinely working, well-architected prototype with production-grade *ideas* and prototype-grade *hardening.*** The ML training discipline (unsupervised, labels quarantined to evaluation), the three-store knowledge design (JSON master → Postgres ledger → Qdrant vectors), the audit-everything CVE agent, and the anti-hallucination gating are the strongest parts — several are better than what I see in real commercial tooling. The weaknesses cluster in four places: (1) a handful of **dead/broken API paths** that crash if exercised, (2) **the `ai_engine.analyze_event` reasoning path has a systemic false-positive flaw** (pattern-matching threat-intel text), (3) **evaluation ground truth partially overlaps model features** (label leakage — must be disclosed, not hidden), and (4) the serving layer has **no authentication and two XSS surfaces** — acceptable for a localhost demo, not for the "production-grade design" claim without the planned API gateway.

**Grade by module:**

| Module | Grade | One-line summary |
|---|---|---|
| `attack_labels.py` | A− | Single source of truth, thoughtful overrides; but `level>=8` rule creates leakage |
| `ai_engine/anomaly_detector.py` | B+ | Excellent feature engineering; silent-failure catches, doc drift |
| `autoencoders_approach/` (train+detect+ensemble) | A− | Iterative trimming is the thesis's best idea, cleanly executed; duplicated extractor |
| `train_isolation_forest.py` | B+ | Honest unsupervised training; adaptive threshold; misleading `contamination` comment |
| `compare_models.py` + eval scripts | B+ | Real three-way evaluation, consistent with ensemble semantics |
| `ai_engine/main.py` + `pattern_analyzer.py` | C | Orchestrator calls nonexistent methods; pattern layer is structurally FP-prone |
| `rag_core/database/` (qdrant_store, postgres_client, config) | A− | The best-engineered package in the repo |
| `rag_core/indexing/` + `ingestion/` | B | Solid fan-out design; bare excepts, no retry/backoff, unpaginated fetches |
| `rag_core/episodes/` + `agent/` + `integration/` | C+ | Prototype-quality heuristics, dead parameters, bottom-of-file imports, broken integration calls |
| `rag_core/evaluation/` | B+ | Broad, honest metric suite (citations, refusals, per-category) |
| `scheduled_agent/` | A− | The most production-shaped code in the repo; minor ledger/pagination issues |
| `monitor_alerts.py` + collectors | B− | Works, but log rotation and dedup gaps corrupt long-running use |
| `backend/server.py` | B | Feature-rich and consistent; no auth, races, unbounded state, per-poll rescoring |
| `frontend/` (chat.html, alerts.html) | B− | Clever SSE-over-fetch; XSS surfaces; external CDN/geo-IP contradicts "fully local" |
| `wazuh_module/` (C) | n/a | Standalone artifact, not wired into any build — label it as future work |

---

## Coverage

| Level | Files |
|---|---|
| **Read in full** | ai_engine/* (4), autoencoders_approach/* (train, detector, ensemble; compare_models §1), train_isolation_forest.py, attack_labels.py, collect_training_data.py, monitor_alerts.py, rag_core_system.py, qdrant_store.py, config.py, postgres_client.py (core), agent_workflow.py, ingest_all.py, sources/cisa_kev.py, qdrant_indexer.py, threat_intel_indexer.py (loaders), episode_builder.py (Process + Alert builders), wazuh_integration.py, scheduled_agent/{agent,scorer,dedup,store,boosts,fetchers,config}.py, backend/server.py (~80%), frontend/chat.html (JS core), frontend/alerts.html (JS core), docker-compose.yml, start_server.sh |
| **Outline/skim only** | rag_core/evaluation/* bodies, threat_intel_ingestion.py bodies, sources/{sigma,d3fend,groups,cis,otx}.py, postgres_setup/viewer.py bodies, compare_models plotting section, evaluate_*.py bodies, episode_builder Auth/Network builders, shell scripts, generate_normal_logs.py, wm_ai_threat_engine.c |

---

# 1 · CRITICAL findings (security)

### C1 — Zero authentication on a root-privileged server; attack-simulation endpoint is CSRF-triggerable
`backend/server.py` exposes 30 endpoints with **no auth of any kind**, and `start_server.sh:54` runs the whole Flask process **as root** (`exec sudo …`). Worst combination: **`GET /api/test-shield`** (server.py:1478) executes `simulate_attack_for_wazuh.sh` — real attack commands — as root. Because it's a **GET with no token**, any web page the operator visits can fire it: `<img src="http://172.23.208.247:5000/api/test-shield">`. CORS does not prevent the request from *executing* — it only blocks reading the response. `ALLOWED_ORIGINS` includes a LAN IP, so this is reachable beyond localhost. Same class: `POST /api/populate-map` (form-CSRF-able, writes to the live Wazuh alert file as root), `/api/cve-agent/run` (spawns a root subprocess with the full root environment, server.py:1636), `DELETE /api/chat/sessions` (no session ownership — clears everyone).
**Fix:** one shared bearer token checked in a `before_request` hook (the planned API-gateway design already specifies this); make test-shield POST-only; drop root by granting the service user read access to `/var/ossec/logs/alerts` via group membership instead of sudo.
**Defense framing:** disclose as "single-user localhost demo; the API gateway design in thesis §X addresses this" — do *not* claim the current server is production-ready.

### C2 — Two XSS paths in the chat UI (LLM output and stored document tags)
- `frontend/chat.html:739-763` `renderMarkdown()` assigns regex-transformed text to `bubble.innerHTML`; **only fenced code blocks pass through `escapeHtml`** — all other model output is injected raw. The model's context includes *user-uploaded documents* and *raw Wazuh logs* (attacker-controlled `full_log`!), so `<img src=x onerror=…>` in a log line that the model quotes verbatim executes in the operator's browser. That is a real SIEM attack pattern (alert-injection → analyst-console XSS).
- `frontend/chat.html:904` `srcModalTags.innerHTML = d.tags.map(t => \`<span…>${t}</span>\`)` — tags originate from uploaded documents (`/api/knowledge/upload` accepts arbitrary `tags` form field, server.py:1210) → **stored XSS** on chip click. 36 `innerHTML` sites total across the two pages; most render server-controlled data, these two render attacker-influenceable data.
**Fix:** escape all text before markdown transforms (run `escapeHtml` first, then apply markdown regexes on the escaped text) and use `textContent` for tags.

### C3 — "Security data never leaves the machine" is contradicted by the map
`frontend/alerts.html:1994` POSTs **attacker source IPs** to `http://ip-api.com/batch` — third party, **plain HTTP** — and loads Leaflet + map tiles from unpkg/CARTO CDNs (alerts.html:8-9). The detection/RAG/LLM pipeline is genuinely local; the *dashboard* is not. This directly contradicts slide 4's headline claim if stated absolutely.
**Fix (or disclose):** GeoLite2 local DB + self-hosted tiles; or scope the thesis claim to "the analysis pipeline" and footnote the map. Do this before the defense — it is the single easiest hole for an examiner to poke.

---

# 2 · HIGH findings (correctness & ML validity)

### H1 — `RAGCoreSystem.index_episodes()` does not exist, but is called from two modules
`ai_engine/main.py:291` and `rag_core/integration/wazuh_integration.py:102,128` call `self.rag_system.index_episodes(...)` — **no such method** on `RAGCoreSystem` (verified: only `ingest_threat_intelligence`, `build_episodes_from_events`, `search_threats`, …). `wazuh_integration.py:106` also reads `self.system.episodes`, an attribute that was removed when episodes moved to direct-Qdrant indexing. Any caller exercising these paths gets `AttributeError`. These are fossils of the pre-Qdrant in-memory design.
**Fix:** delete the delegators or alias them (`index_episodes = lambda **kw: None` is worse than deletion — remove and fix callers).

### H2 — `self.llm_copilot` is used but never created
`ai_engine/main.py:169` calls `self.llm_copilot.analyze_threat(...)` guarded by `self.llm_enabled` — but `__init__` sets `llm_enabled = False` and **never constructs `LLMCopilot`**. The moment anyone flips the flag (the obvious "enable the LLM" step), the pipeline crashes. Latent booby trap.
**Fix:** construct it lazily in a property, or wire `LLMCopilot()` in `__init__` with its own availability check.

### H3 — `analyze_wazuh_alert()` dereferences a None agent
`rag_core/rag_core_system.py:326` calls `self.agent.process(alert)` without the `initialize_agent()` guard that its sibling `analyze()` (line 302) has. `self.agent` is `None` until explicitly initialized → `AttributeError` on the documented "main entry point for Wazuh integration".

### H4 — The pattern layer is structurally biased to fire: it regex-matches *threat-intel text*, not the event
`ai_engine/pattern_analyzer.py:87` `analyze_rag_text()` runs attack regexes (`malware|trojan|backdoor|rootkit` → risk 95; `sudo|privilege` → risk 80; …) over the **retrieved threat-intelligence descriptions**. Threat intel *by definition* describes attacks — MITRE technique summaries and YARA rule text almost always contain these words. Consequence chain in `main.analyze_event`: retrieval returns any typical intel → pattern matches at risk ≥80 → `suspicious=True` → line 184-188 sets `is_anomaly=True` **regardless of the ML score**, and line 177 lifts `final_score` to the pattern's 95. Any event whose description retrieves *anything* plausible is escalated to CRITICAL by construction.
**Mitigating fact:** the live demo path (backend `ensemble.score()`) bypasses this entirely — only `analyze_event`/`monitor_alerts.py` are affected. But `monitor_alerts.py` *does* run it.
**Fix:** match patterns against the **event's own `full_log`** and use RAG text only for the severity *boost*; or require the pattern keyword to appear in both the event and the intel.

### H5 — Two-thirds of every retrieved chunk is thrown away at prompt time
Uploads are chunked at **1500 chars** (`server.py:1170`), and Qdrant returns full summaries — but both chat endpoints truncate each retrieved summary to **500 chars** when building the LLM context (`server.py:797` and `:898`). The retrieval pipeline you ablated and tuned (512-token chunks beat alternatives — thesis §3.3) is then decapitated at the last step; the model reasons over ≤⅓ of the evidence it cites. This silently caps answer quality and citation-groundedness.
**Fix:** raise to ~1500 chars (matches chunk size), or drop truncation and cap by total context budget instead. One-line change, likely the highest quality-per-effort fix in the repo.

### H6 — Multi-tag retrieval filter is AND, so engine-side filtered searches often return nothing
`qdrant_store._build_filter` (qdrant_store.py:209-212) adds one `must` condition **per tag** — documents must carry *all* tags. `ai_engine/main.py:_extract_tags_from_event` happily emits several (`authentication` + `process` + `network` for one SSH log line) → the filtered prefetch demands intel tagged with all three → near-guaranteed empty result → pattern analyzer gets nothing (or, worse, only the weird items that match all tags). The chat path is unaffected (passes no tags).
**Fix:** use one `should`/`MatchAny` condition (OR semantics) for tags; keep `must` for `source_type`.

### H7 — Log rotation silently kills both alert tailers
Both tailers persist a **byte offset** and seek to it: `server.py:137` (`_wazuh_watch_pos`) and `monitor_alerts.py:58` (`/tmp/wazuh_ai_last_position.txt`). Wazuh **rotates `alerts.json` daily** — the new file starts at size 0, the stored offset points past EOF, `f.seek(pos); f.read()` returns `""` forever. Result: the dashboard/monitor silently stops seeing new alerts at midnight until restart. Additionally `monitor_alerts.py`'s position file lives in **/tmp** (lost on reboot → full-file reprocess → duplicate enhanced alerts appended; world-writable → position poisoning).
**Fix:** track `(inode, offset)` or reset the offset when `st_size < saved_pos`; move the position file next to the output file.

### H8 — Evaluation ground truth partially overlaps model features (label leakage)
`attack_labels.py:96`: **`level >= 8 → attack`** is part of the ground-truth labeler. But `rule.level` is **feature 8**, `rule.id` feature 9 (`ATTACK_RULE_IDS` also keys the labels), and rule groups feed both feature 10 and `ATTACK_GROUPS`. So the labels used to score P/R/F1 are partly a *deterministic function of the model's inputs* — the models are partially being graded on recovering the labeling rule, which inflates measured performance relative to true unknown-attack detection. The behavioral features (12–15) are the honest mitigation, and the docstring's MITRE-exclusion reasoning shows real care — but the numbers on slide 8 are an **upper bound**, and a sharp examiner will find `level >= 8` in this file in thirty seconds.
**Fix/disclosure (pick one before the defense):** (a) report an ablation scored on a *hand-labeled* subset, (b) report metrics with features 8-10 removed, or (c) state plainly in the thesis: "labels derive from rule metadata; features 12–15 are rule-agnostic precisely to break this coupling, and the 14 simulated attack families provide labels independent of level."

### H9 — Training corpus contains duplicates by design of the collector
`collect_training_data.py:81`: if no alert matches today's date, it **falls back to collecting ALL alerts** into today's daily file. Combined with `merge_all_daily_files()` (line 120-138), which concatenates daily files **without any cross-day dedup** (the fingerprint dedup at line 99 is per-day only), the same alert can appear in `all_alerts.json` multiple times. Duplicates skew IF density estimation and the AE's trimming percentiles — your 2,171-alert corpus may effectively be smaller and biased toward whatever got double-collected.
**Fix:** apply the existing `fingerprint()` across the merge; delete the all-alerts fallback (fail loudly instead).

### H10 — LLM score parser's fallback is not conservative: a stray digit can auto-index
`scheduled_agent/scorer.py:49-51`: when the model's reply isn't parseable JSON, the fallback regex `\b(10|[0-9])\b` takes the **first standalone digit anywhere in the text** as the relevance score. A reply like *"This has CVSS 9.8 and affects Windows only"* → score **9 → auto-indexed into RAG**, the exact opposite of the intended routing. The docstring promises "conservative mid score" on failure, but only the *network-failure* path returns 5 — the *parse-failure* path can return anything 0–10.
**Fix:** on JSON-parse failure return `(5, "unparseable reply → review queue")`, same as the network path. Three lines, closes a RAG-pollution hole in the agent's one safety-critical decision.

### H11 — NVD fetcher neither paginates nor respects the 120-day window limit
`scheduled_agent/fetchers.py:30-50` requests `resultsPerPage=200` but never walks `startIndex` — a window containing >200 CVEs is silently truncated. And the cursor is "last successful run" (`store.last_cursor`): if the agent doesn't run for >120 days, NVD rejects the window (API constraint noted in your own docstring) and every subsequent run fails-empty until manually reset.
**Fix:** loop on `startIndex` until `totalResults` reached; clamp `since = max(since, now-119d)`.

---

# 3 · MEDIUM findings

**M1 — Feature 10 is dead in the deployed model.** `backend/suspicious_groups.json` contains `{}` (verified, 2 bytes, root-owned). Both detectors load it into `SUSPICIOUS_GROUPS` → `suspicious_group_count` is **constant 0 in training and serving**. One of your 16 features contributes nothing; the ablation chart on slide 6 should be checked against this. Also root ownership means you can't edit it without sudo. *(Populate it from `suggested_suspicious_groups.json`, chown it, retrain.)*

**M2 — Unlocked tail-position race.** `server.py:126-154` `_check_new_alerts()` reads and writes `_wazuh_watch_pos` without holding `_wazuh_alerts_lock`; two concurrent requests (Flask is threaded) can both read the same window → duplicate alerts appended to `_wazuh_alerts`.

**M3 — Unbounded chat-session store.** `_chat_sessions` (server.py:49) trims each session to 20 turns but **never evicts sessions** — every new `session_id` (client-supplied, unauthenticated) grows the dict forever.

**M4 — Full ensemble re-scored on every dashboard poll.** `/api/alerts/scored` runs IF+AE inference on up to 500 alerts per request (server.py:677-706) and the frontend polls it on an interval. Scores for an immutable alert never change — cache by alert fingerprint.

**M5 — `/stream` loads the whole `alerts.log` into memory** (`content = f.read()`, server.py:603) before sending 50 backlog items. The file grows unboundedly; read the tail instead.

**M6 — 120-line feature extractor duplicated** between `anomaly_detector.py:200` and `autoencoder_detector.py:154` with a "must stay in sync" comment as the only enforcement. One drifted constant silently breaks ensemble comparability. Extract to a shared `features.py` (both classes already share constants that also drifted into duplication).

**M7 — `contamination='auto'` narrative mismatch.** The code comment (train_isolation_forest.py:86,109) claims auto "makes no assumption about attack ratio"; in sklearn, `'auto'` is the *fixed offset from the original paper*, not a data-driven estimate. Harmless in practice (you use `decision_function` + your own calibrated threshold, never `predict`), but the thesis/memory text says "contamination=0.3" while the code says `'auto'` — **align the narrative before the defense**, this is an easy examiner catch.

**M8 — Three competing anomaly thresholds.** `analyze_event(threshold=70)` default; detector's calibrated `anomaly_threshold` (gap heuristic, floor 40); `wazuh_integration` config default 70. Same word, three values, different code paths.

**M9 — Batch-offset ID collision.** `qdrant_store.index_episodes` (qdrant_store.py:256) falls back to `uuid5(str(i))` where `i` is the *batch* offset — all episodes lacking `episode_id` within one batch collapse onto one point (last-write-wins). All current loaders set IDs, so latent only.

**M10 — Ledger column lies.** `scheduled_agent/store.py:166` returns `episode_id` as `qdrant_id`; the actual Qdrant point id is `uuid5(episode_id)`. Everything still resolves (the `/api/source` endpoint recomputes uuid5), but the audit column doesn't contain what its name says. Also `close_run` (store.py:89) writes `records_upserted = counts["indexed"]` duplicating `cves_indexed`.

**M11 — Ensemble tier semantics shift silently.** HIGH tier sets `combined = ae_score` alone (ensemble_detector.py:64) — the 0.45/0.55 fusion advertised on slide 5 applies only to CRITICAL/NORMAL/POSSIBLE. And in AE-missing fallback, *any* IF anomaly is labeled CRITICAL (line 57) — "both models agreed" is no longer what CRITICAL means. Document both or unify.

**M12 — Silent zero-scores on failure.** Both detectors' `detect_anomaly` catch **all** exceptions and return score 0 / not-anomaly (anomaly_detector.py:391, autoencoder_detector.py:328). A feature-schema mismatch after a refactor would silently mark every alert NORMAL — the worst possible failure mode for a security tool. Log loudly and/or export a health metric (you already have `monitor_model_health.py` — wire it).

**M13 — Episode-builder heuristics are noisy.** `'process' in message` → `process_injection` indicator; absent `signed` field → `unsigned_process` (episode_builder.py:209-212); keyword hits mint ATT&CK tags (T1055/T1068). These become *indexed intel* in Qdrant that RAG later cites. Fine for prototype; label the tags `heuristic:` so the copilot can't present them as authoritative.

**M14 — TLS verification disabled + default credentials** in the OpenSearch stub (`boosts.py:153-157`, `verify=False`, `admin`/empty-password fallback). It's a stub, but stubs get enabled; at minimum read `verify` from config.

**M15 — Ingestion has no retry/backoff and swallows errors.** `threat_intel_ingestion.py` (outline verified: 10+ bare/broad excepts, unauthenticated GitHub API → 60 req/h rate limit) degrades to silent partial corpora. The `ingestion_log` table exists — record per-source failure there too.

**M16 — `sys.path.insert` in ~10 files** instead of a package install (`pip install -e .`). Imports depend on CWD; the same module can be imported under two names (`rag_core.x` vs `x`), which is exactly how the circular-import in `agent_workflow.py:14-22` arose.

**M17 — Unpinned `qdrant/qdrant:latest`** in docker-compose.yml — a silent Qdrant major bump can break the named-vector API. Pin the version you validated. (Postgres is correctly pinned at 17-alpine.)

**M18 — Agent crash leaves the ledger run open and the dedup set stale.** `process_source` (agent.py:47-117) has no `try/finally`: an exception mid-loop means `close_run` never fires — the `ingestion_log` row stays open forever and `last_cursor` (which requires `status='ok'`) stalls, so the next run refetches the same window (dedup absorbs it, but the ledger misrecords history). Also `known` is never updated **inside** the loop (`known.add(cve_id)` missing after each decision) — a CVE appearing twice within one fetch batch is scored and indexed twice. Cross-*source* duplication is already handled (each source reloads `known` from the DB after the previous source's writes).

**M19 — LLM-down floods the review queue.** Every scorer failure defaults to 5 → queued (scorer.py:73-77). Correctly conservative per-CVE, but if Ollama is down for a whole run, *every* fetched CVE lands in the human queue. Add a circuit breaker: ~3 consecutive LLM failures → abort the run with `status='llm_down'` instead of queueing hundreds of unscored items.

---

# 4 · LOW findings (style, docs, dead code)

- **L1** Docstrings/comments say **"13 features"** (anomaly_detector.py:101,201) — it's 16; the last feature's comment is misnumbered "# 16:" (it's index 15). The 13→16 evolution left doc-drift. Same header drift in `generate_sample_training_data`.
- **L2** Dead parameters: `filter_entities`/`time_window` accepted and documented-as-ignored (rag_core_system.py:141); `agent_workflow._retrieve` builds a `time_window` it never uses (agent_workflow.py:166-171).
- **L3** `datetime.utcnow()` (deprecated in 3.12) throughout; you run 3.13 — switch to `datetime.now(timezone.utc)`.
- **L4** Bottom-of-file imports: `import hashlib` at episode_builder.py:562, `from collections import defaultdict` at agent_workflow.py:533. They work (module-level execution) but read like missing imports and break under refactor.
- **L5** `LLMCopilot.test_connection` can block construction for up to ~35s when Ollama is down (5s probe + 30s completion attempt).
- **L6** `collect_training_data.py:33` lists `alerts.log` (non-JSON format) as a fallback source — if selected, every line silently fails JSON parse and yields zero alerts, indistinguishable from "no alerts."
- **L7** `agent_workflow._retrieve_attack_techniques` is keyword-scoring with a "would use embeddings in production" comment — while a real Qdrant retriever sits one attribute away (`self.retrieval`). Use it or delete the fallback.
- **L8** `qdrant_store.search` applies `score_threshold` *after* the top-k slice (qdrant_store.py:392) — threshold can only shrink results below k, likely intended pre-slice.
- **L9** `dedup.known_cve_ids` uses `ILIKE '%CVE-%'` full-table scan — fine at current scale; add a partial index if threat_intel exceeds ~10⁵ rows.
- **L10** `__pycache__/` directories present in repo tree (ai_threat_engine_starter, backend); add to `.gitignore` if not already ignored.
- **L11** `wazuh_module/wm_ai_threat_engine.c` is not referenced by any build file — it's an unintegrated artifact. Either wire it into the Wazuh build (real integration) or label it "proposed module (future work)" in the thesis so nobody asks you to demo it.
- **L12** `simulate_attack_for_wazuh.sh.bak` and `logs taken on 14 march.txt` are junk files in the tree — remove before sharing the repo publicly.

---

# 5 · ML methodology assessment (thesis-critical)

**What is genuinely strong and should be defended proudly:**
1. **Label quarantine.** Both trainers compute `is_attack_alert` splits *only* for evaluation printouts; training consumes all alerts unlabeled (train_isolation_forest.py:80-86; train_autoencoder.py:93-99). The "zero labels" claim is literally true in code.
2. **Iterative trimming** (train_autoencoder.py:123-148) — train on all → drop worst-reconstructed 25% → retrain → drop 15% → final fit. Cumulative keep ≈64%, well matched to ~30% contamination + margin. Correctly re-fits the scaler per round and calibrates on the final clean estimate. This is the methodological centerpiece and it's implemented exactly as slide 7 describes.
3. **Calibrated scoring.** Both models map raw outputs to 0–100 via 2nd/98th-percentile calibration persisted in the pickle — thresholds mean the same thing across retrains. The **adaptive gap-heuristic threshold** (histogram valley + 70th-pct fallback, identical in both trainers) is a defensible unsupervised threshold choice.
4. **Identical 16-feature contract** between IF and AE makes the comparison genuinely apples-to-apples, and the behavioral features (external-IP with CDN exclusion, URL patterns with the deliberate `wp-admin` exclusion, unknown-user, privileged-change) encode real deployment lessons.
5. **Model archiving before overwrite** (dated `.pkl` copies) — reversible retrains.

**What must be disclosed or fixed (ranked):**
1. **H8 label leakage** — the single most important methodological caveat; own it in the thesis before an examiner finds it.
2. **M1 dead feature 10** — the deployed model was trained with a constant-zero feature; either populate + retrain or state that 15 of 16 features are active in the evaluated configuration.
3. **H9 duplicate training rows** — quantify (run the fingerprint over `all_alerts.json`) and state the corpus's effective unique size.
4. **M7 contamination narrative** — say `'auto'` + own calibrated threshold, not "0.3".
5. **M11 tier semantics** — slide 5's "0.45·IF + 0.55·AE" applies to CRITICAL; HIGH is AE-only by design. One sentence fixes it.

---

# 6 · RAG assessment

**Strong:** hybrid dense+BM25 with a clean, importable `rrf_fusion` (correct 1-based ranks, k=60); the **RRF score normalization to [0,1] with the documented 2/(k+1) ceiling** (qdrant_store.py:386-402) — this correctly fixes the earlier everything-LOW severity bug; deterministic `uuid5` point IDs that make citations *resolvable* (`/api/source` retrieves the exact point without a search — genuinely elegant); the **level ≥5 threat-intel gate** with an explicit "do not map to techniques" instruction — a design-level anti-hallucination control that your generation eval (0 fabricated-intel answers) validates; payload indexes on the filter fields; batch upserts.

**Weak:** H5 (context truncation undoes the tuned chunking), H6 (AND-tag filter starves engine-side retrieval), M13 (heuristic episode tags enter the corpus as if authoritative), and the `PREFETCH_LIMIT=40` ceiling silently caps `top_k>40` requests (`agent_workflow` asks for 20 — fine, but document it). The dual RAG brains (server.py's retrieve-then-read chat vs `SOCAgent`'s 5-step workflow) overlap ~60% in purpose; the thesis should be explicit that the *evaluated* copilot is the server path, and the SOCAgent is the structured-workflow prototype.

---

# 7 · What is genuinely excellent (keep, and say so in the defense)

1. **Three-store knowledge architecture** — JSON master (cache/rebuild seed) → Postgres (ACID ledger, full `raw_data` JSONB survives reindex) → Qdrant (searchable projection). Disposable derived stores, durable source of truth. Textbook.
2. **The CVE agent** — bounded single-LLM-step pipeline, cursor-from-ledger, dedup set loaded once, conservative failure routing (LLM down → score 5 → review queue, *never* silent drop — scorer.py:73-77), every decision upserted with `ON CONFLICT`, review queue held OUT of RAG. This is the most production-shaped subsystem and the one to walk examiners through line by line.
3. **`attack_labels.py`'s MITRE note** (lines 65-71) — understanding that Wazuh's MITRE tags mark *potential* technique, not attack fact, and excluding them from labels, is a subtle and correct call most practitioners miss.
4. **Ollama keep-alive pin** — diagnosing that `/v1` resets `keep_alive` and re-pinning via the native API after every call (server.py:405-425) is a real discovered-and-solved production issue.
5. **Graceful degradation discipline** — ensemble optional, AE optional (IF-only mode), RAG optional, boosts optional, Postgres write non-fatal on upload. Almost every integration point degrades instead of crashing.
6. **Docker hygiene** — 127.0.0.1-bound ports, healthchecks, named volumes, schema auto-init, pinned Postgres.
7. **Frontend cache discipline** — stale-while-revalidate with `server_start`-keyed invalidation; SSE-over-fetch with correct partial-event buffering (`buf = events.pop()`).
8. **Benign-override consistency** — the same user-benign rule cap applied identically in the dashboard, the Scoring Lab, and both detectors, so every surface agrees.

---

# 8 · Prioritized fix plan

| # | Fix | Effort | Payoff |
|---|---|---|---|
| 1 | Remove `[:500]` context truncation (H5) | 1 line | Immediate RAG answer quality |
| 2 | Escape HTML before markdown; `textContent` for tags (C2) | ~20 lines | Closes both XSS paths |
| 3 | Bearer-token `before_request` + POST-only test-shield (C1) | ~30 lines | Closes CSRF/no-auth hole |
| 4 | Handle log rotation via inode/size check, both tailers (H7) | ~15 lines | Survives past midnight |
| 5 | Delete/repair dead API: `index_episodes`, `.episodes`, `llm_copilot`, agent guard (H1-H3) | ~20 lines | No crash paths left |
| 6 | Tags filter OR-semantics (`MatchAny`) (H6) | 5 lines | Engine retrieval stops starving |
| 7 | Cross-day fingerprint dedup in merge + remove date fallback (H9); then retrain | ~15 lines | Clean corpus, honest numbers |
| 8 | Populate `suspicious_groups.json`, chown, retrain (M1) | config | Activates feature 10 |
| 9 | Shared `features.py` for both detectors (M6) | refactor | Kills the sync hazard |
| 10 | Pattern layer: match event text, intel only boosts (H4) | ~20 lines | Fixes analyze_event FP design |
| 11 | Scorer parse-failure → (5, review queue) (H10) | 3 lines | Closes RAG-pollution hole |
| — | Thesis text: disclose H8, M7, C3, M11 | writing | Examiner-proofing |

---

# 9 · Defense-day disclosure cheat-sheet

If asked… say:
- **"Is it production-ready?"** — "The detection engine and knowledge pipeline are; the serving layer is a single-user demo — the API gateway design (thesis §X) adds auth, rate limiting and CORS hardening, and this review documents the exact gaps."
- **"How do you know your labels are right?"** — "They're rule-metadata heuristics, and I document the coupling: level≥8 is both a label rule and a feature. The behavioral features 12–15 exist precisely to break that coupling, and the 14 live attack families give label-independent ground truth."
- **"Everything is local?"** — "The analysis pipeline — detection, retrieval, generation — is fully local. The dashboard's world map uses a public geo-IP API and CDN tiles; swapping to GeoLite2 is future work and changes nothing in the analysis path."
- **"What would you fix first?"** — hand them the table above. Having a ranked, honest defect list is *stronger* than pretending there are none.

*Generated by full-source review; every file:line reference verified 2026-07-06.*
