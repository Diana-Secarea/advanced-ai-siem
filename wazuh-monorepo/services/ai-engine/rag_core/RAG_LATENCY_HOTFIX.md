# RAG production latency failure — root-cause analysis & hotfix

**Branch:** `hotfix/rag-latency`
**Symptom in production:** `/api/chat` intermittently returns **504 Gateway
Timeout** (and, on the streaming path, very slow time-to-first-token) under
concurrent load. It works fine in local/dev and on the first message.

---

## 1. Where the time goes

The chat request path (`apps/backend/server.py`):

```
POST /api/chat
  └─ _chat_context → _build_rag_context()          # the agentic RAG pipeline
       ├─ Stage 1  gate_skip()        → _agentic_llm  (Ollama call #1)
       ├─ Stage 2  rewrite_queries()  → _agentic_llm  (Ollama call #2)
       │             └─ _multi_query_alerts / _multi_query_kb → Qdrant
       ├─ Stage 3  grade_chunks()     → _agentic_llm  (Ollama call #3)
       │             └─ corrective retry:
       │                  rewrite_queries()  → _agentic_llm  (Ollama call #4)
       │                  grade_chunks()     → _agentic_llm  (Ollama call #5)
  └─ _call_ollama(messages)                          # the ANSWER (Ollama call #6)
```

Every request to `/api/chat` therefore issues **up to five extra LLM
completions before the answer even starts**, all against the *same single
Ollama instance* that then also has to generate the answer.

### The trigger: timeouts that stack past the proxy limit

- Each agentic helper (`_agentic_llm`) was called with **`timeout=30` s**.
- The answer call uses `timeout=120` s.
- Nginx (`infra/deploy/nginx.conf.sample`) routes non-streaming `/api/chat`
  through the generic `location /` block, which sets **no `proxy_read_timeout`
  → nginx default 60 s**. (Only `/api/chat/stream` and friends get the explicit
  `proxy_read_timeout 300s`.)

In dev, Ollama is warm and idle, so each helper returns in a fraction of a
second and the whole thing finishes in a few seconds. **In production, under
concurrency**, requests queue on the one Ollama/GPU. Each of the 5 helper calls
can now take several seconds (or hit its 30 s ceiling), they run **sequentially**,
and the total blows past nginx's 60 s window long before the answer is produced:

```
gate(≤30) + rewrite(≤30) + grade(≤30) + corrective rewrite(≤30) + grade(≤30) + answer(≤120)
```

Nginx gives up at 60 s and returns **504** — even though the backend is still
working. This is why it "fails in production" but not in dev, and not on the
very first (uncontended) message.

### Contributing factors

1. **Re-pin storm.** `_call_ollama` fired `_pin_ollama_async()` after *every*
   call, including all 5 helper calls — each spawns a thread + an extra HTTP
   request to Ollama, adding load to the very instance that is the bottleneck.
2. **No wall-clock budget.** Nothing bounded the *total* time spent in the
   agentic stages; individual per-call timeouts don't bound their sum.
3. **Qdrant client had no timeout.** `QdrantClient(host, port)` uses a long
   default; a slow/overloaded Qdrant blocks the request thread instead of
   failing fast.
4. **Two Qdrant round-trips + client-side fusion per search.** `search()` ran a
   dense query and a sparse query sequentially, then fused in Python — double
   the round-trips of a native hybrid query.

---

## 2. The hotfix

All changes fail open — if a helper or the DB misbehaves, the pipeline degrades
to plain retrieval and the chat still answers.

### a. Short helper timeout (primary 504 fix)
`apps/backend/server.py`

- New env-tunable `AGENTIC_LLM_TIMEOUT` (default **8 s**, was 30 s).
- `_agentic_llm` now uses it and passes `pin=False`.

A helper that can't answer in a few seconds isn't worth waiting for when the
safe fallback is "just retrieve".

### b. Wall-clock budget for the whole agentic phase
`apps/backend/server.py` — `_build_rag_context()`

- New env-tunable `RAG_AGENTIC_BUDGET_S` (default **12 s**).
- A deadline is checked (`_budget_left()`) before Stage 1 (gate), Stage 2
  (rewrite), Stage 3 (grade), and the corrective retry. Once the budget is
  spent, remaining LLM stages are skipped and the request proceeds to generate
  the answer with what it already has. `rag_meta["budget_exceeded"]` records it.

This guarantees the answer starts well within the proxy window even when Ollama
is slow enough that the per-call timeouts don't individually trip.

### c. Stop the re-pin storm
`apps/backend/server.py` — `_call_ollama(..., pin=True)`

- New `pin` parameter; helper calls pass `pin=False`. The keep-alive is still
  re-pinned once, after the main generation.

### d. Fail-fast Qdrant client
`rag_core/database/config.py`, `rag_core/database/qdrant_store.py`

- New env-tunable `QDRANT_TIMEOUT` (default **5 s**) passed to `QdrantClient`.

### e. Single native hybrid query (server-side RRF)
`rag_core/database/qdrant_store.py` — `QdrantStore.search()`

- One `query_points` call with `prefetch=[dense, sparse]` +
  `FusionQuery(fusion=Fusion.RRF)` replaces the two sequential queries and the
  Python-side fusion. Qdrant's RRF uses the same `1/(k+rank)` formula, so the
  downstream `[0,1]` similarity normalization (`max_rrf = 2/(rrf_k+1)`) is
  unchanged. Falls back to the old two-query + `rrf_fusion()` path on any error.

---

## 3. Latency budget after the fix

Worst case for the pre-generation agentic phase is now bounded by
`RAG_AGENTIC_BUDGET_S` (12 s) rather than `5 × 30 s`, and each individual helper
by `AGENTIC_LLM_TIMEOUT` (8 s). Combined with the fail-fast Qdrant client and the
single hybrid query, `/api/chat` stays inside nginx's 60 s window under load,
and the streaming path reaches first token sooner.

## 4. Tuning knobs (env vars)

| Var | Default | Purpose |
|---|---|---|
| `AGENTIC_LLM_TIMEOUT` | `8` | Per-helper-call ceiling (seconds) |
| `RAG_AGENTIC_BUDGET_S` | `12` | Wall-clock budget for all agentic stages |
| `QDRANT_TIMEOUT` | `5` | Per-operation Qdrant timeout (seconds) |

## 5. Recommended follow-ups (not in this hotfix)

- Add an explicit `proxy_read_timeout` to the `location /` block in nginx so the
  non-streaming path's limit is intentional rather than the 60 s default.
- Prefer the streaming endpoint (`/api/chat/stream`, 300 s) for the UI so first
  token, not total time, is what the user waits on.
- Consider running the independent helper stages concurrently, or a dedicated
  smaller/faster model for the gate/rewrite/grade helpers so they don't contend
  with answer generation on the same weights.
