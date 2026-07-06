"""
RAG Generation-Quality Evaluation

Evaluates the *generation* stage of the RAG pipeline (the answers produced by
the local llama3.2 model), complementing the retrieval evaluation in
retrieval_metrics.py. Three properties are measured:

  1. Faithfulness   — fraction of atomic claims in an answer that are supported
                      by the retrieved chunks (claim-decomposition method,
                      RAGAS-style). Catches hallucination.
  2. Citation       — of the inline [i] citations the answer emits, the fraction
     correctness      whose cited chunk actually supports the attached sentence
                      (precision), plus citation coverage of factual sentences.
  3. Refusal        — on a separate set of UNANSWERABLE queries, the fraction the
     behaviour        system correctly declines instead of confabulating, plus an
                      over-refusal check on the answerable set.

JUDGE: all automated scores use llama3.2 as an LLM-as-judge. A 3B local model is
a WEAK judge — these numbers are an automated approximation, NOT human ground
truth. The harness also writes a human-annotation worksheet so the same answers
can be scored by hand and the two compared (agreement / Cohen's kappa). For the
thesis, the human-annotated pass is the primary result; the LLM-judge pass is a
secondary automation experiment.

Usage:
    cd /home/sek/wazuh/ai_threat_engine_starter
    ./venv/bin/python3 -m rag_core.evaluation.generation_metrics            # full run
    ./venv/bin/python3 -m rag_core.evaluation.generation_metrics --limit 5  # quick smoke test
    ./venv/bin/python3 -m rag_core.evaluation.generation_metrics --skip-refusal
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import requests

from rag_core.database.qdrant_store import QdrantStore

# ----------------------------------------------------------------------------
# Config — mirrors backend/server.py so the eval reflects the deployed pipeline.
# ----------------------------------------------------------------------------
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
TOP_K = 5

DATASET_PATH = Path(__file__).parent / "eval_dataset.json"
UNANSWERABLE_PATH = Path(__file__).parent / "unanswerable_queries.json"
REPORT_DIR = PROJECT_ROOT / "data" / "eval_reports"

# Exact system prompt from backend/server.py (deployed configuration).
SYSTEM_PROMPT = """You are a cybersecurity analyst assistant powered by the Wazuh AI Threat Engine.
You have access to two data sources:
1. A threat intelligence knowledge base containing MITRE ATT&CK techniques (823), YARA detection rules (378), and vendor security advisories (132).
2. Real Wazuh alert logs from this system — actual security events that have been detected.

When answering questions:
- If the user asks about what happened on the system, attacks detected, or specific alerts, use the Wazuh alert context.
- If the user asks about techniques, detection methods, or threat intelligence, use the knowledge base context.
- Cite specific technique IDs (e.g., T1055), rule IDs, alert timestamps, and severity levels.
- Summarize patterns you see in the alerts (e.g., repeated brute force, privilege escalation chains).
- Provide actionable security guidance based on what's observed.
- Keep answers concise but thorough.

IMPORTANT — Distinguish normal activity from threats:
- Alerts with rule level 1–5 and Anomaly Score labeled NORMAL are almost certainly routine system activity (logins, sudo, PAM sessions, cron jobs). Do NOT map these to attack techniques. State clearly that the activity appears benign.
- Only escalate to threat analysis when: rule level >= 7, OR Anomaly Score is HIGH, OR there is a clear pattern of malicious intent (e.g., repeated failures, off-hours, known-bad IPs).
- When threat intel context is absent (low-level alerts), say so explicitly and do not invent threat connections."""

# Phrase-based refusal detector. On the 12-query unanswerable set this matched
# human labels on 11/12 (91.7%), versus 25% for the llama3.2 LLM-judge — so this
# regex, not the LLM, is the primary automated refusal signal.
REFUSAL_PATTERNS = [
    r"i'?m not aware", r"i am not aware", r"not aware of",
    r"couldn'?t find", r"could not find", r"can'?t find", r"no direct match",
    r"not currently available", r"no .{0,30}available in (?:my|our) knowledge base",
    r"there (?:is|are) no .{0,40}(?:technique|rule|group|cve|record|match|information)",
    r"i'?m not able to (?:assist|provide|help)", r"i am not able to",
    r"no matching .{0,30}found", r"do not have access", r"don'?t have access",
    r"i (?:do not|don't) have", r"no relevant", r"out of scope",
    r"not enough (?:information|context|evidence)", r"no information on",
]


# ============================================================================
# Ollama client (blocking) — same endpoint/params as backend/server.py
# ============================================================================
def ollama_chat(messages: List[Dict], temperature: float = 0.3, max_tokens: int = 1024) -> str:
    url = f"{OLLAMA_URL}/v1/chat/completions"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    resp = requests.post(url, json=payload, timeout=180)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


# ============================================================================
# Generation — replicates the threat-intel path of /api/chat
# ============================================================================
def generate_answer(retriever: QdrantStore, query: str, k: int = TOP_K) -> Dict:
    """Retrieve top-k threat-intel chunks and generate an answer, exactly as the
    deployed chat endpoint does for a knowledge question (no Wazuh alert match)."""
    results = retriever.search(query=query, top_k=k)

    chunks = []
    ti_parts = []
    for i, r in enumerate(results, 1):
        summary = (r.get("summary", "") or "")[:500]
        etype = r.get("episode_type", "")
        eid = r.get("episode_id", "")
        ti_parts.append(f"[{i}] ({etype}) {eid}: {summary}")
        chunks.append({"idx": i, "id": eid, "type": etype, "text": summary})

    ti_block = "\n".join(ti_parts) if ti_parts else "No relevant threat intel found."

    augmented = (
        f"=== Threat Intelligence Context ===\n{ti_block}\n\n"
        f"=== Wazuh Alert Logs (0 matches from 0 total alerts) ===\nNo matching Wazuh alerts found.\n\n"
        f"User question: {query}"
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": augmented},
    ]
    answer = ollama_chat(messages)
    return {"answer": answer, "chunks": chunks, "context_text": ti_block}


# ============================================================================
# 1. Faithfulness  (claim decomposition + LLM-judge entailment)
# ============================================================================
def decompose_claims(answer: str) -> List[str]:
    """Break an answer into atomic factual claims via the LLM."""
    prompt = (
        "Break the following ANSWER into a list of atomic factual claims. "
        "Each claim must be a single, self-contained, verifiable statement. "
        "Ignore questions, hedging, and generic advice that asserts no fact. "
        "Output ONLY the claims, one per line, each starting with '- '. No other text.\n\n"
        f"ANSWER:\n{answer}"
    )
    out = ollama_chat([{"role": "user", "content": prompt}], temperature=0.0)
    claims = []
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^[-*•]\s+(.*)", line)
        if m and len(m.group(1)) > 3:
            claims.append(m.group(1).strip())
    return claims


def judge_claims_supported(claims: List[str], context_text: str) -> List[bool]:
    """For each claim, ask the LLM whether the CONTEXT supports it. One call."""
    if not claims:
        return []
    numbered = "\n".join(f"{i+1}. {c}" for i, c in enumerate(claims))
    prompt = (
        "You are a strict fact-checker. Given the CONTEXT and a numbered list of CLAIMS, "
        "decide for EACH claim whether it is directly supported by the CONTEXT. "
        "A claim is SUPPORTED only if its content can be found in or logically entailed by the CONTEXT. "
        "If the claim adds facts not present in the CONTEXT, answer NO.\n"
        "Reply with exactly one line per claim in the form '<number>: YES' or '<number>: NO'. "
        "No explanation.\n\n"
        f"CONTEXT:\n{context_text}\n\n"
        f"CLAIMS:\n{numbered}"
    )
    out = ollama_chat([{"role": "user", "content": prompt}], temperature=0.0)
    verdicts = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s*[:.\)]\s*(YES|NO)", line.strip(), re.IGNORECASE)
        if m:
            verdicts[int(m.group(1))] = m.group(2).upper() == "YES"
    # Default unparsed claims to NO (conservative).
    return [verdicts.get(i + 1, False) for i in range(len(claims))]


# ============================================================================
# 2. Citation correctness  (entity-ID attribution)
# ----------------------------------------------------------------------------
# The deployed system prompt instructs the model to "cite specific technique IDs
# (e.g., T1055), rule IDs ...". In practice the answers reference entity IDs
# (MITRE T-codes, sigma-*, wazuh-sca-*, yara-*, CVE-*, group-G*), NOT numbered
# [i] markers. A citation is CORRECT (grounded) if the cited ID actually appears
# in the retrieved context; an ID the model invents that was never retrieved is
# a fabricated attribution. This is the ALCE attribution paradigm adapted to the
# system's ID-based citation style.
# ============================================================================
REF_PATTERNS = [
    r"T\d{4}(?:\.\d{3})?",      # MITRE ATT&CK technique / sub-technique
    r"sigma-[\w./-]+",          # Sigma rule episode id
    r"wazuh-sca-\d+",           # Wazuh CIS/SCA check id
    r"yara-[\w./-]+",           # YARA rule episode id
    r"CVE-\d{4}-\d{3,7}",       # CVE id
    r"group-G\d+", r"G\d{4}",   # MITRE group id
]
_REF_RE = re.compile("|".join(f"(?:{p})" for p in REF_PATTERNS))


def extract_citations(answer: str) -> List[str]:
    """Distinct entity IDs the answer cites, in order of first appearance."""
    seen, out = set(), []
    for m in _REF_RE.findall(answer):
        tok = m.strip().rstrip(".,);:")
        if tok and tok.lower() not in seen:
            seen.add(tok.lower())
            out.append(tok)
    return out


def evaluate_citations(answer: str, chunks: List[Dict]) -> Dict:
    """Citation precision = grounded cited IDs / total cited IDs.
    Grounded = the cited ID appears among the retrieved chunk IDs or their text."""
    blob = " ".join((c.get("id", "") + " " + c.get("text", "")) for c in chunks).lower()
    cited = extract_citations(answer)
    grounded = []
    fabricated = []
    for tok in cited:
        if tok.lower() in blob:
            grounded.append(tok)
        else:
            fabricated.append(tok)
    total = len(cited)
    precision = (len(grounded) / total) if total else None
    return {
        "total_citations": total,
        "correct_citations": len(grounded),
        "invalid_citations": len(fabricated),   # cited an ID never retrieved
        "citation_precision": precision,
        "citation_coverage": 1.0 if total else 0.0,   # answer cited ≥1 source
        "grounded": grounded,
        "fabricated": fabricated,
        "details": [{"cite": t, "valid": True, "supported": True} for t in grounded]
                   + [{"cite": t, "valid": False, "supported": False} for t in fabricated],
    }


# ============================================================================
# 3. Refusal behaviour
# ============================================================================
def regex_is_refusal(answer: str) -> bool:
    low = answer.lower()
    return any(re.search(p, low) for p in REFUSAL_PATTERNS)


def judge_is_refusal(answer: str) -> bool:
    prompt = (
        "Classify whether the ASSISTANT answered or refused.\n"
        "- REFUSE: it declined to help, OR stated it has no / could not find relevant "
        "information and therefore gave no substantive answer.\n"
        "- ANSWER: it provided any substantive, on-topic security information or guidance, "
        "even if it added caveats or noted some limitations.\n"
        "Reply with exactly one word: REFUSE or ANSWER.\n\n"
        f"ASSISTANT:\n{answer}"
    )
    out = ollama_chat([{"role": "user", "content": prompt}], temperature=0.0).strip().upper()
    return out.startswith("REFUSE")


# ============================================================================
# Driver
# ============================================================================
def run(limit: Optional[int] = None, k: int = TOP_K, skip_refusal: bool = False) -> Dict:
    retriever = QdrantStore()
    eval_data = json.loads(DATASET_PATH.read_text())
    if limit:
        eval_data = eval_data[:limit]

    print(f"\n{'='*72}")
    print(f"  RAG Generation-Quality Evaluation")
    print(f"  model={OLLAMA_MODEL}  k={k}  queries={len(eval_data)}  (LLM-as-judge)")
    print(f"{'='*72}\n")

    per_query = []
    sum_faith = 0.0
    n_faith = 0
    tot_cit = 0
    tot_cit_correct = 0
    tot_cit_invalid = 0
    cov_vals = []
    overrefusals = 0
    t0 = time.time()

    for i, item in enumerate(eval_data, 1):
        q = item["query"]
        cat = item.get("category", "")
        gen = generate_answer(retriever, q, k)
        answer = gen["answer"]

        claims = decompose_claims(answer)
        supported = judge_claims_supported(claims, gen["context_text"])
        faith = (sum(supported) / len(supported)) if supported else None
        if faith is not None:
            sum_faith += faith
            n_faith += 1

        cit = evaluate_citations(answer, gen["chunks"])
        tot_cit += cit["total_citations"]
        tot_cit_correct += cit["correct_citations"]
        tot_cit_invalid += cit["invalid_citations"]
        if cit["citation_coverage"] is not None:
            cov_vals.append(cit["citation_coverage"])

        refused = regex_is_refusal(answer)
        if refused:
            overrefusals += 1  # these queries ARE answerable, so a refusal here is over-refusal

        per_query.append({
            "query": q, "category": cat, "answer": answer,
            "chunks": gen["chunks"],
            "claims": [{"claim": c, "supported": bool(s)} for c, s in zip(claims, supported)],
            "faithfulness": faith,
            "citations": cit,
            "refused": refused,
        })

        fstr = f"{faith:.2f}" if faith is not None else "n/a"
        pstr = (f"{cit['citation_precision']:.2f}" if cit['citation_precision'] is not None else "n/a")
        print(f"[{i:2d}/{len(eval_data)}] faith={fstr} cit_prec={pstr} "
              f"({cit['correct_citations']}/{cit['total_citations']}) "
              f"claims={len(claims)} {'REFUSED!' if refused else ''}  {q[:48]}")

    mean_faith = (sum_faith / n_faith) if n_faith else None
    cit_precision = (tot_cit_correct / tot_cit) if tot_cit else None
    mean_cov = (sum(cov_vals) / len(cov_vals)) if cov_vals else None

    # ---- Refusal test on unanswerable set ----
    refusal_block = None
    if not skip_refusal and UNANSWERABLE_PATH.exists():
        unans = json.loads(UNANSWERABLE_PATH.read_text())
        print(f"\n{'-'*72}\n  Refusal test on {len(unans)} UNANSWERABLE queries\n{'-'*72}")
        correct = 0
        per_unans = []
        for j, item in enumerate(unans, 1):
            q = item["query"]
            gen = generate_answer(retriever, q, k)
            refused = regex_is_refusal(gen["answer"])       # primary signal
            llm_refused = judge_is_refusal(gen["answer"])   # secondary, for agreement
            if refused:
                correct += 1
            per_unans.append({"query": q, "type": item.get("type"),
                              "refused": refused, "llm_judge_refused": llm_refused,
                              "answer": gen["answer"]})
            print(f"  [{j:2d}/{len(unans)}] {'REFUSE ok' if refused else 'HALLUCINATED'} "
                  f"[{item.get('type')}]  {q[:46]}")
        refusal_block = {
            "n": len(unans),
            "correct_refusals": correct,
            "refusal_accuracy": correct / len(unans) if unans else None,
            "per_query": per_unans,
        }

    elapsed = time.time() - t0
    report = {
        "model": OLLAMA_MODEL, "k": k, "judge": "llm-as-judge (llama3.2)",
        "n_queries": len(eval_data),
        "faithfulness_mean": mean_faith,
        "citation_precision": cit_precision,
        "citation_total": tot_cit,
        "citation_correct": tot_cit_correct,
        "citation_invalid": tot_cit_invalid,
        "citation_coverage_mean": mean_cov,
        "over_refusal_count": overrefusals,
        "over_refusal_rate": overrefusals / len(eval_data) if eval_data else None,
        "refusal": refusal_block,
        "elapsed_sec": round(elapsed, 1),
        "per_query": per_query,
    }
    _print_summary(report)
    _save(report)
    _write_worksheet(report)
    return report


def _fmt(x, pct=True):
    if x is None:
        return "n/a"
    return f"{x*100:.1f}%" if pct else f"{x:.3f}"


def _print_summary(r: Dict):
    print(f"\n{'='*72}\n  SUMMARY  (automated, LLM-as-judge — validate vs. human worksheet)\n{'='*72}")
    print(f"  Faithfulness (mean fraction of supported claims) : {_fmt(r['faithfulness_mean'])}")
    print(f"  Citation precision ({r['citation_correct']}/{r['citation_total']} citations)"
          f"{' ':>8}: {_fmt(r['citation_precision'])}")
    print(f"  Citation coverage (answers citing >=1 source)    : {_fmt(r['citation_coverage_mean'])}")
    print(f"  Fabricated citations (ID never retrieved)        : {r['citation_invalid']}")
    print(f"  Over-refusal rate on answerable queries          : {_fmt(r['over_refusal_rate'])} "
          f"({r['over_refusal_count']}/{r['n_queries']})")
    if r["refusal"]:
        rb = r["refusal"]
        print(f"  Refusal accuracy on UNANSWERABLE set             : {_fmt(rb['refusal_accuracy'])} "
              f"({rb['correct_refusals']}/{rb['n']})")
    print(f"\n  elapsed: {r['elapsed_sec']}s")
    print(f"{'='*72}\n")


def _save(r: Dict):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / "generation_eval.json"
    out.write_text(json.dumps(r, indent=2))
    print(f"  full results  -> {out}")


def _write_worksheet(r: Dict):
    """Human-annotation worksheet: each answer pre-split into claims + the chunks
    it was given, with blank [ ] slots, so the LLM-judge scores can be validated."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / "generation_worksheet.md"
    lines = ["# Generation-Quality Human Annotation Worksheet\n",
             "Tick `[x]` if the claim/citation IS supported by the chunks below it. ",
             "Then compare your column against the LLM-judge column to compute agreement.\n"]
    for i, pq in enumerate(r["per_query"], 1):
        lines.append(f"\n## Q{i}. {pq['query']}  _(category: {pq['category']})_\n")
        lines.append("**Retrieved chunks (context the model saw):**\n")
        for c in pq["chunks"]:
            lines.append(f"- `[{c['idx']}]` ({c['type']}) {c['id']}: {c['text'][:200]}")
        lines.append("\n**Answer:**\n")
        lines.append("> " + pq["answer"].replace("\n", "\n> "))
        lines.append("\n**Faithfulness — claims (LLM judge in parentheses):**\n")
        for cl in pq["claims"]:
            mark = "x" if cl["supported"] else " "
            lines.append(f"- [ ] (LLM said: {'YES' if cl['supported'] else 'NO '}) {cl['claim']}")
        cit = pq["citations"]
        if cit["total_citations"]:
            lines.append("\n**Citation checks — cited IDs (auto-grounded against retrieved chunks):**\n")
            for t in cit.get("grounded", []):
                lines.append(f"- [x] GROUNDED  `{t}`  (present in retrieved chunks)")
            for t in cit.get("fabricated", []):
                lines.append(f"- [ ] FABRICATED `{t}`  (NOT in retrieved chunks — verify)")
    out.write_text("\n".join(lines))
    print(f"  human worksheet -> {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", type=int, default=TOP_K)
    ap.add_argument("--limit", type=int, default=None, help="only first N queries (smoke test)")
    ap.add_argument("--skip-refusal", action="store_true")
    args = ap.parse_args()
    run(limit=args.limit, k=args.k, skip_refusal=args.skip_refusal)
