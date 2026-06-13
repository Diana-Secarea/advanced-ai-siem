"""CVE ingestion agent — scheduled workflow orchestrator.

Pipeline (fixed control flow; the only LLM step is score_relevance):

    fetch  ->  dedup  ->  boost  ->  score  ->  act  ->  log

For each source (NVD, CISA-KEV):
  1. open an ingestion_log run row (records the cursor used)
  2. fetch candidate CVEs
  3. drop ones already in threat_intel (decision='duplicate')
  4. boost relevance from environment evidence (rules + alert history)
  5. score 0-10 with the local LLM, final = min(base + boost, 10)
  6. act on the band:
        >= 7  -> index to Qdrant + threat_intel   (decision='indexed')
        4-6   -> quarantine, HELD OUT of RAG       (decision='queued')
        < 4   -> audit-log only                    (decision='dropped')
  7. close the run with the rollup counts

Run:
    python3 -m scheduled_agent.agent              # both sources
    python3 -m scheduled_agent.agent --source nvd
    python3 -m scheduled_agent.agent --dry-run    # no DB/Qdrant writes
"""
import argparse
import sys
from pathlib import Path

# Make rag_core importable when run as a script/module
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scheduled_agent import config
from scheduled_agent import store
from scheduled_agent.dedup import known_cve_ids, is_duplicate
from scheduled_agent.boosts import compute_boost
from scheduled_agent.scorer import score_relevance
from scheduled_agent.fetchers import fetch_nvd_cves, fetch_cisa_kev


def _decide(final_score: int) -> str:
    if final_score >= config.SCORE_AUTO_INDEX:
        return "indexed"
    if final_score >= config.SCORE_QUEUE_MIN:
        return "queued"
    return "dropped"


def process_source(source_type: str, qdrant_store, dry_run: bool = False) -> dict:
    counts = {"evaluated": 0, "indexed": 0, "queued": 0, "dropped": 0, "duplicate": 0}

    # --- 1. cursor + open run ---
    # Namespace the ingestion_log row so agent runs are distinct from the
    # qdrant_indexer's bulk loads (which also use source_type 'cisa_kev'/etc).
    run_label = f"cve_agent_{source_type}"
    cursor = store.last_cursor(run_label) if not dry_run else None
    run_id = None if dry_run else store.open_run(run_label, cursor)

    # --- 2. fetch ---
    print(f"\n=== {source_type} ===")
    if source_type == "nvd":
        cves = fetch_nvd_cves(since=cursor)
    elif source_type == "cisa_kev":
        cves = fetch_cisa_kev()
    else:
        raise ValueError(f"unknown source: {source_type}")

    if not cves:
        if run_id:
            store.close_run(run_id, counts, status="ok")
        return counts

    # --- 3. dedup set (load once) ---
    known = known_cve_ids() if not dry_run else set()

    for cve in cves:
        if is_duplicate(cve["cve_id"], known):
            counts["duplicate"] += 1
            if run_id:
                store.record_decision(
                    cve, run_id=run_id, base_score=None, boost=0,
                    final_score=None, decision="duplicate",
                    reasoning="already present in threat_intel",
                    boost_reason="",
                )
            continue

        counts["evaluated"] += 1

        # --- 4. boost ---
        boost, boost_reason = compute_boost(cve)

        # --- 5. score ---
        base, reasoning = score_relevance(cve)
        final = min(base + boost, 10)
        decision = _decide(final)

        boost_str = f" (+{boost} boost: {boost_reason})" if boost else ""
        print(f"  {cve['cve_id']:<18} base={base} final={final}{boost_str} "
              f"-> {decision}")

        # --- 6. act ---
        qdrant_id = None
        if decision == "indexed" and not dry_run:
            qdrant_id = store.index_cve(cve, final, reasoning, qdrant_store)

        counts[decision] += 1

        if run_id:
            store.record_decision(
                cve, run_id=run_id, base_score=base, boost=boost,
                final_score=final, decision=decision, reasoning=reasoning,
                boost_reason=boost_reason, qdrant_id=qdrant_id,
            )

    # --- 7. close run ---
    if run_id:
        store.close_run(run_id, counts, status="ok")
    return counts


def main():
    ap = argparse.ArgumentParser(description="Scheduled CVE ingestion agent")
    ap.add_argument("--source", choices=["nvd", "cisa_kev", "all"], default="all")
    ap.add_argument("--dry-run", action="store_true",
                    help="score and print, but write nothing to DB/Qdrant")
    args = ap.parse_args()

    if not args.dry_run:
        store.ensure_schema()

    # Lazy: only spin up Qdrant if we might index
    qdrant_store = None
    if not args.dry_run:
        from rag_core.database.qdrant_store import QdrantStore
        qdrant_store = QdrantStore()

    sources = ["nvd", "cisa_kev"] if args.source == "all" else [args.source]

    grand = {"evaluated": 0, "indexed": 0, "queued": 0, "dropped": 0, "duplicate": 0}
    for src in sources:
        try:
            c = process_source(src, qdrant_store, dry_run=args.dry_run)
            for k in grand:
                grand[k] += c.get(k, 0)
        except Exception as e:
            print(f"  [{src}] run FAILED: {e}")

    print("\n" + "=" * 55)
    print("  CVE ingestion complete")
    print("=" * 55)
    print(f"  evaluated : {grand['evaluated']}")
    print(f"  indexed   : {grand['indexed']}   (score >= {config.SCORE_AUTO_INDEX})")
    print(f"  queued    : {grand['queued']}   (review, held out of RAG)")
    print(f"  dropped   : {grand['dropped']}   (audit-logged)")
    print(f"  duplicate : {grand['duplicate']}")


if __name__ == "__main__":
    main()
