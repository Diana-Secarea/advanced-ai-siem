"""Human review queue helper — approve or reject quarantined (4-6) CVEs.

Mid-score CVEs are HELD OUT of Qdrant until reviewed. Approving one transitions
its decision to 'indexed' and runs the same index path; rejecting transitions
it to 'dropped'. Both keep the full audit trail in cve_decisions.

Usage:
    python3 -m scheduled_agent.review list
    python3 -m scheduled_agent.review approve CVE-2024-12345
    python3 -m scheduled_agent.review reject  CVE-2024-12345
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag_core.database.postgres_client import get_conn
from scheduled_agent.normalize import (
    parse_nvd_item, parse_kev_item,
)


def _fetch_queued(cve_id: str):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source_type, final_score, reasoning, raw_cve "
                "FROM cve_decisions "
                "WHERE cve_id = %s AND decision = 'queued' "
                "ORDER BY decided_at DESC LIMIT 1",
                (cve_id.upper(),),
            )
            return cur.fetchone()
    finally:
        conn.close()


def _set_decision(cve_id: str, decision: str, qdrant_id: str = None):
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE cve_decisions SET decision = %s, qdrant_id = %s "
                "WHERE cve_id = %s AND decision = 'queued'",
                (decision, qdrant_id, cve_id.upper()),
            )
    finally:
        conn.close()


def list_queue():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cve_id, source_type, final_score, boost_reason, reasoning "
                "FROM pending_review LIMIT 100"
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        print("Review queue is empty.")
        return
    print(f"{'CVE':<18}{'src':<10}{'score':<6}reasoning")
    print("-" * 80)
    for cve_id, src, score, boost_reason, reasoning in rows:
        print(f"{cve_id:<18}{src:<10}{score:<6}{(reasoning or '')[:50]}")


def approve(cve_id: str) -> dict:
    """Approve a queued CVE -> index it. Returns {ok, cve_id, qdrant_id?}."""
    row = _fetch_queued(cve_id)
    if not row:
        print(f"{cve_id} is not in the review queue.")
        return {"ok": False, "cve_id": cve_id, "error": "not in review queue"}
    source_type, final_score, reasoning, raw_cve = row

    # rebuild the normalized cve from raw + index it
    cve = parse_nvd_item({"cve": raw_cve}) if source_type == "nvd" \
        else parse_kev_item(raw_cve)
    cve["source_type"] = source_type

    from rag_core.database.qdrant_store import QdrantStore
    from scheduled_agent import store
    qdrant_id = store.index_cve(cve, final_score, reasoning, QdrantStore())
    _set_decision(cve_id, "indexed", qdrant_id)
    print(f"Approved {cve_id} -> indexed to Qdrant (qdrant_id={qdrant_id})")
    return {"ok": True, "cve_id": cve_id, "qdrant_id": qdrant_id}


def reject(cve_id: str) -> dict:
    """Reject a queued CVE -> dropped (audit-logged). Returns {ok, cve_id}."""
    if not _fetch_queued(cve_id):
        print(f"{cve_id} is not in the review queue.")
        return {"ok": False, "cve_id": cve_id, "error": "not in review queue"}
    _set_decision(cve_id, "dropped")
    print(f"Rejected {cve_id} -> dropped (audit-logged)")
    return {"ok": True, "cve_id": cve_id}


def main():
    ap = argparse.ArgumentParser(description="CVE review queue")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("approve"); a.add_argument("cve_id")
    r = sub.add_parser("reject");  r.add_argument("cve_id")
    args = ap.parse_args()

    if args.cmd == "list":
        list_queue()
    elif args.cmd == "approve":
        approve(args.cve_id)
    elif args.cmd == "reject":
        reject(args.cve_id)


if __name__ == "__main__":
    main()
