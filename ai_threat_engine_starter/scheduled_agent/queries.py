"""Audit & analytics queries — the read side of the PostgreSQL backbone.

These are the SQL queries that turn the agent's decision ledger into the
auditability the thesis claims. Each function is a thin wrapper over one
SELECT so the queries themselves are explicit and inspectable.

Usage:
    python3 -m scheduled_agent.queries last-runs
    python3 -m scheduled_agent.queries decision-breakdown
    python3 -m scheduled_agent.queries queue
    python3 -m scheduled_agent.queries drops
    python3 -m scheduled_agent.queries boosted
    python3 -m scheduled_agent.queries indexed-over-time
    python3 -m scheduled_agent.queries cve CVE-2024-12345
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag_core.database.postgres_client import get_conn


def _run(sql: str, params=(), header=None):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
    finally:
        conn.close()
    _print_table(cols if header is None else header, rows)
    return rows


def _print_table(cols, rows):
    widths = [len(str(c)) for c in cols]
    for r in rows:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(str(v)))
    line = "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cols))
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))
    print(f"\n({len(rows)} rows)")


# ---------------------------------------------------------------------------
# 1. "When was each source last fetched, and how many were relevant?"
#    -> the headline thesis query
# ---------------------------------------------------------------------------
def last_runs():
    return _run("""
        SELECT DISTINCT ON (source_type)
               source_type,
               started_at::timestamp(0)        AS last_run,
               status,
               cves_evaluated,
               cves_indexed,
               cves_queued,
               cves_dropped,
               cves_duplicate
        FROM   ingestion_log
        WHERE  source_type LIKE 'cve_agent_%'
        ORDER BY source_type, started_at DESC;
    """)


# ---------------------------------------------------------------------------
# 2. Decision breakdown across all runs (indexed / queued / dropped)
# ---------------------------------------------------------------------------
def decision_breakdown():
    return _run("""
        SELECT decision,
               COUNT(*)                          AS n,
               ROUND(AVG(final_score), 2)        AS avg_score,
               MIN(final_score)                  AS min_score,
               MAX(final_score)                  AS max_score
        FROM   cve_decisions
        GROUP BY decision
        ORDER BY n DESC;
    """)


# ---------------------------------------------------------------------------
# 3. The human review queue (mid-score, held out of RAG)
# ---------------------------------------------------------------------------
def queue():
    return _run("""
        SELECT cve_id, source_type, final_score,
               LEFT(reasoning, 60) AS reasoning
        FROM   pending_review
        LIMIT 50;
    """)


# ---------------------------------------------------------------------------
# 4. Drop audit log — every rejected CVE, with the model's reasoning
#    ("all dropped CVEs are audit-logged")
# ---------------------------------------------------------------------------
def drops():
    return _run("""
        SELECT cve_id, source_type, final_score,
               LEFT(reasoning, 55) AS reasoning,
               decided_at::timestamp(0) AS decided_at
        FROM   cve_decisions
        WHERE  decision = 'dropped'
        ORDER BY decided_at DESC
        LIMIT 50;
    """)


# ---------------------------------------------------------------------------
# 5. CVEs that got an environment boost (feedback loop in action)
# ---------------------------------------------------------------------------
def boosted():
    return _run("""
        SELECT cve_id, base_score, boost, final_score, decision,
               LEFT(boost_reason, 50) AS boost_reason
        FROM   cve_decisions
        WHERE  boost > 0
        ORDER BY boost DESC, final_score DESC
        LIMIT 50;
    """)


# ---------------------------------------------------------------------------
# 6. Indexed intelligence growth over time (JOIN ledger -> run)
#    Demonstrates the relational join Qdrant cannot do.
# ---------------------------------------------------------------------------
def indexed_over_time():
    return _run("""
        SELECT il.source_type,
               DATE(cd.decided_at)        AS day,
               COUNT(*) FILTER (WHERE cd.decision = 'indexed') AS indexed,
               COUNT(*) FILTER (WHERE cd.decision = 'queued')  AS queued,
               COUNT(*) FILTER (WHERE cd.decision = 'dropped') AS dropped
        FROM   cve_decisions cd
        JOIN   ingestion_log il ON il.id = cd.run_id
        GROUP BY il.source_type, DATE(cd.decided_at)
        ORDER BY day DESC, il.source_type
        LIMIT 60;
    """)


# ---------------------------------------------------------------------------
# 7. Full audit trail for one CVE
# ---------------------------------------------------------------------------
def cve_history(cve_id: str):
    return _run("""
        SELECT decided_at::timestamp(0) AS decided_at,
               source_type, base_score, boost, final_score, decision,
               LEFT(reasoning, 50)  AS reasoning,
               LEFT(boost_reason, 40) AS boost_reason
        FROM   cve_decisions
        WHERE  cve_id = %s
        ORDER BY decided_at DESC;
    """, (cve_id.upper(),))


def main():
    ap = argparse.ArgumentParser(description="CVE ledger audit/analytics queries")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("last-runs")
    sub.add_parser("decision-breakdown")
    sub.add_parser("queue")
    sub.add_parser("drops")
    sub.add_parser("boosted")
    sub.add_parser("indexed-over-time")
    c = sub.add_parser("cve"); c.add_argument("cve_id")
    args = ap.parse_args()

    dispatch = {
        "last-runs":          last_runs,
        "decision-breakdown": decision_breakdown,
        "queue":              queue,
        "drops":              drops,
        "boosted":            boosted,
        "indexed-over-time":  indexed_over_time,
    }
    if args.cmd == "cve":
        cve_history(args.cve_id)
    else:
        dispatch[args.cmd]()


if __name__ == "__main__":
    main()
