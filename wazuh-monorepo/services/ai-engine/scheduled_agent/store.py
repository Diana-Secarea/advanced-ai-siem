"""PostgreSQL store layer for the CVE ingestion agent — the audit/analytics
backbone. Everything the agent decides is recorded here.

Responsibilities:
  - ensure_schema()        apply schema_additions.sql (idempotent)
  - last_cursor(source)    where to resume fetching from (from ingestion_log)
  - open_run / close_run   run-level rollup row in ingestion_log
  - record_decision        one CVE-level row in cve_decisions
  - index_cve              side-effect: write a kept CVE to threat_intel + Qdrant
"""
import json
from datetime import datetime
from pathlib import Path

from rag_core.database.postgres_client import get_conn, upsert_threat_intel
from scheduled_agent.normalize import cve_to_episode

_SCHEMA_FILE = Path(__file__).resolve().parent / "schema_additions.sql"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def ensure_schema():
    """Apply schema_additions.sql. Idempotent (IF NOT EXISTS everywhere)."""
    sql = _SCHEMA_FILE.read_text()
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cursor — resume fetching from the last successful run (the log IS the cursor)
# ---------------------------------------------------------------------------
def last_cursor(source_type: str):
    """Return the started_at of the last OK run for this source, or None."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT MAX(started_at) FROM ingestion_log "
                "WHERE source_type = %s AND status = 'ok'",
                (source_type,),
            )
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Run-level rollup (ingestion_log)
# ---------------------------------------------------------------------------
def open_run(source_type: str, cursor_used: datetime = None) -> int:
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ingestion_log (source_type, cursor_used) "
                "VALUES (%s, %s) RETURNING id",
                (source_type, cursor_used),
            )
            return cur.fetchone()[0]
    finally:
        conn.close()


def close_run(run_id: int, counts: dict, status: str = "ok", error: str = None):
    """counts keys: evaluated, indexed, queued, dropped, duplicate."""
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """UPDATE ingestion_log SET
                       finished_at      = NOW(),
                       records_upserted = %s,
                       cves_evaluated   = %s,
                       cves_indexed     = %s,
                       cves_queued      = %s,
                       cves_dropped     = %s,
                       cves_duplicate   = %s,
                       status           = %s,
                       error_msg        = %s
                   WHERE id = %s""",
                (
                    counts.get("indexed", 0),
                    counts.get("evaluated", 0),
                    counts.get("indexed", 0),
                    counts.get("queued", 0),
                    counts.get("dropped", 0),
                    counts.get("duplicate", 0),
                    status, error, run_id,
                ),
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CVE-level ledger (cve_decisions)
# ---------------------------------------------------------------------------
def record_decision(cve: dict, *, run_id: int, base_score, boost, final_score,
                    decision: str, reasoning: str, boost_reason: str,
                    qdrant_id: str = None):
    sql = """
        INSERT INTO cve_decisions
            (cve_id, source_type, run_id, base_score, boost, final_score,
             decision, reasoning, boost_reason, raw_cve, qdrant_id)
        VALUES
            (%(cve_id)s, %(source_type)s, %(run_id)s, %(base_score)s, %(boost)s,
             %(final_score)s, %(decision)s, %(reasoning)s, %(boost_reason)s,
             %(raw_cve)s::jsonb, %(qdrant_id)s)
        ON CONFLICT (cve_id, run_id) DO UPDATE SET
            base_score   = EXCLUDED.base_score,
            boost        = EXCLUDED.boost,
            final_score  = EXCLUDED.final_score,
            decision     = EXCLUDED.decision,
            reasoning    = EXCLUDED.reasoning,
            boost_reason = EXCLUDED.boost_reason,
            qdrant_id    = EXCLUDED.qdrant_id
    """
    params = {
        "cve_id":       cve["cve_id"],
        "source_type":  cve["source_type"],
        "run_id":       run_id,
        "base_score":   base_score,
        "boost":        boost,
        "final_score":  final_score,
        "decision":     decision,
        "reasoning":    reasoning,
        "boost_reason": boost_reason,
        "raw_cve":      json.dumps(cve.get("raw", {})),
        "qdrant_id":    qdrant_id,
    }
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql, params)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Indexing side-effect — only for kept CVEs (score >= 7 or human-approved).
# Reuses the existing upsert_threat_intel + QdrantStore. Returns qdrant_id.
# ---------------------------------------------------------------------------
def index_cve(cve: dict, final_score: int, reasoning: str, qdrant_store) -> str:
    episode = cve_to_episode(cve, final_score, reasoning)

    # 1) authoritative kept-record in Postgres threat_intel
    upsert_threat_intel([{
        "id":          episode["episode_id"],
        "source_type": cve["source_type"],
        "name":        cve["cve_id"],
        "description": (episode["summary"])[:1000],
        "tags":        episode["tags"],
        "raw_data":    episode,
    }])

    # 2) searchable vector in Qdrant
    qdrant_store.index_episodes([episode])

    return episode["episode_id"]
