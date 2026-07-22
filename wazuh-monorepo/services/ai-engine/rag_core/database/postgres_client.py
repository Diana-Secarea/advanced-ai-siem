"""
PostgreSQL client for Wazuh AI Threat Engine.

Tables managed:
  threat_intel      — raw threat intelligence records (all sources)
  wazuh_alerts      — Wazuh alert history
  alert_episodes    — processed alert episodes
  ingestion_log     — tracks ingestion runs per source
"""

import json
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from typing import Optional

from rag_core.database.config import PG_DSN


def get_conn():
    """Return a new psycopg2 connection."""
    return psycopg2.connect(PG_DSN)


# ---------------------------------------------------------------------------
# threat_intel
# ---------------------------------------------------------------------------

def upsert_threat_intel(records: list) -> int:
    """
    Upsert a list of threat intel records.
    Each record must have: source_id, source_type, name, description, raw_data, tags.
    Returns count of rows upserted.
    """
    if not records:
        return 0

    sql = """
        INSERT INTO threat_intel (source_id, source_type, name, description, raw_data, tags, updated_at)
        VALUES (%(source_id)s, %(source_type)s, %(name)s, %(description)s,
                %(raw_data)s::jsonb, %(tags)s, NOW())
        ON CONFLICT (source_id, source_type)
        DO UPDATE SET
            name        = EXCLUDED.name,
            description = EXCLUDED.description,
            raw_data    = EXCLUDED.raw_data,
            tags        = EXCLUDED.tags,
            updated_at  = NOW()
    """

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            rows = []
            for r in records:
                rows.append({
                    "source_id":   str(r.get("id") or r.get("source_id") or ""),
                    "source_type": str(r.get("source_type") or r.get("source", "")),
                    "name":        str(r.get("name") or r.get("title") or "")[:512],
                    "description": str(r.get("description") or ""),
                    "raw_data":    json.dumps(r),
                    "tags":        list(r.get("tags") or []),
                })
            psycopg2.extras.execute_batch(cur, sql, rows, page_size=500)
        return len(records)
    finally:
        conn.close()


def query_threat_intel(source_type: Optional[str] = None, limit: int = 1000) -> list:
    """Fetch threat intel records, optionally filtered by source_type."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if source_type:
                cur.execute(
                    "SELECT * FROM threat_intel WHERE source_type = %s ORDER BY id LIMIT %s",
                    (source_type, limit),
                )
            else:
                cur.execute("SELECT * FROM threat_intel ORDER BY id LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def count_threat_intel() -> dict:
    """Return record count per source_type."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source_type, COUNT(*) FROM threat_intel GROUP BY source_type ORDER BY COUNT(*) DESC"
            )
            return {row[0]: row[1] for row in cur.fetchall()}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# wazuh_alerts
# ---------------------------------------------------------------------------

def insert_alert(alert: dict, anomaly_score: float = 0.0, is_anomaly: bool = False) -> int:
    """Insert a Wazuh alert. Returns the new row id."""
    sql = """
        INSERT INTO wazuh_alerts
            (alert_id, rule_id, rule_level, rule_description,
             agent_id, agent_name, src_ip, alert_timestamp,
             full_log, raw_alert, anomaly_score, is_anomaly)
        VALUES
            (%(alert_id)s, %(rule_id)s, %(rule_level)s, %(rule_description)s,
             %(agent_id)s, %(agent_name)s, %(src_ip)s, %(alert_timestamp)s,
             %(full_log)s, %(raw_alert)s::jsonb, %(anomaly_score)s, %(is_anomaly)s)
        RETURNING id
    """
    rule    = alert.get("rule", {})
    agent   = alert.get("agent", {})
    data    = alert.get("data", {})
    src_ip  = data.get("srcip") or None

    # Parse timestamp
    ts_str = alert.get("timestamp") or alert.get("@timestamp")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else None
    except Exception:
        ts = None

    params = {
        "alert_id":         alert.get("id") or alert.get("_id"),
        "rule_id":          rule.get("id"),
        "rule_level":       rule.get("level"),
        "rule_description": str(rule.get("description") or "")[:512],
        "agent_id":         agent.get("id"),
        "agent_name":       agent.get("name"),
        "src_ip":           src_ip,
        "alert_timestamp":  ts,
        "full_log":         alert.get("full_log"),
        "raw_alert":        json.dumps(alert),
        "anomaly_score":    anomaly_score,
        "is_anomaly":       is_anomaly,
    }

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()[0]
    finally:
        conn.close()


def get_recent_alerts(limit: int = 100, only_anomalies: bool = False) -> list:
    """Fetch the most recent alerts."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if only_anomalies:
                cur.execute(
                    "SELECT * FROM wazuh_alerts WHERE is_anomaly = TRUE "
                    "ORDER BY alert_timestamp DESC LIMIT %s", (limit,)
                )
            else:
                cur.execute(
                    "SELECT * FROM wazuh_alerts ORDER BY alert_timestamp DESC LIMIT %s",
                    (limit,)
                )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# alert_episodes
# ---------------------------------------------------------------------------

def upsert_alert_episode(episode: dict, qdrant_id: Optional[str] = None) -> int:
    """
    Upsert an alert episode. Returns the row id.
    episode must have: episode_id, episode_type, summary, tags, entities,
                       time_range (start/end), metadata
    """
    sql = """
        INSERT INTO alert_episodes
            (episode_id, episode_type, summary, tags, entities,
             time_start, time_end, metadata, qdrant_id)
        VALUES
            (%(episode_id)s, %(episode_type)s, %(summary)s, %(tags)s,
             %(entities)s::jsonb, %(time_start)s, %(time_end)s,
             %(metadata)s::jsonb, %(qdrant_id)s)
        ON CONFLICT (episode_id) DO UPDATE SET
            summary    = EXCLUDED.summary,
            tags       = EXCLUDED.tags,
            entities   = EXCLUDED.entities,
            time_start = EXCLUDED.time_start,
            time_end   = EXCLUDED.time_end,
            metadata   = EXCLUDED.metadata,
            qdrant_id  = EXCLUDED.qdrant_id
        RETURNING id
    """
    tr = episode.get("time_range", {})

    def _parse_ts(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        except Exception:
            return None

    params = {
        "episode_id":   episode["episode_id"],
        "episode_type": episode.get("episode_type"),
        "summary":      episode.get("summary"),
        "tags":         list(episode.get("tags") or []),
        "entities":     json.dumps(episode.get("entities") or {}),
        "time_start":   _parse_ts(tr.get("start")),
        "time_end":     _parse_ts(tr.get("end")),
        "metadata":     json.dumps(episode.get("metadata") or {}),
        "qdrant_id":    qdrant_id,
    }

    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# ingestion_log
# ---------------------------------------------------------------------------

def log_ingestion_start(source_type: str) -> int:
    """Record the start of an ingestion run. Returns log row id."""
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ingestion_log (source_type) VALUES (%s) RETURNING id",
                (source_type,)
            )
            return cur.fetchone()[0]
    finally:
        conn.close()


def log_ingestion_done(log_id: int, records: int, status: str = "ok", error: str = None):
    """Update an ingestion log entry with completion info."""
    conn = get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """UPDATE ingestion_log
                   SET finished_at = NOW(), records_upserted = %s,
                       status = %s, error_msg = %s
                   WHERE id = %s""",
                (records, status, error, log_id)
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def ping() -> bool:
    """Return True if PostgreSQL is reachable."""
    try:
        conn = get_conn()
        conn.close()
        return True
    except Exception:
        return False
