"""Deduplication — skip CVEs we already know about.

Primary check is exact-match against PostgreSQL `threat_intel` on the CVE id,
which is a canonical unique key (so semantic near-dup matching, useful for
free-text techniques, is unnecessary for CVEs). The exact check is cheap and
reliable and catches every re-fetch.
"""
from rag_core.database.postgres_client import get_conn


def known_cve_ids() -> set:
    """Return the set of CVE ids already present in threat_intel.

    Loaded once per run so dedup is a set-membership test, not a query per CVE.
    """
    ids = set()
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # CVE ids are stored as the source_id (e.g. 'cisa_kev-CVE-...'),
            # inside tags, and inside the raw_data entities — match defensively
            # on the source_id suffix which always contains the CVE id.
            cur.execute(
                "SELECT source_id FROM threat_intel "
                "WHERE source_id ILIKE '%%CVE-%%' OR 'cve' = ANY(tags)"
            )
            for (sid,) in cur.fetchall():
                if sid:
                    ids.add(_extract_cve(sid))
    finally:
        conn.close()
    ids.discard(None)
    return ids


def _extract_cve(text: str):
    """Pull a CVE id out of an arbitrary string, upper-cased."""
    import re
    m = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def is_duplicate(cve_id: str, known: set) -> bool:
    return cve_id.upper() in known
