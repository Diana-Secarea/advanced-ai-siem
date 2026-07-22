"""Fetchers — pull new CVEs from NVD and CISA-KEV.

Both return a list of the normalized CVE shape (see normalize.py).
All network failures degrade gracefully to an empty list (logged), so a
scheduled run never crashes the pipeline on a transient outage.
"""
from datetime import datetime, timedelta, timezone

import requests

from scheduled_agent import config
from scheduled_agent.normalize import parse_nvd_item, parse_kev_item


# ---------------------------------------------------------------------------
# NVD 2.0
# ---------------------------------------------------------------------------
def fetch_nvd_cves(since: datetime = None, days_back: int = None) -> list:
    """Fetch CVEs published since `since` (or the last `days_back` days).

    NVD requires pubStartDate/pubEndDate in ISO-8601 with milliseconds and a
    window <= 120 days. Without an API key the public rate limit is low, so we
    keep windows small (daily incremental).
    """
    end = datetime.now(timezone.utc)
    if since is None:
        days = days_back if days_back is not None else config.NVD_DAYS_BACK
        since = end - timedelta(days=days)

    params = {
        "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": config.NVD_MAX_RESULTS,
    }
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}

    try:
        resp = requests.get(
            config.NVD_API_URL, params=params, headers=headers,
            timeout=config.HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  [nvd] fetch failed (non-fatal): {e}")
        return []

    items = data.get("vulnerabilities", [])
    cves = [parse_nvd_item(it) for it in items]
    cves = [c for c in cves if c["cve_id"]]
    print(f"  [nvd] fetched {len(cves)} CVEs "
          f"({since.date()} -> {end.date()})")
    return cves


# ---------------------------------------------------------------------------
# CISA KEV — single JSON catalog; we diff against what we already know in the
# dedup stage, so here we just return everything and let dedup filter.
# ---------------------------------------------------------------------------
def fetch_cisa_kev() -> list:
    """Fetch the full CISA Known Exploited Vulnerabilities catalog."""
    try:
        resp = requests.get(config.CISA_KEV_URL, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  [cisa_kev] fetch failed (non-fatal): {e}")
        return []

    vulns = data.get("vulnerabilities", [])
    cves = [parse_kev_item(v) for v in vulns]
    cves = [c for c in cves if c["cve_id"]]
    print(f"  [cisa_kev] fetched {len(cves)} KEV entries")
    return cves
