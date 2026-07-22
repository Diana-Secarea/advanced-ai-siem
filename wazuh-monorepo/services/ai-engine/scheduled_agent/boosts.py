"""Environment-evidence boosts.

Both boosts are READ-ONLY lookups about a single *new* CVE. They never modify
existing threat_intel or alert data — they only add points to the new CVE's
relevance score. The direction is one-way: what the SIEM observes shapes which
intelligence we prioritize; ingesting intelligence never alters observations.

  check_wazuh_rules(cve)   -> +BOOST_RULE_MATCH    if a detection rule references
                              the CVE id or its affected software.
  check_alert_history(cve) -> +BOOST_ALERT_HISTORY if the environment has fired
                              alerts touching the affected software recently.

The alert-history backend is pluggable:
  - "flatfile"   (prototype): scans /var/ossec/logs/alerts/alerts.json
  - "opensearch" (production): queries the Wazuh Indexer _search API on :9200
Both implement the same count_recent(keywords, days) interface, so swapping is
a one-line config change (CVE_ALERT_BACKEND).
"""
import glob
import json
from datetime import datetime, timedelta, timezone

from scheduled_agent import config
from scheduled_agent.normalize import extract_software


# ===========================================================================
# Boost 1 — Wazuh detection rules
# ===========================================================================
_rules_blob_cache = None


def _load_rules_blob() -> str:
    """Read every Wazuh rule .xml into one lowercased blob (cached per run).

    Best-effort: if the files aren't readable (perms), returns '' so the boost
    simply contributes 0 rather than crashing the run.
    """
    global _rules_blob_cache
    if _rules_blob_cache is not None:
        return _rules_blob_cache

    chunks = []
    for d in config.WAZUH_RULES_DIRS:
        try:
            for path in glob.glob(str(d / "*.xml")):
                try:
                    with open(path, "r", errors="ignore") as f:
                        chunks.append(f.read())
                except (PermissionError, OSError):
                    continue
        except OSError:
            continue
    _rules_blob_cache = "\n".join(chunks).lower()
    if not _rules_blob_cache:
        print("  [boost] note: no Wazuh rules readable "
              "(permissions?) — rule boost disabled this run")
    return _rules_blob_cache


def check_wazuh_rules(cve: dict) -> tuple:
    """Return (boost_points, reason)."""
    blob = _load_rules_blob()
    if not blob:
        return (0, "")

    cve_id = cve["cve_id"].lower()
    if cve_id in blob:
        return (config.BOOST_RULE_MATCH, f"Wazuh rule references {cve['cve_id']}")

    for kw in extract_software(cve):
        if kw in blob:
            return (config.BOOST_RULE_MATCH,
                    f"Wazuh rule references affected software '{kw}'")
    return (0, "")


# ===========================================================================
# Boost 2 — historical alerts (pluggable backend)
# ===========================================================================
class FlatFileAlertHistory:
    """Prototype backend: scan the flat alerts.json log.

    NOTE: alerts.json is rotated by Wazuh, so it holds only recent alerts
    (older ones roll off to logs/alerts/YYYY/). 'last N days' is therefore
    bounded by whatever is still in the live file. The OpenSearch backend
    solves this in production with real retention.
    """

    def __init__(self):
        self._blob = None

    def _load(self) -> str:
        if self._blob is not None:
            return self._blob
        path = config.WAZUH_ALERTS_JSON
        try:
            with open(path, "r", errors="ignore") as f:
                self._blob = f.read().lower()
        except (PermissionError, FileNotFoundError, OSError) as e:
            print(f"  [boost] note: cannot read {path} ({e.__class__.__name__}) "
                  "— alert-history boost disabled this run")
            self._blob = ""
        return self._blob

    def count_recent(self, keywords: list, days: int) -> int:
        """Count how many keywords appear in the recent alert log.

        Prototype simplification: substring presence in the live file (which
        already only contains recent alerts). Returns the number of distinct
        keywords seen, used as a yes/no-ish signal.
        """
        blob = self._load()
        if not blob:
            return 0
        return sum(1 for kw in keywords if kw in blob)


class OpenSearchAlertHistory:
    """Production backend: query the Wazuh Indexer (OpenSearch) _search API.

    Stubbed: requires a running indexer on :9200 (not present on this
    single-node prototype). Wired behind the same interface so enabling it is
    a one-line config change once the indexer stack is deployed.
    """

    INDEX = "wazuh-alerts-*"
    URL   = "https://localhost:9200"

    def count_recent(self, keywords: list, days: int) -> int:
        if not keywords:
            return 0
        import requests
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [{"range": {"timestamp": {"gte": since}}}],
                    "should": [
                        {"match": {"full_log": kw}} for kw in keywords
                    ] + [
                        {"match": {"rule.description": kw}} for kw in keywords
                    ],
                    "minimum_should_match": 1,
                }
            },
        }
        try:
            resp = requests.post(
                f"{self.URL}/{self.INDEX}/_search",
                json=query,
                auth=(  # credentials from env in a real deployment
                    __import__("os").environ.get("INDEXER_USER", "admin"),
                    __import__("os").environ.get("INDEXER_PASS", ""),
                ),
                verify=False,
                timeout=config.HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json().get("hits", {}).get("total", {}).get("value", 0)
        except Exception as e:
            print(f"  [boost] OpenSearch query failed (non-fatal): {e}")
            return 0


def _get_alert_backend():
    if config.ALERT_HISTORY_BACKEND == "opensearch":
        return OpenSearchAlertHistory()
    return FlatFileAlertHistory()


_alert_backend = None


def check_alert_history(cve: dict) -> tuple:
    """Return (boost_points, reason)."""
    global _alert_backend
    if _alert_backend is None:
        _alert_backend = _get_alert_backend()

    keywords = extract_software(cve)
    if not keywords:
        return (0, "")

    hits = _alert_backend.count_recent(keywords, config.ALERT_HISTORY_DAYS)
    if hits > 0:
        return (config.BOOST_ALERT_HISTORY,
                f"environment fired alerts matching affected software "
                f"({hits} keyword hit(s) in last {config.ALERT_HISTORY_DAYS}d)")
    return (0, "")


# ===========================================================================
# Combined
# ===========================================================================
def compute_boost(cve: dict) -> tuple:
    """Return (total_boost, combined_reason)."""
    pts1, r1 = check_wazuh_rules(cve)
    pts2, r2 = check_alert_history(cve)
    reasons = [r for r in (r1, r2) if r]
    return (pts1 + pts2, "; ".join(reasons))
