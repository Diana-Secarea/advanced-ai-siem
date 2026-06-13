"""Configuration for the scheduled CVE ingestion agent.

All values can be overridden via environment variables.
"""
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Deployment profile — the context the LLM scores each CVE against.
# This is what makes scores environment-specific rather than raw CVSS.
# ---------------------------------------------------------------------------
ENV_CONTEXT = """\
Deployment profile:
- OS: Linux (Debian-based) host monitored by a Wazuh SIEM (single node).
- Exposed / monitored services: OpenSSH (remote login), web services
  (HTTP, WordPress/PHP), and file-integrity monitoring on /etc, /usr/bin,
  /usr/sbin (system integrity).
- NOT present: Windows, Active Directory, macOS, industrial/ICS/SCADA,
  cloud IAM, Kubernetes, mobile.

Task: score how relevant this CVE is to THIS environment's attack surface,
from 0 (irrelevant — affects software/platforms not present) to 10
(critical — directly affects an exposed service like OpenSSH or the web
stack). A Windows-only or ICS-only CVE should score near 0. An OpenSSH or
web-server CVE should score high.
"""

# ---------------------------------------------------------------------------
# Scoring thresholds  (final_score = min(base_score + boost, 10))
# ---------------------------------------------------------------------------
SCORE_AUTO_INDEX = int(os.environ.get("CVE_SCORE_AUTO_INDEX", "7"))   # >= -> index
SCORE_QUEUE_MIN  = int(os.environ.get("CVE_SCORE_QUEUE_MIN",  "4"))   # >= -> queue
#                                                              else  -> drop

# Boost weights (added to base_score, result capped at 10)
BOOST_RULE_MATCH    = int(os.environ.get("CVE_BOOST_RULE",  "3"))  # Wazuh rule exists
BOOST_ALERT_HISTORY = int(os.environ.get("CVE_BOOST_ALERT", "2"))  # seen in alert history

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
NVD_API_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY   = os.environ.get("NVD_API_KEY", "")          # optional; raises rate limit
NVD_DAYS_BACK = int(os.environ.get("CVE_NVD_DAYS_BACK", "1"))
NVD_MAX_RESULTS = int(os.environ.get("CVE_NVD_MAX_RESULTS", "200"))

CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

HTTP_TIMEOUT  = int(os.environ.get("CVE_HTTP_TIMEOUT", "60"))

# ---------------------------------------------------------------------------
# Environment evidence sources (prototype: flat files; production: Indexer)
# ---------------------------------------------------------------------------
WAZUH_RULES_DIRS = [
    Path(os.environ.get("WAZUH_RULES_DIR", "/var/ossec/etc/rules")),
    Path("/var/ossec/ruleset/rules"),
]
WAZUH_ALERTS_JSON = Path(
    os.environ.get("WAZUH_ALERTS_JSON", "/var/ossec/logs/alerts/alerts.json")
)
ALERT_HISTORY_DAYS = int(os.environ.get("CVE_ALERT_HISTORY_DAYS", "90"))

# Which alert-history backend to use: "flatfile" (prototype) or "opensearch"
# (production, requires a running Wazuh Indexer on :9200 — see boosts.py).
ALERT_HISTORY_BACKEND = os.environ.get("CVE_ALERT_BACKEND", "flatfile")

# ---------------------------------------------------------------------------
# LLM (Ollama) — same endpoint/model the Flask server uses
# ---------------------------------------------------------------------------
OLLAMA_URL   = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
