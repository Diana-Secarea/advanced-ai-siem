#!/usr/bin/env python3
"""
Ingest all threat intelligence sources into threat_intel/.

Existing sources (via ThreatIntelIngestion class):
  1. MITRE ATT&CK techniques
  2. Wazuh vendor advisories (GitHub releases, blog, docs)
  3. IOCs
  4. YARA rules (Yara-Rules/rules GitHub repo)
  5. Internal TI notes

New sources (via sources/ modules):
  6. CISA KEV — actively exploited CVE catalog
  7. MITRE ATT&CK Groups — threat actor groups (APT28, Lazarus, etc.)
  8. MITRE ATT&CK Software — malware and tools (Mimikatz, Cobalt Strike, etc.)
  9. MITRE D3FEND — defensive countermeasures mapped to ATT&CK
 10. Sigma rules (full SigmaHQ) — 3,000+ detection rules
 11. CIS Controls v8 + Wazuh SCA checks
 12. OTX AlienVault pulses (requires OTX_API_KEY env var)

Usage:
    python3 ingest_all.py [--refresh-all] [--only SOURCE]

    --refresh-all    Force re-download of all cached sources
    --only SOURCE    Run only one source: attack, vendor, ioc, yara,
                     cisa_kev, groups, software, d3fend, sigma, cis, otx
"""

import sys
import argparse
from pathlib import Path

# Add rag_core/ to path for intra-package imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Add sources/ to path for direct source module imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ingestion.threat_intel_ingestion import ThreatIntelIngestion
from ingestion.sources import (
    cisa_kev,
    mitre_groups_software,
    mitre_d3fend,
    sigma_full,
    cis_controls,
    otx_alienvault,
)


def _section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)


def main():
    parser = argparse.ArgumentParser(description="Ingest all threat intelligence sources")
    parser.add_argument("--refresh-all", action="store_true",
                        help="Force re-download of all cached sources")
    parser.add_argument("--only", metavar="SOURCE",
                        help="Run only one source (attack, vendor, ioc, yara, "
                             "cisa_kev, groups, software, d3fend, sigma, cis, otx)")
    args = parser.parse_args()

    refresh = args.refresh_all
    only    = args.only

    print("=" * 60)
    print("  Threat Intelligence Ingestion Pipeline")
    print("=" * 60)

    # -----------------------------------------------------------------------
    # Existing sources via ThreatIntelIngestion
    # -----------------------------------------------------------------------
    ingester = ThreatIntelIngestion()

    counts = {}

    if not only or only == "attack":
        _section("1. MITRE ATT&CK Techniques")
        items = ingester.ingest_mitre_attack(force_refresh=refresh)
        counts["attack_techniques"] = len(items)
        print(f"  => {len(items)} techniques")

    if not only or only == "vendor":
        _section("2. Wazuh Vendor Advisories")
        wazuh_sources = [
            {"name": "Wazuh GitHub Releases", "url": "https://github.com/wazuh/wazuh/releases",
             "type": "GITHUB_API"},
            {"name": "Wazuh Blog",            "url": "https://wazuh.com/blog",
             "type": "BLOG"},
            {"name": "Wazuh Documentation",   "url": "https://documentation.wazuh.com/current/security/index.html",
             "type": "DOCS"},
        ]
        items = ingester.ingest_vendor_advisories(sources=wazuh_sources)
        counts["vendor_advisories"] = len(items)
        print(f"  => {len(items)} advisories")

    if not only or only == "ioc":
        _section("3. IOC Indicators")
        items = ingester.ingest_iocs()
        counts["iocs"] = len(items)
        print(f"  => {len(items)} IOCs")

    if not only or only == "yara":
        _section("4. YARA Rules")
        items = ingester.ingest_yara_rules()
        counts["yara_rules"] = len(items)
        print(f"  => {len(items)} rules")

    # -----------------------------------------------------------------------
    # New sources via sources/ modules
    # -----------------------------------------------------------------------

    if not only or only == "cisa_kev":
        _section("5. CISA Known Exploited Vulnerabilities (KEV)")
        items = cisa_kev.ingest(force_refresh=refresh)
        counts["cisa_kev"] = len(items)
        ransomware_count = sum(1 for v in items if v.get("known_ransomware"))
        print(f"  => {len(items)} KEV entries ({ransomware_count} ransomware-linked)")

    if not only or only in ("groups", "software"):
        _section("6+7. MITRE ATT&CK Groups and Software")
        result = mitre_groups_software.ingest(force_refresh=refresh)
        counts["mitre_groups"]   = len(result["groups"])
        counts["mitre_software"] = len(result["software"])
        print(f"  => {len(result['groups'])} threat actor groups")
        print(f"  => {len(result['software'])} malware/tools")

    if not only or only == "d3fend":
        _section("8. MITRE D3FEND Defensive Techniques")
        items = mitre_d3fend.ingest(force_refresh=refresh)
        counts["d3fend"] = len(items)
        print(f"  => {len(items)} D3FEND techniques")

    if not only or only == "sigma":
        _section("9. Sigma Rules (full SigmaHQ)")
        items = sigma_full.ingest(force_refresh=refresh)
        counts["sigma_rules"] = len(items)
        print(f"  => {len(items)} Sigma rules")

    if not only or only == "cis":
        _section("10. CIS Controls v8 + Wazuh SCA")
        items = cis_controls.ingest(force_refresh=refresh)
        counts["cis_controls"] = len(items)
        print(f"  => {len(items)} CIS control records")

    if not only or only == "otx":
        _section("11. OTX AlienVault Pulses")
        items = otx_alienvault.ingest(force_refresh=refresh)
        counts["otx_pulses"] = len(items)
        print(f"  => {len(items)} OTX pulses")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    _section("Ingestion Summary")
    total = 0
    for source, count in counts.items():
        print(f"  {source:<25} {count:>6}")
        total += count
    print(f"  {'─' * 33}")
    print(f"  {'TOTAL':<25} {total:>6}")

    threat_intel_path = Path(__file__).resolve().parents[2] / "threat_intel"
    print(f"\n  Data stored in: {threat_intel_path}/")
    print("\n  Next step — rebuild the Qdrant index:")
    print("    python3 -m rag_core.indexing.qdrant_indexer --wipe")
    print()


if __name__ == "__main__":
    main()
