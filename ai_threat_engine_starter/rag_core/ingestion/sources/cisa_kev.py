#!/usr/bin/env python3
"""
CISA Known Exploited Vulnerabilities (KEV) Catalog ingestion.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Free JSON feed, updated daily. ~1,100+ CVEs actively exploited in the wild.

Fields per entry:
  cveID, vendorProject, product, vulnerabilityName, dateAdded,
  shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse

Output: threat_intel/cisa_kev/kev_catalog.json

Run standalone:
    python3 sources/cisa_kev.py [--refresh]
"""

import json
import sys
import requests
from datetime import datetime
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ai_threat_engine_starter/ (4 levels up from this file)
BASE_DIR = Path(__file__).resolve().parents[3]
STORAGE_DIR = BASE_DIR / "threat_intel" / "cisa_kev"


def ingest(force_refresh: bool = False) -> list:
    """
    Fetch CISA KEV catalog and return a list of normalized vulnerability dicts.
    Caches results to disk; pass force_refresh=True to re-download.
    """
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = STORAGE_DIR / "kev_catalog.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [cisa_kev] Using cached data (updated: {data.get('last_updated', 'unknown')})")
        return data.get("vulnerabilities", [])

    print("  [cisa_kev] Fetching from CISA KEV feed...")
    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as e:
        print(f"  [cisa_kev] ERROR: {e}")
        return []

    vulns = []
    for entry in raw.get("vulnerabilities", []):
        cve_id = entry.get("cveID", "")
        ransomware_flag = entry.get("knownRansomwareCampaignUse", "Unknown")
        known_ransomware = ransomware_flag.lower() in ("known", "yes", "true")

        vulns.append({
            "id": cve_id,
            "cve_id": cve_id,
            "vendor_project": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "name": entry.get("vulnerabilityName", ""),
            "date_added": entry.get("dateAdded", ""),
            "due_date": entry.get("dueDate", ""),
            "description": entry.get("shortDescription", ""),
            "required_action": entry.get("requiredAction", ""),
            "known_ransomware": known_ransomware,
            "cwes": entry.get("cwes", []),
            "source": "CISA_KEV",
            "ingested_at": datetime.utcnow().isoformat(),
        })

    catalog = {
        "catalog_version": raw.get("catalogVersion", ""),
        "date_released": raw.get("dateReleased", ""),
        "count": len(vulns),
        "last_updated": datetime.utcnow().isoformat(),
        "vulnerabilities": vulns,
    }
    with open(out_file, "w") as f:
        json.dump(catalog, f, indent=2)

    ransomware_count = sum(1 for v in vulns if v["known_ransomware"])
    print(f"  [cisa_kev] Ingested {len(vulns)} KEV entries ({ransomware_count} linked to ransomware)")
    return vulns


if __name__ == "__main__":
    force = "--refresh" in sys.argv
    records = ingest(force_refresh=force)
    print(f"\nTotal: {len(records)} CISA KEV entries")
    if records:
        r = records[-1]  # Most recently added
        print(f"Latest: {r['cve_id']} | {r['name']}")
        print(f"  Vendor: {r['vendor_project']} | Product: {r['product']}")
        print(f"  Ransomware: {r['known_ransomware']} | Added: {r['date_added']}")
