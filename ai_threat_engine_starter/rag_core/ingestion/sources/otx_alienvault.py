#!/usr/bin/env python3
"""
OTX AlienVault threat intelligence pulse ingestion.

Fetches recent threat pulses from OTX (malware families, IOC context,
campaign summaries, attacker tools and techniques).

API key setup:
  1. Register free at https://otx.alienvault.com/
  2. Copy your key from https://otx.alienvault.com/api
  3. Export it: export OTX_API_KEY=your_key_here

Without a key the script falls back to the public /activity feed,
which returns fewer pulses and has stricter rate limits.

Output: threat_intel/otx/pulses.json

Run standalone:
    python3 sources/otx_alienvault.py [--refresh] [--days N] [--max N]
"""

import json
import os
import sys
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path

OTX_BASE = "https://otx.alienvault.com/api/v1"

BASE_DIR    = Path(__file__).resolve().parents[3]
STORAGE_DIR = BASE_DIR / "threat_intel" / "otx"

# Defaults (overridable via CLI args)
DEFAULT_DAYS_BACK  = 30
DEFAULT_MAX_PULSES = 500
PAGE_SIZE          = 20


def _headers() -> dict:
    api_key = os.environ.get("OTX_API_KEY", "").strip()
    h = {"Content-Type": "application/json"}
    if api_key:
        h["X-OTX-API-KEY"] = api_key
    return h


def _ioc_summary(indicators: list) -> dict:
    """Return a count-by-type dict for a pulse's indicators."""
    counts: dict = {}
    for ind in indicators:
        t = ind.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


def ingest(
    force_refresh: bool = False,
    days_back: int = DEFAULT_DAYS_BACK,
    max_pulses: int = DEFAULT_MAX_PULSES,
) -> list:
    """
    Fetch OTX pulses from the last `days_back` days.
    Returns a list of normalized pulse dicts.
    """
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = STORAGE_DIR / "pulses.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [otx] Using cached ({data.get('count', 0)} pulses)")
        return data.get("pulses", [])

    api_key = os.environ.get("OTX_API_KEY", "").strip()
    if not api_key:
        print("  [otx] WARNING: OTX_API_KEY not set.")
        print("        Free key at: https://otx.alienvault.com/ → API menu")
        print("        export OTX_API_KEY=your_key  then re-run.")

    since   = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    headers = _headers()
    url     = (
        f"{OTX_BASE}/pulses/subscribed"
        if api_key
        else f"{OTX_BASE}/pulses/activity"
    )

    print(f"  [otx] Fetching pulses (last {days_back} days, max {max_pulses})...")

    pulses = []
    page   = 1

    while len(pulses) < max_pulses:
        params = {
            "modified_since": since,
            "limit":          PAGE_SIZE,
            "page":           page,
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)

            # Try public endpoint if auth fails
            if resp.status_code in (401, 403):
                if url.endswith("subscribed"):
                    print("  [otx] Auth failed; retrying with public endpoint.")
                    url = f"{OTX_BASE}/pulses/activity"
                    resp = requests.get(url, headers={}, params=params, timeout=30)
                else:
                    print(f"  [otx] Access denied (HTTP {resp.status_code}). Stopping.")
                    break

            resp.raise_for_status()
            data = resp.json()

        except Exception as e:
            print(f"  [otx] ERROR on page {page}: {e}")
            break

        results = data.get("results", [])
        if not results:
            break

        for pulse in results:
            attack_ids = [
                a.get("id", "") for a in (pulse.get("attack_ids") or [])
            ]
            malware_families = [
                m.get("display_name", m.get("id", ""))
                for m in (pulse.get("malware_families") or [])
            ]

            pulses.append({
                "id":                 pulse.get("id", ""),
                "name":               pulse.get("name", ""),
                "description":        (pulse.get("description") or "")[:500],
                "author":             pulse.get("author_name", ""),
                "tags":               pulse.get("tags") or [],
                "targeted_countries": pulse.get("targeted_countries") or [],
                "malware_families":   malware_families,
                "attack_ids":         attack_ids,
                "ioc_count":          len(pulse.get("indicators") or []),
                "ioc_types":          _ioc_summary(pulse.get("indicators") or []),
                "tlp":                pulse.get("tlp", "white"),
                "created":            pulse.get("created", ""),
                "modified":           pulse.get("modified", ""),
                "source":             "OTX_AlienVault",
                "ingested_at":        datetime.utcnow().isoformat(),
            })

        if not data.get("next"):
            break
        page += 1

    saved = {
        "pulses":       pulses,
        "count":        len(pulses),
        "days_fetched": days_back,
        "last_updated": datetime.utcnow().isoformat(),
    }
    with open(out_file, "w") as f:
        json.dump(saved, f, indent=2)

    total_iocs = sum(p["ioc_count"] for p in pulses)
    print(f"  [otx] Ingested {len(pulses)} pulses ({total_iocs} total IOCs)")
    return pulses


if __name__ == "__main__":
    force    = "--refresh" in sys.argv
    days     = DEFAULT_DAYS_BACK
    max_p    = DEFAULT_MAX_PULSES

    # Simple CLI: --days N --max N
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--days" and i + 1 < len(args):
            days = int(args[i + 1])
        if arg == "--max" and i + 1 < len(args):
            max_p = int(args[i + 1])

    records = ingest(force_refresh=force, days_back=days, max_pulses=max_p)

    print(f"\nTotal: {len(records)} OTX pulses")
    if records:
        # Top malware families
        families: dict = {}
        for p in records:
            for fam in p.get("malware_families", []):
                families[fam] = families.get(fam, 0) + 1
        if families:
            print("\nTop malware families:")
            for fam, count in sorted(families.items(), key=lambda x: -x[1])[:10]:
                print(f"  {fam}: {count}")
