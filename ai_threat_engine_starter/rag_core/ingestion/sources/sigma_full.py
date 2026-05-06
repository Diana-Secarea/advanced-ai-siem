#!/usr/bin/env python3
"""
Full SigmaHQ rule ingestion.

Downloads the complete SigmaHQ master archive from GitHub (~50 MB zip),
parses all YAML rule files, and saves a flat JSON catalog.

Coverage: Linux, Windows, Cloud, Network, Web, Application, Proxy, Firewall, DNS
Result:   3,000+ detection rules with ATT&CK technique tags

Set GITHUB_TOKEN env var to avoid GitHub rate limits (5,000 req/hr vs 60/hr).

Output: threat_intel/sigma/rules.json

Run standalone:
    python3 sources/sigma_full.py [--refresh]
"""

import io
import json
import os
import sys
import zipfile
import requests
from datetime import datetime
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("WARNING: PyYAML not installed. Run: pip install pyyaml")

SIGMA_ARCHIVE_URL = (
    "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
)

BASE_DIR    = Path(__file__).resolve().parents[3]
STORAGE_DIR = BASE_DIR / "threat_intel" / "sigma"

# Categories to include (subset of sigma/rules/<category>/)
# Empty list = include all
INCLUDE_CATEGORIES = [
    "linux", "windows", "cloud", "network", "web",
    "application", "proxy", "firewall", "dns",
]

# Skip deprecated rules
SKIP_STATUSES = {"deprecated", "unsupported"}


def _github_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def ingest(force_refresh: bool = False) -> list:
    """
    Download SigmaHQ archive and return a normalized list of rule dicts.
    Each rule includes: id, title, description, level, category, logsource,
    detection_summary, tags, attack_tags, author, date, source, file_path.
    """
    if not HAS_YAML:
        print("  [sigma] Cannot ingest without PyYAML. Run: pip install pyyaml")
        return []

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = STORAGE_DIR / "rules.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [sigma] Using cached ({data.get('count', 0)} rules)")
        return data.get("rules", [])

    print("  [sigma] Downloading SigmaHQ master archive (~50 MB)...")
    try:
        resp = requests.get(
            SIGMA_ARCHIVE_URL,
            timeout=180,
            headers=_github_headers(),
        )
        resp.raise_for_status()
        archive_bytes = resp.content
    except Exception as e:
        print(f"  [sigma] ERROR downloading archive: {e}")
        return []

    print("  [sigma] Parsing rule files...")
    rules = []
    skipped_status = 0
    skipped_category = 0
    parse_errors = 0

    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
        # Rule files are at: sigma-master/rules/<category>/.../*.yml
        rule_files = [
            name for name in zf.namelist()
            if "/rules/" in name and name.endswith(".yml")
        ]

        for name in rule_files:
            # Derive category from path: sigma-master/rules/<category>/...
            parts = name.split("/")
            # parts[0]=sigma-master, parts[1]=rules, parts[2]=category
            category = parts[2] if len(parts) > 2 else ""

            if INCLUDE_CATEGORIES and category not in INCLUDE_CATEGORIES:
                skipped_category += 1
                continue

            try:
                raw_text = zf.read(name).decode("utf-8", errors="replace")
                rule_dict = yaml.safe_load(raw_text)

                if not isinstance(rule_dict, dict):
                    continue

                status = rule_dict.get("status", "")
                if status in SKIP_STATUSES:
                    skipped_status += 1
                    continue

                title       = rule_dict.get("title", "")
                level       = rule_dict.get("level", "")
                description = (rule_dict.get("description") or "")[:500]
                tags        = rule_dict.get("tags") or []
                author      = rule_dict.get("author", "")
                date_val    = str(rule_dict.get("date", ""))
                logsource   = rule_dict.get("logsource") or {}
                detection   = rule_dict.get("detection") or {}

                attack_tags = [t for t in tags if t.lower().startswith("attack.")]

                rules.append({
                    "id":                f"sigma-{Path(name).stem}",
                    "title":             title,
                    "description":       description,
                    "level":             level,
                    "status":            status,
                    "category":          category,
                    "logsource":         logsource,
                    "detection_summary": str(detection)[:400],
                    "tags":              tags,
                    "attack_tags":       attack_tags,
                    "author":            author,
                    "date":              date_val,
                    "source":            "SigmaHQ",
                    "file_path":         name,
                    "ingested_at":       datetime.utcnow().isoformat(),
                })

            except Exception:
                parse_errors += 1
                continue

    except Exception as e:
        print(f"  [sigma] ERROR reading archive: {e}")
        return []

    # Stats
    by_level = {}
    by_cat   = {}
    for r in rules:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1

    data = {
        "rules":        rules,
        "count":        len(rules),
        "by_category":  by_cat,
        "by_level":     by_level,
        "last_updated": datetime.utcnow().isoformat(),
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  [sigma] Ingested {len(rules)} rules "
          f"(skipped: {skipped_status} deprecated, "
          f"{skipped_category} out-of-category, "
          f"{parse_errors} parse errors)")
    return rules


if __name__ == "__main__":
    force = "--refresh" in sys.argv
    records = ingest(force_refresh=force)

    print(f"\nTotal: {len(records)} Sigma rules")

    by_cat = {}
    by_level = {}
    for r in records:
        by_cat[r["category"]]   = by_cat.get(r["category"], 0) + 1
        by_level[r["level"]]    = by_level.get(r["level"], 0) + 1

    print("\nBy category:")
    for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {cat:<20} {count}")

    print("\nBy level:")
    for level, count in sorted(by_level.items(), key=lambda x: -x[1]):
        print(f"  {level:<20} {count}")
