#!/usr/bin/env python3
"""
MITRE ATT&CK Groups and Software ingestion.

Parses the same STIX bundle used for techniques, extracting:
  - intrusion-set  → threat actor groups (APT28, Lazarus, Sandworm, etc.)
  - malware + tool → software (Mimikatz, Cobalt Strike, Metasploit, etc.)
  - relationship   → group-to-technique and software-to-technique links

The STIX bundle is cached alongside the existing attack_techniques.json so
it is only downloaded once even when both this module and the technique
ingestion run in sequence.

Output:
  threat_intel/mitre_groups/groups.json
  threat_intel/mitre_software/software.json

Run standalone:
    python3 sources/mitre_groups_software.py [--refresh]
"""

import json
import sys
import requests
from datetime import datetime
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master"
    "/enterprise-attack/enterprise-attack.json"
)

BASE_DIR = Path(__file__).resolve().parents[3]
GROUPS_DIR   = BASE_DIR / "threat_intel" / "mitre_groups"
SOFTWARE_DIR = BASE_DIR / "threat_intel" / "mitre_software"
STIX_CACHE   = BASE_DIR / "threat_intel" / "attack" / "stix_bundle.json"


# ---------------------------------------------------------------------------
# STIX bundle helpers
# ---------------------------------------------------------------------------

def _load_stix(force_refresh: bool = False) -> dict:
    """Download or return the cached STIX bundle (~20 MB)."""
    STIX_CACHE.parent.mkdir(parents=True, exist_ok=True)

    if STIX_CACHE.exists() and not force_refresh:
        print("  [mitre] Using cached STIX bundle")
        with open(STIX_CACHE) as f:
            return json.load(f)

    print("  [mitre] Downloading STIX bundle (~20 MB)...")
    try:
        resp = requests.get(STIX_URL, timeout=120)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  [mitre] ERROR downloading STIX bundle: {e}")
        return {"objects": []}

    with open(STIX_CACHE, "w") as f:
        json.dump(data, f)

    return data


def _id_map(objects: list) -> dict:
    """Map STIX id → object for fast relationship lookups."""
    return {obj["id"]: obj for obj in objects if "id" in obj}


def _mitre_id(obj: dict) -> str:
    """Extract the ATT&CK ID (e.g. G0007, S0002) from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _technique_ids_used_by(stix_id: str, objects: list, id_map: dict) -> list:
    """Return ATT&CK technique IDs used by a given group or software STIX ID."""
    tids = []
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref") == stix_id
        ):
            tgt = id_map.get(obj.get("target_ref", ""), {})
            if tgt.get("type") == "attack-pattern":
                tid = _mitre_id(tgt)
                if tid:
                    tids.append(tid)
    return tids


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

def ingest_groups(force_refresh: bool = False) -> list:
    """Extract threat actor groups from the ATT&CK STIX bundle."""
    GROUPS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = GROUPS_DIR / "groups.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [mitre_groups] Using cached ({data.get('count', 0)} groups)")
        return data.get("groups", [])

    stix    = _load_stix(force_refresh)
    objects = stix.get("objects", [])
    imap    = _id_map(objects)

    groups = []
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        gid        = _mitre_id(obj)
        aliases    = obj.get("aliases", [])
        techniques = _technique_ids_used_by(obj["id"], objects, imap)

        groups.append({
            "id":             gid,
            "stix_id":        obj["id"],
            "name":           obj.get("name", ""),
            "aliases":        aliases,
            "description":    obj.get("description", ""),
            "techniques":     techniques,
            "technique_count": len(techniques),
            "source":         "MITRE_ATTACK",
            "ingested_at":    datetime.utcnow().isoformat(),
        })

    data = {
        "groups":       groups,
        "count":        len(groups),
        "last_updated": datetime.utcnow().isoformat(),
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  [mitre_groups] Ingested {len(groups)} threat actor groups")
    return groups


# ---------------------------------------------------------------------------
# Software (malware + tools)
# ---------------------------------------------------------------------------

def ingest_software(force_refresh: bool = False) -> list:
    """Extract malware and tools from the ATT&CK STIX bundle."""
    SOFTWARE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = SOFTWARE_DIR / "software.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [mitre_software] Using cached ({data.get('count', 0)} items)")
        return data.get("software", [])

    stix    = _load_stix(force_refresh)
    objects = stix.get("objects", [])
    imap    = _id_map(objects)

    software = []
    for obj in objects:
        if obj.get("type") not in ("malware", "tool"):
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        sid        = _mitre_id(obj)
        techniques = _technique_ids_used_by(obj["id"], objects, imap)

        software.append({
            "id":             sid,
            "stix_id":        obj["id"],
            "name":           obj.get("name", ""),
            "type":           obj.get("type", ""),     # 'malware' or 'tool'
            "aliases":        obj.get("x_mitre_aliases", []),
            "description":    obj.get("description", ""),
            "platforms":      obj.get("x_mitre_platforms", []),
            "techniques":     techniques,
            "technique_count": len(techniques),
            "source":         "MITRE_ATTACK",
            "ingested_at":    datetime.utcnow().isoformat(),
        })

    data = {
        "software":     software,
        "count":        len(software),
        "last_updated": datetime.utcnow().isoformat(),
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    malware_count = sum(1 for s in software if s["type"] == "malware")
    tool_count    = sum(1 for s in software if s["type"] == "tool")
    print(f"  [mitre_software] Ingested {len(software)} items ({malware_count} malware, {tool_count} tools)")
    return software


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------

def ingest(force_refresh: bool = False) -> dict:
    """Ingest both groups and software. Returns {'groups': [...], 'software': [...]}."""
    return {
        "groups":   ingest_groups(force_refresh),
        "software": ingest_software(force_refresh),
    }


if __name__ == "__main__":
    force   = "--refresh" in sys.argv
    results = ingest(force_refresh=force)
    groups  = results["groups"]
    software = results["software"]

    print(f"\nGroups:   {len(groups)}")
    print(f"Software: {len(software)}")

    if groups:
        g = max(groups, key=lambda x: x["technique_count"])
        print(f"\nMost-active group:    {g['id']} {g['name']} "
              f"({g['technique_count']} techniques, aliases: {g['aliases'][:3]})")

    if software:
        s = max(software, key=lambda x: x["technique_count"])
        print(f"Most-used software:   {s['id']} {s['name']} "
              f"({s['type']}, {s['technique_count']} techniques)")
