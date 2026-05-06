#!/usr/bin/env python3
"""
MITRE D3FEND defensive technique ingestion.

D3FEND maps *defensive* countermeasures to ATT&CK offensive techniques,
answering "how do I stop or detect this attack?".

API endpoints tried in order:
  1. https://d3fend.mitre.org/api/technique/all.json   (REST, preferred)
  2. https://d3fend.mitre.org/ontologies/d3fend.json   (JSON-LD ontology, fallback)

Output: threat_intel/mitre_d3fend/techniques.json

Run standalone:
    python3 sources/mitre_d3fend.py [--refresh]
"""

import json
import sys
import requests
from datetime import datetime
from pathlib import Path

D3FEND_API_URL      = "https://d3fend.mitre.org/api/technique/all.json"
D3FEND_ONTOLOGY_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"

BASE_DIR    = Path(__file__).resolve().parents[3]
STORAGE_DIR = BASE_DIR / "threat_intel" / "mitre_d3fend"


def _parse_api_response(raw) -> list:
    """Parse the REST API response format."""
    technique_list = (
        raw if isinstance(raw, list)
        else raw.get("techniques", raw.get("results", []))
    )

    techniques = []
    for entry in technique_list:
        def_id = (
            entry.get("def_tech_id")
            or entry.get("d3fend_id")
            or entry.get("id", "")
        )
        name = (
            entry.get("def_tech_label")
            or entry.get("name")
            or entry.get("label", "")
        )
        description = (
            entry.get("def_tech_description")
            or entry.get("description")
            or entry.get("comment", "")
        )
        tactic = (
            entry.get("top_def_tactic_label")
            or entry.get("tactic", "")
        )
        offends = entry.get("off_tech_id") or entry.get("attack_techniques", [])
        if isinstance(offends, str):
            offends = [offends]

        if not def_id or not name:
            continue

        techniques.append({
            "id":                        def_id,
            "name":                      name,
            "tactic":                    tactic,
            "description":               description,
            "attack_techniques_countered": list(offends) if offends else [],
            "source":                    "MITRE_D3FEND",
            "ingested_at":               datetime.utcnow().isoformat(),
        })

    return techniques


def _parse_ontology(raw: dict) -> list:
    """
    Parse the JSON-LD ontology as a fallback.
    The ontology uses @graph with @type filtering.
    """
    graph = raw.get("@graph", [])

    # Collect only D3FEND technique nodes
    techniques = []
    for node in graph:
        node_types = node.get("@type", [])
        if isinstance(node_types, str):
            node_types = [node_types]

        # Filter for technique nodes
        if not any("Technique" in t or "DefensiveTechnique" in t for t in node_types):
            continue

        def_id = node.get("d3f:d3fend-id", node.get("@id", "")).split("/")[-1]
        name   = node.get("rdfs:label", "")
        if isinstance(name, dict):
            name = name.get("@value", "")
        desc = node.get("d3f:definition", node.get("rdfs:comment", ""))
        if isinstance(desc, dict):
            desc = desc.get("@value", "")

        if not def_id or not name:
            continue

        techniques.append({
            "id":                        def_id,
            "name":                      name,
            "tactic":                    "",
            "description":               str(desc)[:500],
            "attack_techniques_countered": [],
            "source":                    "MITRE_D3FEND",
            "ingested_at":               datetime.utcnow().isoformat(),
        })

    return techniques


def ingest(force_refresh: bool = False) -> list:
    """
    Fetch D3FEND techniques and return normalized records.
    Tries the REST API first, falls back to the ontology JSON.
    """
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = STORAGE_DIR / "techniques.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [d3fend] Using cached ({data.get('count', 0)} techniques)")
        return data.get("techniques", [])

    techniques = []

    # --- Attempt 1: REST API ---
    print("  [d3fend] Trying D3FEND REST API...")
    try:
        resp = requests.get(D3FEND_API_URL, timeout=30,
                            headers={"Accept": "application/json"})
        if resp.status_code == 200:
            raw = resp.json()
            techniques = _parse_api_response(raw)
            if techniques:
                print(f"  [d3fend] REST API returned {len(techniques)} techniques")
    except Exception as e:
        print(f"  [d3fend] REST API failed: {e}")

    # --- Attempt 2: Ontology JSON fallback ---
    if not techniques:
        print("  [d3fend] Falling back to ontology JSON (~30 MB)...")
        try:
            resp = requests.get(D3FEND_ONTOLOGY_URL, timeout=120,
                                headers={"Accept": "application/json"})
            resp.raise_for_status()
            raw = resp.json()
            techniques = _parse_ontology(raw)
            print(f"  [d3fend] Ontology returned {len(techniques)} techniques")
        except Exception as e:
            print(f"  [d3fend] Ontology fetch also failed: {e}")
            return []

    data = {
        "techniques":   techniques,
        "count":        len(techniques),
        "last_updated": datetime.utcnow().isoformat(),
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  [d3fend] Ingested {len(techniques)} D3FEND techniques")
    return techniques


if __name__ == "__main__":
    force   = "--refresh" in sys.argv
    records = ingest(force_refresh=force)

    print(f"\nTotal: {len(records)} D3FEND techniques")
    tactics = {}
    for t in records:
        tac = t.get("tactic") or "unknown"
        tactics[tac] = tactics.get(tac, 0) + 1
    for tac, count in sorted(tactics.items(), key=lambda x: -x[1]):
        print(f"  {tac}: {count}")

    if records:
        example = next((t for t in records if t.get("attack_techniques_countered")), records[0])
        print(f"\nExample: {example['id']} | {example['name']}")
        if example.get("attack_techniques_countered"):
            print(f"  Counters: {example['attack_techniques_countered'][:5]}")
