"""
Qdrant + PostgreSQL indexer.

Reads from the JSON source files in threat_intel/, writes to:
  - PostgreSQL threat_intel table  (raw records, queryable)
  - Qdrant wazuh_threat_intel      (vector embeddings, searchable)

Run:
    python3 -m rag_core.indexing.qdrant_indexer
"""

import json
import sys
from pathlib import Path

# Allow running as script
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rag_core.database.postgres_client import upsert_threat_intel, log_ingestion_start, log_ingestion_done, ping as pg_ping
from rag_core.database.qdrant_store import QdrantStore
from rag_core.database.config import COLLECTION_THREAT_INTEL

# Reuse the episode-builder functions from the old indexer
from rag_core.indexing.threat_intel_indexer import (
    load_attack_techniques,
    load_yara_rules,
    load_vendor_advisories,
    load_cisa_kev,
    load_mitre_groups,
    load_mitre_software,
    load_mitre_d3fend,
    load_sigma_rules,
    load_cis_controls,
    load_otx_pulses,
)


# ---------------------------------------------------------------------------
# Source → Postgres record converter
# ---------------------------------------------------------------------------

def episodes_to_pg_records(episodes: list, source_type: str) -> list:
    """Convert episode dicts to the flat format expected by upsert_threat_intel."""
    records = []
    for ep in episodes:
        records.append({
            "id":          ep.get("episode_id", ""),
            "source_type": source_type,
            "name":        ep.get("metadata", {}).get("name") or ep.get("episode_id", ""),
            "description": (ep.get("summary") or "")[:1000],
            "tags":        ep.get("tags") or [],
            "raw_data":    ep,   # full episode dict stored as JSONB
        })
    return records


# ---------------------------------------------------------------------------
# Main indexer
# ---------------------------------------------------------------------------

LOADERS = [
    ("mitre_attack",   load_attack_techniques),
    ("yara",           load_yara_rules),
    ("vendor",         load_vendor_advisories),
    ("cisa_kev",       load_cisa_kev),
    ("mitre_groups",   load_mitre_groups),
    ("mitre_software", load_mitre_software),
    ("mitre_d3fend",   load_mitre_d3fend),
    ("sigma",          load_sigma_rules),
    ("cis_controls",   load_cis_controls),
    ("otx",            load_otx_pulses),
]


def build_index(wipe_first: bool = False):
    """
    Load all threat intel from JSON files, write to Postgres + Qdrant.

    Args:
        wipe_first  If True, delete the Qdrant collection before indexing
                    (forces a full rebuild; Postgres uses UPSERT so always safe).
    """
    base_path         = Path(__file__).resolve().parents[2]
    threat_intel_path = base_path / "threat_intel"

    # --- connectivity checks ---
    if not pg_ping():
        print("ERROR: Cannot connect to PostgreSQL. Is the container running?")
        print("  Run: docker compose up -d")
        sys.exit(1)

    store = QdrantStore()
    if not store.ping():
        print("ERROR: Cannot connect to Qdrant. Is the container running?")
        print("  Run: docker compose up -d")
        sys.exit(1)

    print(f"PostgreSQL  OK")
    print(f"Qdrant      OK")
    print()

    if wipe_first:
        print("Wiping Qdrant collection for full rebuild...")
        store.delete_collection(COLLECTION_THREAT_INTEL)

    # --- load, write to Postgres, write to Qdrant (source by source — no bulk RAM) ---
    totals = {}

    for source_type, loader in LOADERS:
        print(f"Loading {source_type}...")
        episodes = loader(threat_intel_path)

        if not episodes:
            print(f"  [skip] no episodes for {source_type}")
            continue

        # Tag each episode with source_type for Qdrant payload
        for ep in episodes:
            ep.setdefault("source", source_type)

        # --- PostgreSQL ---
        log_id = log_ingestion_start(source_type)
        try:
            pg_records = episodes_to_pg_records(episodes, source_type)
            upsert_threat_intel(pg_records)
            log_ingestion_done(log_id, len(pg_records))
            print(f"  Postgres: {len(pg_records)} rows upserted")
        except Exception as e:
            log_ingestion_done(log_id, 0, status="error", error=str(e))
            print(f"  Postgres ERROR: {e}")

        # --- Qdrant: index immediately and release the list from memory ---
        store.index_episodes(episodes, collection=COLLECTION_THREAT_INTEL)
        totals[source_type] = len(episodes)

    # --- Summary ---
    total = sum(totals.values())
    print("\n" + "=" * 55)
    print("  Indexing complete")
    print("=" * 55)
    for src, count in totals.items():
        print(f"  {src:<25} {count:>6}")
    print(f"  {'─' * 33}")
    print(f"  {'TOTAL':<25} {total:>6}")

    info = store.collection_info(COLLECTION_THREAT_INTEL)
    print(f"\nQdrant collection '{COLLECTION_THREAT_INTEL}':")
    print(f"  Points: {info['points_count']}")

    print("\nNext steps:")
    print("  Query: python3 -m rag_core.indexing.qdrant_indexer --search 'ssh brute force'")


if __name__ == "__main__":
    wipe = "--wipe" in sys.argv

    if "--search" in sys.argv:
        idx = sys.argv.index("--search")
        query = " ".join(sys.argv[idx + 1:])
        store = QdrantStore()
        results = store.search(query, top_k=5)
        print(f"\nTop {len(results)} results for: '{query}'\n")
        for i, r in enumerate(results, 1):
            print(f"{i}. [{r['score']:.3f}] {r['episode_type']} | {r['summary'][:120]}")
    else:
        build_index(wipe_first=wipe)
