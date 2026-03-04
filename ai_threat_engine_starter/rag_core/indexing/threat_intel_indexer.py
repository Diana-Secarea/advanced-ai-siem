"""
Threat Intel Indexer
Converts JSON knowledge bases (MITRE ATT&CK, YARA, Vendor advisories)
into the episode dict format that HybridRetrieval.index_episodes() expects,
builds FAISS + BM25 index, and saves to disk.
"""

import json
import os
from pathlib import Path
from datetime import datetime


def load_attack_techniques(threat_intel_path: Path) -> list:
    """Load MITRE ATT&CK techniques and convert to episode dicts."""
    attack_file = threat_intel_path / "attack" / "attack_techniques.json"
    if not attack_file.exists():
        print(f"  [skip] {attack_file} not found")
        return []

    with open(attack_file) as f:
        data = json.load(f)

    episodes = []
    for tech in data.get("techniques", []):
        tid = tech.get("id", "")
        name = tech.get("name", "")
        desc = tech.get("description", "")
        tactics = tech.get("tactics", [])
        platforms = tech.get("platforms", [])

        summary = f"[{tid}] {name}: {desc}"

        tags = ["mitre-attack", tid]
        if tactics:
            tags.extend(tactics)

        episodes.append({
            "episode_id": tid,
            "episode_type": "mitre_attack",
            "summary": summary,
            "entities": {
                "technique": [tid],
                "tactic": tactics,
                "platform": platforms,
            },
            "tags": tags,
            "time_range": {
                "start": tech.get("ingested_at", datetime.utcnow().isoformat()),
                "end": tech.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source": tech.get("source", "mitre"),
                "name": name,
                "platforms": platforms,
            },
            "source": "mitre_attack",
            "raw_refs": [],
        })

    return episodes


def load_yara_rules(threat_intel_path: Path) -> list:
    """Load YARA rules and convert to episode dicts."""
    yara_file = threat_intel_path / "yara" / "rules.json"
    if not yara_file.exists():
        print(f"  [skip] {yara_file} not found")
        return []

    with open(yara_file) as f:
        data = json.load(f)

    episodes = []
    for rule in data.get("rules", []):
        rid = rule.get("id", "")
        name = rule.get("name", "")
        category = rule.get("category", "unknown")
        content = rule.get("content", "")
        # Truncate content for embedding (first 1000 chars)
        content_preview = content[:1000] if content else ""

        summary = f"YARA Rule [{name}] (category: {category}): {content_preview}"

        tags = ["yara", category]

        episodes.append({
            "episode_id": f"yara-{rid}",
            "episode_type": "yara_rule",
            "summary": summary,
            "entities": {
                "rule_name": [name],
                "category": [category],
            },
            "tags": tags,
            "time_range": {
                "start": rule.get("ingested_at", datetime.utcnow().isoformat()),
                "end": rule.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source": rule.get("source", ""),
                "url": rule.get("url", ""),
                "full_content": content,
            },
            "source": "yara",
            "raw_refs": [],
        })

    return episodes


def load_vendor_advisories(threat_intel_path: Path) -> list:
    """Load vendor security advisories and convert to episode dicts."""
    vendor_file = threat_intel_path / "vendor" / "advisories.json"
    if not vendor_file.exists():
        print(f"  [skip] {vendor_file} not found")
        return []

    with open(vendor_file) as f:
        data = json.load(f)

    episodes = []
    for adv in data.get("advisories", []):
        aid = adv.get("id", "")
        title = adv.get("title", "")
        desc = adv.get("description", "")
        source = adv.get("source", "")
        tag_name = adv.get("tag_name", "")

        summary = f"Advisory [{title}]: {desc}"

        tags = ["vendor-advisory", source]
        if tag_name:
            tags.append(tag_name)

        episodes.append({
            "episode_id": f"vendor-{aid}",
            "episode_type": "vendor_advisory",
            "summary": summary,
            "entities": {
                "source": [source],
            },
            "tags": tags,
            "time_range": {
                "start": adv.get("published_at", adv.get("ingested_at", datetime.utcnow().isoformat())),
                "end": adv.get("published_at", adv.get("ingested_at", datetime.utcnow().isoformat())),
            },
            "metadata": {
                "url": adv.get("url", ""),
                "source": source,
                "tag_name": tag_name,
                "is_security_related": adv.get("is_security_related", False),
            },
            "source": "vendor",
            "raw_refs": [],
        })

    return episodes


def build_index():
    """Main entry point: load all KBs, build index, save to disk."""
    base_path = Path(__file__).resolve().parent.parent.parent
    threat_intel_path = base_path / "threat_intel"
    index_output_path = base_path / "data" / "threat_intel_index"

    print(f"Threat intel path: {threat_intel_path}")
    print(f"Index output path: {index_output_path}")
    print()

    # Load all knowledge bases
    print("Loading MITRE ATT&CK techniques...")
    attack_episodes = load_attack_techniques(threat_intel_path)
    print(f"  Loaded {len(attack_episodes)} techniques")

    print("Loading YARA rules...")
    yara_episodes = load_yara_rules(threat_intel_path)
    print(f"  Loaded {len(yara_episodes)} rules")

    print("Loading vendor advisories...")
    vendor_episodes = load_vendor_advisories(threat_intel_path)
    print(f"  Loaded {len(vendor_episodes)} advisories")

    all_episodes = attack_episodes + yara_episodes + vendor_episodes
    print(f"\nTotal episodes: {len(all_episodes)}")

    if not all_episodes:
        print("No episodes to index. Exiting.")
        return

    # Build index using HybridRetrieval
    from rag_core.indexing.hybrid_retrieval import HybridRetrieval

    retrieval = HybridRetrieval(
        embedding_model="all-MiniLM-L6-v2",
        use_reranker=False,  # Skip reranker for indexing speed
        semantic_weight=0.6,
        keyword_weight=0.3,
        freshness_weight=0.1,
    )

    print("\nBuilding index (this may take 30-60 seconds)...")
    retrieval.index_episodes(all_episodes)

    # Save
    index_output_path.mkdir(parents=True, exist_ok=True)
    retrieval.save_index(str(index_output_path))

    print(f"\nIndex saved to {index_output_path}")
    print(f"Total indexed: {len(all_episodes)} episodes")


if __name__ == "__main__":
    build_index()
