"""
Threat Intel Indexer
Loader functions that convert JSON knowledge bases into episode dicts.
These are imported by rag_core.indexing.qdrant_indexer, which writes
them to Qdrant (dense + sparse) and PostgreSQL.

Sources loaded:
  - MITRE ATT&CK techniques  (attack/attack_techniques.json)
  - YARA rules               (yara/rules.json)
  - Vendor advisories        (vendor/advisories.json)
  - CISA KEV                 (cisa_kev/kev_catalog.json)
  - MITRE ATT&CK Groups      (mitre_groups/groups.json)
  - MITRE ATT&CK Software    (mitre_software/software.json)
  - MITRE D3FEND             (mitre_d3fend/techniques.json)
  - Sigma rules              (sigma/rules.json)
  - CIS Controls             (cis_controls/controls.json)
  - OTX AlienVault pulses    (otx/pulses.json)
"""

import json
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------------------------
# Existing loaders
# ---------------------------------------------------------------------------

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
        tid      = tech.get("id", "")
        name     = tech.get("name", "")
        desc     = tech.get("description", "")
        tactics  = tech.get("tactics", [])
        platforms = tech.get("platforms", [])

        summary = f"[{tid}] {name}: {desc}"
        tags    = ["mitre-attack", tid] + list(tactics)

        episodes.append({
            "episode_id":   tid,
            "episode_type": "mitre_attack",
            "summary":      summary,
            "entities": {
                "technique": [tid],
                "tactic":    tactics,
                "platform":  platforms,
            },
            "tags": tags,
            "time_range": {
                "start": tech.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   tech.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":    tech.get("source", "mitre"),
                "name":      name,
                "platforms": platforms,
            },
            "source":   "mitre_attack",
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
        rid      = rule.get("id", "")
        name     = rule.get("name", "")
        category = rule.get("category", "unknown")
        content  = rule.get("content", "")
        preview  = content[:1000] if content else ""

        summary = f"YARA Rule [{name}] (category: {category}): {preview}"
        tags    = ["yara", category]

        episodes.append({
            "episode_id":   f"yara-{rid}",
            "episode_type": "yara_rule",
            "summary":      summary,
            "entities": {
                "rule_name": [name],
                "category":  [category],
            },
            "tags": tags,
            "time_range": {
                "start": rule.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   rule.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":       rule.get("source", ""),
                "url":          rule.get("url", ""),
                "full_content": content,
            },
            "source":   "yara",
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
        aid      = adv.get("id", "")
        title    = adv.get("title", "")
        desc     = adv.get("description", "")
        source   = adv.get("source", "")
        tag_name = adv.get("tag_name", "")

        summary = f"Advisory [{title}]: {desc}"
        tags    = ["vendor-advisory", source]
        if tag_name:
            tags.append(tag_name)

        episodes.append({
            "episode_id":   f"vendor-{aid}",
            "episode_type": "vendor_advisory",
            "summary":      summary,
            "entities": {"source": [source]},
            "tags": tags,
            "time_range": {
                "start": adv.get("published_at", adv.get("ingested_at", datetime.utcnow().isoformat())),
                "end":   adv.get("published_at", adv.get("ingested_at", datetime.utcnow().isoformat())),
            },
            "metadata": {
                "url":                adv.get("url", ""),
                "source":             source,
                "tag_name":           tag_name,
                "is_security_related": adv.get("is_security_related", False),
            },
            "source":   "vendor",
            "raw_refs": [],
        })

    return episodes


# ---------------------------------------------------------------------------
# New loaders
# ---------------------------------------------------------------------------

def load_cisa_kev(threat_intel_path: Path) -> list:
    """Load CISA KEV catalog and convert to episode dicts."""
    kev_file = threat_intel_path / "cisa_kev" / "kev_catalog.json"
    if not kev_file.exists():
        print(f"  [skip] {kev_file} not found")
        return []

    with open(kev_file) as f:
        data = json.load(f)

    episodes = []
    for vuln in data.get("vulnerabilities", []):
        cve_id   = vuln.get("cve_id", vuln.get("id", ""))
        name     = vuln.get("name", "")
        vendor   = vuln.get("vendor_project", "")
        product  = vuln.get("product", "")
        desc     = vuln.get("description", "")
        action   = vuln.get("required_action", "")
        added    = vuln.get("date_added", "")
        ransomware = vuln.get("known_ransomware", False)

        ransomware_str = "YES — linked to active ransomware campaigns" if ransomware else "No"

        summary = (
            f"{cve_id} [{name}] | Vendor: {vendor} | Product: {product} | "
            f"Ransomware: {ransomware_str} | Date added to KEV: {added} | "
            f"Description: {desc} | Required action: {action}"
        )

        tags = ["cisa-kev", "cve", cve_id.lower()]
        if ransomware:
            tags.append("ransomware")

        episodes.append({
            "episode_id":   f"kev-{cve_id}",
            "episode_type": "cisa_kev",
            "summary":      summary,
            "entities": {
                "cve":     [cve_id],
                "vendor":  [vendor],
                "product": [product],
            },
            "tags": tags,
            "time_range": {
                "start": added or vuln.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   vuln.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":          "CISA_KEV",
                "known_ransomware": ransomware,
                "required_action": action,
                "due_date":        vuln.get("due_date", ""),
            },
            "source":   "cisa_kev",
            "raw_refs": [],
        })

    return episodes


def load_mitre_groups(threat_intel_path: Path) -> list:
    """Load MITRE ATT&CK threat actor groups and convert to episode dicts."""
    groups_file = threat_intel_path / "mitre_groups" / "groups.json"
    if not groups_file.exists():
        print(f"  [skip] {groups_file} not found")
        return []

    with open(groups_file) as f:
        data = json.load(f)

    episodes = []
    for group in data.get("groups", []):
        gid        = group.get("id", "")
        name       = group.get("name", "")
        aliases    = group.get("aliases", [])
        desc       = group.get("description", "")
        techniques = group.get("techniques", [])

        alias_str = ", ".join(aliases[:5]) if aliases else "none"
        tech_str  = ", ".join(techniques[:10])
        if len(techniques) > 10:
            tech_str += f" (+{len(techniques) - 10} more)"

        summary = (
            f"Threat Actor Group: {name} [{gid}] "
            f"(also known as: {alias_str}) | "
            f"Techniques ({len(techniques)}): {tech_str} | "
            f"Description: {desc}"
        )

        tags = ["mitre-group", "threat-actor", gid] + [a.lower().replace(" ", "-") for a in aliases[:3]]

        episodes.append({
            "episode_id":   f"group-{gid}",
            "episode_type": "mitre_group",
            "summary":      summary,
            "entities": {
                "group":     [gid],
                "alias":     aliases,
                "technique": techniques[:20],
            },
            "tags": tags,
            "time_range": {
                "start": group.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   group.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":          "MITRE_ATTACK",
                "name":            name,
                "aliases":         aliases,
                "technique_count": len(techniques),
            },
            "source":   "mitre_groups",
            "raw_refs": [],
        })

    return episodes


def load_mitre_software(threat_intel_path: Path) -> list:
    """Load MITRE ATT&CK malware/tools and convert to episode dicts."""
    sw_file = threat_intel_path / "mitre_software" / "software.json"
    if not sw_file.exists():
        print(f"  [skip] {sw_file} not found")
        return []

    with open(sw_file) as f:
        data = json.load(f)

    episodes = []
    for sw in data.get("software", []):
        sid        = sw.get("id", "")
        name       = sw.get("name", "")
        sw_type    = sw.get("type", "")   # 'malware' or 'tool'
        aliases    = sw.get("aliases", [])
        desc       = sw.get("description", "")
        platforms  = sw.get("platforms", [])
        techniques = sw.get("techniques", [])

        alias_str = ", ".join(aliases[:5]) if aliases else "none"
        tech_str  = ", ".join(techniques[:10])
        if len(techniques) > 10:
            tech_str += f" (+{len(techniques) - 10} more)"
        plat_str  = ", ".join(platforms[:5])

        summary = (
            f"{sw_type.capitalize()}: {name} [{sid}] "
            f"(aliases: {alias_str}) | "
            f"Platforms: {plat_str} | "
            f"Techniques ({len(techniques)}): {tech_str} | "
            f"Description: {desc}"
        )

        tags = ["mitre-software", sw_type, sid] + [a.lower().replace(" ", "-") for a in aliases[:3]]

        episodes.append({
            "episode_id":   f"software-{sid}",
            "episode_type": "mitre_software",
            "summary":      summary,
            "entities": {
                "software":  [sid],
                "alias":     aliases,
                "platform":  platforms,
                "technique": techniques[:20],
            },
            "tags": tags,
            "time_range": {
                "start": sw.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   sw.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":          "MITRE_ATTACK",
                "name":            name,
                "type":            sw_type,
                "aliases":         aliases,
                "technique_count": len(techniques),
            },
            "source":   "mitre_software",
            "raw_refs": [],
        })

    return episodes


def load_mitre_d3fend(threat_intel_path: Path) -> list:
    """Load MITRE D3FEND defensive techniques and convert to episode dicts."""
    d3_file = threat_intel_path / "mitre_d3fend" / "techniques.json"
    if not d3_file.exists():
        print(f"  [skip] {d3_file} not found")
        return []

    with open(d3_file) as f:
        data = json.load(f)

    episodes = []
    for tech in data.get("techniques", []):
        did       = tech.get("id", "")
        name      = tech.get("name", "")
        tactic    = tech.get("tactic", "")
        desc      = tech.get("description", "")
        counters  = tech.get("attack_techniques_countered", [])

        counter_str = ", ".join(counters[:10]) if counters else "none"

        summary = (
            f"D3FEND Defensive Technique: {name} [{did}] | "
            f"Tactic: {tactic} | "
            f"Counters ATT&CK: {counter_str} | "
            f"Description: {desc}"
        )

        tags = ["d3fend", "defensive", did]
        if tactic:
            tags.append(tactic.lower().replace(" ", "-"))

        episodes.append({
            "episode_id":   f"d3fend-{did}",
            "episode_type": "mitre_d3fend",
            "summary":      summary,
            "entities": {
                "technique":   [did],
                "tactic":      [tactic],
                "counters":    counters[:10],
            },
            "tags": tags,
            "time_range": {
                "start": tech.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   tech.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":          "MITRE_D3FEND",
                "name":            name,
                "tactic":          tactic,
                "counters_count":  len(counters),
            },
            "source":   "mitre_d3fend",
            "raw_refs": [],
        })

    return episodes


def load_sigma_rules(threat_intel_path: Path) -> list:
    """Load Sigma detection rules and convert to episode dicts."""
    sigma_file = threat_intel_path / "sigma" / "rules.json"
    if not sigma_file.exists():
        print(f"  [skip] {sigma_file} not found")
        return []

    with open(sigma_file) as f:
        data = json.load(f)

    episodes = []
    for rule in data.get("rules", []):
        rid       = rule.get("id", "")
        title     = rule.get("title", "")
        level     = rule.get("level", "")
        category  = rule.get("category", "")
        desc      = rule.get("description", "")
        logsource = rule.get("logsource", {})
        detection = rule.get("detection_summary", "")
        atk_tags  = rule.get("attack_tags", [])
        author    = rule.get("author", "")

        logsrc_str = (
            f"{logsource.get('product', '')} {logsource.get('service', '')} "
            f"{logsource.get('category', '')}".strip()
        )
        atk_str = ", ".join(atk_tags[:8]) if atk_tags else ""

        summary = (
            f"Sigma [{level.upper()}] {title} | "
            f"Category: {category} | "
            f"Logsource: {logsrc_str} | "
            f"ATT&CK: {atk_str} | "
            f"Description: {desc} | "
            f"Detection: {detection}"
        )

        tags = ["sigma", category, level]
        tags.extend(atk_tags[:5])

        episodes.append({
            "episode_id":   rid,
            "episode_type": "sigma_rule",
            "summary":      summary,
            "entities": {
                "rule":     [rid],
                "category": [category],
                "level":    [level],
                "attack":   atk_tags[:10],
            },
            "tags": [t for t in tags if t],
            "time_range": {
                "start": rule.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   rule.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source":    "SigmaHQ",
                "title":     title,
                "level":     level,
                "category":  category,
                "author":    author,
                "file_path": rule.get("file_path", ""),
            },
            "source":   "sigma",
            "raw_refs": [],
        })

    return episodes


def load_cis_controls(threat_intel_path: Path) -> list:
    """Load CIS Controls v8 safeguards and Wazuh SCA checks, convert to episodes."""
    cis_file = threat_intel_path / "cis_controls" / "controls.json"
    if not cis_file.exists():
        print(f"  [skip] {cis_file} not found")
        return []

    with open(cis_file) as f:
        data = json.load(f)

    episodes = []
    for item in data.get("controls", []):
        item_id  = item.get("id", "")
        item_type = item.get("type", item.get("source", "unknown"))
        name     = item.get("name", item.get("title", ""))
        desc     = item.get("description", "")

        if item_type in ("control", "safeguard"):
            cid      = item.get("control_id", "")
            sg_id    = item.get("safeguard_id", cid)
            ig       = item.get("implementation_group", item.get("implementation_groups", ""))
            parent   = item.get("parent_control", "")
            summary  = (
                f"CIS {item_type.capitalize()} {sg_id}: {name} | "
                f"Implementation Group: {ig} | "
                + (f"Part of Control {cid}: {parent} | " if parent else "")
                + f"Description: {desc}"
            )
            tags = ["cis", f"cis-control-{cid}", item_type]

        elif item_type == "wazuh_sca":
            policy   = item.get("policy", "")
            rat      = item.get("rationale", "")
            remediation = item.get("remediation", "")
            summary  = (
                f"Wazuh SCA Check [{item_id}]: {name} | "
                f"Policy: {policy} | "
                f"Rationale: {rat} | "
                f"Remediation: {remediation}"
            )
            tags = ["cis", "wazuh-sca", policy.lower().replace(" ", "-")]

        else:
            summary = f"{item_type}: {name} | {desc}"
            tags    = ["cis", item_type]

        episodes.append({
            "episode_id":   item_id,
            "episode_type": "cis_control",
            "summary":      summary,
            "entities": {"control": [item_id]},
            "tags": tags,
            "time_range": {
                "start": item.get("ingested_at", datetime.utcnow().isoformat()),
                "end":   item.get("ingested_at", datetime.utcnow().isoformat()),
            },
            "metadata": {
                "source": item.get("source", "CIS_Controls_v8"),
                "name":   name,
                "type":   item_type,
            },
            "source":   "cis_controls",
            "raw_refs": [],
        })

    return episodes


def load_otx_pulses(threat_intel_path: Path) -> list:
    """Load OTX AlienVault pulses and convert to episode dicts."""
    otx_file = threat_intel_path / "otx" / "pulses.json"
    if not otx_file.exists():
        print(f"  [skip] {otx_file} not found")
        return []

    with open(otx_file) as f:
        data = json.load(f)

    episodes = []
    for pulse in data.get("pulses", []):
        pid        = pulse.get("id", "")
        name       = pulse.get("name", "")
        desc       = pulse.get("description", "")
        author     = pulse.get("author", "")
        tags_list  = pulse.get("tags", [])
        countries  = pulse.get("targeted_countries", [])
        malware    = pulse.get("malware_families", [])
        attack_ids = pulse.get("attack_ids", [])
        ioc_count  = pulse.get("ioc_count", 0)
        ioc_types  = pulse.get("ioc_types", {})

        ioc_str     = ", ".join(f"{k}:{v}" for k, v in ioc_types.items()) if ioc_types else "0"
        malware_str = ", ".join(malware[:5]) if malware else "none"
        country_str = ", ".join(countries[:5]) if countries else "unspecified"
        atk_str     = ", ".join(attack_ids[:5]) if attack_ids else "none"

        summary = (
            f"OTX Pulse: {name} | "
            f"Author: {author} | "
            f"Malware families: {malware_str} | "
            f"Targeted countries: {country_str} | "
            f"ATT&CK: {atk_str} | "
            f"IOCs: {ioc_count} ({ioc_str}) | "
            f"Tags: {', '.join(tags_list[:8])} | "
            f"Description: {desc}"
        )

        episode_tags = ["otx", "alienvault"] + [t.lower() for t in tags_list[:5]]

        episodes.append({
            "episode_id":   f"otx-{pid}",
            "episode_type": "otx_pulse",
            "summary":      summary,
            "entities": {
                "malware":   malware[:5],
                "country":   countries[:5],
                "technique": attack_ids[:5],
            },
            "tags": episode_tags,
            "time_range": {
                "start": pulse.get("created", pulse.get("ingested_at", datetime.utcnow().isoformat())),
                "end":   pulse.get("modified", pulse.get("ingested_at", datetime.utcnow().isoformat())),
            },
            "metadata": {
                "source":    "OTX_AlienVault",
                "author":    author,
                "ioc_count": ioc_count,
                "tlp":       pulse.get("tlp", "white"),
            },
            "source":   "otx",
            "raw_refs": [],
        })

    return episodes


if __name__ == "__main__":
    print("This module provides loader functions only.")
    print("To build the Qdrant index run:")
    print("  python3 -m rag_core.indexing.qdrant_indexer [--wipe]")
