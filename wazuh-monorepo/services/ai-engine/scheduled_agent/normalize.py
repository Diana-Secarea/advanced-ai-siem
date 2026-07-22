"""Normalize raw NVD / CISA-KEV records into one common CVE shape, and
convert that shape into the episode format the existing Qdrant indexer expects.

Common CVE shape (dict):
    {
        "cve_id":      "CVE-2024-12345",
        "source_type": "nvd" | "cisa_kev",
        "description": str,
        "products":    [str, ...],   # software keywords for boosting/dedup
        "vendor":      str,
        "cvss":        float | None,
        "published":   ISO-8601 str | "",
        "raw":         {...}         # full original record
    }
"""
from datetime import datetime, timezone
import re


# ---------------------------------------------------------------------------
# CPE parsing  (cpe:2.3:a:vendor:product:version:...)
# ---------------------------------------------------------------------------
def _parse_cpe(cpe_uri: str):
    """Return (vendor, product) from a CPE 2.3 URI, or (None, None)."""
    parts = cpe_uri.split(":")
    if len(parts) >= 5 and cpe_uri.startswith("cpe:2.3:"):
        vendor  = parts[3].replace("_", " ").strip("*").strip()
        product = parts[4].replace("_", " ").strip("*").strip()
        return (vendor or None, product or None)
    return (None, None)


def _collect_cpe_products(configurations) -> list:
    """Walk an NVD 2.0 `configurations` tree and pull out product names."""
    products = set()
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                _, product = _parse_cpe(match.get("criteria", ""))
                if product:
                    products.add(product)
    return sorted(products)


# ---------------------------------------------------------------------------
# NVD 2.0
# ---------------------------------------------------------------------------
def parse_nvd_item(item: dict) -> dict:
    """Normalize one element of NVD 2.0 `vulnerabilities[]`."""
    cve = item.get("cve", item)
    cve_id = cve.get("id", "")

    # English description
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS base score (prefer v3.1 > v3.0 > v2)
    cvss = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            try:
                cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                break
            except (KeyError, IndexError, TypeError, ValueError):
                continue

    products = _collect_cpe_products(cve.get("configurations", []))
    vendor = ""  # NVD vendor lives in CPE; first product's vendor is good enough
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                v, _ = _parse_cpe(match.get("criteria", ""))
                if v:
                    vendor = v
                    break

    return {
        "cve_id":      cve_id,
        "source_type": "nvd",
        "description": description,
        "products":    products,
        "vendor":      vendor,
        "cvss":        cvss,
        "published":   cve.get("published", ""),
        "raw":         cve,
    }


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------
def parse_kev_item(vuln: dict) -> dict:
    """Normalize one element of CISA KEV `vulnerabilities[]`."""
    cve_id  = vuln.get("cveID", vuln.get("cve_id", ""))
    product = vuln.get("product", "")
    vendor  = vuln.get("vendorProject", vuln.get("vendor_project", ""))
    desc    = vuln.get("shortDescription", vuln.get("description", ""))

    products = [p.strip() for p in re.split(r"[,/]", product) if p.strip()]

    return {
        "cve_id":      cve_id,
        "source_type": "cisa_kev",
        "description": desc,
        "products":    products or ([product] if product else []),
        "vendor":      vendor,
        "cvss":        None,
        "published":   vuln.get("dateAdded", vuln.get("date_added", "")),
        "raw":         vuln,
    }


# ---------------------------------------------------------------------------
# Software keyword extraction (for boosting + dedup keyword matching)
# ---------------------------------------------------------------------------
def extract_software(cve: dict) -> list:
    """Return lowercased software/vendor keywords for matching against the
    environment (Wazuh rules, alert logs)."""
    kws = set()
    for p in cve.get("products", []):
        p = p.strip().lower()
        if len(p) >= 3:
            kws.add(p)
    v = (cve.get("vendor") or "").strip().lower()
    if len(v) >= 3:
        kws.add(v)
    return sorted(kws)


# ---------------------------------------------------------------------------
# Episode builder — mirrors load_cisa_kev() output so the existing
# QdrantStore.index_episodes() + upsert_threat_intel() accept it unchanged.
# ---------------------------------------------------------------------------
def cve_to_episode(cve: dict, final_score: int, reasoning: str) -> dict:
    cve_id   = cve["cve_id"]
    vendor   = cve.get("vendor", "")
    products = ", ".join(cve.get("products", [])) or "n/a"
    cvss     = cve.get("cvss")
    now_iso  = datetime.now(timezone.utc).isoformat()

    summary = (
        f"{cve_id} | Vendor: {vendor or 'n/a'} | Product(s): {products} | "
        f"CVSS: {cvss if cvss is not None else 'n/a'} | "
        f"Relevance: {final_score}/10 | {cve.get('description', '')}"
    )

    tags = [cve["source_type"], "cve", cve_id.lower()]
    if cve.get("source_type") == "cisa_kev":
        tags.append("cisa-kev")

    return {
        "episode_id":   f"{cve['source_type']}-{cve_id}",
        "episode_type": "cve",
        "summary":      summary,
        "entities": {
            "cve":     [cve_id],
            "vendor":  [vendor] if vendor else [],
            "product": cve.get("products", []),
        },
        "tags": tags,
        "time_range": {
            "start": cve.get("published") or now_iso,
            "end":   now_iso,
        },
        "metadata": {
            "source":          cve["source_type"],
            "cvss":            cvss,
            "relevance_score": final_score,
            "relevance_reason": reasoning,
            "agent_ingested":  True,
        },
        "source":   cve["source_type"],
        "raw_refs": [],
    }
