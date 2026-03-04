#!/usr/bin/env python3
"""
Ingest all threat intelligence sources
Run this to populate the knowledge database
"""

import sys
from pathlib import Path

# Add parent paths
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion.threat_intel_ingestion import ThreatIntelIngestion


def main():
    """Main ingestion function"""
    print("=" * 60)
    print("Threat Intelligence Ingestion - Final RAG System")
    print("=" * 60)
    print()
    
    # Initialize ingester (defaults to ai_threat_engine_starter/threat_intel)
    ingester = ThreatIntelIngestion()
    
    # Ingest MITRE ATT&CK
    print("\n" + "=" * 60)
    print("1. Ingesting MITRE ATT&CK")
    print("=" * 60)
    attack_techniques = ingester.ingest_mitre_attack(force_refresh=False)
    print(f"✅ Imported {len(attack_techniques)} MITRE ATT&CK techniques")
    
    # Ingest Wazuh vendor advisories
    print("\n" + "=" * 60)
    print("2. Ingesting Wazuh Vendor Advisories")
    print("=" * 60)
    
    # Wazuh-specific vendor sources
    wazuh_sources = [
        {
            'name': 'Wazuh Security Advisories',
            'url': 'https://github.com/wazuh/wazuh/releases',
            'type': 'GITHUB_RELEASES'
        },
        {
            'name': 'Wazuh Blog',
            'url': 'https://wazuh.com/blog',
            'type': 'BLOG'
        },
        {
            'name': 'Wazuh Documentation Security',
            'url': 'https://documentation.wazuh.com/current/security/index.html',
            'type': 'DOCS'
        }
    ]
    
    vendor_advisories = ingester.ingest_vendor_advisories(sources=wazuh_sources)
    print(f"✅ Imported {len(vendor_advisories)} vendor advisories")
    
    # Ingest IOCs
    print("\n" + "=" * 60)
    print("3. Ingesting IOCs")
    print("=" * 60)
    iocs = ingester.ingest_iocs()
    print(f"✅ Imported {len(iocs)} IOCs")
    
    # Ingest YARA Rules
    print("\n" + "=" * 60)
    print("4. Ingesting YARA Rules")
    print("=" * 60)
    yara_rules = ingester.ingest_yara_rules()
    print(f"✅ Imported {len(yara_rules)} YARA rules")
    
    # Ingest Sigma Rules
    print("\n" + "=" * 60)
    print("5. Ingesting Sigma Rules")
    print("=" * 60)
    sigma_rules = ingester.ingest_sigma_rules()
    print(f"✅ Imported {len(sigma_rules)} Sigma rules")
    
    # Ingest Internal TI
    print("\n" + "=" * 60)
    print("6. Ingesting Internal Threat Intelligence")
    print("=" * 60)
    internal_notes = ingester.ingest_internal_ti()
    print(f"✅ Imported {len(internal_notes)} internal TI notes")
    
    # Summary
    print("\n" + "=" * 60)
    print("Ingestion Summary")
    print("=" * 60)
    print(f"  MITRE ATT&CK: {len(attack_techniques)} techniques")
    print(f"  Vendor Advisories: {len(vendor_advisories)} advisories")
    print(f"  IOCs: {len(iocs)} indicators")
    print(f"  YARA Rules: {len(yara_rules)} rules")
    print(f"  Sigma Rules: {len(sigma_rules)} rules")
    print(f"  Internal TI: {len(internal_notes)} notes")
    print("=" * 60)
    print()
    import os
    threat_intel_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "threat_intel")
    print(f"Data stored in: {threat_intel_path}/")
    print()
    print("Next steps:")
    print("  1. View threats: python3 view_threats.py")
    print("  2. Migrate to PostgreSQL: python3 database/postgres_setup.py")
    print()


if __name__ == "__main__":
    main()
