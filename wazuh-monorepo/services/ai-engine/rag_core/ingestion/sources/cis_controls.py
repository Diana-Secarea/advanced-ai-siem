#!/usr/bin/env python3
"""
CIS Controls v8 + Wazuh SCA policy ingestion.

Sources:
  1. CIS Controls v8 framework (18 controls, 153 safeguards)
     The CIS Controls are freely available public guidance.
     https://www.cisecurity.org/controls/v8

  2. Wazuh SCA policy files at /var/ossec/ruleset/sca/
     These YAML files map Wazuh checks to CIS Benchmark items,
     providing direct links between live Wazuh alerts and CIS controls.

Output: threat_intel/cis_controls/controls.json

Run standalone:
    python3 sources/cis_controls.py [--refresh]
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

BASE_DIR        = Path(__file__).resolve().parents[3]
STORAGE_DIR     = BASE_DIR / "threat_intel" / "cis_controls"
WAZUH_SCA_DIR   = Path("/var/ossec/ruleset/sca")

# ---------------------------------------------------------------------------
# CIS Controls v8 — 18 controls, 153 safeguards (public domain framework)
# ---------------------------------------------------------------------------
CIS_CONTROLS_V8 = [
    {
        "id": "1",
        "name": "Inventory and Control of Enterprise Assets",
        "description": "Actively manage all enterprise assets connected to the infrastructure "
                       "including end-user devices, network devices, IoT devices, and servers.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "1.1", "name": "Establish and Maintain Detailed Enterprise Asset Inventory", "ig": "IG1"},
            {"id": "1.2", "name": "Address Unauthorized Assets", "ig": "IG1"},
            {"id": "1.3", "name": "Utilize an Active Discovery Tool", "ig": "IG2"},
            {"id": "1.4", "name": "Use DHCP Logging to Update Asset Inventory", "ig": "IG2"},
            {"id": "1.5", "name": "Use a Passive Asset Discovery Tool", "ig": "IG3"},
        ],
    },
    {
        "id": "2",
        "name": "Inventory and Control of Software Assets",
        "description": "Actively manage all software on the network to prevent unauthorized "
                       "software from being installed or executed.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "2.1", "name": "Establish and Maintain a Software Inventory", "ig": "IG1"},
            {"id": "2.2", "name": "Ensure Authorized Software is Currently Supported", "ig": "IG1"},
            {"id": "2.3", "name": "Address Unauthorized Software", "ig": "IG1"},
            {"id": "2.4", "name": "Utilize Automated Software Inventory Tools", "ig": "IG2"},
            {"id": "2.5", "name": "Allowlist Authorized Software", "ig": "IG2"},
            {"id": "2.6", "name": "Allowlist Authorized Libraries", "ig": "IG2"},
            {"id": "2.7", "name": "Allowlist Authorized Scripts", "ig": "IG3"},
        ],
    },
    {
        "id": "3",
        "name": "Data Protection",
        "description": "Develop processes and technical controls to identify, classify, securely "
                       "handle, retain, and dispose of data.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "3.1",  "name": "Establish and Maintain a Data Management Process", "ig": "IG1"},
            {"id": "3.2",  "name": "Establish and Maintain a Data Inventory", "ig": "IG1"},
            {"id": "3.3",  "name": "Configure Data Access Control Lists", "ig": "IG1"},
            {"id": "3.4",  "name": "Enforce Data Retention", "ig": "IG1"},
            {"id": "3.5",  "name": "Securely Dispose of Data", "ig": "IG1"},
            {"id": "3.6",  "name": "Encrypt Data on End-User Devices", "ig": "IG2"},
            {"id": "3.7",  "name": "Establish and Maintain a Data Classification Scheme", "ig": "IG2"},
            {"id": "3.8",  "name": "Document Data Flows", "ig": "IG2"},
            {"id": "3.9",  "name": "Encrypt Data on Removable Media", "ig": "IG2"},
            {"id": "3.10", "name": "Encrypt Sensitive Data in Transit", "ig": "IG2"},
            {"id": "3.11", "name": "Encrypt Sensitive Data at Rest", "ig": "IG3"},
            {"id": "3.12", "name": "Segment Data Processing and Storage Based on Sensitivity", "ig": "IG3"},
            {"id": "3.13", "name": "Deploy a Data Loss Prevention Solution", "ig": "IG3"},
            {"id": "3.14", "name": "Log Sensitive Data Access", "ig": "IG3"},
        ],
    },
    {
        "id": "4",
        "name": "Secure Configuration of Enterprise Assets and Software",
        "description": "Establish and maintain the secure configuration of enterprise assets "
                       "and software to reduce the attack surface.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "4.1",  "name": "Establish and Maintain a Secure Configuration Process", "ig": "IG1"},
            {"id": "4.2",  "name": "Establish and Maintain a Secure Configuration Process for Network Infrastructure", "ig": "IG1"},
            {"id": "4.3",  "name": "Configure Automatic Session Locking on Enterprise Assets", "ig": "IG1"},
            {"id": "4.4",  "name": "Implement and Manage a Firewall on Servers", "ig": "IG1"},
            {"id": "4.5",  "name": "Implement and Manage a Firewall on End-User Devices", "ig": "IG1"},
            {"id": "4.6",  "name": "Securely Manage Enterprise Assets and Software", "ig": "IG2"},
            {"id": "4.7",  "name": "Manage Default Accounts on Enterprise Assets and Software", "ig": "IG2"},
            {"id": "4.8",  "name": "Uninstall or Disable Unnecessary Services", "ig": "IG2"},
            {"id": "4.9",  "name": "Configure Trusted DNS Servers on Enterprise Assets", "ig": "IG2"},
            {"id": "4.10", "name": "Enforce Automatic Device Lockout on Portable End-User Devices", "ig": "IG2"},
            {"id": "4.11", "name": "Enforce Remote Wipe Capability on Portable End-User Devices", "ig": "IG2"},
            {"id": "4.12", "name": "Separate Enterprise Workspaces on Mobile End-User Devices", "ig": "IG3"},
        ],
    },
    {
        "id": "5",
        "name": "Account Management",
        "description": "Use processes and tools to assign and manage authorization to credentials "
                       "for user accounts including administrator accounts.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "5.1", "name": "Establish and Maintain an Inventory of Accounts", "ig": "IG1"},
            {"id": "5.2", "name": "Use Unique Passwords", "ig": "IG1"},
            {"id": "5.3", "name": "Disable Dormant Accounts", "ig": "IG1"},
            {"id": "5.4", "name": "Restrict Administrator Privileges to Dedicated Accounts", "ig": "IG1"},
            {"id": "5.5", "name": "Establish and Maintain an Inventory of Service Accounts", "ig": "IG2"},
            {"id": "5.6", "name": "Centralize Account Management", "ig": "IG2"},
        ],
    },
    {
        "id": "6",
        "name": "Access Control Management",
        "description": "Use processes and tools to create, assign, manage, and revoke access "
                       "credentials and privileges.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "6.1", "name": "Establish an Access Granting Process", "ig": "IG1"},
            {"id": "6.2", "name": "Establish an Access Revoking Process", "ig": "IG1"},
            {"id": "6.3", "name": "Require MFA for Externally-Exposed Applications", "ig": "IG1"},
            {"id": "6.4", "name": "Require MFA for Remote Network Access", "ig": "IG1"},
            {"id": "6.5", "name": "Require MFA for Administrative Access", "ig": "IG2"},
            {"id": "6.6", "name": "Establish and Maintain an Inventory of Authentication and Authorization Systems", "ig": "IG2"},
            {"id": "6.7", "name": "Centralize Access Control", "ig": "IG2"},
            {"id": "6.8", "name": "Define and Maintain Role-Based Access Control", "ig": "IG3"},
        ],
    },
    {
        "id": "7",
        "name": "Continuous Vulnerability Management",
        "description": "Develop a plan to continuously assess and track vulnerabilities on all "
                       "enterprise assets to remediate and minimize the window of opportunity for attackers.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "7.1", "name": "Establish and Maintain a Vulnerability Management Process", "ig": "IG1"},
            {"id": "7.2", "name": "Establish and Maintain a Remediation Process", "ig": "IG1"},
            {"id": "7.3", "name": "Perform Automated Operating System Patch Management", "ig": "IG1"},
            {"id": "7.4", "name": "Perform Automated Application Patch Management", "ig": "IG1"},
            {"id": "7.5", "name": "Perform Automated Vulnerability Scans of Internal Assets", "ig": "IG2"},
            {"id": "7.6", "name": "Perform Automated Vulnerability Scans of Externally-Exposed Assets", "ig": "IG2"},
            {"id": "7.7", "name": "Remediate Detected Vulnerabilities", "ig": "IG2"},
        ],
    },
    {
        "id": "8",
        "name": "Audit Log Management",
        "description": "Collect, alert, review, and retain audit logs of events that could help "
                       "detect, understand, or recover from an attack.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "8.1",  "name": "Establish and Maintain an Audit Log Management Process", "ig": "IG1"},
            {"id": "8.2",  "name": "Collect Audit Logs", "ig": "IG1"},
            {"id": "8.3",  "name": "Ensure Adequate Audit Log Storage", "ig": "IG1"},
            {"id": "8.4",  "name": "Standardize Time Synchronization", "ig": "IG1"},
            {"id": "8.5",  "name": "Collect Detailed Audit Logs", "ig": "IG2"},
            {"id": "8.6",  "name": "Collect DNS Query Audit Logs", "ig": "IG2"},
            {"id": "8.7",  "name": "Collect URL Request Audit Logs", "ig": "IG2"},
            {"id": "8.8",  "name": "Collect Command-Line Audit Logs", "ig": "IG2"},
            {"id": "8.9",  "name": "Centralize Audit Logs", "ig": "IG2"},
            {"id": "8.10", "name": "Retain Audit Logs", "ig": "IG2"},
            {"id": "8.11", "name": "Conduct Audit Log Reviews", "ig": "IG2"},
            {"id": "8.12", "name": "Collect Service Provider Logs", "ig": "IG3"},
        ],
    },
    {
        "id": "9",
        "name": "Email and Web Browser Protections",
        "description": "Improve protections and detections of threats from email and web vectors.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "9.1", "name": "Ensure Use of Only Fully Supported Browsers and Email Clients", "ig": "IG1"},
            {"id": "9.2", "name": "Use DNS Filtering Services", "ig": "IG1"},
            {"id": "9.3", "name": "Maintain and Enforce Network-Based URL Filters", "ig": "IG2"},
            {"id": "9.4", "name": "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions", "ig": "IG2"},
            {"id": "9.5", "name": "Implement DMARC", "ig": "IG2"},
            {"id": "9.6", "name": "Block Unnecessary File Types", "ig": "IG2"},
            {"id": "9.7", "name": "Deploy and Maintain Email Server Anti-Malware Protections", "ig": "IG3"},
        ],
    },
    {
        "id": "10",
        "name": "Malware Defenses",
        "description": "Prevent or control the installation, spread, and execution of malicious "
                       "applications, code, and scripts on enterprise assets.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "10.1", "name": "Deploy and Maintain Anti-Malware Software", "ig": "IG1"},
            {"id": "10.2", "name": "Configure Automatic Anti-Malware Signature Updates", "ig": "IG1"},
            {"id": "10.3", "name": "Disable Autorun and Autoplay for Removable Media", "ig": "IG1"},
            {"id": "10.4", "name": "Configure Automatic Anti-Malware Scanning of Removable Media", "ig": "IG2"},
            {"id": "10.5", "name": "Enable Anti-Exploitation Features", "ig": "IG2"},
            {"id": "10.6", "name": "Centrally Manage Anti-Malware Software", "ig": "IG2"},
            {"id": "10.7", "name": "Use Behavior-Based Anti-Malware Software", "ig": "IG3"},
        ],
    },
    {
        "id": "11",
        "name": "Data Recovery",
        "description": "Establish and maintain data recovery practices sufficient to restore data "
                       "to a pre-incident and trusted state.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "11.1", "name": "Establish and Maintain a Data Recovery Process", "ig": "IG1"},
            {"id": "11.2", "name": "Perform Automated Backups", "ig": "IG1"},
            {"id": "11.3", "name": "Protect Recovery Data", "ig": "IG1"},
            {"id": "11.4", "name": "Establish and Maintain an Isolated Instance of Recovery Data", "ig": "IG2"},
            {"id": "11.5", "name": "Test Data Recovery", "ig": "IG2"},
        ],
    },
    {
        "id": "12",
        "name": "Network Infrastructure Management",
        "description": "Establish, implement, and actively manage network devices to prevent "
                       "attackers from exploiting vulnerable network services.",
        "implementation_groups": ["IG2", "IG3"],
        "safeguards": [
            {"id": "12.1", "name": "Ensure Network Infrastructure is Up-to-Date", "ig": "IG2"},
            {"id": "12.2", "name": "Establish and Maintain a Secure Network Architecture", "ig": "IG2"},
            {"id": "12.3", "name": "Securely Manage Network Infrastructure", "ig": "IG2"},
            {"id": "12.4", "name": "Establish and Maintain Architecture Diagram(s)", "ig": "IG2"},
            {"id": "12.5", "name": "Centralize Network Authentication, Authorization, and Auditing (AAA)", "ig": "IG2"},
            {"id": "12.6", "name": "Use of Secure Network Management and Communication Protocols", "ig": "IG2"},
            {"id": "12.7", "name": "Ensure Remote Devices Utilize a VPN", "ig": "IG2"},
            {"id": "12.8", "name": "Establish and Maintain Dedicated Computing Resources for All Administrative Work", "ig": "IG3"},
        ],
    },
    {
        "id": "13",
        "name": "Network Monitoring and Defense",
        "description": "Operate processes and tooling to establish and maintain comprehensive "
                       "network monitoring and defense against security threats.",
        "implementation_groups": ["IG2", "IG3"],
        "safeguards": [
            {"id": "13.1",  "name": "Centralize Security Event Alerting", "ig": "IG2"},
            {"id": "13.2",  "name": "Deploy a Host-Based Intrusion Detection Solution", "ig": "IG2"},
            {"id": "13.3",  "name": "Deploy a Network Intrusion Detection Solution", "ig": "IG2"},
            {"id": "13.4",  "name": "Perform Traffic Filtering Between Network Segments", "ig": "IG2"},
            {"id": "13.5",  "name": "Manage Access Control for Remote Assets", "ig": "IG2"},
            {"id": "13.6",  "name": "Collect Network Traffic Flow Logs", "ig": "IG2"},
            {"id": "13.7",  "name": "Deploy a Host-Based Intrusion Prevention Solution", "ig": "IG3"},
            {"id": "13.8",  "name": "Deploy a Network Intrusion Prevention Solution", "ig": "IG3"},
            {"id": "13.9",  "name": "Deploy Port-Level Access Control", "ig": "IG3"},
            {"id": "13.10", "name": "Perform Application Layer Filtering", "ig": "IG3"},
            {"id": "13.11", "name": "Tune Security Event Alerting Thresholds", "ig": "IG3"},
        ],
    },
    {
        "id": "14",
        "name": "Security Awareness and Skills Training",
        "description": "Establish and maintain a security awareness program to influence behavior "
                       "among the workforce to be security conscious.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "14.1", "name": "Establish and Maintain a Security Awareness Program", "ig": "IG1"},
            {"id": "14.2", "name": "Train Workforce Members to Recognize Social Engineering Attacks", "ig": "IG1"},
            {"id": "14.3", "name": "Train Workforce Members on Authentication Best Practices", "ig": "IG1"},
            {"id": "14.4", "name": "Train Workforce on Data Handling Best Practices", "ig": "IG1"},
            {"id": "14.5", "name": "Train Workforce on Causes of Unintentional Data Exposure", "ig": "IG1"},
            {"id": "14.6", "name": "Train Workforce on Recognizing and Reporting Security Incidents", "ig": "IG1"},
            {"id": "14.7", "name": "Train Workforce on Identifying Missing Security Updates", "ig": "IG2"},
            {"id": "14.8", "name": "Train Workforce on Dangers of Insecure Networks", "ig": "IG2"},
            {"id": "14.9", "name": "Conduct Role-Specific Security Awareness and Skills Training", "ig": "IG3"},
        ],
    },
    {
        "id": "15",
        "name": "Service Provider Management",
        "description": "Develop a process to evaluate service providers who hold sensitive data "
                       "or are responsible for critical IT platforms or processes.",
        "implementation_groups": ["IG2", "IG3"],
        "safeguards": [
            {"id": "15.1", "name": "Establish and Maintain an Inventory of Service Providers", "ig": "IG2"},
            {"id": "15.2", "name": "Establish and Maintain a Service Provider Management Policy", "ig": "IG2"},
            {"id": "15.3", "name": "Classify Service Providers", "ig": "IG2"},
            {"id": "15.4", "name": "Ensure Service Provider Contracts Include Security Requirements", "ig": "IG2"},
            {"id": "15.5", "name": "Assess Service Providers", "ig": "IG3"},
            {"id": "15.6", "name": "Monitor Service Providers", "ig": "IG3"},
            {"id": "15.7", "name": "Securely Decommission Service Providers", "ig": "IG3"},
        ],
    },
    {
        "id": "16",
        "name": "Application Software Security",
        "description": "Manage the security life cycle of in-house developed, hosted, or acquired "
                       "software to prevent, detect, and remediate security weaknesses.",
        "implementation_groups": ["IG2", "IG3"],
        "safeguards": [
            {"id": "16.1",  "name": "Establish and Maintain a Secure Application Development Process", "ig": "IG2"},
            {"id": "16.2",  "name": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities", "ig": "IG2"},
            {"id": "16.3",  "name": "Perform Root Cause Analysis on Security Vulnerabilities", "ig": "IG2"},
            {"id": "16.4",  "name": "Establish and Maintain a Process for Security Testing of Software", "ig": "IG2"},
            {"id": "16.5",  "name": "Use Up-to-Date and Trusted Third-Party Software Components", "ig": "IG2"},
            {"id": "16.6",  "name": "Establish and Maintain a Severity Rating System for Application Vulnerabilities", "ig": "IG2"},
            {"id": "16.7",  "name": "Use Standard Hardening Configuration Templates for Application Infrastructure", "ig": "IG2"},
            {"id": "16.8",  "name": "Separate Production and Non-Production Systems", "ig": "IG2"},
            {"id": "16.9",  "name": "Train Developers in Application Security Concepts and Secure Coding", "ig": "IG2"},
            {"id": "16.10", "name": "Apply Secure Design Principles in Application Architectures", "ig": "IG3"},
            {"id": "16.11", "name": "Leverage Vetted Modules or Services for Application Security Components", "ig": "IG3"},
            {"id": "16.12", "name": "Implement Code-Level Security Checks", "ig": "IG3"},
            {"id": "16.13", "name": "Conduct Application Penetration Testing", "ig": "IG3"},
            {"id": "16.14", "name": "Conduct Threat Modeling", "ig": "IG3"},
        ],
    },
    {
        "id": "17",
        "name": "Incident Response Management",
        "description": "Establish a program to develop and maintain an incident response capability "
                       "to prepare, detect, contain, and recover from attacks.",
        "implementation_groups": ["IG1", "IG2", "IG3"],
        "safeguards": [
            {"id": "17.1", "name": "Designate Personnel to Manage Incident Handling", "ig": "IG1"},
            {"id": "17.2", "name": "Establish and Maintain Contact Information for Reporting Security Incidents", "ig": "IG1"},
            {"id": "17.3", "name": "Establish and Maintain an Enterprise Process for Reporting Incidents", "ig": "IG1"},
            {"id": "17.4", "name": "Establish and Maintain an Incident Response Process", "ig": "IG2"},
            {"id": "17.5", "name": "Assign Key Roles and Responsibilities", "ig": "IG2"},
            {"id": "17.6", "name": "Define Mechanisms for Communicating During Incident Response", "ig": "IG2"},
            {"id": "17.7", "name": "Conduct Routine Incident Response Exercises", "ig": "IG2"},
            {"id": "17.8", "name": "Conduct Post-Incident Reviews", "ig": "IG2"},
            {"id": "17.9", "name": "Establish and Maintain Security Incident Thresholds", "ig": "IG3"},
        ],
    },
    {
        "id": "18",
        "name": "Penetration Testing",
        "description": "Test the effectiveness and resiliency of enterprise assets through "
                       "identifying and exploiting weaknesses in controls (people, process, and technology).",
        "implementation_groups": ["IG2", "IG3"],
        "safeguards": [
            {"id": "18.1", "name": "Establish and Maintain a Penetration Testing Program", "ig": "IG2"},
            {"id": "18.2", "name": "Perform Periodic External Penetration Tests", "ig": "IG2"},
            {"id": "18.3", "name": "Remediate Penetration Test Findings", "ig": "IG2"},
            {"id": "18.4", "name": "Validate Security Measures", "ig": "IG2"},
            {"id": "18.5", "name": "Perform Periodic Internal Penetration Tests", "ig": "IG3"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Wazuh SCA loader
# ---------------------------------------------------------------------------

def _load_wazuh_sca() -> list:
    """
    Read Wazuh SCA policy YAML files from /var/ossec/ruleset/sca/.
    Uses sudo since /var/ossec is root-owned. Requires passwordless sudo.
    """
    if not HAS_YAML:
        return []

    sca_checks = []

    # Find active (non-disabled) SCA files
    try:
        result = subprocess.run(
            ["sudo", "find", str(WAZUH_SCA_DIR), "-name", "*.yml",
             "!", "-name", "*.disabled"],
            capture_output=True, text=True, timeout=10,
        )
        sca_files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except Exception as e:
        print(f"  [cis_controls] Cannot list SCA files: {e}")
        return []

    for sca_file in sca_files:
        try:
            cat_result = subprocess.run(
                ["sudo", "cat", sca_file],
                capture_output=True, text=True, timeout=15,
            )
            if cat_result.returncode != 0:
                continue

            doc = yaml.safe_load(cat_result.stdout)
            if not isinstance(doc, dict):
                continue

            policy_info = doc.get("policy", {}) or {}
            policy_name = policy_info.get("name", Path(sca_file).stem)
            policy_id   = policy_info.get("id", Path(sca_file).stem)

            for check in doc.get("checks", []):
                sca_checks.append({
                    "id":          f"wazuh-sca-{check.get('id', '')}",
                    "type":        "wazuh_sca",
                    "policy_id":   policy_id,
                    "policy":      policy_name,
                    "title":       check.get("title", ""),
                    "description": check.get("description", ""),
                    "rationale":   check.get("rationale", ""),
                    "remediation": check.get("remediation", ""),
                    "references":  check.get("references", ""),
                    "source_file": Path(sca_file).name,
                })
        except Exception as e:
            print(f"  [cis_controls] Warning reading {sca_file}: {e}")
            continue

    return sca_checks


# ---------------------------------------------------------------------------
# Main ingestion function
# ---------------------------------------------------------------------------

def ingest(force_refresh: bool = False) -> list:
    """
    Return all CIS Controls v8 safeguards plus Wazuh SCA checks.
    Each record is a flat dict suitable for episode conversion.
    """
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = STORAGE_DIR / "controls.json"

    if out_file.exists() and not force_refresh:
        with open(out_file) as f:
            data = json.load(f)
        print(f"  [cis_controls] Using cached ({data.get('count', 0)} records)")
        return data.get("controls", [])

    records = []
    now = datetime.utcnow().isoformat()

    # --- CIS Controls v8 ---
    for control in CIS_CONTROLS_V8:
        cid = control["id"]
        records.append({
            "id":                   f"cis-control-{cid}",
            "type":                 "control",
            "control_id":           cid,
            "name":                 control["name"],
            "description":          control["description"],
            "implementation_groups": control["implementation_groups"],
            "source":               "CIS_Controls_v8",
            "ingested_at":          now,
        })
        for sg in control.get("safeguards", []):
            records.append({
                "id":               f"cis-safeguard-{sg['id']}",
                "type":             "safeguard",
                "control_id":       cid,
                "safeguard_id":     sg["id"],
                "name":             sg["name"],
                "description":      (
                    f"CIS Safeguard {sg['id']}: {sg['name']}. "
                    f"Part of Control {cid}: {control['name']}. "
                    f"Implementation Group: {sg['ig']}."
                ),
                "implementation_group": sg["ig"],
                "parent_control":   control["name"],
                "source":           "CIS_Controls_v8",
                "ingested_at":      now,
            })

    # --- Wazuh SCA ---
    sca_checks = _load_wazuh_sca()
    for check in sca_checks:
        check["source"]      = "Wazuh_SCA"
        check["ingested_at"] = now
        records.append(check)

    data = {
        "controls":        records,
        "count":           len(records),
        "cis_v8_controls": len(CIS_CONTROLS_V8),
        "cis_v8_safeguards": sum(len(c["safeguards"]) for c in CIS_CONTROLS_V8),
        "wazuh_sca_checks": len(sca_checks),
        "last_updated":    now,
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  [cis_controls] Ingested {len(records)} records "
          f"({data['cis_v8_safeguards']} CIS safeguards, "
          f"{len(sca_checks)} Wazuh SCA checks)")
    return records


if __name__ == "__main__":
    force   = "--refresh" in sys.argv
    records = ingest(force_refresh=force)

    print(f"\nTotal: {len(records)} records")
    by_type = {}
    for r in records:
        t = r.get("type") or r.get("source", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    for t, count in sorted(by_type.items()):
        print(f"  {t}: {count}")
