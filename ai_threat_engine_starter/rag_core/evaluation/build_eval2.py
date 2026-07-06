"""Build eval_dataset_82.json with ground-truth IDs verified against the live Qdrant index."""
import json, re, sys
from pathlib import Path
sys.path.insert(0, "/home/sek/wazuh/ai_threat_engine_starter")
from rag_core.database.qdrant_store import QdrantStore, COLLECTION_THREAT_INTEL

s = QdrantStore()
ALL = set()
off = None
while True:
    pts, off = s.client.scroll(collection_name=COLLECTION_THREAT_INTEL, limit=700,
                               offset=off, with_payload=True, with_vectors=False)
    for p in pts:
        pl = p.payload or {}
        ALL.add(str(pl.get("episode_id") or p.id))
    if off is None:
        break
print("indexed ids:", len(ALL))

# Technique IDs present (bare T id, e.g. "T1021")
TECH = {i for i in ALL if re.fullmatch(r"T\d{4}(\.\d{3})?", i)}

def fam(*bases):
    """Expand base technique ids to themselves + indexed sub-techniques."""
    out = []
    for b in bases:
        if b in TECH:
            out.append(b)
        out += sorted(t for t in TECH if t.startswith(b + "."))
    return out

def kev(*cves):
    return [f"kev-{c}" for c in cves]

# ---- 6 categories ----------------------------------------------------------
DATA = []
def add(query, relevant, category):
    DATA.append({"query": query, "relevant": relevant, "category": category})

# 1) MITRE ATT&CK techniques (22)
M = "mitre-attack"
add("How does process injection work on Linux?", fam("T1055"), M)
add("DLL side-loading and hijacking execution flow", fam("T1574"), M)
add("Scheduled task and cron job persistence", fam("T1053"), M)
add("OS credential dumping techniques", fam("T1003"), M)
add("Phishing as an initial access vector", fam("T1566"), M)
add("Command and scripting interpreter abuse", fam("T1059"), M)
add("Masquerading to evade detection", fam("T1036"), M)
add("Obfuscated files or information", fam("T1027"), M)
add("Account discovery on a compromised host", fam("T1087"), M)
add("System information discovery", fam("T1082"), M)
add("Boot or logon autostart execution persistence", fam("T1547"), M)
add("Create or modify system services for persistence", fam("T1543"), M)
add("Data encrypted for impact by ransomware", fam("T1486"), M)
add("Inhibit system recovery to prevent restoration", fam("T1490"), M)
add("Abuse of valid accounts for access", fam("T1078"), M)
add("Indicator removal and log deletion on a host", fam("T1070"), M)
add("Brute force authentication attacks", fam("T1110"), M)
add("Exploit public-facing application", fam("T1190"), M)
add("Ingress tool transfer onto a victim", fam("T1105"), M)
add("File and directory discovery", fam("T1083"), M)
add("Abuse elevation control mechanism with sudo", fam("T1548"), M)
add("Modify registry to hide configuration", fam("T1112"), M)

# 2) CVE / vulnerability details (18)
C = "cve-vulnerability"
add("Apache Log4j2 deserialization remote code execution", kev("CVE-2021-45046"), C)
add("Spring Framework JDK 9+ remote code execution Spring4Shell", kev("CVE-2022-22965"), C)
add("Microsoft Exchange Server ProxyLogon remote code execution", kev("CVE-2021-26855"), C)
add("Microsoft Exchange Server privilege escalation ProxyShell", kev("CVE-2021-34523"), C)
add("Ivanti Connect Secure server-side request forgery vulnerability", kev("CVE-2024-21893"), C)
add("Ivanti Pulse Connect Secure use-after-free vulnerability", kev("CVE-2021-22893"), C)
add("Fortinet FortiOS SSL-VPN heap buffer overflow", kev("CVE-2023-27997"), C)
add("Fortinet FortiOS heap-based buffer overflow exploited in the wild", kev("CVE-2022-42475"), C)
add("Fortinet FortiOS SSL VPN improper authentication bypass", kev("CVE-2020-12812"), C)
add("Atlassian Confluence broken access control privilege escalation", kev("CVE-2023-22515"), C)
add("Atlassian Confluence template injection remote code execution", kev("CVE-2023-22527"), C)
add("Atlassian Confluence pre-authorization arbitrary file read", kev("CVE-2021-26085"), C)
add("Citrix NetScaler ADC and Gateway buffer overflow", kev("CVE-2025-6543"), C)
add("Citrix ADC and Gateway authorization bypass", kev("CVE-2020-8193"), C)
add("Progress MOVEit Transfer SQL injection vulnerability", kev("CVE-2023-34362"), C)
add("Oracle WebLogic Server OS command injection", kev("CVE-2017-3506"), C)
add("Apache Struts remote code execution vulnerability", kev("CVE-2020-17530"), C)
add("Palo Alto Networks Expedition OS command injection", kev("CVE-2024-9463"), C)

# 3) Lateral movement TTPs (12)
L = "lateral-movement"
add("Lateral movement using remote services", fam("T1021"), L)
add("Remote Desktop Protocol lateral movement", ["T1021.001"], L)
add("SSH used to move laterally between hosts", ["T1021.004"], L)
add("SMB and Windows admin shares lateral movement", ["T1021.002"], L)
add("Pass the hash using stolen password hashes", ["T1550.002"], L)
add("Pass the ticket with stolen Kerberos tickets", ["T1550.003"], L)
add("Use of alternate authentication material", fam("T1550"), L)
add("Lateral tool transfer between compromised systems", fam("T1570"), L)
add("Remote service session hijacking", fam("T1563"), L)
add("Windows Remote Management WinRM lateral movement", ["T1021.006"], L)
add("Internal spearphishing to move within a network", fam("T1534"), L)
add("Exploitation of remote services for lateral movement", fam("T1210"), L)

# 4) C2 / exfiltration patterns (14)
X = "c2-exfiltration"
add("Application layer protocol command and control", fam("T1071"), X)
add("Command and control over web protocols HTTP HTTPS", ["T1071.001"], X)
add("DNS tunneling for command and control", ["T1071.004"], X)
add("Exfiltration over the existing C2 channel", fam("T1041"), X)
add("Exfiltration over alternative protocol", fam("T1048"), X)
add("Encrypted channel for covert C2 communication", fam("T1573"), X)
add("Command and control over a non-standard port", fam("T1571"), X)
add("Protocol tunneling to bypass network controls", fam("T1572"), X)
add("Connection proxy to obscure C2 infrastructure", fam("T1090"), X)
add("Data encoding for C2 traffic", fam("T1132"), X)
add("Fallback channels for resilient C2", fam("T1008"), X)
add("Web service used as a C2 dead drop resolver", fam("T1102"), X)
add("Scheduled transfer of exfiltrated data", fam("T1029"), X)
add("Data transfer size limits to evade detection", fam("T1030"), X)

# 5) APT group profiles (9)
A = "apt-group"
add("APT29 Cozy Bear nation-state actor TTPs", ["group-G0016"], A)
add("APT28 Fancy Bear campaign techniques", ["group-G0007"], A)
add("Lazarus Group HIDDEN COBRA operations", ["group-G0032"], A)
add("FIN7 Carbon Spider financial threat actor", ["group-G0046"], A)
add("Sandworm Team BlackEnergy attacks", ["group-G0034"], A)
add("OilRig APT34 Helix Kitten activity", ["group-G0049"], A)
add("APT41 Wicked Panda dual espionage and crime", ["group-G0096"], A)
add("Volt Typhoon living-off-the-land intrusions", ["group-G1017"], A)
add("Scattered Spider Octo Tempest social engineering", ["group-G1015"], A)

# 6) Wazuh rules and responses (7) -> SCA / CIS hardening checks
W = "wazuh-rules"
def sca(*ids):
    return [f"wazuh-sca-{i}" for i in ids]
add("Ensure SSH idle timeout interval is configured", sca("36153"), W)
add("Ensure SSH MaxStartups is configured", sca("36159"), W)
add("Ensure inactive password lock is 30 days or less", sca("36167"), W)
add("Ensure TCP SYN cookies is enabled", sca("36091"), W)
add("Ensure TIPC uncommon network protocol is disabled", sca("36100"), W)
add("Wazuh SCA SSH hardening configuration checks", sca("36153", "36159"), W)
add("Wazuh CIS benchmark password policy compliance", sca("36167"), W)

# ---- validate every relevant id exists, drop missing -----------------------
print("\nValidation:")
clean = []
for d in DATA:
    present = [r for r in d["relevant"] if r in ALL]
    missing = [r for r in d["relevant"] if r not in ALL]
    if missing:
        print(f"  ! {d['query'][:50]:50s} missing {missing}")
    if not present:
        print(f"  XX DROPPED (no relevant indexed): {d['query']}")
        continue
    d["relevant"] = present
    clean.append(d)

from collections import Counter
cc = Counter(d["category"] for d in clean)
print("\nPer-category counts:", dict(cc), "TOTAL", len(clean))
avg = sum(len(d["relevant"]) for d in clean) / len(clean)
print("overall avg relevant chunks:", round(avg, 2))

out = Path("/home/sek/wazuh/ai_threat_engine_starter/rag_core/evaluation/eval_dataset_82.json")
out.write_text(json.dumps(clean, indent=2))
print("wrote", out, len(clean), "queries")
