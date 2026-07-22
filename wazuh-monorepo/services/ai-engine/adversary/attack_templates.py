"""
Attack families: malicious seed alerts + the invariant that keeps a mutated
variant a *real* attack.

The point of the attacker-in-the-loop is honest blind-spot mining: a variant
only counts if it is STILL an attack. We enforce that on two levels:

  1. The repo's own oracle — attack_labels.is_attack_alert(alert) — must stay
     True. That is the same ground-truth labeler train_stacking.py uses, so any
     banked blind spot is guaranteed to be labeled an attack when it is later
     harvested into the training corpus. No label leakage, no cheating by
     turning the attack benign.

  2. A family invariant() — the semantic core of THIS attack (e.g. a brute
     force must keep a public external source IP and auth-failure semantics).
     This stops the search from "evading" by mutating a brute force into some
     other, unrelated benign-looking event that merely happens to trip the
     oracle on a technicality.

Each family also declares which fields the mutator may freely change (`genome`)
— exactly the levers a real adversary has: timing (low-and-slow), log verbosity,
which Wazuh rule/group the activity trips (living-off-the-land), and how much
side data the event carries. The attack's identity stays fixed; its disguise
does not.
"""

import copy
import ipaddress


# Public, routable attacker IPs (Tor exits / bulletproof ranges) — kept external
# so network-attack invariants hold. Feature 12 (external IP) keys on this.
PUBLIC_ATTACKER_IPS = [
    "185.220.101.4", "45.155.205.233", "193.169.255.78",
    "141.98.10.63", "89.248.165.191", "212.70.149.150",
]
INTERNAL_IPS = ["192.168.1.10", "192.168.1.24", "10.0.0.15", "10.0.0.42"]

# Hours the mutator may move an event to. Off-hours (2-6) is a feature the model
# keys on, so business hours are part of a realistic disguise.
BUSINESS_HOURS = [8, 9, 10, 11, 13, 14, 15, 16, 17]
OFF_HOURS = [2, 3, 4, 5]
ALL_HOURS = BUSINESS_HOURS + [12, 18, 19, 20, 21, 22] + OFF_HOURS


def _is_public(ip):
    try:
        return not ipaddress.ip_address(str(ip)).is_private
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Family invariants — the semantic core each variant must preserve.          #
#  (The global attack-oracle check is applied separately in the environment.) #
# --------------------------------------------------------------------------- #

def _inv_bruteforce(a):
    data = a.get("data", {})
    log = str(a.get("full_log", "")).lower()
    # must still be a credential-guessing attempt from a public source
    return (_is_public(data.get("srcip", ""))
            and any(k in log for k in ("password", "authentication", "login", "auth")))


def _inv_web(a):
    data = a.get("data", {})
    blob = (str(a.get("full_log", "")) + " " + str(data)).lower()
    web_markers = ("union select", "../", "<script", "/etc/passwd", "' or ",
                   "concat(", "sleep(", "sqlmap", "wp-login", "/admin")
    return _is_public(data.get("srcip", "")) and any(m in blob for m in web_markers)


def _inv_privesc(a):
    data = a.get("data", {})
    log = str(a.get("full_log", "")).lower()
    # unknown/zero-uid escalation or an explicit privilege/group change
    return (str(data.get("user_id", "")) == "0"
            or str(data.get("CurrentUserID", "")) == "0"
            or "to root" in log or "sudo" in log or "group added" in log
            or "promiscuous" in log)


def _inv_c2(a):
    data = a.get("data", {})
    log = str(a.get("full_log", "")).lower()
    # outbound beacon to a public host with process/exec context
    return (_is_public(data.get("dstip", "")) or _is_public(data.get("srcip", ""))) and \
           any(k in log for k in ("exec", "process", "connect", "beacon", "curl", "powershell"))


def _inv_exfil(a):
    data = a.get("data", {})
    log = str(a.get("full_log", "")).lower()
    return _is_public(data.get("dstip", data.get("srcip", ""))) and \
           any(k in log for k in ("bytes", "transfer", "upload", "outbound", "gb", "mb"))


def _inv_ransomware(a):
    # Host-based: mass-encryption + shadow-copy destruction + ransom-note markers.
    log = str(a.get("full_log", "")).lower()
    return any(k in log for k in (
        "encrypt", ".locked", ".crypt", "ransom", "vssadmin", "shadow copy",
        "readme", "renamed", "extension", "bulk file"))


def _inv_lateral(a):
    # Internal host-to-host movement via remote-exec / SMB / admin session.
    data = a.get("data", {})
    log = str(a.get("full_log", "")).lower()
    internal_src = not _is_public(data.get("srcip", ""))   # absent/private both count
    return internal_src and any(k in log for k in (
        "psexec", "smb", "admin$", "wmi", "remote service", "lateral",
        "pass-the-hash", "\\\\", "net use", "rdp"))


def _inv_creddump(a):
    log = str(a.get("full_log", "")).lower()
    return any(k in log for k in (
        "lsass", "mimikatz", "sekurlsa", "/etc/shadow", "sam database",
        "ntds.dit", "credential", "hashdump", "procdump", "logonpasswords"))


def _inv_persistence(a):
    log = str(a.get("full_log", "")).lower()
    return any(k in log for k in (
        "schtasks", "scheduled task", "cron", "systemd", "run key",
        "registry run", "autorun", "service install", "startup", "launchd", "implant"))


# --------------------------------------------------------------------------- #
#  Family definitions                                                          #
# --------------------------------------------------------------------------- #

FAMILIES = {
    "ssh_bruteforce": {
        "invariant": _inv_bruteforce,
        "genome": ["hour", "srcip", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T03:12:00.000+0000",
            "rule": {"id": 5712, "level": 10,
                     "description": "sshd: Multiple authentication failures (brute force)",
                     "groups": ["authentication_failed", "bruteforce", "syslog"]},
            "agent": {"id": "001", "ip": "192.168.1.10"},
            "data": {"srcip": "185.220.101.4", "srcport": "44210", "dstuser": "root"},
            "full_log": ("Failed password for invalid user root from 185.220.101.4 "
                         "port 44210 ssh2; failed password; failed password; "
                         "authentication failure; invalid user (47 failed attempts)"),
            "decoder": {"name": "sshd"},
        },
    },
    "web_sqli": {
        "invariant": _inv_web,
        "genome": ["hour", "srcip", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T03:40:00.000+0000",
            "rule": {"id": 31103, "level": 12,
                     "description": "SQL injection attack detected in web request",
                     "groups": ["web", "web_attack", "sql_injection", "attack"]},
            "agent": {"id": "003", "ip": "192.168.1.20"},
            "data": {"srcip": "45.155.205.233", "srcport": "51044",
                     "url": "/products.php?id=1' UNION SELECT username,password FROM users--",
                     "protocol": "GET"},
            "full_log": ("GET /products.php?id=1' UNION SELECT username,password FROM users-- "
                         "HTTP/1.1 from 45.155.205.233 - sql injection web attack detected"),
            "decoder": {"name": "web-accesslog"},
        },
    },
    "privilege_escalation": {
        "invariant": _inv_privesc,
        "genome": ["hour", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T04:05:00.000+0000",
            "rule": {"id": 5715, "level": 10,
                     "description": "Privilege escalation attempt to root via sudo",
                     "groups": ["syslog", "sudo", "privilege_escalation", "attack"]},
            "agent": {"id": "002", "ip": "192.168.1.11"},
            "data": {"srcip": "192.168.1.11", "user_id": "0", "CurrentUserID": "0",
                     "command": "/bin/bash"},
            "full_log": ("user webadmin : TTY=pts/2 ; PWD=/tmp ; USER=root ; "
                         "COMMAND=/bin/bash — privilege escalation attempt to root uid=0"),
            "decoder": {"name": "sudo"},
        },
    },
    "c2_beacon": {
        "invariant": _inv_c2,
        "genome": ["hour", "dstip", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T03:55:00.000+0000",
            "rule": {"id": 100002, "level": 12,
                     "description": "Process execution beaconing to external host (possible C2)",
                     "groups": ["attack", "command_and_control", "ids"]},
            "agent": {"id": "004", "ip": "10.0.0.15"},
            "data": {"srcip": "10.0.0.15", "dstip": "193.169.255.78", "dstport": "443",
                     "process": "powershell.exe"},
            "full_log": ("process powershell.exe exec outbound connect to 193.169.255.78:443 "
                         "beacon interval 60s — possible C2 command and control"),
            "decoder": {"name": "sysmon"},
        },
    },
    "data_exfil": {
        "invariant": _inv_exfil,
        "genome": ["hour", "dstip", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T04:20:00.000+0000",
            "rule": {"id": 100003, "level": 11,
                     "description": "Large outbound data transfer to external host (exfiltration)",
                     "groups": ["attack", "exfiltration", "ids"]},
            "agent": {"id": "005", "ip": "10.0.0.42"},
            "data": {"srcip": "10.0.0.42", "dstip": "141.98.10.63", "dstport": "443",
                     "bytes": "5300000000"},
            "full_log": ("outbound transfer 5.3 GB bytes upload to 141.98.10.63:443 "
                         "over 4 minutes — possible data exfiltration"),
            "decoder": {"name": "netflow"},
        },
    },
    # ---- Advanced / host-based families (endpoint telemetry, no external IP) ----
    "ransomware": {
        "invariant": _inv_ransomware,
        "genome": ["hour", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T02:40:00.000+0000",
            "rule": {"id": 100050, "level": 13,
                     "description": "Ransomware behavior: mass file encryption + shadow copy deletion",
                     "groups": ["attack", "ransomware", "malware", "ids"]},
            "agent": {"id": "006", "ip": "192.168.1.30"},
            "data": {"process": "svchost32.exe", "files_changed": "1842",
                     "extension": ".locked", "user": "jdoe"},
            "full_log": ("process svchost32.exe renamed 1842 files to .locked extension; "
                         "vssadmin delete shadows /all /quiet executed; dropped "
                         "README_RESTORE.txt ransom note — mass file encryption detected"),
            "decoder": {"name": "sysmon"},
        },
    },
    "lateral_movement": {
        "invariant": _inv_lateral,
        "genome": ["hour", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T03:05:00.000+0000",
            "rule": {"id": 100051, "level": 12,
                     "description": "Lateral movement: remote service creation via SMB/PsExec",
                     "groups": ["attack", "lateral_movement", "ids"]},
            "agent": {"id": "007", "ip": "192.168.1.40"},
            "data": {"srcip": "192.168.1.40", "dstip": "192.168.1.55",
                     "user": "administrator", "process": "psexesvc.exe"},
            "full_log": ("psexec remote service psexesvc.exe created on \\\\192.168.1.55 "
                         "admin$ share using administrator credentials — lateral movement via SMB"),
            "decoder": {"name": "sysmon"},
        },
    },
    "credential_dumping": {
        "invariant": _inv_creddump,
        "genome": ["hour", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T03:20:00.000+0000",
            "rule": {"id": 100052, "level": 13,
                     "description": "Credential dumping: LSASS memory access (Mimikatz)",
                     "groups": ["attack", "credential_access", "malware", "ids"]},
            "agent": {"id": "008", "ip": "192.168.1.45"},
            "data": {"process": "m1m.exe", "target": "lsass.exe", "user": "svc_admin"},
            "full_log": ("m1m.exe sekurlsa::logonpasswords accessed lsass.exe memory to dump "
                         "credentials from the SAM database — credential theft detected"),
            "decoder": {"name": "sysmon"},
        },
    },
    "apt_persistence": {
        "invariant": _inv_persistence,
        "genome": ["hour", "rule_level", "rule_group", "log_verbosity", "data_fields"],
        "seed": {
            "timestamp": "2025-02-01T04:50:00.000+0000",
            "rule": {"id": 100053, "level": 10,
                     "description": "Persistence: scheduled-task / run-key implant",
                     "groups": ["attack", "persistence", "ids"]},
            "agent": {"id": "009", "ip": "192.168.1.50"},
            "data": {"process": "schtasks.exe", "task_name": "WindowsUpdateCheck",
                     "user": "SYSTEM"},
            "full_log": ("schtasks /create /tn WindowsUpdateCheck /tr "
                         "C:\\Users\\Public\\svc.exe /sc onlogon /ru SYSTEM — scheduled task "
                         "persistence implant created"),
            "decoder": {"name": "sysmon"},
        },
    },
}


def get_seed(family):
    """Return a deep copy of the family's malicious seed alert."""
    return copy.deepcopy(FAMILIES[family]["seed"])


def invariant_for(family):
    return FAMILIES[family]["invariant"]


def genome_for(family):
    return list(FAMILIES[family]["genome"])


def all_families():
    return list(FAMILIES.keys())
