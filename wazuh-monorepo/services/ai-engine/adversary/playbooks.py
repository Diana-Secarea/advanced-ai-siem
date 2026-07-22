"""
Blue-team playbooks — the "detect and react" half of the training loop.

For each attack family the adversary can synthesise, this maps out what the
activity looks like, how to spot it (the signals the detector keys on and the
Wazuh rules/groups involved), the MITRE ATT&CK technique, and a concrete
incident-response runbook. The adversary shows you WHERE the detector is blind;
these playbooks teach you WHAT to do about each family when it fires.

Nothing here is offensive tooling — it is detection guidance and response steps
keyed to the synthetic alerts in attack_templates.py.
"""

PLAYBOOKS = {
    "ssh_bruteforce": {
        "title": "SSH brute force",
        "mitre": "T1110 — Brute Force",
        "what": "Repeated failed authentication against SSH from one (often public) source, guessing credentials.",
        "detect": [
            "Spike in failed-auth keyword density (feature: failed_count) from one srcip",
            "External source IP + off-hours timing raise the ensemble score",
            "Wazuh rules 5710/5712/5720/5758 (authentication_failed, bruteforce groups)",
        ],
        "respond": [
            "Confirm the source IP is not a known jump host or scanner you run",
            "Block the source IP at the firewall (Reactor: block-ip) — public IPs only, TTL-bounded",
            "Check for any SUCCESSFUL login from that IP after the burst — if yes, treat as compromise",
            "Enforce key-only SSH + fail2ban/rate-limit; rotate any exposed account",
        ],
    },
    "web_sqli": {
        "title": "SQL injection",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "what": "Malicious SQL in a web request trying to read or alter the database.",
        "detect": [
            "URL/body markers: UNION SELECT, ' OR, sleep(, /etc/passwd (feature: url_suspicious)",
            "External srcip against a web-facing agent",
            "Wazuh web_attack / sql_injection rule groups (31103-range)",
        ],
        "respond": [
            "Pull the full request + response size — did the query return rows (data leak)?",
            "Block the source IP; put the app behind a WAF rule for that pattern",
            "Patch the injectable parameter (parameterised queries) — this is the real fix",
            "Review DB audit logs for what the query touched; rotate DB creds if reads succeeded",
        ],
    },
    "privilege_escalation": {
        "title": "Privilege escalation",
        "mitre": "T1068 / T1548 — Privilege Escalation",
        "what": "A low-privilege account gaining root/SYSTEM — sudo abuse, uid-0 transition, group change.",
        "detect": [
            "uid=0 / CurrentUserID=0 transitions (feature: unknown_user_flag, privileged_change)",
            "'to root', 'sudo', 'group added' in the log",
            "Correlate with a preceding initial-access alert on the same host",
        ],
        "respond": [
            "Identify the parent process / command that escalated",
            "Isolate the host if the escalation was not an approved admin action",
            "Audit sudoers + recently-changed SUID binaries and group memberships",
            "Reset the abused account; hunt for persistence dropped post-escalation",
        ],
    },
    "c2_beacon": {
        "title": "C2 beacon",
        "mitre": "T1071 / T1571 — Command and Control",
        "what": "An internal host beaconing out to an attacker-controlled server on a regular interval.",
        "detect": [
            "Outbound connection to an external IP with process/exec context (feature: is_external_srcip)",
            "Regular interval / long-lived connection, often 443 to a fresh domain",
            "Wazuh command_and_control group; sysmon process+network correlation",
        ],
        "respond": [
            "Block the destination IP/domain egress immediately (Reactor: block-ip)",
            "Identify and kill the beaconing process; capture it for analysis",
            "Isolate the host from the network; it is likely already compromised",
            "Hunt the same C2 indicator across all hosts (pivot on dstip/domain)",
        ],
    },
    "data_exfil": {
        "title": "Data exfiltration",
        "mitre": "T1041 / T1567 — Exfiltration",
        "what": "Large or unusual outbound transfer moving data off the network.",
        "detect": [
            "High byte-count outbound to an external host (feature: is_external_srcip + size)",
            "Transfer volume/timing anomalous for that host (UEBA behavioral deviation)",
            "Off-hours large uploads to cloud/unknown endpoints",
        ],
        "respond": [
            "Block the destination and throttle/kill the session",
            "Determine WHAT was sent (DLP, proxy logs) and its sensitivity",
            "Isolate the source host; begin breach-assessment if regulated data left",
            "Notify per your incident/legal policy if exfil is confirmed",
        ],
    },
    "ransomware": {
        "title": "Ransomware",
        "mitre": "T1486 (Data Encrypted for Impact) + T1490 (Inhibit Recovery)",
        "what": "Mass file encryption on a host, usually with shadow-copy deletion and a ransom note.",
        "detect": [
            "Rapid bulk file renames to a new extension (.locked/.crypt) — many files, one process",
            "'vssadmin delete shadows' / backup-destruction commands",
            "Ransom-note filenames (README_RESTORE.txt) dropped across directories",
            "UEBA: a single process touching an abnormal number of files fast",
        ],
        "respond": [
            "ISOLATE the host from the network NOW — pull it off the LAN to stop spread",
            "Do NOT power off if you need memory forensics; do disconnect storage/shares",
            "Identify and kill the encrypting process; block its hash fleet-wide",
            "Restore from offline/immutable backups — never pay based on the note alone",
            "Hunt for the initial access + lateral movement that delivered it (this is rarely the first host)",
        ],
    },
    "lateral_movement": {
        "title": "Lateral movement",
        "mitre": "T1021 / T1570 — Lateral Movement",
        "what": "An attacker pivoting host-to-host inside the network using remote exec (PsExec/SMB/WMI/RDP).",
        "detect": [
            "Internal→internal admin session creating a remote service (psexesvc, \\\\host\\admin$)",
            "One account authenticating to many hosts in a short window (UEBA new user-host pairs)",
            "Pass-the-hash / unusual service installs via SMB",
        ],
        "respond": [
            "Map the movement graph: which accounts touched which hosts, in what order",
            "Disable the compromised account(s) and reset the credentials used",
            "Isolate the hosts already reached; block SMB/RDP between segments if not needed",
            "Hunt for the dumped credentials that enabled the pivot (see credential_dumping)",
        ],
    },
    "credential_dumping": {
        "title": "Credential dumping",
        "mitre": "T1003 — OS Credential Dumping",
        "what": "Stealing credentials from memory or disk — LSASS access, Mimikatz, /etc/shadow, NTDS.dit.",
        "detect": [
            "Process opening lsass.exe memory (sekurlsa::logonpasswords), or reads of shadow/SAM/NTDS",
            "Known tools (Mimikatz/procdump) even under renamed binaries — behavior over name",
            "Sysmon process-access events to LSASS from a non-security process",
        ],
        "respond": [
            "Isolate the host — assume every credential used on it is now burned",
            "Force-reset the exposed accounts (especially domain/admin) and any reused elsewhere",
            "Enable LSASS protection (RunAsPPL) / Credential Guard; restrict debug privilege",
            "Pivot: dumped creds usually precede lateral movement — hunt for their reuse",
        ],
    },
    "apt_persistence": {
        "title": "Persistence implant",
        "mitre": "T1053 / T1547 — Persistence",
        "what": "Backdoor that survives reboot — scheduled task, run key, cron, or a rogue service.",
        "detect": [
            "New scheduled task / service / run-key pointing at an unusual path (C:\\Users\\Public, /tmp)",
            "Autostart entries created outside change windows, often as SYSTEM",
            "Low-and-slow: persistence alerts are quiet (level often <=10) — easy to miss",
        ],
        "respond": [
            "Capture the implant path/hash before removing it (evidence + fleet hunt)",
            "Remove the persistence mechanism AND the payload it launches",
            "Determine how it was planted (prior escalation/access) — removing persistence alone is not eradication",
            "Sweep the fleet for the same task name / path / hash",
        ],
    },
}


def get(family):
    return PLAYBOOKS.get(family)


def all_playbooks():
    return PLAYBOOKS
