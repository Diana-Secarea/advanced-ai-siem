#!/usr/bin/env python3
"""
Generate realistic normal/clean Wazuh alerts simulating Diana's daily work activity.

These represent what the Isolation Forest should learn as NORMAL behaviour:
  - SSH logins from home IP during work hours
  - PAM session open/close (sek, sudo)
  - Routine sudo usage (apt, systemctl, python, nano)
  - Wazuh/OSSEC integrity and rootcheck scans
  - Cron job executions
  - File reads of standard config files
  - Normal syslog: NTP sync, DNS, DHCP
  - VS Code / git / python script runs detected via syslog
  - Docker container start/stop (normal dev work)

Output: one daily JSON file per generated day → merged into combined/all_alerts.json
"""

import json
import random
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent
DAILY_DIR    = SCRIPT_DIR / "data" / "training" / "daily_logs"
COMBINED_DIR = SCRIPT_DIR / "data" / "training" / "combined"

DAILY_DIR.mkdir(parents=True, exist_ok=True)
COMBINED_DIR.mkdir(parents=True, exist_ok=True)

# ── Constants ─────────────────────────────────────────────────────────────────
AGENT_ID   = "001"
AGENT_NAME = "LAPTOP-M9GQ2F87"
AGENT_IP   = "192.168.1.10"
HOME_IP    = "192.168.1.1"
USER       = "sek"
HOSTNAME   = "LAPTOP-M9GQ2F87"

# Normal rule IDs and their metadata (rule_id, level, description, decoder, mitre=[])
NORMAL_RULES = [
    # ── SSH ──────────────────────────────────────────────────────────────────
    {
        "id": 5715, "level": 3,
        "description": "sshd: authentication success.",
        "decoder": "sshd",
        "full_log_tpl": "Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:abcxyz",
        "data": {"srcip": HOME_IP, "srcuser": USER},
        "mitre": [],
    },
    {
        "id": 5710, "level": 3,
        "description": "sshd: Successful login.",
        "decoder": "sshd",
        "full_log_tpl": "Accepted password for {user} from {ip} port {port} ssh2",
        "data": {"srcip": HOME_IP, "srcuser": USER},
        "mitre": [],
    },
    {
        "id": 5501, "level": 3,
        "description": "Login session opened.",
        "decoder": "pam",
        "full_log_tpl": "pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        "data": {"srcuser": USER},
        "mitre": [],
    },
    {
        "id": 5502, "level": 3,
        "description": "Login session closed.",
        "decoder": "pam",
        "full_log_tpl": "pam_unix(sshd:session): session closed for user {user}",
        "data": {"srcuser": USER},
        "mitre": [],
    },
    # ── PAM / sudo sessions ──────────────────────────────────────────────────
    {
        "id": 5503, "level": 3,
        "description": "PAM: Login session opened.",
        "decoder": "pam",
        "full_log_tpl": "pam_unix(sudo:session): session opened for user root by {user}(uid=1000)",
        "data": {"srcuser": USER},
        "mitre": [],
    },
    {
        "id": 5504, "level": 3,
        "description": "PAM: Login session closed.",
        "decoder": "pam",
        "full_log_tpl": "pam_unix(sudo:session): session closed for user root",
        "data": {"srcuser": USER},
        "mitre": [],
    },
    # ── Sudo ─────────────────────────────────────────────────────────────────
    {
        "id": 5402, "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "decoder": "sudo",
        "full_log_tpl": "{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
        "data": {"srcuser": USER},
        "mitre": [],
        "cmds": [
            "/usr/bin/apt update",
            "/usr/bin/apt upgrade -y",
            "/usr/bin/systemctl restart wazuh-manager",
            "/usr/bin/systemctl status wazuh-manager",
            "/usr/bin/systemctl restart ssh",
            "/usr/bin/systemctl status docker",
            "/usr/bin/nano /etc/wazuh/ossec.conf",
            "/usr/bin/tail -f /var/ossec/logs/ossec.log",
            "/usr/bin/python3 train_isolation_forest.py",
            "/usr/bin/python3 collect_training_data.py",
            "/usr/bin/python3 evaluate_isolation_forest.py",
            "/usr/bin/docker compose up -d",
            "/usr/bin/docker compose down",
            "/usr/bin/journalctl -u wazuh-manager -n 50",
            "/usr/bin/cat /var/ossec/logs/alerts/alerts.json",
        ],
    },
    # ── OSSEC / Wazuh integrity ───────────────────────────────────────────────
    {
        "id": 510, "level": 3,
        "description": "Host-based anomaly detection event (rootcheck).",
        "decoder": "rootcheck",
        "full_log_tpl": "Rootcheck event: No issues found in the rootcheck scan.",
        "data": {},
        "mitre": [],
    },
    {
        "id": 516, "level": 3,
        "description": "Integrity checksum changed (syscheck).",
        "decoder": "syscheck",
        "full_log_tpl": "File '/etc/hosts' checksum changed. Old md5sum was: 'abc' and new md5sum is: 'def'",
        "data": {"file": "/etc/hosts"},
        "mitre": [],
    },
    {
        "id": 554, "level": 3,
        "description": "File added to system.",
        "decoder": "syscheck",
        "full_log_tpl": "New file '/home/{user}/.bash_history' added to the file system.",
        "data": {"file": "/home/sek/.bash_history"},
        "mitre": [],
    },
    # ── Cron ─────────────────────────────────────────────────────────────────
    {
        "id": 2502, "level": 3,
        "description": "Crontab has been edited.",
        "decoder": "cron",
        "full_log_tpl": "({user}) CMD ({cmd})",
        "data": {"srcuser": USER},
        "mitre": [],
        "cmds": [
            "/home/sek/wazuh/ai_threat_engine_starter/collect_daily.sh",
            "/usr/bin/python3 /home/sek/wazuh/ai_threat_engine_starter/collect_training_data.py",
            "/usr/bin/certbot renew --quiet",
            "/usr/bin/logrotate /etc/logrotate.conf",
        ],
    },
    # ── syslog general ───────────────────────────────────────────────────────
    {
        "id": 1002, "level": 2,
        "description": "Unknown problem somewhere in the system.",
        "decoder": "syslog",
        "full_log_tpl": "systemd[1]: Started {service}.",
        "data": {},
        "mitre": [],
        "services": [
            "Daily apt upgrade and clean activities",
            "Cleanup of Temporary Directories",
            "Network Time Synchronization",
            "Docker Application Container Engine",
            "OpenSSH Daemon",
            "Wazuh Manager Daemon",
        ],
    },
    {
        "id": 1003, "level": 2,
        "description": "Non standard syslog message (no header).",
        "decoder": "syslog",
        "full_log_tpl": "kernel: [UFW ALLOW] IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT={port} DPT={port2}",
        "data": {},
        "mitre": [],
    },
    # ── dpkg / apt ───────────────────────────────────────────────────────────
    {
        "id": 2902, "level": 3,
        "description": "New dpkg (Debian Package) installed.",
        "decoder": "dpkg",
        "full_log_tpl": "status installed {pkg}:{arch} {ver}",
        "data": {},
        "mitre": [],
        "pkgs": [
            "python3-sklearn", "python3-numpy", "python3-joblib",
            "curl", "wget", "git", "nano", "htop",
            "docker-compose-plugin", "openssh-server",
        ],
    },
    # ── Docker ───────────────────────────────────────────────────────────────
    {
        "id": 87701, "level": 3,
        "description": "Docker: Container started.",
        "decoder": "docker-listener",
        "full_log_tpl": "docker: Container {container} started.",
        "data": {},
        "mitre": [],
        "containers": ["wazuh_qdrant", "wazuh_postgres", "wazuh_ollama"],
    },
    {
        "id": 87702, "level": 3,
        "description": "Docker: Container stopped.",
        "decoder": "docker-listener",
        "full_log_tpl": "docker: Container {container} stopped.",
        "data": {},
        "mitre": [],
        "containers": ["wazuh_qdrant", "wazuh_postgres"],
    },
    # ── NTP / DNS ────────────────────────────────────────────────────────────
    {
        "id": 1001, "level": 1,
        "description": "Syslog message from {decoder}.",
        "decoder": "ntpd",
        "full_log_tpl": "ntpd[{pid}]: synchronized to 216.239.35.4, stratum 1",
        "data": {},
        "mitre": [],
    },
    # ── Network connections (normal dev) ──────────────────────────────────────
    {
        "id": 4112, "level": 3,
        "description": "syslog: User logged on.",
        "decoder": "syslog",
        "full_log_tpl": "sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2",
        "data": {"srcip": HOME_IP, "srcuser": USER},
        "mitre": [],
    },
]

# ── Weight by how often each event really occurs during a work day ────────────
RULE_WEIGHTS = {
    5501: 12,  # PAM session open — very common
    5502: 12,  # PAM session close
    5503: 20,  # sudo PAM session open — frequent dev work
    5504: 20,  # sudo PAM session close
    5402: 15,  # Successful sudo
    5715: 6,   # SSH pubkey
    5710: 4,   # SSH password
    510:  3,   # rootcheck
    516:  2,   # syscheck
    554:  2,   # new file
    2502: 8,   # cron
    1002: 5,   # systemd started
    1003: 3,   # UFW allow
    2902: 1,   # dpkg install
    87701: 4,  # docker start
    87702: 2,  # docker stop
    1001: 3,   # NTP
    4112: 4,   # sshd accepted
}


def make_alert(rule_def: dict, ts: datetime) -> dict:
    """Build one alert JSON matching the 13-feature extractor's expectations."""
    rid   = rule_def["id"]
    level = rule_def["level"]
    desc  = rule_def["description"]

    # Fill in the full_log template
    port  = random.randint(32768, 60999)
    port2 = random.randint(1024, 9999)
    pid   = random.randint(1000, 65000)
    cmd   = random.choice(rule_def.get("cmds", ["/usr/bin/ls"]))
    svc   = random.choice(rule_def.get("services", ["openssh"]))
    pkg   = random.choice(rule_def.get("pkgs", ["curl"]))
    ctr   = random.choice(rule_def.get("containers", ["wazuh_qdrant"]))

    full_log = (
        rule_def["full_log_tpl"]
        .replace("{user}", USER)
        .replace("{ip}", HOME_IP)
        .replace("{port}", str(port))
        .replace("{port2}", str(port2))
        .replace("{cmd}", cmd)
        .replace("{pid}", str(pid))
        .replace("{service}", svc)
        .replace("{pkg}", pkg)
        .replace("{arch}", "amd64")
        .replace("{ver}", f"1.{random.randint(0,9)}.{random.randint(0,20)}")
        .replace("{container}", ctr)
    )

    data = dict(rule_def.get("data", {}))

    alert = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "id": rid,
            "level": level,
            "description": desc,
            "groups": ["syslog"],
        },
        "agent": {
            "id": AGENT_ID,
            "name": AGENT_NAME,
            "ip": AGENT_IP,
        },
        "manager": {"name": HOSTNAME},
        "decoder": {"name": rule_def["decoder"]},
        "full_log": full_log,
        "message": full_log,
        "data": data,
    }

    if rule_def.get("mitre"):
        alert["rule"]["mitre"] = {"id": rule_def["mitre"], "tactic": [], "technique": []}

    return alert


def work_hour_ts(date: datetime) -> datetime:
    """Return a timestamp during Diana's working hours (8:30–22:00) on the given date."""
    # Weighted: heavier during 9-12 and 14-18
    segments = [
        (8, 10, 20),   # (start_h, end_h, weight)
        (10, 12, 30),
        (12, 14, 10),
        (14, 18, 35),
        (18, 22, 5),
    ]
    total = sum(w for _, _, w in segments)
    r = random.uniform(0, total)
    cumulative = 0
    start_h, end_h = 9, 17
    for sh, eh, w in segments:
        cumulative += w
        if r <= cumulative:
            start_h, end_h = sh, eh
            break
    hour   = random.randint(start_h, end_h - 1)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return date.replace(hour=hour, minute=minute, second=second, tzinfo=timezone.utc)


def generate_day(date: datetime, n_alerts: int) -> list:
    """Generate n_alerts normal alerts for a single day."""
    # Build weighted pool
    rule_by_id = {r["id"]: r for r in NORMAL_RULES}
    pool = []
    for rid, weight in RULE_WEIGHTS.items():
        pool.extend([rid] * weight)

    alerts = []
    # Cluster timestamps: morning login burst, midday work, afternoon work
    timestamps = sorted(work_hour_ts(date) for _ in range(n_alerts))

    for ts in timestamps:
        rid = random.choice(pool)
        rule_def = rule_by_id[rid]
        alerts.append(make_alert(rule_def, ts))

    return alerts


def save_daily(alerts: list, date_str: str):
    out_file = DAILY_DIR / f"{date_str}.json"
    with open(out_file, "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
    print(f"  {date_str}  →  {len(alerts):>5} alerts  →  {out_file.name}")


def rebuild_combined():
    combined = COMBINED_DIR / "all_alerts.json"
    total = 0
    daily_files = sorted(DAILY_DIR.glob("*.json"))
    with open(combined, "w") as out:
        for df in daily_files:
            with open(df) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.write(line + "\n")
                        total += 1
    print(f"\n  Combined: {len(daily_files)} days → {total} total alerts → {combined.name}")
    return total


def main():
    print("=" * 52)
    print("  Normal Activity Log Generator")
    print("  User: Diana (sek) on LAPTOP-M9GQ2F87")
    print("=" * 52)
    print()

    # Generate 20 working days (Mon–Fri) worth of normal activity
    # Spread across recent weeks; each day ~200–400 alerts
    # That gives 4,000–8,000 clean training samples
    today = datetime(2026, 4, 19, tzinfo=timezone.utc)

    generated_days = []
    day_cursor = today - timedelta(days=60)  # start ~2 months back
    while len(generated_days) < 25:
        # Skip weekends (5=Sat, 6=Sun)
        if day_cursor.weekday() < 5:
            generated_days.append(day_cursor)
        day_cursor += timedelta(days=1)

    print(f"Generating {len(generated_days)} days of normal activity...\n")

    # Skip days that already exist (don't overwrite real attack data from specific dates)
    existing_dates = {f.stem for f in DAILY_DIR.glob("*.json")}

    # Assign per-day volumes (more alerts on "active" work days)
    volumes = []
    for d in generated_days:
        # Monday and Wednesday tend to be busier
        if d.weekday() in (0, 2):
            volumes.append(random.randint(280, 380))
        else:
            volumes.append(random.randint(180, 280))

    skipped = 0
    for date, vol in zip(generated_days, volumes):
        date_str = date.strftime("%Y-%m-%d")
        if date_str in existing_dates:
            print(f"  {date_str}  →  SKIP (file already exists, preserving real data)")
            skipped += 1
            continue
        alerts = generate_day(date, vol)
        save_daily(alerts, date_str)

    print(f"\n  Skipped {skipped} existing day(s).")
    print("\nRebuilding combined training file...")
    total = rebuild_combined()

    print()
    print("=" * 52)
    print(f"  Done!  {total} total alerts in combined file.")
    print()
    print("  Next step — retrain the model:")
    print("    cd ai_threat_engine_starter")
    print("    ./venv/bin/python3 train_isolation_forest.py")
    print("=" * 52)


if __name__ == "__main__":
    main()
