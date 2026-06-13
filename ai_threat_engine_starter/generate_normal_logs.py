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

EXTERNAL_IPS = [
    "5.188.10.250", "51.15.120.74", "77.234.42.11", "82.102.17.83",
    "85.214.67.22", "93.184.216.34", "95.216.34.195", "213.32.75.110",
    "37.59.100.201", "46.101.127.41", "54.72.9.51",  "62.210.138.7",
    "78.47.250.30",  "89.234.157.254","91.121.88.21", "94.23.33.92",
    "130.185.250.68","136.243.154.56","151.80.119.120","163.172.6.50",
    "176.9.0.67",    "178.63.48.166", "188.165.200.156","194.32.107.41",
    HOME_IP, HOME_IP, HOME_IP, "10.0.0.50", "10.0.0.100",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "python-requests/2.31.0", "curl/7.88.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
]

WEB_PAGES = [
    "/", "/index.html", "/about", "/about-us", "/contact", "/contact-us",
    "/products", "/services", "/portfolio", "/team", "/faq", "/pricing",
    "/blog/", "/blog/getting-started-with-siem/", "/blog/threat-detection-tips/",
    "/blog/network-security-best-practices/", "/blog/wazuh-configuration-guide/",
    "/page/2/", "/page/3/", "/category/security/", "/category/tutorials/",
    "/tag/wazuh/", "/tag/siem/", "/search?q=security+monitoring",
    "/dashboard", "/profile", "/settings", "/reports", "/alerts",
    "/wp-content/themes/astra/style.css", "/wp-content/themes/twentytwenty/index.php",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/posts?per_page=10",
    "/wp-json/wp/v2/categories", "/wp-admin/admin-ajax.php",
    "/feed/", "/sitemap.xml", "/robots.txt",
    "/wp-content/plugins/contact-form-7/includes/js/scripts.js",
    "/wp-content/uploads/2026/01/security-report.pdf",
]

WEB_STATIC = [
    "/css/main.css", "/css/style.css", "/css/bootstrap.min.css",
    "/js/app.min.js", "/js/jquery.min.js", "/js/bootstrap.bundle.min.js",
    "/images/logo.png", "/images/hero-bg.jpg", "/images/icons/shield.svg",
    "/fonts/roboto-v30-latin-regular.woff2", "/favicon.ico", "/favicon.png",
    "/assets/img/banner.webp", "/static/reports/monthly-2026-01.pdf",
]

WEB_API = [
    "/api/v1/alerts", "/api/v1/alerts?page=1&limit=20", "/api/v1/alerts/stats",
    "/api/v1/dashboard", "/api/v1/dashboard/metrics", "/api/v1/users/me",
    "/api/v1/rules", "/api/v1/agents/status", "/api/v1/reports/summary",
    "/api/v1/health", "/api/v1/status", "/api/v2/threats?severity=high",
    "/api/chat", "/api/v1/search?q=brute+force",
]

WEB_POST_URLS = [
    "/api/v1/data", "/api/v1/submit", "/api/v1/authenticate",
    "/api/v1/feedback", "/api/v2/events", "/api/chat",
    "/contact/send", "/newsletter/subscribe", "/form/submit",
    "/wp-comments-post.php", "/wp-admin/admin-ajax.php",
]

WEB_REFERRERS = [
    "-", "-", "-",
    "https://google.com/", "https://www.google.com/search?q=wazuh+siem",
    "https://mysite.com/blog/", "https://mysite.com/", "https://github.com/",
]

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
    # ── Web traffic — normal GET page requests ────────────────────────────────
    {
        "id": 31100, "level": 2, "description": "Web request.",
        "decoder": "web-accesslog",
        "full_log_tpl": '{srcip_web} - - [{ts_fmt}] "GET {url_page} HTTP/1.1" {status} {size} "{referer}" "{useragent}"',
        "data": {}, "mitre": [], "data_web": True,
        "statuses": ["200","200","200","200","301","302","304"], "size_range": (512, 65536), "url_type": "page",
    },
    # ── Web traffic — static file requests ───────────────────────────────────
    {
        "id": 31108, "level": 2, "description": "Web request - static content cached.",
        "decoder": "web-accesslog",
        "full_log_tpl": '{srcip_web} - - [{ts_fmt}] "GET {url_page} HTTP/1.1" {status} {size} "{referer}" "{useragent}"',
        "data": {}, "mitre": [], "data_web": True,
        "statuses": ["200","304","304","304"], "size_range": (100, 200000), "url_type": "static",
    },
    # ── Web traffic — API GET requests ────────────────────────────────────────
    {
        "id": 31110, "level": 2, "description": "Web request - API.",
        "decoder": "web-accesslog",
        "full_log_tpl": '{srcip_web} - {user} [{ts_fmt}] "GET {url_page} HTTP/1.1" {status} {size} "-" "{useragent}"',
        "data": {}, "mitre": [], "data_web": True,
        "statuses": ["200","200","200","304"], "size_range": (128, 8192), "url_type": "api",
    },
    # ── Web traffic — POST submissions ────────────────────────────────────────
    {
        "id": 31111, "level": 2, "description": "Web request - POST submission.",
        "decoder": "web-accesslog",
        "full_log_tpl": '{srcip_web} - {user} [{ts_fmt}] "POST {url_page} HTTP/1.1" {status} {size} "{referer}" "{useragent}"',
        "data": {}, "mitre": [], "data_web": True,
        "statuses": ["200","201","302","204"], "size_range": (64, 2048), "url_type": "post",
    },
    # ── Web traffic — 404 not found ───────────────────────────────────────────
    {
        "id": 31112, "level": 2, "description": "Web request - 404 not found.",
        "decoder": "web-accesslog",
        "full_log_tpl": '{srcip_web} - - [{ts_fmt}] "GET {url_page} HTTP/1.1" 404 {size} "{referer}" "{useragent}"',
        "data": {}, "mitre": [], "data_web": True,
        "statuses": ["404"], "size_range": (200, 2048), "url_type": "page",
    },
    # ── Web traffic — crawler ─────────────────────────────────────────────────
    {
        "id": 31113, "level": 2, "description": "Web request - crawler.",
        "decoder": "web-accesslog",
        "full_log_tpl": '{srcip_web} - - [{ts_fmt}] "GET {url_page} HTTP/1.1" 200 {size} "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"',
        "data": {}, "mitre": [], "data_web": True,
        "statuses": ["200"], "size_range": (1024, 32768), "url_type": "page",
    },
]

# ── Weight by how often each event really occurs during a work day ────────────
RULE_WEIGHTS = {
    5501: 12,   5502: 12,   5503: 20,   5504: 20,
    5402: 15,   5715: 6,    5710: 4,    510:  3,
    516:  2,    554:  2,    2502: 8,    1002: 5,
    1003: 3,    2902: 1,    87701: 4,   87702: 2,
    1001: 3,    4112: 4,
    # Web traffic — heavy weight to build diverse normal web baseline
    31100: 70,   # GET page requests
    31108: 90,   # static file requests (highest volume)
    31110: 45,   # API GET
    31111: 30,   # POST submissions
    31112: 15,   # 404 not found
    31113: 20,   # crawler
}


def make_alert(rule_def: dict, ts: datetime) -> dict:
    """Build one alert JSON matching the 16-feature extractor's expectations."""
    rid   = rule_def["id"]
    level = rule_def["level"]
    desc  = rule_def["description"]

    port      = random.randint(32768, 60999)
    port2     = random.randint(1024, 9999)
    pid       = random.randint(1000, 65000)
    cmd       = random.choice(rule_def.get("cmds", ["/usr/bin/ls"]))
    svc       = random.choice(rule_def.get("services", ["openssh"]))
    pkg       = random.choice(rule_def.get("pkgs", ["curl"]))
    ctr       = random.choice(rule_def.get("containers", ["wazuh_qdrant"]))

    srcip_web = random.choice(EXTERNAL_IPS)
    useragent = random.choice(USER_AGENTS)
    referer   = random.choice(WEB_REFERRERS)
    status    = random.choice(rule_def.get("statuses", ["200"]))
    sz_min, sz_max = rule_def.get("size_range", (200, 10000))
    size      = str(random.randint(sz_min, sz_max))
    ts_fmt    = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    url_type  = rule_def.get("url_type", "page")
    if url_type == "static":
        url_val = random.choice(WEB_STATIC)
    elif url_type == "api":
        url_val = random.choice(WEB_API)
    elif url_type == "post":
        url_val = random.choice(WEB_POST_URLS)
    else:
        url_val = random.choice(WEB_PAGES)

    full_log = (
        rule_def["full_log_tpl"]
        .replace("{user}",      USER)
        .replace("{ip}",        HOME_IP)
        .replace("{port}",      str(port))
        .replace("{port2}",     str(port2))
        .replace("{cmd}",       cmd)
        .replace("{pid}",       str(pid))
        .replace("{service}",   svc)
        .replace("{pkg}",       pkg)
        .replace("{arch}",      "amd64")
        .replace("{ver}",       f"1.{random.randint(0,9)}.{random.randint(0,20)}")
        .replace("{container}", ctr)
        .replace("{srcip_web}", srcip_web)
        .replace("{useragent}", useragent)
        .replace("{referer}",   referer)
        .replace("{status}",    status)
        .replace("{size}",      size)
        .replace("{ts_fmt}",    ts_fmt)
        .replace("{url_page}",  url_val)
    )

    if rule_def.get("data_web"):
        data   = {"srcip": srcip_web, "url": url_val, "id": status}
        groups = ["web", "accesslog"]
    else:
        data   = dict(rule_def.get("data", {}))
        groups = ["syslog"]

    alert = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"id": rid, "level": level, "description": desc, "groups": groups},
        "agent": {"id": AGENT_ID, "name": AGENT_NAME, "ip": AGENT_IP},
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

    # Generate 50 working days of web-heavy normal activity.
    # ~70% web traffic to teach both models what normal web requests look like.
    today = datetime(2026, 5, 26, tzinfo=timezone.utc)

    generated_days = []
    day_cursor = today - timedelta(days=120)  # start ~4 months back
    while len(generated_days) < 50:
        if day_cursor.weekday() < 5:  # Mon–Fri only
            generated_days.append(day_cursor)
        day_cursor += timedelta(days=1)

    print(f"Generating {len(generated_days)} days of normal activity...\n")

    existing_dates = {f.stem for f in DAILY_DIR.glob("*.json")}

    volumes = []
    for d in generated_days:
        if d.weekday() in (0, 2):
            volumes.append(random.randint(650, 800))
        elif d.weekday() == 4:
            volumes.append(random.randint(400, 550))
        else:
            volumes.append(random.randint(500, 700))

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
