#!/usr/bin/env python3
"""
populate_map.py — Append synthetic attack alerts with public source IPs to
/var/ossec/logs/alerts/alerts.json so the Leaflet attack-origin map in
alerts.html gets populated.

Usage:
    sudo python3 populate_map.py [--count N] [--output PATH]

    --count N      Number of synthetic alerts to generate (default: 40)
    --output PATH  Target file (default: /var/ossec/logs/alerts/alerts.json)
    --delay S      Seconds to wait between writing alerts (default: 0)
    --dry-run      Print generated JSON to stdout instead of writing to file
"""

import argparse
import datetime
import json
import random
import sys
import time

# ---------------------------------------------------------------------------
# Attack catalogue — each entry produces a realistic Wazuh-style alert.
# The srcip is a real public IP known to be associated with a country/region.
# ---------------------------------------------------------------------------

ATTACK_SOURCES = [
    # (ip, city, country_hint) — IPs are real public addresses from threat feeds
    ("185.220.101.45",  "Frankfurt",   "DE"),
    ("195.54.160.149",  "Moscow",      "RU"),
    ("45.33.32.156",    "Fremont",     "US"),
    ("103.41.204.177",  "Beijing",     "CN"),
    ("91.108.4.1",      "Amsterdam",   "NL"),
    ("194.165.16.11",   "Kyiv",        "UA"),
    ("185.107.47.215",  "Bucharest",   "RO"),
    ("5.188.206.14",    "St. Petersburg", "RU"),
    ("45.142.212.100",  "Warsaw",      "PL"),
    ("185.156.73.54",   "Sofia",       "BG"),
    ("212.95.50.190",   "Paris",       "FR"),
    ("80.82.77.33",     "London",      "GB"),
    ("200.58.101.190",  "São Paulo",   "BR"),
    ("117.239.239.5",   "Mumbai",      "IN"),
    ("203.176.135.102", "Seoul",       "KR"),
    ("41.210.64.1",     "Lagos",       "NG"),
    ("80.94.95.226",    "Istanbul",    "TR"),
    ("66.240.192.138",  "Chicago",     "US"),
    ("218.92.0.31",     "Shanghai",    "CN"),
    ("176.31.15.185",   "Lisbon",      "PT"),
    ("162.55.36.54",    "Helsinki",    "FI"),
    ("37.49.231.200",   "Tehran",      "IR"),
    ("103.199.16.99",   "Dhaka",       "BD"),
    ("185.191.34.96",   "Cairo",       "EG"),
    ("5.2.69.50",       "Stockholm",   "SE"),
    ("196.202.240.1",   "Nairobi",     "KE"),
    ("196.244.191.3",   "Johannesburg","ZA"),
    ("85.31.44.220",    "Madrid",      "ES"),
    ("58.218.199.230",  "Hangzhou",    "CN"),
    ("103.82.92.114",   "Hanoi",       "VN"),
]

ATTACK_TEMPLATES = [
    # SSH brute force
    {
        "rule": {"level": 10, "description": "Multiple authentication failures.", "id": "5503",
                 "firedtimes": random.randint(5, 30), "mail": False,
                 "groups": ["authentication_failures", "sshd"]},
        "full_log_tmpl": "sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2",
        "location": "/var/log/auth.log",
    },
    {
        "rule": {"level": 10, "description": "sshd: brute force trying to get access to the system.", "id": "5712",
                 "firedtimes": random.randint(10, 50), "mail": False,
                 "groups": ["authentication_failures", "sshd", "recon"]},
        "full_log_tmpl": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "location": "/var/log/auth.log",
    },
    # Web attack — SQL injection
    {
        "rule": {"level": 6, "description": "SQL injection attempt.", "id": "31106",
                 "firedtimes": 1, "mail": False,
                 "groups": ["web", "accesslog", "attack", "sql_injection"]},
        "full_log_tmpl": '{ip} - - [{timestamp_log}] "GET /index.php?id=1\' OR 1=1-- HTTP/1.1" 200 1234',
        "location": "/var/log/nginx/access.log",
    },
    # Web attack — directory traversal
    {
        "rule": {"level": 6, "description": "A web attack was detected.", "id": "31101",
                 "firedtimes": 1, "mail": False,
                 "groups": ["web", "accesslog", "attack"]},
        "full_log_tmpl": '{ip} - - [{timestamp_log}] "GET /../../../../etc/passwd HTTP/1.1" 400 512',
        "location": "/var/log/apache2/access.log",
    },
    # Port scan
    {
        "rule": {"level": 7, "description": "Possible port scan detected.", "id": "40101",
                 "firedtimes": 1, "mail": False,
                 "groups": ["recon", "network"]},
        "full_log_tmpl": "kernel: iptables DROP IN=eth0 SRC={ip} DST=192.168.1.1 PROTO=TCP DPT={port}",
        "location": "/var/log/syslog",
    },
    # Successful login from suspicious IP
    {
        "rule": {"level": 5, "description": "PAM: Login session opened.", "id": "5501",
                 "firedtimes": 1, "mail": False,
                 "groups": ["pam", "syslog", "authentication_success"]},
        "full_log_tmpl": "sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
        "location": "/var/log/auth.log",
    },
    # High-severity: reverse shell attempt
    {
        "rule": {"level": 12, "description": "Possible reverse shell connection detected.", "id": "87105",
                 "firedtimes": 1, "mail": True,
                 "groups": ["attack", "shell", "malware"]},
        "full_log_tmpl": "kernel: iptables ACCEPT OUT=eth0 DST={ip} PROTO=TCP DPT=4444",
        "location": "/var/log/syslog",
    },
    # XSS attempt
    {
        "rule": {"level": 6, "description": "XSS (Cross Site Scripting) attempt.", "id": "31103",
                 "firedtimes": 1, "mail": False,
                 "groups": ["web", "accesslog", "attack", "xss"]},
        "full_log_tmpl": '{ip} - - [{timestamp_log}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 654',
        "location": "/var/log/nginx/access.log",
    },
    # Malware download
    {
        "rule": {"level": 11, "description": "Malware download attempt detected.", "id": "87201",
                 "firedtimes": 1, "mail": True,
                 "groups": ["malware", "attack"]},
        "full_log_tmpl": '{ip} - - [{timestamp_log}] "GET /shell.sh HTTP/1.1" 200 2048',
        "location": "/var/log/nginx/access.log",
    },
    # C2 beacon
    {
        "rule": {"level": 13, "description": "Possible C2 communication detected.", "id": "87301",
                 "firedtimes": random.randint(3, 20), "mail": True,
                 "groups": ["attack", "malware", "c2"]},
        "full_log_tmpl": "kernel: iptables ACCEPT OUT=eth0 DST={ip} PROTO=TCP DPT=443",
        "location": "/var/log/syslog",
    },
    # DNS exfiltration
    {
        "rule": {"level": 9, "description": "Suspicious DNS query (possible data exfiltration).", "id": "87401",
                 "firedtimes": 1, "mail": False,
                 "groups": ["attack", "dns", "exfiltration"]},
        "full_log_tmpl": "named[1234]: query: dGVzdGRhdGE.{ip}.dns.attacker.com IN TXT",
        "location": "/var/log/named.log",
    },
    # Telnet brute force
    {
        "rule": {"level": 8, "description": "Telnet authentication failure.", "id": "5300",
                 "firedtimes": random.randint(5, 25), "mail": False,
                 "groups": ["authentication_failures", "telnet"]},
        "full_log_tmpl": "telnetd: failed login from {ip}",
        "location": "/var/log/auth.log",
    },
]

USERNAMES = ["root", "admin", "ubuntu", "deploy", "test", "user", "oracle", "postgres", "ftp", "guest"]


def _rand_pid():
    return random.randint(10000, 65535)


def _rand_port():
    return random.randint(1024, 65535)


def _rand_user():
    return random.choice(USERNAMES)


def _ts_now(offset_secs=0):
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset_secs)
    tz_offset = "+0300"
    local = dt.astimezone(datetime.timezone(datetime.timedelta(hours=3)))
    return local.strftime(f"%Y-%m-%dT%H:%M:%S.%f")[:-3] + tz_offset


def _ts_log(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _event_id(i):
    return f"{random.randint(10**9, 10**10 - 1)}.{i}"


def build_alert(i, src):
    ip, city, country = src
    template = random.choice(ATTACK_TEMPLATES)
    rule = dict(template["rule"])
    rule["firedtimes"] = random.randint(1, 30)

    now = datetime.datetime.utcnow()
    # Scatter timestamps over the last 30 minutes
    offset = random.randint(-1800, 0)
    ts = _ts_now(offset)
    log_ts = _ts_log(now + datetime.timedelta(seconds=offset))

    pid = _rand_pid()
    port = _rand_port()
    user = _rand_user()

    full_log = template["full_log_tmpl"].format(
        ip=ip, pid=pid, port=port, user=user, timestamp_log=log_ts
    )

    alert = {
        "timestamp": ts,
        "rule": rule,
        "agent": {"id": "001", "name": "LAPTOP-M9GQ2F87", "ip": "127.0.0.1"},
        "manager": {"name": "LAPTOP-M9GQ2F87"},
        "id": _event_id(i),
        "full_log": full_log,
        "decoder": {"name": "sshd" if "sshd" in full_log else "web-accesslog"},
        "data": {
            "srcip": ip,
            "srcport": str(port),
        },
        "location": template["location"],
        "_synthetic": True,
    }
    return alert


def main():
    parser = argparse.ArgumentParser(description="Populate the attack-origin map with synthetic alerts.")
    parser.add_argument("--count", type=int, default=40,
                        help="Number of synthetic alerts to generate (default: 40)")
    parser.add_argument("--output", default="/var/ossec/logs/alerts/alerts.json",
                        help="Path to alerts.json (default: /var/ossec/logs/alerts/alerts.json)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Seconds to wait between writing alerts (default: 0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print generated JSON to stdout instead of writing")
    args = parser.parse_args()

    sources = ATTACK_SOURCES.copy()
    random.shuffle(sources)
    # Repeat sources if we need more alerts than unique IPs (cycle through)
    sources_cycle = [sources[i % len(sources)] for i in range(args.count)]

    alerts = [build_alert(i, sources_cycle[i]) for i in range(args.count)]

    if args.dry_run:
        for a in alerts:
            print(json.dumps(a))
        print(f"\n[dry-run] {len(alerts)} alerts generated (not written)", file=sys.stderr)
        return

    try:
        with open(args.output, "a", encoding="utf-8") as fh:
            for i, alert in enumerate(alerts):
                fh.write(json.dumps(alert) + "\n")
                if args.delay:
                    time.sleep(args.delay)
                if (i + 1) % 10 == 0 or i + 1 == len(alerts):
                    print(f"  Written {i + 1}/{len(alerts)} alerts...")
        print(f"\nDone. {len(alerts)} synthetic alerts appended to {args.output}")
        print("Refresh alerts.html to see the map populated.")
    except PermissionError:
        print(f"Permission denied: {args.output}", file=sys.stderr)
        print("Run with sudo: sudo python3 populate_map.py", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
