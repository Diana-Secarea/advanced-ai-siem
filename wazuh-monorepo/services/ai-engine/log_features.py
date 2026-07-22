"""
Structural feature extraction for RAW log lines (not Wazuh alerts).

The alert ensemble (IF/AE/UEBA) reads structured Wazuh fields — rule level,
groups, srcip — that raw collector logs simply don't have. And pure novelty
(log_stream.py) judges a line only by how *rare* its template is, so a benign
command an admin runs once still looks anomalous.

This module adds the missing third view: what KIND of log line is this, judged
from its own content? A supervised content model (train_log_model.py) over these
behavioural features learns benign-vs-hostile; a genuinely hostile line (reverse
shell, `wget | bash`, `/etc/passwd` read, base64-piped exec) scores high on the
attack signals regardless of whether that exact line was ever seen before.

Features are intentionally rule-agnostic and stateless — they describe the line
itself, so the same vector is produced at train and serve time with no external
lookup. Familiarity ("have we seen this before") is deliberately NOT a feature
here — it is judged by the persistent novelty baseline and combined by max at
scoring time, so a new-but-benign line reads as novel, not hostile.
"""

import ipaddress
import re

from log_stream import templatize

# Placeholder tokens emitted by templatize(); their MIX is a fingerprint of the
# log family (a df table is mostly <NUM>/<COLS>; an auth line has <IP>+words;
# a JSON SCA blob is long with many <Q>).
_PLACEHOLDERS = ["<IP>", "<NUM>", "<PATH>", "<HEX>", "<ID>",
                 "<Q>", "<TS>", "<TIME>", "<PID>", "<MAC>", "<UUID>", "<COLS>"]

# Content signals that raise the odds a raw line describes an attack rather than
# routine operation. Kept as whole-word / substring probes against the RAW text
# so they fire on unknown log formats too. This is NOT a blocklist that decides
# the verdict — it is one numeric feature the trained content model weighs against
# the others, so a benign line that happens to contain "error" is not condemned.
_ATTACK_TERMS = (
    # remote shells / piped execution
    "reverse shell", "/dev/tcp", "bash -i", "bash -li", "sh -i", "nc -e", "ncat",
    "/bin/bash", "/bin/sh -c", "base64 -d", "base64 --decode", "| bash", "|bash",
    "| sh", "chmod +x", "chmod 777", "socket.socket", "pty.spawn", "mkfifo",
    "socat", "exec:", "sockaddr_in",
    # download-and-run
    "curl", "wget", "certutil", "urlcache",
    # recon / tooling
    "nmap", "sqlmap", "nikto", "-perm -4000", "perm -2000", "find / -perm",
    "netcat", "nc -zv", "masscan",
    # lateral movement / pass-the-hash
    "impacket", "psexec", "wmiexec", "smbexec", "-hashes", "aad3b435",
    "crackmapexec", "evil-winrm", "secretsdump", "-hashes :",
    # web exploitation (sqli / xss / traversal / injection / log4shell / shellshock)
    "union select", "union all select", "' or '1'='1", "or 1=1", "information_schema",
    "@@version", "version()", "sleep(", "benchmark(", "<script", "onerror=",
    "xmlrpc.php", "wp-login", "phpmyadmin", "/shell", "eval-stdin", "?cmd=",
    "?c=id", "/proc/self", "${jndi:", "jndi:ldap", "jndi:rmi", "${lower:",
    "() { :", "/bin/eject",
    # local files / secrets / privesc
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "nopasswd",
    "usermod -ag", "chmod u+s", "chmod +s", "id_rsa", "authorized_keys",
    "known_hosts", ".aws/credentials", ".kube/config", ".git-credentials",
    "setuid", "ld_preload", "mimikatz", "powershell", "-enc ", "cmd.exe",
    "pkexec", "pwnkit", "user=#-1", "gcore", "lsass",
    # traversal / obfuscation / persistence
    "../", "%2e%2e", "%00", "crontab", "@reboot", "backdoor", "rootkit",
    # anti-forensics
    "shred -u", "history -c", ".bash_history", "> /var/log", "rm -rf /var/log",
    "--vacuum-time", "truncate -s0",
)
_FAIL_TERMS = ("failed", "denied", "invalid", "error", "refused", "unauthorized",
               "not permitted", "illegal", "violation", "segfault")

# High-confidence subset: tokens that are almost never benign, so the model can
# weight them far above the dual-use verbs (curl/wget/find/chmod) that also appear
# in _ATTACK_TERMS but legitimately in admin work. A single strong hit
# (`cat /etc/shadow`, `usermod -aG sudo`, `/dev/tcp`) should stand on its own.
_STRONG_TERMS = (
    # secrets / privesc
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "nopasswd", "usermod -ag",
    "chmod u+s", "chmod +s", "id_rsa", ".aws/credentials", ".kube/config",
    ".git-credentials", "mimikatz", "pkexec", "pwnkit", "user=#-1", "gcore",
    "lsass", "setuid", "-perm -4000",
    # remote shells / lateral movement
    "/dev/tcp", "reverse shell", "bash -i", "bash -li", "sh -i", "nc -e",
    "pty.spawn", "sockaddr_in", "socat", "mkfifo", "| bash", "|bash",
    "impacket", "psexec", "wmiexec", "-hashes", "crackmapexec", "secretsdump",
    # web exploitation
    "union select", "union all select", "' or '1'='1", "or 1=1", "sleep(",
    "benchmark(", "information_schema", "${jndi:", "jndi:ldap", "jndi:rmi",
    "() { :", "%2e%2e", "%00", "/etc/passwd", "eval-stdin", "?cmd=", "?c=id",
    "xmlrpc.php", "wp-login", "phpmyadmin",
    # download / obfuscation / anti-forensics
    "certutil", "urlcache", "base64 -d", "base64 --decode", "powershell", "-enc ",
    "shred -u", "history -c", "rm -rf /var/log", "> /var/log", "--vacuum-time",
    "backdoor", "rootkit", "@reboot",
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Reuse the alert detector's CDN/private notion of "external" so a CDN hop or a
# LAN address isn't treated as a hostile remote peer.
try:
    from ai_engine.anomaly_detector import AnomalyDetector as _AD
    _is_external_ip = _AD._is_external_ip
except Exception:  # pragma: no cover - keep importable standalone
    def _is_external_ip(ip):
        try:
            a = ipaddress.ip_address(ip.strip())
            return 0 if (a.is_private or a.is_loopback or a.is_link_local
                         or a.is_reserved) else 1
        except ValueError:
            return 0


# Order is the feature schema — keep stable; train and serve read it identically.
# NOTE: raw-length and character-ratio features were deliberately REMOVED. They
# carried no reliable attack signal (attacks are not inherently long or punctuation-
# heavy) yet let the model treat any longer/denser benign line — a REST API path, a
# verbose but harmless log — as suspicious. Detection rests on behavioural content
# (attack/strong terms, failures, external IP) + rarity (novelty), which is both
# more robust under distribution shift and fully interpretable. Token-placeholder
# counts stay: they fingerprint the log FAMILY without the length artifact.
FEATURE_NAMES = (
    [f"tok{p.strip('<>').lower()}" for p in _PLACEHOLDERS] +
    ["attack_terms", "strong_terms", "fail_terms", "has_external_ip", "rule_level"]
)


def extract(ev):
    """Return the structural feature vector (list[float]) for one raw event."""
    full = str(ev.get("full_log", "") or "")
    low = full.lower()
    tmpl = templatize(full)

    feats = [float(tmpl.count(p.lower())) for p in _PLACEHOLDERS]

    ext = 0
    for ip in _IP_RE.findall(full):
        if _is_external_ip(ip):
            ext = 1
            break

    feats.append(float(sum(t in low for t in _ATTACK_TERMS)))  # attack_terms (broad)

    # strong_terms: high-confidence malicious tokens PLUS behavioural COMPOUNDS.
    # Each compound is a pairing that is benign in isolation but hostile together,
    # so single dual-use verbs (admins wget tarballs, gzip backups, scp to a peer)
    # don't get condemned — only the malicious combination counts.
    strong = sum(t in low for t in _STRONG_TERMS)
    # download-and-execute: fetch + execution / temp-drop.
    fetch = any(t in low for t in ("wget ", "curl ", "certutil"))
    execute = any(t in low for t in ("| bash", "|bash", "| sh", "|sh",
                                     "-o /tmp", "; sh", "&& sh", "exec("))
    if fetch and execute:
        strong += 1
    # encode-and-exfil: packaging data + a local egress channel (dns tunnel, netcat…).
    encode = any(t in low for t in ("base64", "openssl enc", "tar cz", "gzip", "zip ", "xxd"))
    egress = any(t in low for t in ("dig +", "nslookup", "nc ", "/dev/tcp",
                                    "curl -t", "curl --upload", "> /dev/udp"))
    if encode and egress:
        strong += 1
    # remote-copy-to-external: bulk copy (scp/rsync/sftp) to a PUBLIC host — the
    # classic staged-data exfil. scp to a LAN peer stays benign (ext == 0).
    remote_copy = any(t in low for t in ("scp ", "rsync ", "sftp "))
    if remote_copy and ext:
        strong += 1
    feats.append(float(strong))                                # strong_terms

    feats.append(float(sum(low.count(t) for t in _FAIL_TERMS)))  # fail_terms
    feats.append(float(ext))                                   # has_external_ip

    rule = ev.get("rule") if isinstance(ev.get("rule"), dict) else {}
    try:
        feats.append(float(int(rule.get("level", 0) or 0)))    # rule_level
    except (TypeError, ValueError):
        feats.append(0.0)

    return feats
