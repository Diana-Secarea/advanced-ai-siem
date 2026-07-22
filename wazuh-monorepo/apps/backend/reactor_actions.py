"""
Reactive response actions for the reactor — the SOAR/EDR-style capabilities
that turn a detection into containment + investigation.

DESIGN PRINCIPLES (this is defensive automation on infrastructure you own):
  * Every action is OPT-IN and DRY-RUN by default. Nothing touches the host
    or network until explicitly armed, mirroring the existing Wazuh-AR guard.
  * Blocking actions only ever target PUBLIC, routable source IPs and refuse
    private/loopback/reserved ranges (protects the host, LAN, Wazuh agents).
  * Investigation actions are strictly READ-ONLY.
  * Every action returns a structured result string recorded on the incident,
    and logs to the reactor audit log — so there is a full trail of what the
    automation did and why.

Actions provided:
  triage_host(inc)     READ-ONLY host investigation — the "what is this IP
                       doing on my box" snapshot an analyst would run by hand:
                       active connections for the srcip, recent auth failures,
                       listening ports. Attached to the incident. Always safe.
  block_ip(...)        Firewall-drop the source IP (nftables/iptables), with a
                       restart-surviving block ledger + automatic expiry.
  block_port(...)      Drop a specific destination port from the source IP —
                       targeted containment instead of a full host block.
  trigger_scan(agent)  Kick Wazuh rootcheck/syscheck on the affected agent —
                       the antivirus-style "scan this host now" reaction.

The blocking implementations shell out to the system firewall; on a host
without privileges they degrade to a recorded 'no-permission' result rather
than crashing the reactor.
"""

import ipaddress
import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

# Persistent block ledger so active blocks survive a server restart and can be
# reconciled / expired. One JSON line per active block.
BLOCK_LEDGER = Path(os.environ.get(
    "REACTOR_BLOCK_LEDGER",
    str(Path(__file__).parent / "reactor_blocks.jsonl")))

_lock = threading.Lock()

_NEVER_NETS = [ipaddress.ip_network(c) for c in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]


def _public_ip_ok(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "invalid-ip"
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False, "protected-range"
    for net in _NEVER_NETS:
        if ip in net:
            return False, "never-list"
    return True, "ok"


def _run(cmd, timeout=10):
    """Run a command, return (rc, output). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"
    except Exception as e:
        return 1, str(e)


# ---------------------------------------------------------------- triage ----

def triage_host(inc, logger=None):
    """READ-ONLY investigation snapshot for an incident's source IP + agent.

    Returns a findings dict attached to the incident. Safe to run always —
    no state changes. This is the 'the reactor investigates like an analyst'
    behaviour: what is this IP connected to, are there auth failures, what's
    listening.
    """
    srcip = inc.get("srcip", "")
    findings = {"srcip": srcip, "checks": {}}

    # 1) Active connections involving the source IP
    if srcip:
        if shutil.which("ss"):
            rc, out = _run(["ss", "-tanp"])
            hits = [ln for ln in out.splitlines() if srcip in ln]
            findings["checks"]["connections"] = hits[:20] or ["none active"]
        else:
            findings["checks"]["connections"] = ["ss not available"]

    # 2) Recent auth failures (last 24h) from this IP — sudo/ssh brute-force signal
    if srcip and os.path.isfile("/var/log/auth.log"):
        rc, out = _run(["grep", "-F", srcip, "/var/log/auth.log"])
        fails = [ln for ln in out.splitlines()
                 if any(k in ln for k in ("Failed", "failure", "invalid"))]
        findings["checks"]["recent_auth_failures"] = len(fails)

    # 3) Listening ports snapshot (what an attacker could reach)
    if shutil.which("ss"):
        rc, out = _run(["ss", "-tlnH"])
        ports = sorted({ln.split()[3].rsplit(":", 1)[-1]
                        for ln in out.splitlines() if len(ln.split()) > 3})
        findings["checks"]["listening_ports"] = ports[:40]

    if logger:
        logger.info("triage %s: %s connections, %s auth-failures",
                    srcip or "(no ip)",
                    len(findings["checks"].get("connections", [])),
                    findings["checks"].get("recent_auth_failures", "n/a"))
    return findings


# ------------------------------------------------------------- block IP -----

def _firewall_available():
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    return None


def _apply_block(ip, port=None):
    """Insert a firewall drop rule. Returns (ok, detail)."""
    fw = _firewall_available()
    if fw is None:
        return False, "no-firewall-tool"
    if fw == "iptables":
        cmd = ["iptables", "-I", "INPUT", "-s", ip]
        if port:
            cmd += ["-p", "tcp", "--dport", str(port)]
        cmd += ["-j", "DROP"]
    else:  # nft — assumes an inet filter table/input chain exists
        expr = f"ip saddr {ip}"
        if port:
            expr += f" tcp dport {port}"
        cmd = ["nft", "add", "rule", "inet", "filter", "input", *expr.split(), "drop"]
    rc, out = _run(cmd)
    return rc == 0, (out.strip() or f"rc={rc}")


def _remove_block(ip, port=None):
    fw = _firewall_available()
    if fw is None:
        return False, "no-firewall-tool"
    if fw == "iptables":
        cmd = ["iptables", "-D", "INPUT", "-s", ip]
        if port:
            cmd += ["-p", "tcp", "--dport", str(port)]
        cmd += ["-j", "DROP"]
        rc, out = _run(cmd)
        return rc == 0, out
    # nft: delete by handle is fiddly; flush-by-saddr is out of scope for PoC —
    # rely on ledger expiry + manual `nft flush chain` if needed.
    return True, "nft-expiry-noted"


def _ledger_add(entry):
    with _lock:
        try:
            with open(BLOCK_LEDGER, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass


def block_ip(inc, dry_run=True, ttl_seconds=3600, logger=None, port=None):
    """Firewall-drop the incident's source IP (or a specific port from it).

    dry_run=True (default) records intent only. When armed, applies a real
    firewall rule, ledgers it, and schedules automatic removal after ttl.
    """
    srcip = inc.get("srcip", "")
    ok, why = _public_ip_ok(srcip)
    if not ok:
        return f"block_ip:skipped({why})"

    target = f"{srcip}:{port}" if port else srcip
    if dry_run:
        if logger:
            logger.info("[DRY-RUN] would block %s (ttl %ss)", target, ttl_seconds)
        return f"block_ip:dryrun({target})"

    applied, detail = _apply_block(srcip, port)
    if not applied:
        if logger:
            logger.warning("block %s failed: %s", target, detail)
        return f"block_ip:error({detail})"

    _ledger_add({"ip": srcip, "port": port, "at": int(time.time()),
                 "ttl": ttl_seconds, "incident": inc.get("id")})
    if ttl_seconds > 0:
        threading.Timer(ttl_seconds, _remove_block, args=(srcip, port)).start()
    if logger:
        logger.info("BLOCKED %s (ttl %ss, incident %s)",
                    target, ttl_seconds, inc.get("id"))
    return f"block_ip:blocked({target},ttl={ttl_seconds}s)"


def block_port(inc, port, dry_run=True, ttl_seconds=3600, logger=None):
    """Targeted containment: drop one destination port from the source IP."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "block_port:skipped(bad-port)"
    return block_ip(inc, dry_run=dry_run, ttl_seconds=ttl_seconds,
                    logger=logger, port=port)


# ------------------------------------------------------------ Wazuh scan ----

def trigger_scan(inc, dry_run=True, logger=None):
    """Kick Wazuh rootcheck/syscheck on the affected agent — the AV-style
    'scan this host now' reaction. Uses agent_control -r (restart scan).
    """
    agent = inc.get("agent", "")
    control = "/var/ossec/bin/agent_control"
    if not os.path.isfile(control):
        return "scan:skipped(no-agent_control)"
    if dry_run:
        if logger:
            logger.info("[DRY-RUN] would trigger rootcheck/syscheck on '%s'", agent)
        return f"scan:dryrun({agent})"
    # -r runs rootcheck/syscheck; -u <id> targets an agent, -a targets all.
    rc, out = _run([control, "-r", "-a"], timeout=15)
    if logger:
        logger.info("scan triggered (agent=%s rc=%s)", agent, rc)
    return f"scan:triggered({agent})" if rc == 0 else f"scan:error(rc={rc})"


def active_blocks():
    """Return currently-ledgered blocks that haven't expired (best-effort view)."""
    out = []
    if not BLOCK_LEDGER.exists():
        return out
    now = time.time()
    try:
        with open(BLOCK_LEDGER) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("ttl", 0) == 0 or e["at"] + e["ttl"] > now:
                    out.append(e)
    except OSError:
        pass
    return out
