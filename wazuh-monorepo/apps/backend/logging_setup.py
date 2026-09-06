"""
Centralized logging for the backend.

Before this, everything used bare print() — fine for a terminal, useless for
production monitoring (no levels, no timestamps you can filter, no rotation,
nothing to point a log shipper at). This wires a root logger that writes to:

  * the console (so `docker logs` / journald still show everything)
  * a rotating file  logs/backend.log   (10 MB × 5)
  * a rotating file  logs/reactor.log    (reactor + active-response actions only —
    this is the audit trail for anything that touched the network/host)
  * a rotating file  logs/selenne-audit.json  (one JSON object per line — security
    events meant to be ingested by the Wazuh log collector and turned into real
    alerts; see AUDIT_LOG below)
  * a rotating file  logs/flask_access.log (Apache combined format — HTTP access
    log for the same collector; see ACCESS_LOG below)

The last two exist because a human-readable line in backend.log is invisible to
the console: nothing in ossec.conf watches this directory, and the decoders
cannot parse "2026-09-03T18:09:36 INFO [backend] ..." into fields anyway. These
two files are written in formats Wazuh already decodes (json, apache), so an
event here becomes a rule-matchable alert rather than text nobody reads.

Use get_logger(name) anywhere. The reactor uses get_logger("reactor") so its
events also land in the dedicated security-action log.

LOG_LEVEL env var (default INFO) controls verbosity. LOG_DIR overrides where
files go (default: <backend>/logs). AUDIT_LOG and ACCESS_LOG override the two
collector-facing files individually — in production point them somewhere the
Wazuh agent already reads (e.g. /var/log/wazuh-ai/) rather than moving LOG_DIR
and dragging backend.log along with it.
"""

import json
import logging
import os
import socket
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False
_HOSTNAME = socket.gethostname()

# Schema version for the JSON audit records. The Wazuh rules key off
# selenne.event, so bumping this must not change existing event names —
# add new ones instead.
AUDIT_SCHEMA = 1


class _JsonLineFormatter(logging.Formatter):
    """Render one flat JSON object per line for the Wazuh json decoder.

    Wazuh flattens nested JSON into dotted field names, so the payload is
    namespaced under "selenne" and rules match on selenne.event. Anything the
    caller passes that will not serialise is coerced to str rather than
    dropping the whole record — an audit line that loses one field still beats
    an audit line that never gets written.
    """

    def format(self, record):
        payload = dict(getattr(record, "audit", {}) or {})
        payload.setdefault("event", record.getMessage())
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "host": _HOSTNAME,
            "selenne": dict(payload, schema=AUDIT_SCHEMA, level=record.levelname),
        }
        return json.dumps(doc, default=str, ensure_ascii=False)


def setup_logging():
    global _CONFIGURED
    if _CONFIGURED:
        return
    level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    log_dir = Path(os.environ.get("LOG_DIR", Path(__file__).parent / "logs"))
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir = None  # read-only fs — console logging still works

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S")

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    if log_dir:
        backend_fh = RotatingFileHandler(
            log_dir / "backend.log", maxBytes=10 * 1024 * 1024, backupCount=5)
        backend_fh.setFormatter(fmt)
        root.addHandler(backend_fh)

        # Dedicated reactor/security-action audit log (INFO+ from 'reactor' only)
        reactor_fh = RotatingFileHandler(
            log_dir / "reactor.log", maxBytes=10 * 1024 * 1024, backupCount=5)
        reactor_fh.setFormatter(fmt)
        reactor_fh.addFilter(lambda r: r.name.startswith("reactor"))
        logging.getLogger("reactor").addHandler(reactor_fh)

        # --- Collector-facing files ------------------------------------- #
        # Both bypass the root logger (propagate=False): their formats are
        # machine-readable, and mixing Apache lines into backend.log or the
        # console would corrupt exactly the thing that makes them parseable.
        audit_path = Path(os.environ.get("AUDIT_LOG",
                                         log_dir / "selenne-audit.json"))
        access_path = Path(os.environ.get("ACCESS_LOG",
                                          log_dir / "flask_access.log"))
        for path, logger_name, formatter in (
                (audit_path, "audit", _JsonLineFormatter()),
                (access_path, "access", logging.Formatter("%(message)s"))):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                handler = RotatingFileHandler(
                    path, maxBytes=10 * 1024 * 1024, backupCount=5)
            except OSError as exc:
                # A misconfigured path must not take the server down, but it
                # must be loud: this is the difference between "the console
                # shows downloads" and "the console silently shows nothing".
                logging.getLogger("backend").error(
                    "cannot open %s log at %s (%s) — these events will NOT "
                    "reach the Wazuh collector", logger_name, path, exc)
                continue
            handler.setFormatter(formatter)
            lg = logging.getLogger(logger_name)
            lg.setLevel(logging.INFO)
            lg.addHandler(handler)
            lg.propagate = False

    # Quiet the noisy libraries; keep our own signal readable
    for noisy in ("werkzeug", "urllib3", "httpx", "qdrant_client"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True
    logging.getLogger("backend").info(
        "Logging initialized (level=%s, dir=%s)",
        logging.getLevelName(level), log_dir or "console-only")


def get_logger(name):
    return logging.getLogger(name)


def audit(event, **fields):
    """Record one security-relevant event for the Wazuh collector.

    Writes a single JSON line to AUDIT_LOG. Never raises: an audit sink that
    can crash a request handler would be worse than the blind spot it fixes.
    """
    try:
        logging.getLogger("audit").info(
            event, extra={"audit": dict(fields, event=event)})
    except Exception:            # noqa: BLE001 - deliberately swallowing
        logging.getLogger("backend").exception("audit sink failed for %s", event)


def access(line):
    """Append one Apache-combined-format line to ACCESS_LOG."""
    try:
        logging.getLogger("access").info(line)
    except Exception:            # noqa: BLE001
        pass
