"""
Centralized logging for the backend.

Before this, everything used bare print() — fine for a terminal, useless for
production monitoring (no levels, no timestamps you can filter, no rotation,
nothing to point a log shipper at). This wires a root logger that writes to:

  * the console (so `docker logs` / journald still show everything)
  * a rotating file  logs/backend.log   (10 MB × 5)
  * a rotating file  logs/reactor.log    (reactor + active-response actions only —
    this is the audit trail for anything that touched the network/host)

Use get_logger(name) anywhere. The reactor uses get_logger("reactor") so its
events also land in the dedicated security-action log.

LOG_LEVEL env var (default INFO) controls verbosity. LOG_DIR overrides where
files go (default: <backend>/logs).
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


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

    # Quiet the noisy libraries; keep our own signal readable
    for noisy in ("werkzeug", "urllib3", "httpx", "qdrant_client"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True
    logging.getLogger("backend").info(
        "Logging initialized (level=%s, dir=%s)",
        logging.getLevelName(level), log_dir or "console-only")


def get_logger(name):
    return logging.getLogger(name)
