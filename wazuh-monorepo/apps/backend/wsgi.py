"""
Production entry point — serves the Flask app under waitress, a proper
multi-threaded WSGI server (the built-in Flask server is single-purpose and
explicitly "not for production").

    ../../services/ai-engine/venv/bin/python wsgi.py

Config via env: BIND_HOST, BIND_PORT (default 127.0.0.1:5000),
WAITRESS_THREADS (default 8 — sized for SSE chat fan-out + API concurrency).

The one-time startup work the dev server did in __main__ (alert load, model
warm-up, reactor + CVE-agent boot) is triggered here too so behavior matches.
"""

import os

from waitress import serve

import server  # importing runs module-level setup (routes, logging, auth, etc.)


def _startup():
    server.log.info("Production WSGI startup (waitress)")
    server._load_all_wazuh_alerts()
    server._pin_ollama_async()
    server._restore_incidents()
    server._start_reactor()
    server._start_cve_agent_autostart()


if __name__ == "__main__":
    _startup()
    host = os.environ.get("BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("BIND_PORT", "5000"))
    threads = int(os.environ.get("WAITRESS_THREADS", "8"))
    server.log.info("waitress serving on %s:%s (%s threads)", host, port, threads)
    serve(server.app, host=host, port=port, threads=threads,
          channel_timeout=300)   # allow long-lived SSE chat streams
