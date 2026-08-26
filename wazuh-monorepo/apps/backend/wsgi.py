"""
Production entry point — serves the Flask app under waitress, a proper
multi-threaded WSGI server (the built-in Flask server is single-purpose and
explicitly "not for production").

    ../../services/ai-engine/venv/bin/python wsgi.py

Config via env: BIND_HOST, BIND_PORT (default 127.0.0.1:5000),
WAITRESS_THREADS (default 8 — sized for SSE chat fan-out + API concurrency).
TRUST_PROXY=1 makes waitress accept X-Forwarded-* from TRUSTED_PROXY_IP
(default 127.0.0.1); without it waitress discards them and the backend sees
only the proxy's address.

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
    # waitress STRIPS every X-Forwarded-* header before the app ever sees it
    # unless a proxy is explicitly trusted: clear_untrusted_proxy_headers
    # defaults to True and trusted_proxy to None. Without this, server.py's
    # ProxyFix has nothing left to read and every request looks like 127.0.0.1,
    # which collapses the rate limiter and the per-(user, ip) login lockout into
    # one shared counter — nginx doing its part is not enough on its own.
    # Gated on the same TRUST_PROXY flag, so a directly-exposed deployment keeps
    # discarding caller-supplied forwarding headers.
    proxy_kw = {}
    if os.environ.get("TRUST_PROXY", "0") == "1":
        proxy_kw = dict(
            trusted_proxy=os.environ.get("TRUSTED_PROXY_IP", "127.0.0.1"),
            trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto",
                                   "x-forwarded-host"},
            clear_untrusted_proxy_headers=True,
        )
        server.log.info("trusting forwarding headers from %s", proxy_kw["trusted_proxy"])

    server.log.info("waitress serving on %s:%s (%s threads)", host, port, threads)
    serve(server.app, host=host, port=port, threads=threads,
          channel_timeout=300,   # allow long-lived SSE chat streams
          **proxy_kw)
