"""
Full log-collector stream scoring — anomalies across ALL logs, not just alerts.

Wazuh's log collector receives far more than the events that match a rule:
journald, /var/log/*, auditd, apache, command output, dpkg/apt, … With
`<logall_json>yes</logall_json>` every one of those lands in archives.json,
whether or not a rule fired. This module scores that whole stream.

Why not just run the ensemble on it? The IF/AE/UEBA ensemble was trained on
structured Wazuh *alerts* (rule level, groups, srcip). Raw log lines have almost
none of that, so the ensemble misreads repetitive benign lines (e.g. dockerd
journald spam) as anomalies. The right tool for raw logs is NOVELTY detection:

  * Reduce each line to a template — mask IPs, numbers, hex, UUIDs, paths,
    timestamps — so "Failed password for alice" and "Failed password for bob"
    collapse to one pattern.
  * Learn how often each (source, template) normally occurs.
  * Score a line by how RARE its template is. A template never seen before, or
    seen only once against thousands of others, is the anomaly — a new kind of
    log line appearing is exactly what unsupervised log monitoring should catch.

Hybrid: events that DID match a rule (level > 0) still get the calibrated
ensemble score; raw events get the novelty score. We rank the stream by whichever
applies, so a real attack alert and a never-before-seen syslog line both surface.
"""

import math
import re
from collections import Counter, defaultdict

try:
    from attack_labels import is_operational_log
except Exception:  # pragma: no cover - keeps log_stream importable standalone
    def is_operational_log(event):
        return False

# --- template masking: order matters (specific → general) ------------------- #
_MASKS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b"), "<MAC>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX>"),
    # Random identifiers: tokens mixing letters+digits, 6+ chars (container ids,
    # veth/interface names, session hashes) — collapse so churn shares a template.
    (re.compile(r"\b(?=\w*[a-zA-Z])(?=\w*\d)[a-zA-Z0-9]{6,}\b"), "<ID>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"), "<TS>"),
    (re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+"
                r"\d{2}:\d{2}:\d{2}\b"), "<TS>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TIME>"),
    (re.compile(r"/[\w./\-]+"), "<PATH>"),
    (re.compile(r"\[\d+\]"), "[<PID>]"),
    # Numbers with an optional decimal and an optional short unit suffix, glued
    # or space-separated: 42, 10.965s, 2G, 476k, 20.5MB, 2 GB, 99%.  Must be
    # case-insensitive and unit-aware — otherwise "consumed 10.965s ... 2G memory"
    # only partially masks (leaving ".965s"/"2g"), so every systemd cgroup-teardown
    # line looks like a brand-new template and scores as novel. One mask now
    # collapses all of them to "<NUM>".
    (re.compile(r"\b\d+(?:\.\d+)?(?:\s?(?:[kmgtp]i?b|kb|mb|gb|tb|[kmgt]|ms|us|ns|s|%))?\b",
                re.IGNORECASE), "<NUM>"),
]
# Anything the caller quoted (command lines, filenames, reasons) varies run to
# run; collapse quoted spans so "COMMAND=... 'python wsgi.py'" and its neighbours
# share a template instead of each reading as unique.
_QUOTED = re.compile(r"'[^']{0,120}'|\"[^\"]{0,120}\"")
_WS = re.compile(r"\s+")
# Tabular command output (df, netstat, ps…) prints rows of numbers/paths whose
# column COUNT varies between runs; collapse any run of ≥2 masked tokens so those
# rows share one template instead of each looking brand-new.
_TABLE = re.compile(r"(?:<(?:NUM|PATH|HEX|IP)>[\s|]*){2,}")


def templatize(text):
    """Reduce a raw log line to a stable template string."""
    t = str(text or "")
    t = _QUOTED.sub("<Q>", t)
    for rx, repl in _MASKS:
        t = rx.sub(repl, t)
    t = _TABLE.sub("<COLS> ", t)
    return _WS.sub(" ", t).strip().lower()[:400]


def event_location(ev):
    return str(ev.get("location") or (ev.get("decoder") or {}).get("name") or "unknown")


class LogNoveltyIndex:
    """Frequency model of (source, template) built from a baseline window."""

    def __init__(self):
        self.per_loc = defaultdict(Counter)   # location -> Counter(template -> count)
        self.loc_totals = Counter()           # location -> total events
        self.total = 0

    def add(self, ev):
        loc = event_location(ev)
        tmpl = templatize(ev.get("full_log", ""))
        self.per_loc[loc][tmpl] += 1
        self.loc_totals[loc] += 1
        self.total += 1

    def build(self, events):
        for ev in events:
            self.add(ev)
        return self

    # --- persistence: remember templates across scoring runs -------------- #
    # A stateless window only knows what is in the last N lines, so a benign
    # command the admin runs once a day always looks novel. Persisting the
    # frequency model lets recurring-but-infrequent system activity accumulate
    # counts over days and sink, while genuinely first-seen lines still score high.

    def merge_counts(self, other):
        """Fold another index's counts into this one (used for scoring lookups)."""
        for loc, ctr in other.per_loc.items():
            self.per_loc[loc].update(ctr)
        self.loc_totals.update(other.loc_totals)
        self.total += other.total
        return self

    def decay(self, factor):
        """Multiply every count by `factor` (0<factor<1) so stale templates fade.
        Counts that fall below 1 are dropped; empty locations are pruned."""
        for loc in list(self.per_loc):
            ctr = self.per_loc[loc]
            for tmpl in list(ctr):
                v = ctr[tmpl] * factor
                if v < 1.0:
                    del ctr[tmpl]
                else:
                    ctr[tmpl] = v
            if not ctr:
                del self.per_loc[loc]
                self.loc_totals.pop(loc, None)
            else:
                self.loc_totals[loc] = sum(ctr.values())
        self.total = sum(self.loc_totals.values())
        return self

    def prune(self, max_templates_per_loc=400):
        """Cap memory: keep only the most frequent templates per location."""
        for loc, ctr in list(self.per_loc.items()):
            if len(ctr) > max_templates_per_loc:
                keep = dict(ctr.most_common(max_templates_per_loc))
                self.per_loc[loc] = Counter(keep)
                self.loc_totals[loc] = sum(keep.values())
        self.total = sum(self.loc_totals.values())
        return self

    def to_dict(self):
        return {
            "per_loc": {loc: dict(ctr) for loc, ctr in self.per_loc.items()},
            "loc_totals": dict(self.loc_totals),
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, d):
        idx = cls()
        for loc, ctr in (d.get("per_loc") or {}).items():
            idx.per_loc[loc] = Counter({t: float(c) for t, c in ctr.items()})
        idx.loc_totals = Counter({k: float(v) for k, v in (d.get("loc_totals") or {}).items()})
        idx.total = float(d.get("total") or 0)
        return idx

    def save(self, path):
        import json as _json, os as _os
        _os.makedirs(_os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            _json.dump(self.to_dict(), f)
        _os.replace(tmp, path)   # atomic

    @classmethod
    def load(cls, path):
        import json as _json, os as _os
        if not _os.path.exists(path):
            return cls()
        try:
            with open(path) as f:
                return cls.from_dict(_json.load(f))
        except Exception:
            return cls()

    def novelty(self, ev):
        """0-100 rarity score for one event. Excludes the event's own count so a
        template unique to this event scores as unseen (max novelty)."""
        loc = event_location(ev)
        full = str(ev.get("full_log", ""))
        tmpl = templatize(full)
        others = self.per_loc[loc][tmpl] - 1        # how many OTHER times we've seen it
        if others <= 0:
            base = 100.0                            # never seen elsewhere → novel
        else:
            # rare → high, common → ~0.  1 other ≈ 67, 4 ≈ 33, 20 ≈ 9.
            base = 100.0 / (1.0 + others / 2.0)
        # A line from an otherwise near-silent source is more interesting; a line
        # from a firehose source (journald) needs to be rarer to stand out.
        loc_share = self.loc_totals[loc] / self.total if self.total else 0
        damp = 1.0 - 0.25 * math.tanh(loc_share * 4)   # up to -25% for firehose sources
        # Periodic command/inventory snapshots (df, netstat, ps via <log_format>
        # command) are EXPECTED to change every run — their per-row novelty is
        # meaningless, so discount them heavily rather than let df output top the list.
        if full.startswith("ossec: output:"):
            damp *= 0.2
        return round(max(0.0, min(100.0, base * damp)), 1), tmpl, max(0, others)


def score_stream(events, ensemble=None, recent=None, persistent=None, raw_scorer=None):
    """Score a list of collector events (oldest→newest).

    Three complementary views decide a raw line's anomaly score:
      * novelty   — how rare its template is, measured against the current window
                    PLUS an optional `persistent` baseline so recurring-but-
                    infrequent system activity accumulates counts across runs and
                    stops looking novel;
      * raw model — an optional trained `raw_scorer` (raw_log_scorer.get_scorer())
                    that blends novelty with STRUCTURAL features, so a rare but
                    structurally-ordinary line (a one-off admin command) is judged
                    benign while a hostile-looking line is flagged even if unseen;
      * ensemble  — the calibrated alert ensemble, trusted only for genuine
                    high-severity Wazuh alerts (level >= 8).

    Returns list of dicts (unsorted) — caller ranks by 'anomaly_score'.
    """
    index = LogNoveltyIndex().build(events)
    if persistent is not None:
        index.merge_counts(persistent)   # remembered history sinks recurring lines
    window = events if recent is None else events[-recent:]
    out = []
    for ev in window:
        nov, tmpl, seen = index.novelty(ev)
        # Wazuh's own operational telemetry (rootcheck/SCA scans, monitord status,
        # PAM session open/close) is novel every run but never a threat — cap it
        # low so it can't top the anomaly ranking or trip the reactor.
        operational = is_operational_log(ev)
        if operational:
            nov = min(nov, 5.0)
        rule = ev.get("rule") if isinstance(ev.get("rule"), dict) else {}
        try:
            level = int(rule.get("level", 0) or 0)
        except (TypeError, ValueError):
            level = 0

        # The ensemble is calibrated on high-severity Wazuh ALERTS, not raw log
        # lines. Wazuh tags plenty of benign decoded events with a low level, and
        # the ensemble mis-scores those, so only trust it for genuine high-severity
        # alerts (level >= 8). Everything else is judged purely on novelty.
        ens_score = ens_label = None
        if ensemble is not None and level >= 8 and not operational:
            try:
                r = ensemble.score(ev)
                ens_score, ens_label = r["combined_score"], r["anomaly_label"]
            except Exception:
                pass

        # Trained CONTENT model: "is this raw line's content hostile?" — behavioural
        # only, no novelty input. Combined with novelty by MAX so the two axes stay
        # independent: hostile content OR an unseen template can each surface a line,
        # and the winning axis is reported in `method` (logmodel = likely malicious;
        # novelty = merely new/unusual). This is what keeps a brand-new BENIGN line
        # from ever reading as "malicious" — it wins on novelty, labelled as such.
        content_score = content_prob = None
        if raw_scorer is not None and getattr(raw_scorer, "ok", False) and not operational:
            try:
                content_score, content_prob = raw_scorer.score(ev)
            except Exception:
                content_score = content_prob = None

        raw = nov if content_score is None else max(content_score, nov)
        raw_method = "novelty" if (content_score is None or nov >= content_score) else "logmodel"

        if operational:
            anomaly, method = nov, "routine"        # capped; Wazuh operational noise
        elif ens_score is not None:
            # A real high-severity alert, hostile content, or an unseen line — worst wins.
            anomaly = max(ens_score, raw)
            method = "ensemble" if ens_score >= raw else raw_method
        else:
            anomaly = raw
            method = raw_method
        out.append({
            "anomaly_score": int(round(anomaly)),
            "method": method,
            "novelty_score": nov,
            "content_score": content_score,      # trained content-hostility score (0-100)
            "content_prob": content_prob,        # raw model probability ×100
            "ensemble_score": ens_score,
            "ensemble_label": ens_label,
            "template_seen": seen,           # times this template appears elsewhere
            "location": event_location(ev),
            "decoder": (ev.get("decoder") or {}).get("name"),
            "timestamp": ev.get("timestamp"),
            "full_log": str(ev.get("full_log", ""))[:2000],
            "rule_level": level or None,
            "rule_description": (rule.get("description") or "")[:300] or None,
        })
    return out
