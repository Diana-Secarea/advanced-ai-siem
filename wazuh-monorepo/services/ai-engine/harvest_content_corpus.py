#!/usr/bin/env python3
"""Build a REAL labelled corpus for the content model, with provenance.

    ./venv/bin/python harvest_content_corpus.py --dry-run
    ./venv/bin/python harvest_content_corpus.py --alerts /var/ossec/logs/alerts/alerts.json

Why
---
Every positive example the content model has ever seen is hand-written:
`log_synthetic.py` supplies 1,600 synthetic attacks and 0 real ones. That is
why editing the corpus moves the decision boundary unpredictably while the
held-out score stays at a perfect 1.000 — synthetic benign and synthetic
attack are trivially separable, so the boundary is unconstrained in the region
where real traffic actually lives.

The fix is real examples. This collects them.

The circularity problem, and why PROVENANCE is the whole design
---------------------------------------------------------------
The obvious move — label prod traffic with `attack_labels.classify()` and
train on it — does not escape the hardcoded rules. It *distils* them. A model
trained on rule-made labels learns to imitate the rules and can never discover
anything they do not already know, while looking like it validated them.

So every example records WHERE ITS LABEL CAME FROM, and the sources are not
equal:

    simulation an attack by CONSTRUCTION, in REAL host traffic — you ran a
               known attack in a known window, so every alert inside it is a
               true positive whose text came off the wire. The only source
               that is both independent of the rules AND real. Best there is.
    adversary  an attack by construction, independent of the rules, but the
               TEXT is adversary-generated rather than captured. Catching
               these proves the model beats the adversary, not the internet.
    analyst    a human said so. Independent. Gold.
    observed   real traffic from a running host, presumed benign. Weak, but
               independent of the rules and abundant.
    rules      labelled by attack_labels. Fine to TRAIN on, worthless as
               evidence the model beats the rules.

Every row carries `source`, so the trainer can split on it: train on
everything, but hold out ONLY rows whose source is in INDEPENDENT. Evaluating
on `rules`-labelled rows measures whether the model imitates the rules, which
is a mirror rather than a measurement. Consuming that split is the trainer's
job, not this script's — this one only makes the distinction available and
refuses to let it go unnoticed.
"""

import argparse
import collections
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ALERTS = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_ARCHIVES = "/var/ossec/logs/archives/archives.json"
DEFAULT_LEDGER = SCRIPT_DIR / "data" / "blindspots" / "blindspots.jsonl"
DEFAULT_OUT = SCRIPT_DIR / "data" / "training" / "content_corpus.jsonl"

#: Label sources, ordered by how much the evaluation can trust them.
INDEPENDENT = ("simulation", "adversary", "analyst", "observed")
#: Independent AND real text. The only rows an honest generalisation claim
#: can rest on.
REAL_POSITIVE = ("simulation", "analyst")
DERIVED = ("rules",)

#: Cap per distinct log TEMPLATE. Production is enormously repetitive — one
#: host produced 542 near-identical scan lines in a day — and without this the
#: corpus becomes a single sentence repeated until the model memorises it.
#: The cap is what turns "a lot of logs" into "a lot of DIFFERENT logs".
PER_TEMPLATE_CAP = 25

_NUM = re.compile(r"\d+")
_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def templatize(line):
    """Collapse a log line to its shape, so near-duplicates group together."""
    s = _IP.sub("<ip>", str(line or ""))
    s = _HEX.sub("<hex>", s)
    s = _NUM.sub("<n>", s)
    return s.strip()[:300]


def _load_jsonl(path, limit=None):
    out = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
                if limit and len(out) >= limit:
                    break
    except OSError:
        pass
    return out


def _event(alert):
    """The shape log_features.extract() and the content model consume."""
    return {"full_log": str(alert.get("full_log") or alert.get("message") or ""),
            "location": str(alert.get("location") or "")}


def _parse_window(spec):
    """'2026-09-26T14:00,2026-09-26T14:30' -> (start, end) as ISO prefixes."""
    if not spec:
        return None
    parts = [p.strip() for p in str(spec).split(",")]
    if len(parts) != 2 or not all(parts):
        raise ValueError("window must be 'START,END' in ISO form")
    return parts[0], parts[1]


def harvest(alerts_path, archives_path, ledger_path, baseline_days=3,
            cap=PER_TEMPLATE_CAP, windows=None):
    """Return (rows, stats). Each row carries its label AND its provenance."""
    import attack_labels as L
    from rule_baseline import RuleBaseline

    rows = []
    stats = collections.Counter()
    seen = collections.Counter()      # template -> kept count

    def add(ev, label, source, reason):
        blob = ev.get("full_log", "")
        if not blob or len(blob) < 8:
            return
        t = templatize(blob)
        if seen[t] >= cap:
            stats[f"capped:{source}"] += 1
            return
        seen[t] += 1
        rows.append({"full_log": blob, "location": ev.get("location", ""),
                     "label": label, "source": source, "reason": reason,
                     "template": t})
        stats[f"{label}:{source}"] += 1

    # ---- 1. adversary ledger: attacks by construction, rules not involved --
    for rec in _load_jsonl(ledger_path):
        if not rec.get("oracle_attack"):
            continue
        alert = rec.get("alert") or {}
        add(_event(alert), "attack", "adversary",
            f"adversary blind spot ({rec.get('family', '?')})")

    # ---- 2. real host traffic, classified --------------------------------
    alerts = _load_jsonl(alerts_path)
    stats["alerts_read"] = len(alerts)

    baseline = RuleBaseline()
    days = sorted({str(a.get("timestamp", ""))[:10] for a in alerts if a.get("timestamp")})
    for day in (days[-baseline_days:] or ["unknown"]):
        for a in alerts:
            r = a.get("rule") or {}
            d = a.get("data") or {}
            baseline.observe(r.get("id"), day, srcip=d.get("srcip"),
                             is_failure=L.failure_outcome(a))
    today = days[-1] if days else None

    for a in alerts:
        ts = str(a.get("timestamp", ""))
        # A simulation window overrides everything. You ran the attack; the
        # rules' opinion about it is not evidence, and neither is their
        # silence — this is the one place a label is simply known.
        hit = next((w for w in (windows or []) if w[0] <= ts <= w[1]), None)
        if hit:
            add(_event(a), "attack", "simulation",
                f"inside simulation window {hit[0]}..{hit[1]}")
            continue

        verdict, why = L.classify(a, baseline=baseline, today=today)
        ev = _event(a)
        if verdict in (L.ATTACK, L.AMBIENT_HOSTILE):
            # Hostile, but the RULES said so — training signal, not evidence.
            add(ev, "attack", "rules", (why or ["rule verdict"])[0])
        else:
            # Ordinary traffic on a running host. Weakly supervised, but the
            # label does not come from the thing we are trying to test.
            add(ev, "benign", "observed", verdict)

    # ---- 3. archives: bulk real benign -----------------------------------
    if archives_path:
        try:
            from attack_labels import is_operational_log
        except Exception:                       # noqa: BLE001
            def is_operational_log(_):
                return False
        for e in _load_jsonl(archives_path, limit=40000):
            if is_operational_log(e):
                stats["skipped:operational"] += 1
                continue
            add(_event(e), "benign", "observed", "archive line")

    return rows, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--alerts", default=DEFAULT_ALERTS)
    ap.add_argument("--archives", default=DEFAULT_ARCHIVES)
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--cap", type=int, default=PER_TEMPLATE_CAP,
                    help="max rows per distinct log template")
    ap.add_argument("--window", action="append", default=[],
                    metavar="START,END",
                    help="ISO time range in which a known attack was run; every "
                         "alert inside is labelled a true positive. Repeatable. "
                         "e.g. --window 2026-09-26T14:00,2026-09-26T14:30")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    sys.path.insert(0, str(SCRIPT_DIR))
    windows = [_parse_window(w) for w in args.window]
    rows, stats = harvest(args.alerts, args.archives, args.ledger,
                          cap=args.cap, windows=windows)

    by_label = collections.Counter(r["label"] for r in rows)
    by_source = collections.Counter(r["source"] for r in rows)
    indep_attacks = sum(1 for r in rows
                        if r["label"] == "attack" and r["source"] in INDEPENDENT)
    real_attacks = sum(1 for r in rows
                       if r["label"] == "attack" and r["source"] in REAL_POSITIVE)
    indep_tpl = len({r["template"] for r in rows
                     if r["label"] == "attack" and r["source"] in INDEPENDENT})

    print(f"harvested {len(rows)} rows from {stats.get('alerts_read', 0)} alerts")
    print(f"  by label : {dict(by_label)}")
    print(f"  by source: {dict(by_source)}")
    print(f"  distinct templates: {len({r['template'] for r in rows})}")
    print()
    print(f"  INDEPENDENT attack examples : {indep_attacks} "
          f"({indep_tpl} distinct templates)")
    print(f"  …of which REAL captured text : {real_attacks}")
    if indep_attacks and not real_attacks:
        # The count flatters itself otherwise: adversary rows are labelled
        # independently but written by us, so a model can ace them and still
        # miss everything the internet actually sends.
        print("  ⚠ every independent example is adversary-GENERATED text. A model")
        print("    scoring well on these has beaten the adversary, not the wild.")
        print("    For real positives: run attack_simulation/simulate_attack_for_wazuh.sh")
        print("    and re-harvest with --window START,END covering the run.")
    if not indep_attacks:
        # Saying this plainly matters more than the corpus itself. Without
        # independent positives there is nothing to evaluate against that the
        # rules did not already decide, and a good score would mean nothing.
        print("  ⚠ none. Every attack label here came from the rules, so this")
        print("    corpus can TRAIN a model but cannot show it beats the rules.")
        print("    Run the adversary (run_adversary.py) to mine real blind")
        print("    spots, or label incidents by hand, before trusting an eval.")

    if args.dry_run:
        print("\ndry run — nothing written")
        for r in rows[:5]:
            print(f"  [{r['label']}/{r['source']}] {r['full_log'][:88]}")
        return 0

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
