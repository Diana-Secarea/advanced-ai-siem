#!/usr/bin/env python3
"""
Harvest mined blind spots back into the training corpus — the step that turns a
static detector into a self-training one.

Each blind spot is a synthetic alert the ensemble missed but the attack oracle
labels an attack. Appending them (JSONL) to data/training/combined/all_alerts.json
means the next `./retrain_all.sh` trains the stacker against exactly the false
negatives the adversary just found, tightening the decision boundary where it was
weakest. Re-run the adversary afterward and it has to work harder — the loop.

    ./venv/bin/python harvest.py                 # fold ledger into the corpus
    ./venv/bin/python harvest.py --dry-run       # show what would be added
"""

import argparse
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LEDGER = SCRIPT_DIR / "data" / "blindspots" / "blindspots.jsonl"
CORPUS = SCRIPT_DIR / "data" / "training" / "combined" / "all_alerts.json"


def _load_jsonl(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in open(p):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _canon(alert):
    """Stable key for de-duping an alert against the corpus."""
    return json.dumps(alert, sort_keys=True)


def harvest(ledger=LEDGER, corpus=CORPUS, dry_run=False):
    """Append unique blind-spot alerts to the corpus. Returns count added."""
    records = _load_jsonl(ledger)
    if not records:
        return 0

    existing = {_canon(a) for a in _load_jsonl(corpus)}
    to_add, seen = [], set()
    for rec in records:
        alert = rec.get("alert") if isinstance(rec, dict) else None
        if not isinstance(alert, dict):
            continue
        key = _canon(alert)
        if key in existing or key in seen:
            continue
        seen.add(key)
        to_add.append(alert)

    if dry_run or not to_add:
        return len(to_add)

    Path(corpus).parent.mkdir(parents=True, exist_ok=True)
    # Ensure the corpus ends with a newline before appending.
    if Path(corpus).exists() and Path(corpus).stat().st_size:
        with open(corpus, "rb") as f:
            f.seek(-1, 2)
            needs_nl = f.read(1) != b"\n"
    else:
        needs_nl = False
    with open(corpus, "a") as f:
        if needs_nl:
            f.write("\n")
        for alert in to_add:
            f.write(json.dumps(alert) + "\n")
    return len(to_add)


def main():
    ap = argparse.ArgumentParser(description="Fold mined blind spots into the training corpus")
    ap.add_argument("--ledger", default=str(LEDGER))
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    n = harvest(args.ledger, args.corpus, dry_run=args.dry_run)
    verb = "would add" if args.dry_run else "added"
    print(f"Harvest: {verb} {n} unique blind-spot alerts "
          f"{'to ' + args.corpus if not args.dry_run else '(dry run)'}.")
    if n and not args.dry_run:
        print("Retrain to close the loop:  ./retrain_all.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
