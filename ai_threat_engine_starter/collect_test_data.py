#!/usr/bin/env python3
"""
Collect Wazuh alerts into the TEST set (not training).

Run this AFTER training the model to collect fresh alerts for evaluation.
Saves to data/test/<date>.json and merges into data/test/all_test_alerts.json

Usage:
    sudo ./venv/bin/python3 collect_test_data.py
"""
import json
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
TEST_DIR    = SCRIPT_DIR / "data" / "test"
TEST_DIR.mkdir(parents=True, exist_ok=True)

WAZUH_ALERTS_SOURCES = [
    Path("/var/ossec/logs/alerts/alerts.json"),
    Path("/var/ossec/logs/alerts/alerts.log"),
]

TODAY = datetime.now().strftime("%Y-%m-%d")


def load_alerts(filepath):
    alerts = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return alerts


def fingerprint(a):
    ts      = a.get("timestamp", a.get("@timestamp", ""))
    rule_id = a.get("rule", {}).get("id", "")
    agent   = a.get("agent", {}).get("id", "")
    log     = str(a.get("full_log", a.get("message", "")))[:100]
    return f"{ts}|{rule_id}|{agent}|{log}"


def save_snapshot(alerts, date_str):
    out = TEST_DIR / f"{date_str}.json"
    existing = []
    if out.exists():
        existing = load_alerts(out)

    seen = {fingerprint(a) for a in existing}
    new  = [a for a in alerts if fingerprint(a) not in seen]

    if new:
        with open(out, "a") as f:
            for a in new:
                f.write(json.dumps(a) + "\n")
        print(f"  Added {len(new)} new alerts to test/{date_str}.json")
    else:
        print("  No new alerts to add.")
    return len(existing) + len(new)


def rebuild_combined():
    out   = TEST_DIR / "all_test_alerts.json"
    files = sorted(TEST_DIR.glob("????-??-??.json"))
    total = 0
    with open(out, "w") as f:
        for df in files:
            for line in open(df):
                line = line.strip()
                if line:
                    f.write(line + "\n")
                    total += 1
    print(f"  Combined test file: {total} alerts ({len(files)} days)")
    return total


def main():
    print("=" * 48)
    print("  Wazuh TEST Data Collector")
    print(f"  Date: {TODAY}")
    print("=" * 48)

    source = None
    for s in WAZUH_ALERTS_SOURCES:
        try:
            if s.exists() and s.stat().st_size > 0:
                with open(s) as f:
                    f.readline()
                source = s
                break
        except (PermissionError, OSError):
            continue

    if not source:
        print("No alert source found. Make sure Wazuh is running.")
        return

    print(f"Source: {source}")
    alerts = load_alerts(source)
    print(f"Loaded {len(alerts)} alerts\n")

    print("Saving to test set...")
    save_snapshot(alerts, TODAY)

    print("\nRebuilding combined test file...")
    total = rebuild_combined()

    print(f"\nTest set status:")
    for f in sorted(TEST_DIR.glob("????-??-??.json")):
        count = sum(1 for l in open(f) if l.strip())
        print(f"  {f.stem}: {count} alerts")

    print(f"\nTo evaluate model on test data:")
    print(f"  ./venv/bin/python3 evaluate_isolation_forest.py --test-file data/test/all_test_alerts.json")


if __name__ == "__main__":
    main()
