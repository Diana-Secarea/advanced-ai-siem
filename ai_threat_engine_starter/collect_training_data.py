#!/usr/bin/env python3
"""
Collect Wazuh alerts daily for Isolation Forest training.

Run this daily (via cron or manually) to accumulate real alert data.
After collecting enough data (1-2 weeks), train the model with:
    python3 train_isolation_forest.py

Directory structure created:
    data/training/
    ├── daily_logs/          # One file per day
    │   ├── 2026-02-16.json
    │   ├── 2026-02-17.json
    │   └── ...
    └── combined/
        └── all_alerts.json  # Merged file for training
"""
import json
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

# --- Configuration ---
SCRIPT_DIR = Path(__file__).parent
TRAINING_DIR = SCRIPT_DIR / "data" / "training"
DAILY_DIR = TRAINING_DIR / "daily_logs"
COMBINED_DIR = TRAINING_DIR / "combined"

# Where Wazuh writes live alerts (line-delimited JSON)
WAZUH_ALERTS_SOURCES = [
    Path("/var/ossec/logs/alerts/alerts.json"),          # Standard Wazuh path
    Path("/var/ossec/logs/alerts/alerts.log"),            # Alternative log format
    SCRIPT_DIR / "data" / "alerts.json",                 # Local dev/test alerts
]

TODAY = datetime.now().strftime("%Y-%m-%d")


def find_alerts_source():
    """Find the first available alerts source file."""
    for source in WAZUH_ALERTS_SOURCES:
        try:
            if source.exists() and source.stat().st_size > 0:
                # Verify we can actually read it
                with open(source, "r") as f:
                    f.readline()
                return source
        except (PermissionError, OSError):
            continue
    return None


def load_alerts_from_file(filepath):
    """Load line-delimited JSON alerts from a file."""
    alerts = []
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                pass  # Skip malformed lines silently
    return alerts


def filter_today_alerts(alerts, date_str=None):
    """Filter alerts that match today's date (or a given date)."""
    target_date = date_str or TODAY
    filtered = []
    for alert in alerts:
        ts = alert.get("timestamp", alert.get("@timestamp", ""))
        if target_date in str(ts):
            filtered.append(alert)

    # If no date-filtered alerts found, include all (the file might not have dates
    # or might be a snapshot that should all be captured)
    if not filtered and alerts:
        print(f"  No alerts match date {target_date}, collecting all {len(alerts)} alerts")
        return alerts

    return filtered


def save_daily_snapshot(alerts, date_str=None):
    """Save alerts to a daily snapshot file (line-delimited JSON)."""
    target_date = date_str or TODAY
    daily_file = DAILY_DIR / f"{target_date}.json"

    existing_alerts = []
    if daily_file.exists():
        existing_alerts = load_alerts_from_file(daily_file)
        print(f"  Existing daily file has {len(existing_alerts)} alerts")

    # Deduplicate by creating a fingerprint (timestamp + rule_id + agent_id)
    def fingerprint(a):
        ts = a.get("timestamp", a.get("@timestamp", ""))
        rule_id = a.get("rule", {}).get("id", "")
        agent_id = a.get("agent", {}).get("id", "")
        msg = str(a.get("full_log", a.get("message", "")))[:100]
        return f"{ts}|{rule_id}|{agent_id}|{msg}"

    seen = set(fingerprint(a) for a in existing_alerts)
    new_alerts = [a for a in alerts if fingerprint(a) not in seen]

    if new_alerts:
        with open(daily_file, "a") as f:
            for alert in new_alerts:
                f.write(json.dumps(alert) + "\n")
        print(f"  Added {len(new_alerts)} new alerts to {daily_file.name}")
    else:
        print(f"  No new alerts to add for {target_date}")

    return len(existing_alerts) + len(new_alerts)


def merge_all_daily_files():
    """Merge all daily snapshots into a single training file."""
    combined_file = COMBINED_DIR / "all_alerts.json"
    total = 0

    daily_files = sorted(DAILY_DIR.glob("*.json"))
    if not daily_files:
        print("  No daily files to merge")
        return 0

    with open(combined_file, "w") as out:
        for daily_file in daily_files:
            alerts = load_alerts_from_file(daily_file)
            for alert in alerts:
                out.write(json.dumps(alert) + "\n")
                total += 1

    print(f"  Merged {len(daily_files)} days -> {total} total alerts in {combined_file.name}")
    return total


def print_collection_status():
    """Print summary of collected training data."""
    daily_files = sorted(DAILY_DIR.glob("*.json"))
    combined_file = COMBINED_DIR / "all_alerts.json"

    print("\n========================================")
    print("  Training Data Collection Status")
    print("========================================\n")

    if not daily_files:
        print("  No data collected yet. Run this script daily.\n")
        return 0

    total_alerts = 0
    print(f"  Days collected: {len(daily_files)}")
    print(f"  Date range: {daily_files[0].stem} to {daily_files[-1].stem}")
    print()

    for df in daily_files:
        count = sum(1 for _ in open(df))
        total_alerts += count
        print(f"    {df.stem}:  {count:>6} alerts")

    print(f"\n  Total alerts: {total_alerts}")

    if combined_file.exists():
        combined_count = sum(1 for _ in open(combined_file))
        print(f"  Combined file: {combined_count} alerts")

    # Training readiness
    print("\n  Training readiness:")
    if total_alerts < 100:
        print(f"    Need at least 100 alerts. Currently: {total_alerts}")
        print(f"    Keep collecting for more days.")
    elif total_alerts < 1000:
        print(f"    Minimum met ({total_alerts} alerts). Model will be basic.")
        print(f"    Recommended: collect 1,000+ alerts for better accuracy.")
    elif total_alerts < 10000:
        print(f"    Good amount ({total_alerts} alerts). Ready for solid training.")
    else:
        print(f"    Excellent! {total_alerts} alerts. Model will be highly accurate.")

    print(f"\n  To train: python3 train_isolation_forest.py")

    return total_alerts


def main():
    # Ensure directories exist
    DAILY_DIR.mkdir(parents=True, exist_ok=True)
    COMBINED_DIR.mkdir(parents=True, exist_ok=True)

    print("========================================")
    print("  Wazuh Alert Collector for IF Training")
    print(f"  Date: {TODAY}")
    print("========================================\n")

    # Find alerts source
    source = find_alerts_source()
    if not source:
        print("No alert source found. Checked:")
        for s in WAZUH_ALERTS_SOURCES:
            print(f"  - {s}  {'(exists)' if s.exists() else '(not found)'}")
        print("\nMake sure Wazuh is running and generating alerts.")
        print("Or place test alerts in: data/alerts.json")
        return

    print(f"Source: {source}")
    print(f"  File size: {source.stat().st_size:,} bytes\n")

    # Load alerts
    alerts = load_alerts_from_file(source)
    print(f"  Loaded {len(alerts)} alerts from source\n")

    if not alerts:
        print("  No alerts found in source file.")
        return

    # Save daily snapshot
    print("Saving daily snapshot...")
    daily_count = save_daily_snapshot(alerts)

    # Merge all daily files into combined training file
    print("\nMerging daily files...")
    total = merge_all_daily_files()

    # Print status
    print_collection_status()


if __name__ == "__main__":
    main()
