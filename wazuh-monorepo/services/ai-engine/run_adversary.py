#!/usr/bin/env python3
"""
Attacker-in-the-loop runner — mine ensemble blind spots, then (optionally)
harvest them back into the training corpus so the detector self-trains.

    ./venv/bin/python run_adversary.py --budget 300 --lives 3
    ./venv/bin/python run_adversary.py --families ssh_bruteforce,web_sqli --no-llm
    ./venv/bin/python run_adversary.py --budget 400 --harvest    # mine + fold in

Each banked blind spot is a synthetic Wazuh alert that the repo's own attack
oracle labels an attack, yet the ensemble scored NORMAL — a real false negative.
The ledger is JSONL at data/blindspots/blindspots.jsonl (override with --out).
"""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from autoencoders_approach.ensemble_detector import load_ensemble
from adversary import AttackerInLoop


def _load_benign_ids():
    f = SCRIPT_DIR.parent.parent / "apps" / "backend" / "benign_rules.json"
    try:
        if f.exists():
            return set(json.load(open(f)).keys())
    except Exception:
        pass
    return set()


def _print_report(rep):
    d = rep.as_dict()
    print("\n" + "=" * 62)
    print("  ATTACKER-IN-THE-LOOP — BLIND-SPOT MINING REPORT")
    print("=" * 62)
    print(f"  budget spent      : {d['budget_spent']}/{d['budget_total']} probes")
    print(f"  detector caught   : {d['total_detections']} probes flagged")
    print(f"  lives             : {d['lives_left']}/{d['lives_start']} left")
    print(f"  LLM strategist    : {'ON' if d['llm_used'] else 'off (mutation-only)'}")
    print(f"  blind spots mined : {d['total_blind_spots']}  "
          f"(evasion rate {d['evasion_rate']*100:.1f}%)")
    print(f"  wall time         : {d['elapsed_s']}s")
    print("-" * 62)
    print(f"  {'family':<22}{'seed':>10}{'best evade':>12}{'mined':>8}{'caught':>8}")
    for fam, info in d["families"].items():
        seed = f"{info['seed_score']}({info['seed_label'][:4]})"
        best = "—" if info["best_evasion_score"] is None else info["best_evasion_score"]
        print(f"  {fam:<22}{seed:>10}{str(best):>12}{info['blind_spots']:>8}"
              f"{'YES' if info['caught'] else '·':>8}")
    print("=" * 62)
    if d["total_blind_spots"]:
        print(f"  ↳ {d['total_blind_spots']} false negatives banked — "
              f"run with --harvest (or harvest.py) to retrain on them.")
    else:
        print("  ↳ No blind spots found — the detector held. Raise --budget to push harder.")
    print()


def main():
    ap = argparse.ArgumentParser(description="Adversarial blind-spot miner for the ensemble")
    ap.add_argument("--budget", type=int, default=300, help="total ensemble query budget")
    ap.add_argument("--lives", type=int, default=None,
                    help="families the agent may be caught on before it dies (default: one per family)")
    ap.add_argument("--families", default="all", help="comma list or 'all'")
    ap.add_argument("--no-llm", action="store_true", help="disable the LLM strategist (mutation-only)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--pop-size", type=int, default=6)
    ap.add_argument("--out", default=str(SCRIPT_DIR / "data" / "blindspots" / "blindspots.jsonl"))
    ap.add_argument("--harvest", action="store_true",
                    help="after mining, fold blind spots into the training corpus")
    args = ap.parse_args()

    fams = None if args.families == "all" else [s.strip() for s in args.families.split(",") if s.strip()]

    print("Loading ensemble (IF + AE + UEBA + stacker)...")
    ens = load_ensemble()

    agent = AttackerInLoop(
        ens, benign_ids=_load_benign_ids(),
        budget=args.budget, lives=args.lives, families=fams,
        use_llm=not args.no_llm, ledger_path=args.out, seed=args.seed,
        pop_size=args.pop_size,
    )
    print(f"Adversary armed — budget={args.budget}, lives={args.lives}, "
          f"families={fams or 'all'}, ledger={args.out}\n")
    rep = agent.run()
    _print_report(rep)

    if args.harvest and rep.total_blind_spots:
        from harvest import harvest
        added = harvest(ledger=args.out)
        print(f"Harvested {added} new blind spots into the training corpus. "
              f"Retrain with:  ./retrain_all.sh\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
