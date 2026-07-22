# Attacker-in-the-loop — adversarial self-training for the ensemble

A budget-constrained agent that hunts for the ensemble's blind spots and turns
them into retrain data. It generates synthetic Wazuh alerts that stay **real
attacks** — they satisfy the repo's own attack oracle (`attack_labels.is_attack_alert`,
the same labeler `train_stacking.py` uses) — yet are tuned to score **NORMAL**.
Every such alert is a false negative the detector has never caught. Harvest those
back into the training corpus and the detector learns from exactly what it missed,
so the SIEM trains itself instead of staying static.

## Why this is honest (no cheating, no label leakage)

A variant only counts as a blind spot if **both** hold:

1. `is_attack_alert(alert) == True` — it is still an attack by the repo's ground truth.
2. A family **invariant** — the attack's semantic core is intact (a brute force
   keeps a public source IP + auth-failure semantics; a C2 beacon keeps an
   external destination + process/exec context; etc.).

So the agent cannot "win" by mutating an attack into something benign. Because
every banked alert is oracle-labeled an attack, harvesting adds correctly-labeled
hard negatives — no manual labeling, no leakage.

## The game

- **Budget** — every alert scored against the ensemble costs one query. Probing a
  live SIEM is not free; the budget forces efficient search, not brute force.
- **Heat & lives** — flagged probes raise heat, evaded ones cool it; crossing
  `heat_max` means the agent is *caught* on that family (a life). A family the
  detector genuinely resists (e.g. external-IP brute force, which the autoencoder
  pins) ends *caught* — a win for the defender, reported as such.
- **Blind spots** — still-an-attack + scored NORMAL ⇒ banked to
  `data/blindspots/blindspots.jsonl`.

## Search

Per family, a small (μ+λ) evolutionary loop minimises the ensemble's combined
score subject to "still an attack", seeded at the stealthiest disguise corner
(`max_disguise`) and exploring outward. Disguise levers map onto the model's
features: timing (low-and-slow), rule severity/id/groups (living-off-the-land),
log keyword density, and data richness. An optional **LLM strategist** (Ollama,
same model as the copilot) proposes targeted edits each generation; if it is
offline or slow the search runs on the mutation operators alone — deterministic
and demo-safe.

## Usage

```bash
# mine blind spots (mutation-only, fast, offline)
./venv/bin/python run_adversary.py --budget 400 --no-llm

# let the LLM steer the search
./venv/bin/python run_adversary.py --budget 400

# just two families
./venv/bin/python run_adversary.py --families ssh_bruteforce,c2_beacon

# mine, then fold the misses into the training corpus in one shot
./venv/bin/python run_adversary.py --budget 400 --harvest
./retrain_all.sh                 # retrain on the hard negatives — closes the loop

# harvest a prior run's ledger on its own
./venv/bin/python harvest.py --dry-run
./venv/bin/python harvest.py
```

## Backend API (auth-protected)

| Method + path | purpose |
|---|---|
| `POST /api/adversary/run` | start a run `{budget, lives, use_llm, families}` (one at a time) |
| `GET  /api/adversary/status` | run state + last report |
| `GET  /api/adversary/blindspots?limit=N` | recent banked false negatives |
| `POST /api/adversary/harvest` | fold the ledger into the training corpus |

The **ML Engine** page (`ml.html`) has an *Attacker-in-the-loop* panel that drives
these: launch a run, watch the per-family outcome (held vs. missed), and harvest.

## Attack families (synthetic detection scenarios — inert alert JSON, not malware)

Nine families, each a realistic Wazuh **alert record** the ensemble scores. They
describe attacks the way a SIEM log would; there is no exploit code or payload.

- Network / auth: `ssh_bruteforce`, `web_sqli`, `privilege_escalation`, `c2_beacon`, `data_exfil`
- Host / endpoint: `ransomware`, `lateral_movement`, `credential_dumping`, `apt_persistence`

Observed result: the ensemble **holds** on the network/auth families (autoencoder
pins them) but is largely **blind to the host-based ones** — `credential_dumping`
and `apt_persistence` score NORMAL even undisguised, and `ransomware` is trivially
hidden. That gap is the training signal: the models were built on network telemetry
and have not learned endpoint behavior. Harvest those blind spots + add endpoint
alerts to the clean baseline to fix it.

## Detect & react — the blue-team half

`playbooks.py` gives every family a defensive runbook: MITRE technique, what the
activity looks like, the signals/rules to detect it, and step-by-step response.
Served at `GET /api/adversary/playbook[?family=…]` and shown inline on the ML
Engine page — click any family row in the results table to expand its playbook.
The adversary shows you WHERE the detector is blind; the playbook teaches you what
to DO when each family fires.

## Files

- `attack_templates.py` — malicious seeds + family invariants + disguise genome (9 families)
- `mutator.py` — evasion operators, `max_disguise`, and the evolutionary search
- `llm_strategist.py` — optional Ollama-guided mutation hints
- `environment.py` — budget/heat/lives game + blind-spot ledger + attack oracle
- `playbooks.py` — per-family detection + incident-response guidance
- `agent.py` — `AttackerInLoop`, orchestrates search across families
- `../run_adversary.py` — CLI · `../harvest.py` — corpus harvester
