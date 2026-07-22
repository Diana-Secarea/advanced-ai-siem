"""
The attacker's environment — the "game" the agent plays against the detector.

Rules:
  * Query budget. Every alert the agent scores against the ensemble costs one
    unit. When the budget is gone, the run ends. (Probing a live SIEM is not free
    or risk-free; the budget forces the agent to be efficient, not brute-force.)
  * Heat & lives. Each scored variant the detector flags raises "heat"; each one
    that slips past cools it. If heat crosses heat_max the agent is CAUGHT — it
    loses a life and that family's run stops. Out of lives ⇒ the whole agent dies.
    This rewards finding evasions fast over blasting thousands of loud probes.
  * Blind spots. A variant that stays a real attack (family invariant + the repo
    attack oracle both True) yet scores NORMAL is a false negative. It is banked
    to the ledger — this is the retrain data the loop produces.

A banked blind spot is, by construction, `is_attack_alert(alert) == True` and
`ensemble.is_anomaly == False`: a genuine miss, correctly labeled for harvest.
"""

import json
import time
from pathlib import Path

from attack_labels import is_attack_alert as _oracle
from .attack_templates import invariant_for


class AgentCaught(Exception):
    """Raised when heat crosses heat_max — the current family run is blown."""


def _signature(alert):
    """Coarse identity of a variant, for de-duping banked blind spots."""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    return (
        rule.get("id"), rule.get("level"),
        tuple(sorted(rule.get("groups", []))),
        str(alert.get("timestamp", ""))[11:13],   # hour bucket
        data.get("srcip"), data.get("dstip"),
        len(str(alert.get("full_log", "")).split()),
        len(data),
    )


class AttackerEnvironment:
    def __init__(self, ensemble, benign_ids=frozenset(), *,
                 budget=300, lives=3, heat_max=12.0, detect_heat=1.0,
                 cool_rate=3.0, passive_cool=0.1, ledger_path=None):
        self.ens = ensemble
        self.benign_ids = benign_ids
        self.budget_total = budget
        self.budget_left = budget
        self.lives = lives
        self.heat = 0.0
        self.heat_max = heat_max
        self.detect_heat = detect_heat
        self.cool_rate = cool_rate
        # Heat bleeds off slowly every probe: a patient, mostly-quiet search can
        # keep going, but a family that trips the detector on *every* probe still
        # heats up to the alarm and gets caught (the detector genuinely won).
        self.passive_cool = passive_cool

        self.ledger_path = Path(ledger_path) if ledger_path else None
        if self.ledger_path:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

        self._banked_sigs = set()
        self.blind_spots = []          # list of records banked this run
        self.probes = 0                # total ensemble queries spent
        self.detections = 0            # variants the detector caught

    # ------------------------------------------------------------------ #
    def is_attack(self, alert):
        """Repo ground-truth oracle — same labeler train_stacking.py uses."""
        return _oracle(alert, self.benign_ids)

    def _bank(self, alert, family, result):
        sig = _signature(alert)
        if sig in self._banked_sigs:
            return False
        self._banked_sigs.add(sig)
        rec = {
            "ts": time.time(),
            "family": family,
            "ensemble": {k: result[k] for k in
                         ("combined_score", "anomaly_label", "if_score",
                          "ae_score", "ueba_score", "meta_probability")},
            "oracle_attack": True,
            "alert": alert,
        }
        self.blind_spots.append(rec)
        if self.ledger_path:
            with open(self.ledger_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        return True

    # ------------------------------------------------------------------ #
    def make_fitness(self, family):
        """Build the fitness_fn the evolutionary search minimises for `family`.

        Returns (score, valid). Spends budget, updates heat, banks blind spots,
        and raises AgentCaught when the alarm trips. Tracks the family's running
        best so a caught mid-search still yields its best evader.
        """
        invariant = invariant_for(family)
        state = {"best_alert": None, "best_score": 101.0, "evasions": 0}
        self._family_state = state
        self.heat = 0.0   # each family starts cold — one family's noise doesn't doom the next

        def fitness(alert):
            if self.budget_left <= 0:
                return 101.0, False
            self.budget_left -= 1
            self.probes += 1
            self.heat = max(0.0, self.heat - self.passive_cool)

            # A variant only counts if it is STILL an attack.
            valid = bool(invariant(alert)) and self.is_attack(alert)
            if not valid:
                return 101.0, False

            result = self.ens.score(alert)
            score = result["combined_score"]

            if result["is_anomaly"]:
                self.detections += 1
                self.heat += self.detect_heat
                if self.heat >= self.heat_max:
                    raise AgentCaught(family)
            else:
                # evaded: a genuine blind spot
                self.heat = max(0.0, self.heat - self.cool_rate)
                state["evasions"] += 1
                self._bank(alert, family, result)

            if score < state["best_score"]:
                state["best_score"] = score
                state["best_alert"] = alert
            return score, valid

        return fitness

    def lose_life(self):
        self.lives -= 1
        self.heat = 0.0
        return self.lives > 0
