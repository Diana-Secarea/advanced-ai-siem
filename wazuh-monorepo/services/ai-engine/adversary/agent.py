"""
AttackerInLoop — the budget-constrained adversary that mines detector blind spots.

For each attack family it runs an evolutionary search (optionally steered by the
LLM strategist) against the live ensemble, spending query budget, banking every
still-an-attack variant that scores NORMAL, and stopping a family early if the
detector's alarm (heat) trips. What the run produces is a ledger of false
negatives — retrain data the ensemble has, by definition, never caught.
"""

import random
import time
from dataclasses import dataclass, field

from .attack_templates import all_families, get_seed, genome_for
from .environment import AttackerEnvironment, AgentCaught
from .mutator import evolve
from .llm_strategist import LLMStrategist


@dataclass
class RunReport:
    families: dict = field(default_factory=dict)
    total_probes: int = 0
    total_detections: int = 0
    total_blind_spots: int = 0
    budget_total: int = 0
    budget_spent: int = 0
    lives_start: int = 0
    lives_left: int = 0
    llm_used: bool = False
    elapsed_s: float = 0.0

    def as_dict(self):
        return {
            "families": self.families,
            "total_probes": self.total_probes,
            "total_detections": self.total_detections,
            "total_blind_spots": self.total_blind_spots,
            "evasion_rate": round(
                self.total_blind_spots / self.total_probes, 4) if self.total_probes else 0.0,
            "budget_total": self.budget_total,
            "budget_spent": self.budget_spent,
            "lives_start": self.lives_start,
            "lives_left": self.lives_left,
            "llm_used": self.llm_used,
            "elapsed_s": round(self.elapsed_s, 2),
        }


class AttackerInLoop:
    def __init__(self, ensemble, benign_ids=frozenset(), *,
                 budget=300, lives=None, families=None, use_llm=True,
                 ledger_path=None, seed=1337,
                 per_family_budget=None, pop_size=6):
        self.rng = random.Random(seed)
        self.families = families or all_families()
        # Default: one life per family, so being caught on a robust family (the
        # detector winning) doesn't end the run before the evadable ones are tried.
        if lives is None:
            lives = len(self.families)
        self.env = AttackerEnvironment(
            ensemble, benign_ids, budget=budget, lives=lives, ledger_path=ledger_path)
        self.strategist = LLMStrategist() if use_llm else None
        self.pop_size = pop_size
        # Split the query budget across the families we still have lives for.
        self.per_family_budget = per_family_budget or max(
            self.pop_size * 4, budget // max(1, len(self.families)))

    def _hint_fn(self):
        """Wrap the LLM strategist as an evolve() hint provider, or None."""
        if not self.strategist or not self.strategist.enabled:
            return None

        def hint(best_alert):
            try:
                scores = self.env.ens.score(best_alert)
                small = {k: scores.get(k) for k in
                         ("combined_score", "if_score", "ae_score", "ueba_score")}
                return self.strategist.propose(best_alert, small)
            except Exception:
                return None
        return hint

    def run(self):
        t0 = time.time()
        rep = RunReport(
            budget_total=self.env.budget_total,
            lives_start=self.env.lives,
        )
        hint_fn = self._hint_fn()

        for family in self.families:
            if self.env.budget_left <= 0 or self.env.lives <= 0:
                break
            seed = get_seed(family)
            genome = genome_for(family)
            fitness = self.env.make_fitness(family)
            fam_budget = min(self.per_family_budget, self.env.budget_left)
            banked_before = len(self.env.blind_spots)
            caught = False

            try:
                best_alert, best_score, _, _ = evolve(
                    seed, genome, fitness,
                    budget=fam_budget, rng=self.rng,
                    pop_size=self.pop_size, hint_fn=hint_fn)
            except AgentCaught:
                caught = True
                st = self.env._family_state
                best_alert, best_score = st["best_alert"], st["best_score"]

            banked = len(self.env.blind_spots) - banked_before
            baseline = self.env.ens.score(get_seed(family))   # seed's score, for contrast
            rep.families[family] = {
                "blind_spots": banked,
                "best_evasion_score": None if best_score > 100 else round(best_score, 1),
                "seed_score": baseline["combined_score"],
                "seed_label": baseline["anomaly_label"],
                "caught": caught,
                "best_alert": best_alert,
            }
            if caught and not self.env.lose_life():
                break

        rep.total_probes = self.env.probes
        rep.total_detections = self.env.detections
        rep.total_blind_spots = len(self.env.blind_spots)
        rep.budget_spent = self.env.budget_total - self.env.budget_left
        rep.lives_left = self.env.lives
        rep.llm_used = bool(hint_fn is not None)
        rep.elapsed_s = time.time() - t0
        return rep
