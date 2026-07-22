"""
Attacker-in-the-loop: an adversarial self-training loop for the ensemble.

A budget-constrained agent generates synthetic Wazuh alerts that are *genuinely
malicious* (they satisfy the repo's own attack oracle, attack_labels.is_attack_alert)
yet crafted to slip past the ensemble detector. Every alert that stays an attack
but scores NORMAL is a false negative — a blind spot — and gets banked as fresh
retrain data. Harvesting those blind spots back into the training corpus turns a
static detector into one that keeps learning from what it has never caught.

Pieces:
    attack_templates  — malicious seed alerts per family + maliciousness invariants
    mutator           — evasion operators + evolutionary search over one alert
    llm_strategist    — optional Ollama-guided mutation hints (graceful fallback)
    environment       — the "game": budget, heat/lives, blind-spot ledger
    agent             — AttackerInLoop, ties search + environment together
    harvest           — merge banked blind spots into the training corpus
"""

from .agent import AttackerInLoop, RunReport
from .environment import AttackerEnvironment

__all__ = ["AttackerInLoop", "RunReport", "AttackerEnvironment"]
