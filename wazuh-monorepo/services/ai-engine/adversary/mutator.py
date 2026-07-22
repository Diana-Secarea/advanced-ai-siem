"""
Evasion operators + evolutionary search over a single malicious alert.

Each operator changes ONE disguise lever without touching the attack's identity
(the family invariant + the repo attack oracle guard that, checked by the
caller). The levers map directly onto the features the ensemble reads:

  hour          → feature 3/4  (hour-of-day, off-hours flag)
  rule_level    → feature 8    (Wazuh severity)
  rule_meta     → feature 9/10 (rule id, suspicious-group count) — living-off-the-land
  log_verbosity → feature 2 (+0/1) (failed/denied/invalid/error keyword density)
  data_fields   → feature 11   (how much side data the event carries)
  srcip/dstip   → rotate attacker IP (keeps the external-IP invariant)

The search is a small (μ+λ) evolutionary loop: keep the best evaders, mutate
them, and minimise the ensemble's combined score subject to "still an attack".
Every fitness evaluation spends one unit of the agent's query budget.
"""

import copy
import random

from .attack_templates import (
    PUBLIC_ATTACKER_IPS, BUSINESS_HOURS, ALL_HOURS,
)

# "Quiet" rule ids — plausible for the activity but NOT in attack_labels'
# ATTACK_RULE_IDS, so they lower feature 9's signal. The oracle still labels the
# variant an attack via its groups/keywords/level; this is living-off-the-land.
QUIET_RULE_IDS = [5715, 5716, 5501, 5502, 1002, 2501, 18107, 80700]

# Softening map: drop the exact tokens feature 2 counts while keeping the event
# human-readable as the same attack. "failed"/"invalid"/"error"/"denied" → words
# the counter ignores. This models an attacker tuning log noise, not changing acts.
_SOFTEN = [
    ("failed password", "password not accepted"),
    ("failed", "unsuccessful"),
    ("invalid user", "unrecognised account"),
    ("invalid", "unrecognised"),
    ("error", "issue"),
    ("denied", "refused"),
    ("brute force", "repeated"),
    ("attack detected", "activity observed"),
]

# Benign-looking filler fields that pad/shrink the data section (feature 11).
_FILLER_FIELDS = {"tty": "pts/1", "protocol": "tcp", "id": "seq-1", "session": "s-1"}

# Data keys an invariant may depend on — never dropped by the data_fields lever.
_PROTECTED_DATA_KEYS = {"srcip", "dstip", "user_id", "CurrentUserID", "url"}


def _set_hour(alert, hour):
    ts = str(alert.get("timestamp", "2025-02-01T03:00:00.000+0000"))
    if "T" in ts:
        date, rest = ts.split("T", 1)
        tail = rest[rest.find(":"):] if ":" in rest else ":00:00.000+0000"
        alert["timestamp"] = f"{date}T{hour:02d}{tail}"
    return alert


# --------------------------------------------------------------------------- #
#  Operators — each returns a NEW (deep-copied) alert with one change.         #
# --------------------------------------------------------------------------- #

def op_hour(alert, rng):
    a = copy.deepcopy(alert)
    return _set_hour(a, rng.choice(BUSINESS_HOURS if rng.random() < 0.8 else ALL_HOURS))


def op_srcip(alert, rng):
    a = copy.deepcopy(alert)
    a.setdefault("data", {})["srcip"] = rng.choice(PUBLIC_ATTACKER_IPS)
    return a


def op_dstip(alert, rng):
    a = copy.deepcopy(alert)
    if "dstip" in a.get("data", {}):
        a["data"]["dstip"] = rng.choice(PUBLIC_ATTACKER_IPS)
    return a


def op_rule_level(alert, rng):
    a = copy.deepcopy(alert)
    a.setdefault("rule", {})["level"] = rng.choice([3, 4, 5, 6, 7, 7, 8])
    return a


def op_rule_meta(alert, rng):
    a = copy.deepcopy(alert)
    rule = a.setdefault("rule", {})
    move = rng.random()
    if move < 0.5:
        rule["id"] = rng.choice(QUIET_RULE_IDS)          # lower-profile rule id
    else:
        groups = list(rule.get("groups", []))
        if len(groups) > 1:
            groups.remove(rng.choice(groups))            # thin suspicious-group count
            rule["groups"] = groups
    return a


def op_log_verbosity(alert, rng):
    a = copy.deepcopy(alert)
    log = str(a.get("full_log", ""))
    low = log.lower()
    # soften harsh keywords (case-insensitively, preserving nothing fancy)
    for harsh, soft in _SOFTEN:
        if harsh in low:
            # replace all case-variants crudely: operate on the lowercased copy
            low = low.replace(harsh, soft)
    if rng.random() < 0.5:
        low = " ".join(low.split()[:12])                 # trim to a terse line
    a["full_log"] = low
    a["message"] = low
    return a


def op_data_fields(alert, rng):
    a = copy.deepcopy(alert)
    data = a.setdefault("data", {})
    if rng.random() < 0.6:
        droppable = [k for k in data if k not in _PROTECTED_DATA_KEYS]
        if droppable:
            data.pop(rng.choice(droppable))
    else:
        k = rng.choice(list(_FILLER_FIELDS))
        data[k] = _FILLER_FIELDS[k]
    return a


_OPERATORS = {
    "hour": op_hour,
    "srcip": op_srcip,
    "dstip": op_dstip,
    "rule_level": op_rule_level,
    "rule_group": op_rule_meta,      # genome name → rule id / group operator
    "log_verbosity": op_log_verbosity,
    "data_fields": op_data_fields,
}


def mutate(alert, genome, rng, n_ops=1):
    """Apply n_ops random applicable operators, returning a new alert."""
    ops = [g for g in genome if g in _OPERATORS]
    if not ops:
        return copy.deepcopy(alert)
    out = alert
    for _ in range(n_ops):
        out = _OPERATORS[rng.choice(ops)](out, rng)
    return out


def max_disguise(alert, genome, rng=None):
    """Deterministically push every applicable lever to its stealthiest setting.

    This is the corner of the search space a competent low-and-slow adversary
    aims for: business-hours timing, minimum severity, a living-off-the-land rule
    id, a single (still-attack) group, a terse log stripped of counted keywords,
    and only the data fields the attack semantically needs. Seeding the population
    here means an evadable family reaches NORMAL on the first generation; the
    search then explores nearby to mine several distinct blind spots.
    """
    a = copy.deepcopy(alert)
    g = set(genome)
    if "hour" in g:
        _set_hour(a, 14)
    if "rule_level" in g:
        a.setdefault("rule", {})["level"] = 3
    if "rule_group" in g:
        rule = a.setdefault("rule", {})
        rule["id"] = QUIET_RULE_IDS[0]
        groups = list(rule.get("groups", []))
        if len(groups) > 1:
            rule["groups"] = groups[:1]          # keep one (still-attack) group
    if "log_verbosity" in g:
        low = str(a.get("full_log", "")).lower()
        for harsh, soft in _SOFTEN:
            low = low.replace(harsh, soft)
        a["full_log"] = " ".join(low.split()[:9])
        a["message"] = a["full_log"]
    if "data_fields" in g:
        data = a.setdefault("data", {})
        for k in [k for k in data if k not in _PROTECTED_DATA_KEYS]:
            data.pop(k, None)
    return a


def saturate(alert, genome, rng):
    """Apply every genome lever once — a fully-disguised variant.

    Evasions that need several levers at once (low-and-slow + living-off-the-land
    + terse logs together) live near this corner of the search space, so we seed
    the population there instead of hoping random 1-2-op mutations stack up before
    the detector's alarm trips.
    """
    ops = [g for g in genome if g in _OPERATORS]
    out = alert
    for g in rng.sample(ops, len(ops)):
        out = _OPERATORS[g](out, rng)
    return out


def evolve(seed, genome, fitness_fn, *, budget, rng,
           pop_size=6, elite=2, hint_fn=None):
    """(μ+λ) search minimising an ensemble score via fitness_fn.

    fitness_fn(alert) -> (score, valid): `score` is the ensemble combined score
    (lower = stealthier, so we minimise it); `valid` is False when the variant
    stopped being an attack (disqualified). Each call spends one budget unit.

    hint_fn(best_alert) -> alert|None : optional strategist (e.g. the LLM) that
    proposes a targeted variant; evaluated like any other candidate when given.

    Returns (best_alert, best_score, evals_used, valid_seen). `best_*` is the
    lowest-scoring VALID variant found (None if the seed itself is invalid).
    """
    evals = 0
    # Seed the population across the disguise spectrum: the stealthiest corner
    # (max_disguise) plus a jittered neighbour, a saturated variant, and a ramp
    # of milder mutations. Evadable families reach NORMAL on generation 1; the
    # rest of the population keeps the search exploring for distinct blind spots.
    population = [
        max_disguise(seed, genome, rng),
        mutate(max_disguise(seed, genome, rng), genome, rng, n_ops=1),
        saturate(seed, genome, rng),
    ]
    while len(population) < pop_size:
        population.append(mutate(seed, genome, rng, n_ops=rng.randint(1, max(2, len(genome)))))

    best_alert, best_score = None, 101.0
    valid_seen = 0

    while evals < budget:
        scored = []
        for cand in population:
            if evals >= budget:
                break
            score, valid = fitness_fn(cand)
            evals += 1
            if valid:
                valid_seen += 1
                scored.append((score, cand))
                if score < best_score:
                    best_score, best_alert = score, cand
        if evals >= budget:
            break
        if not scored:
            # whole generation disqualified — reseed with fresh saturated variants
            population = [saturate(seed, genome, rng) for _ in range(pop_size)]
            continue
        scored.sort(key=lambda t: t[0])
        elites = [c for _, c in scored[:elite]]

        # Next generation: elites + their mutations (+ optional LLM hint)
        nxt = list(elites)
        if hint_fn is not None and best_alert is not None:
            hinted = hint_fn(best_alert)
            if hinted is not None:
                nxt.append(hinted)
        while len(nxt) < pop_size:
            parent = rng.choice(elites)
            nxt.append(mutate(parent, genome, rng, n_ops=rng.randint(1, 2)))
        population = nxt

    return best_alert, best_score, evals, valid_seen
