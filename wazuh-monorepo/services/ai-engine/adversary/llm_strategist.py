"""
Optional LLM strategist — the "agent" that reasons about how to evade.

Given the current best-evading alert and which base model is still flagging it
(IF vs AE vs UEBA), the LLM proposes a targeted disguise edit as strict JSON.
It is one more candidate in the evolutionary population, never the only driver:
if Ollama is down, slow, or returns junk, the search runs on the mutation
operators alone. This keeps the demo deterministic and offline-safe while still
letting the LLM steer when it is available.

The LLM only ever adjusts *disguise* levers (timing, verbosity, rule metadata,
data richness). The family invariant + attack oracle are re-checked by the
environment on every candidate, so the LLM cannot "win" by making the event
benign — an invalid suggestion is simply discarded.
"""

import copy
import json
import os
import re

import requests

from .mutator import _set_hour, QUIET_RULE_IDS

_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")

_SYS = (
    "You are a red-team evasion strategist stress-testing a machine-learning "
    "intrusion detector so the blue team can harden it. You are given a JSON "
    "security alert that IS a real attack and its detector scores. Suggest how "
    "to make the SAME attack look routine to the detector WITHOUT changing what "
    "the attack does. You may only adjust: hour (0-23), rule_level (3-8), "
    "rule_id (a quieter Wazuh id), drop_data_fields (list), and rewrite_log (a "
    "terser log line that still describes the same malicious action). Reply with "
    "ONLY a compact JSON object using those keys; omit keys you don't want to "
    "change. No prose."
)


class LLMStrategist:
    def __init__(self, timeout=12):
        self.timeout = timeout
        self.url = f"{_OLLAMA_URL}/api/generate"
        self.enabled = self._ping()

    def _ping(self):
        try:
            r = requests.get(f"{_OLLAMA_URL}/api/tags", timeout=4)
            return r.status_code == 200
        except Exception:
            return False

    def _ask(self, alert, scores):
        prompt = (
            f"{_SYS}\n\nDETECTOR SCORES (0-100, higher = more suspicious): "
            f"{json.dumps(scores)}\nALERT:\n{json.dumps(alert)[:1600]}\n\nJSON:"
        )
        r = requests.post(
            self.url,
            json={"model": _MODEL, "prompt": prompt, "stream": False,
                  "format": "json", "keep_alive": "24h",
                  "options": {"temperature": 0.8, "num_predict": 220}},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json().get("response", "")

    @staticmethod
    def _parse(text):
        try:
            return json.loads(text)
        except Exception:
            m = re.search(r"\{.*\}", text, re.S)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
        return None

    def propose(self, alert, scores):
        """Return a mutated alert from the LLM's suggestion, or None."""
        if not self.enabled:
            return None
        try:
            plan = self._parse(self._ask(alert, scores))
        except Exception:
            self.enabled = False   # stop hammering a dead endpoint this run
            return None
        if not isinstance(plan, dict):
            return None

        a = copy.deepcopy(alert)
        try:
            if isinstance(plan.get("hour"), (int, float)) and 0 <= plan["hour"] <= 23:
                _set_hour(a, int(plan["hour"]))
            lvl = plan.get("rule_level")
            if isinstance(lvl, (int, float)) and 1 <= lvl <= 15:
                a.setdefault("rule", {})["level"] = int(lvl)
            rid = plan.get("rule_id")
            if isinstance(rid, (int, float)):
                a.setdefault("rule", {})["id"] = int(rid)
            elif isinstance(rid, str) and rid.isdigit():
                a.setdefault("rule", {})["id"] = int(rid)
            drop = plan.get("drop_data_fields")
            if isinstance(drop, list):
                data = a.setdefault("data", {})
                for k in drop:
                    if k in data and k not in ("srcip", "dstip", "user_id", "CurrentUserID", "url"):
                        data.pop(k, None)
            rew = plan.get("rewrite_log")
            if isinstance(rew, str) and rew.strip():
                a["full_log"] = rew.strip()[:400]
                a["message"] = a["full_log"]
        except Exception:
            return None
        # Fallback safety: if the model gave an out-of-range id, nudge to a quiet one
        try:
            int(a.get("rule", {}).get("id", 0))
        except Exception:
            a["rule"]["id"] = QUIET_RULE_IDS[0]
        return a
