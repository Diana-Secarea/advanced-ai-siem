"""LLM relevance scorer — the single bounded reasoning step in the pipeline.

Asks the local Ollama model (llama3.2) to score a CVE 0-10 against the
deployment profile and return JSON {score, reasoning}. Uses the same
OpenAI-compatible endpoint the Flask server uses.
"""
import json
import re

import requests

from scheduled_agent import config


_SYSTEM = (
    "You are a security analyst triaging CVEs for a specific environment. "
    "Respond with ONLY a JSON object: {\"score\": <int 0-10>, "
    "\"reasoning\": \"<one sentence>\"}. No other text."
)


def _build_prompt(cve: dict) -> str:
    products = ", ".join(cve.get("products", [])) or "unknown"
    cvss = cve.get("cvss")
    return (
        f"{config.ENV_CONTEXT}\n\n"
        f"CVE: {cve['cve_id']}\n"
        f"Vendor: {cve.get('vendor') or 'unknown'}\n"
        f"Affected product(s): {products}\n"
        f"CVSS base score: {cvss if cvss is not None else 'unknown'}\n"
        f"Description: {cve.get('description', '')[:1200]}\n\n"
        f"Score this CVE's relevance to the environment above."
    )


def _parse(text: str) -> tuple:
    """Extract (score, reasoning) from the model output, robust to extra text."""
    # Try strict JSON first
    try:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            obj = json.loads(m.group(0))
            score = int(round(float(obj.get("score"))))
            reason = str(obj.get("reasoning", "")).strip()
            return (max(0, min(10, score)), reason)
    except (ValueError, TypeError, json.JSONDecodeError):
        pass
    # Fallback: first integer 0-10 in the text
    m = re.search(r"\b(10|[0-9])\b", text)
    score = int(m.group(1)) if m else 0
    return (score, text.strip()[:300])


def score_relevance(cve: dict) -> tuple:
    """Return (base_score 0-10, reasoning). On LLM failure returns a
    conservative mid score so the CVE lands in the review queue rather than
    being silently dropped."""
    url = f"{config.OLLAMA_URL}/v1/chat/completions"
    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user",   "content": _build_prompt(cve)},
        ],
        "temperature": 0,
        "stream": False,
    }
    try:
        resp = requests.post(url, json=payload, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return _parse(content)
    except Exception as e:
        print(f"  [scorer] LLM call failed for {cve['cve_id']} "
              f"(non-fatal, routing to review queue): {e}")
        # Conservative: 5 -> lands in the 4-6 review band, never auto-dropped
        return (5, f"LLM unavailable; defaulted to review queue ({e})")
