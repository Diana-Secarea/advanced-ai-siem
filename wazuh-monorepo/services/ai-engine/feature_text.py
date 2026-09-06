"""Text measurements shared by every alert feature extractor.

Kept in one module because the Isolation Forest and the autoencoder each build
the same 16-feature vector independently: a tokenisation that only one of them
agrees with is worse than no fix at all, since the stacker would then be
combining two models that disagree about what the input means.
"""

import json

WORD_COUNT_CAP = 60


def _json_tokens(node):
    """Whitespace tokens across a decoded JSON document's keys and scalars.

    Keys are counted alongside values because the prose logs this feature was
    calibrated on carry their field names inline too — a syslog line reads
    ``USER=root TTY=pts/0``, so the schema is part of what the model learned to
    see as message complexity. Counting values alone would make the same event
    look about half as complex as its syslog equivalent.
    """
    if isinstance(node, dict):
        n = 0
        for key, value in node.items():
            n += len(str(key).split()) + _json_tokens(value)
        return n
    if isinstance(node, (list, tuple)):
        return sum(_json_tokens(v) for v in node)
    if node is None or isinstance(node, bool):
        return 1
    return len(str(node).split()) or 1


def message_word_count(message, cap=WORD_COUNT_CAP):
    """Feature 0: message complexity, in tokens, capped.

    Whitespace splitting alone is blind to structured logs. Wazuh re-serialises
    a ``json`` <localfile> line compactly before storing it in ``full_log``
    (``{"a":1,"b":2}`` — no spaces), so ``.split()`` returns ONE token for an
    event carrying a dozen fields. Nothing in a corpus of syslog prose looks
    like that, so the autoencoder cannot reconstruct it and pins at 100: every
    structured event reads as CRITICAL regardless of content. The backend's own
    audit log was the first json source to hit this, but it applies to any of
    them.

    Falling back to the whitespace count whenever the payload is not JSON keeps
    this a strict no-op for every prose log, which is what lets the fix land
    without retraining the models that were calibrated on them.
    """
    text = message if isinstance(message, str) else str(message)
    # Cheap gate first: only strings that could be a JSON document are parsed,
    # so the common prose path costs one character comparison.
    head = text.lstrip()[:1]
    if head in ("{", "["):
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            pass                      # not JSON after all — prose path below
        else:
            tokens = _json_tokens(doc)
            if tokens:
                return min(tokens, cap)
    return min(len(text.split()), cap)
