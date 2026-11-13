"""Strength rating.

Uses zxcvbn when it is installed (it models dictionary words, l33t-speak,
repeats and keyboard walks). Falls back to a pattern-aware heuristic so the
tool works with only the standard library plus requests.
"""

from __future__ import annotations

import re
import string

try:  # optional dependency
    from zxcvbn import zxcvbn as _zxcvbn
except ImportError:  # pragma: no cover - exercised only when zxcvbn absent
    _zxcvbn = None

HAS_ZXCVBN = _zxcvbn is not None

# Score scale 0-4 to match zxcvbn, so both paths speak the same language.
_LABELS = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong"}

_KEYBOARD_RUNS = ("qwerty", "asdf", "zxcv", "1234", "qazwsx", "1qaz", "password")


def label(score: int) -> str:
    return _LABELS.get(max(0, min(4, score)), "Unknown")


def _has_sequential_run(password: str, length: int = 4) -> bool:
    """Detect runs like 'abcd' or '4321' of the given length."""
    lowered = password.lower()
    for i in range(len(lowered) - length + 1):
        window = lowered[i : i + length]
        if not window.isalnum():
            continue
        codes = [ord(c) for c in window]
        ascending = all(b - a == 1 for a, b in zip(codes, codes[1:]))
        descending = all(a - b == 1 for a, b in zip(codes, codes[1:]))
        if ascending or descending:
            return True
    return False


def _heuristic_findings(password: str) -> list[str]:
    findings: list[str] = []
    lowered = password.lower()
    if len(password) < 12:
        findings.append("Shorter than 12 characters.")
    classes = sum(
        bool(set(password) & set(group))
        for group in (
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            string.punctuation,
        )
    )
    if classes < 3:
        findings.append("Uses fewer than 3 character classes.")
    if re.search(r"(.)\1{2,}", password):
        findings.append("Contains a character repeated 3+ times in a row.")
    if _has_sequential_run(password):
        findings.append("Contains a sequential run (e.g. abcd / 1234).")
    if any(run in lowered for run in _KEYBOARD_RUNS):
        findings.append("Contains a common keyboard pattern or dictionary word.")
    return findings


def rate(password: str, entropy_bits: float) -> tuple[int, str, list[str]]:
    """Return (score 0-4, label, findings).

    Findings are human-readable reasons the password lost points.
    """
    if _zxcvbn is not None:
        result = _zxcvbn(password)
        score = int(result["score"])
        feedback = result.get("feedback", {})
        findings = list(feedback.get("suggestions", []))
        warning = feedback.get("warning")
        if warning:
            findings.insert(0, warning)
        return score, label(score), findings

    # Fallback: start from entropy bands, then dock points for patterns.
    if entropy_bits < 28:
        score = 0
    elif entropy_bits < 40:
        score = 1
    elif entropy_bits < 60:
        score = 2
    elif entropy_bits < 80:
        score = 3
    else:
        score = 4

    findings = _heuristic_findings(password)
    # Each structural weakness knocks the score down, floored at 0.
    score = max(0, score - max(0, len(findings) - 1))
    if len(password) < 8:
        score = min(score, 1)
    return score, label(score), findings
