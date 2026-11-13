"""Orchestration: run entropy, breach check and strength rating for a password."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Iterable

from . import entropy as _entropy
from . import hibp as _hibp
from . import strength as _strength


class Verdict(str, enum.Enum):
    COMPROMISED = "COMPROMISED"  # found in a breach corpus
    WEAK = "WEAK"
    FAIR = "FAIR"
    STRONG = "STRONG"


# Maps zxcvbn-style 0-4 score to a verdict when the password is not breached.
_SCORE_TO_VERDICT = {
    0: Verdict.WEAK,
    1: Verdict.WEAK,
    2: Verdict.FAIR,
    3: Verdict.STRONG,
    4: Verdict.STRONG,
}


def mask(password: str) -> str:
    """Redacted label for reports: keeps length, hides the secret."""
    n = len(password)
    if n == 0:
        return "(empty)"
    if n <= 2:
        return "*" * n
    return f"{password[0]}{'*' * (n - 2)}{password[-1]} (len {n})"


@dataclass
class AuditResult:
    label: str  # masked password, or plaintext if caller opts in
    length: int
    entropy_bits: float
    score: int
    score_label: str
    verdict: Verdict
    breach_count: int | None  # None = check skipped or failed
    breach_checked: bool
    findings: list[str] = field(default_factory=list)
    error: str | None = None  # set when the breach check raised

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


def audit_password(
    password: str,
    *,
    check_breach: bool = True,
    min_count: int = 1,
    reveal: bool = False,
    session=None,
) -> AuditResult:
    """Audit one password. Never raises for breach failures; records them."""
    length = len(password)
    bits = _entropy.calculate_entropy(password)
    score, score_label, findings = _strength.rate(password, bits)

    breach_count: int | None = None
    breach_error: str | None = None
    if check_breach:
        try:
            breach_count = _hibp.pwned_count(password, session=session)
        except _hibp.HIBPError as exc:
            breach_error = str(exc)

    if breach_count is not None and breach_count >= min_count:
        verdict = Verdict.COMPROMISED
        findings = [
            f"Seen {breach_count:,} times in breach corpora; do not use.",
            *findings,
        ]
    else:
        verdict = _SCORE_TO_VERDICT[max(0, min(4, score))]

    return AuditResult(
        label=password if reveal else mask(password),
        length=length,
        entropy_bits=bits,
        score=score,
        score_label=score_label,
        verdict=verdict,
        breach_count=breach_count,
        breach_checked=check_breach and breach_error is None,
        findings=findings,
        error=breach_error,
    )


def audit_many(
    passwords: Iterable[str],
    *,
    check_breach: bool = True,
    min_count: int = 1,
    reveal: bool = False,
    session=None,
) -> list[AuditResult]:
    """Audit a batch, reusing one HTTP session for the breach checks."""
    import requests

    owns_session = session is None and check_breach
    if owns_session:
        session = requests.Session()
    try:
        return [
            audit_password(
                pw,
                check_breach=check_breach,
                min_count=min_count,
                reveal=reveal,
                session=session,
            )
            for pw in passwords
        ]
    finally:
        if owns_session:
            session.close()
