"""Password auditor: entropy, breach check (HIBP k-anonymity) and strength rating."""

from .audit import AuditResult, Verdict, audit_password, audit_many
from .entropy import calculate_entropy
from .hibp import HIBPError, pwned_count

__all__ = [
    "AuditResult",
    "Verdict",
    "audit_password",
    "audit_many",
    "calculate_entropy",
    "pwned_count",
    "HIBPError",
]

__version__ = "2.0.0"
