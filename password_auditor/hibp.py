"""Have I Been Pwned 'Pwned Passwords' range client using k-anonymity.

Only the first 5 hex chars of the SHA-1 hash ever leave this machine; the
plaintext password does not. See https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib

import requests

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# HIBP returns HTTP 403 without a User-Agent, so this header is mandatory.
DEFAULT_USER_AGENT = "password-auditor/2.0 (+https://github.com/Hawkode/PasswordAnalyzer)"
DEFAULT_TIMEOUT = 10.0


class HIBPError(RuntimeError):
    """Raised when the breach lookup cannot be completed."""


def _sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def pwned_count(
    password: str,
    *,
    session: requests.Session | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = DEFAULT_TIMEOUT,
) -> int:
    """Return how many times ``password`` appears in HIBP breach data.

    0 means not found. The count lets callers apply a NIST-style threshold
    ("reject if seen more than N times") instead of a bare boolean.

    Raises HIBPError on any network or HTTP failure, so a failed check is never
    silently reported as "safe".
    """
    digest = _sha1_upper(password)
    prefix, suffix = digest[:5], digest[5:]

    headers = {
        "User-Agent": user_agent,
        # Pads the response with fake count-0 rows so an on-wire observer
        # cannot infer the real range size.
        "Add-Padding": "true",
    }

    getter = session.get if session is not None else requests.get
    try:
        response = getter(
            RANGE_URL.format(prefix=prefix), headers=headers, timeout=timeout
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HIBPError(f"HIBP lookup failed: {exc}") from exc

    for line in response.text.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            try:
                return int(count)
            except ValueError as exc:
                raise HIBPError(f"Malformed HIBP response line: {line!r}") from exc
    return 0


def is_pwned(password: str, *, min_count: int = 1, **kwargs) -> bool:
    """True if the password has been seen at least ``min_count`` times."""
    return pwned_count(password, **kwargs) >= min_count
