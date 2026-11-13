"""Charset-pool entropy estimate.

This is a *ceiling*: it assumes every character was chosen at random from the
detected pool. Real passwords rarely are, so entropy alone over-rates things
like ``P@ssw0rd1``. The breach check and pattern scorer exist to catch that.
"""

from __future__ import annotations

import math
import string

# Explicit pools, so the sizes are auditable rather than hidden behind \w/\W.
_POOLS: tuple[tuple[frozenset[str], int], ...] = (
    (frozenset(string.ascii_lowercase), 26),
    (frozenset(string.ascii_uppercase), 26),
    (frozenset(string.digits), 10),
    (frozenset(" "), 1),
    # Printable ASCII punctuation (33 symbols). Underscore lives here, so the
    # old "\W misses _" gap is closed.
    (frozenset(string.punctuation), len(string.punctuation)),
)


def pool_size(password: str) -> int:
    """Sum the sizes of every character pool the password draws from."""
    size = 0
    for members, weight in _POOLS:
        if any(ch in members for ch in password):
            size += weight
    # Anything outside printable ASCII (accented, unicode) adds a conservative
    # bump so such characters are never scored as zero.
    if any(ch not in string.printable for ch in password):
        size += 100
    return size


def calculate_entropy(password: str) -> float:
    """Return estimated entropy in bits, rounded to 2 dp."""
    if not password:
        return 0.0
    size = pool_size(password)
    if size <= 0:
        return 0.0
    return round(len(password) * math.log2(size), 2)
