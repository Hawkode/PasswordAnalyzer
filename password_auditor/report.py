"""Render audit results as text, JSON or CSV, and write them out safely."""

from __future__ import annotations

import csv
import io
import json
import os
import stat
from typing import Sequence

from .audit import AuditResult

_VERDICT_MARK = {
    "COMPROMISED": "[!!]",
    "WEAK": "[! ]",
    "FAIR": "[~ ]",
    "STRONG": "[ok]",
}


def _one_text(r: AuditResult) -> str:
    lines = [
        f"{_VERDICT_MARK.get(r.verdict.value, '[??]')} {r.label}",
        f"     Verdict : {r.verdict.value}",
        f"     Length  : {r.length}",
        f"     Entropy : {r.entropy_bits} bits (ceiling estimate)",
        f"     Strength: {r.score}/4 ({r.score_label})",
    ]
    if not r.breach_checked:
        reason = r.error or "skipped"
        lines.append(f"     Breach  : not checked ({reason})")
    elif r.breach_count:
        lines.append(f"     Breach  : seen {r.breach_count:,} times")
    else:
        lines.append("     Breach  : not found in HIBP corpus")
    for f in r.findings:
        lines.append(f"       - {f}")
    return "\n".join(lines)


def render_text(results: Sequence[AuditResult]) -> str:
    header = "Password Security Audit\n" + "=" * 23
    return header + "\n\n" + "\n\n".join(_one_text(r) for r in results) + "\n"


def render_json(results: Sequence[AuditResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


def render_csv(results: Sequence[AuditResult]) -> str:
    buf = io.StringIO()
    fields = [
        "label",
        "verdict",
        "length",
        "entropy_bits",
        "score",
        "score_label",
        "breach_count",
        "breach_checked",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        row = r.to_dict()
        writer.writerow({k: row.get(k) for k in fields})
    return buf.getvalue()


_RENDERERS = {"text": render_text, "json": render_json, "csv": render_csv}


def render(results: Sequence[AuditResult], fmt: str = "text") -> str:
    try:
        return _RENDERERS[fmt](results)
    except KeyError:
        raise ValueError(f"Unknown format: {fmt!r}. Use one of {sorted(_RENDERERS)}.")


def write_report(results: Sequence[AuditResult], path: str, fmt: str = "text") -> None:
    """Write the report, then restrict permissions to owner-only where supported.

    On POSIX this becomes 0600. On Windows os.chmod only toggles the read-only
    bit, so the call is best-effort and never fatal.
    """
    content = render(results, fmt)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 on POSIX
    except (OSError, NotImplementedError):
        pass
