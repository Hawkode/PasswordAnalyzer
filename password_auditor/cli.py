"""Command-line interface for the password auditor.

Exit codes (useful in scripts / CI):
  0  every password audited is STRONG or FAIR and not breached
  1  at least one password is WEAK or COMPROMISED
  2  usage / input error
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Sequence

from . import __version__
from .audit import Verdict, audit_many
from .report import render, write_report
from .strength import HAS_ZXCVBN

_FAIL_VERDICTS = {Verdict.WEAK, Verdict.COMPROMISED}


def _read_passwords(args: argparse.Namespace) -> list[str]:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            pwds = [line.rstrip("\n") for line in f if line.strip()]
        if not pwds:
            raise SystemExit(f"No passwords found in {args.file}")
        return pwds
    if args.password is not None:
        return [args.password]
    # Interactive: getpass does not echo, so the secret stays off-screen.
    pw = getpass.getpass("Enter a password to audit: ")
    return [pw]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="password-auditor",
        description="Audit password strength: entropy, HIBP breach check, pattern rating.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--password", help="Password to audit (omit for a hidden prompt).")
    src.add_argument("--file", help="Path to a file with one password per line.")

    p.add_argument(
        "--format",
        choices=("text", "json", "csv"),
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument("--save", metavar="PATH", help="Write the report to PATH (0600 on POSIX).")
    p.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip the HIBP lookup (fully offline).",
    )
    p.add_argument(
        "--min-count",
        type=int,
        default=1,
        help="Treat as compromised at this breach count or higher (default: 1).",
    )
    p.add_argument(
        "--show-passwords",
        action="store_true",
        help="Include plaintext in output instead of masking it.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        passwords = _read_passwords(args)
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    results = audit_many(
        passwords,
        check_breach=not args.no_breach_check,
        min_count=args.min_count,
        reveal=args.show_passwords,
    )

    output = render(results, args.format)
    print(output)

    if args.save:
        try:
            write_report(results, args.save, args.format)
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 2
        print(f"\nReport saved to {args.save}", file=sys.stderr)

    if not HAS_ZXCVBN:
        print(
            "\nNote: zxcvbn not installed; using the built-in pattern heuristic. "
            "Install it (pip install -r requirements.txt) for stronger ratings.",
            file=sys.stderr,
        )

    failed = any(r.verdict in _FAIL_VERDICTS for r in results)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
