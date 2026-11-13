# Testing

The suite is pytest-based and runs fully offline — the HIBP client is mocked,
so no real network calls are made.

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

Expected: all tests pass. Add `-v` for per-test output or `-q` for quiet.

## What is covered

| File | Covers |
|------|--------|
| `tests/test_entropy.py` | Pool sizing per character class; the underscore regression; empty and non-ASCII input. |
| `tests/test_hibp.py` | User-Agent and `Add-Padding` headers are sent; a known hit returns its count; a miss returns 0; network errors and HTTP 403 raise `HIBPError`. |
| `tests/test_audit.py` | Breached passwords → `COMPROMISED`; `--min-count` threshold; breach failures recorded (not raised); masking; the `--show-passwords` path. |
| `tests/test_report.py` | text / JSON / CSV rendering and the file-write round trip. |

## Manual smoke test (hits the live API)

A known-breached password should come back `COMPROMISED` with a large count:

```bash
python -m password_auditor --password 'password'
```

A long random passphrase should come back `STRONG` and not found:

```bash
python -m password_auditor --password "$(head -c 24 /dev/urandom | base64)"
```

On Windows PowerShell, substitute any long random string for the `/dev/urandom`
line.
