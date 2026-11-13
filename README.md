# Password Auditor

A command-line password auditor. It rates password strength from three angles
and prints a clear verdict:

- **Entropy**: a charset-pool estimate (a ceiling, not the whole story).
- **Breach check**: looks the password up in [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
  using the k-anonymity range API. Only the first 5 characters of the SHA-1
  hash ever leave your machine; the password itself does not.
- **Strength rating**: [zxcvbn](https://github.com/dropbox/zxcvbn) when installed
  (dictionary words, l33t-speak, keyboard walks), with a built-in pattern
  heuristic as a fallback.

This replaces the earlier version, which wrapped `john`/`hashcat`. Cracking is
out of scope now; this is an auditor. It is pure Python and runs on Windows,
macOS and Linux, no Kali or wordlists required.

## Install

Python 3.10+.

```bash
git clone https://github.com/Hawkode/PasswordAnalyzer.git
cd PasswordAnalyzer
pip install -r requirements.txt
```

`requests` is the only hard dependency. `zxcvbn` is optional; without it the
tool uses its fallback scorer and tells you so.

## Usage

Run as a module (recommended) or via the compatibility shim
`python password_analyzer.py ...`.

**Audit one password (hidden prompt, nothing echoed):**

```bash
python -m password_auditor
```

**Audit one password inline:**

```bash
python -m password_auditor --password 'Tr0ub4dour&3'
```

**Audit a file, one password per line:**

```bash
python -m password_auditor --file passwords.txt
```

**JSON or CSV output, saved to a file:**

```bash
python -m password_auditor --file passwords.txt --format json --save audit.json
```

**Offline (skip the breach lookup):**

```bash
python -m password_auditor --password 'example' --no-breach-check
```

### Options

| Flag | Purpose |
|------|---------|
| `--password PW` | Audit a single password. Omit it (and `--file`) for a hidden prompt. |
| `--file PATH` | Audit every non-blank line of a file. |
| `--format {text,json,csv}` | Output format. Default `text`. |
| `--save PATH` | Write the report to a file (set to `0600` on POSIX). |
| `--no-breach-check` | Skip the HIBP lookup and run fully offline. |
| `--min-count N` | Flag as compromised only at N breach sightings or more. Default `1`. |
| `--show-passwords` | Print plaintext instead of masking it. Off by default. |

### Exit codes

Scriptable, so you can gate a pipeline on it:

- `0`: everything audited is FAIR or STRONG and not breached.
- `1`: at least one password is WEAK or COMPROMISED.
- `2`: usage or input error.

## Privacy and handling

- The plaintext password never leaves the machine. Only a 5-character SHA-1
  prefix is sent to HIBP, and the `Add-Padding` header masks the response size.
- Interactive input uses `getpass`, so the password is not echoed or left in
  shell history.
- Reports mask passwords by default and are written owner-only on POSIX.
  `.gitignore` excludes report files and `test_passwords.txt` so secrets are
  not committed.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

The breach-check tests mock the network, so the suite runs offline. See
[TESTING.md](TESTING.md).

## License

MIT.
