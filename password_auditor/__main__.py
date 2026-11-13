"""Enable ``python -m password_auditor``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
