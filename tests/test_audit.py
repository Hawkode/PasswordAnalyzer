from password_auditor import audit
from password_auditor.audit import Verdict, audit_password, mask


def test_mask_hides_secret_keeps_length():
    m = mask("Sup3rSecret!")
    assert "Sup3rSecret!" not in m
    assert "len 12" in m


def test_breached_password_is_compromised(monkeypatch):
    monkeypatch.setattr(audit._hibp, "pwned_count", lambda *a, **k: 5000)
    r = audit_password("password", check_breach=True)
    assert r.verdict is Verdict.COMPROMISED
    assert r.breach_count == 5000
    assert any("5,000" in f for f in r.findings)


def test_min_count_threshold(monkeypatch):
    monkeypatch.setattr(audit._hibp, "pwned_count", lambda *a, **k: 3)
    # Below threshold: not flagged as compromised on the breach axis.
    r = audit_password("whatever", check_breach=True, min_count=10)
    assert r.verdict is not Verdict.COMPROMISED


def test_breach_failure_is_recorded_not_raised(monkeypatch):
    def boom(*a, **k):
        raise audit._hibp.HIBPError("offline")

    monkeypatch.setattr(audit._hibp, "pwned_count", boom)
    r = audit_password("anything", check_breach=True)
    assert r.breach_checked is False
    assert r.breach_count is None
    assert r.error == "offline"


def test_strong_passphrase_when_not_breached(monkeypatch):
    monkeypatch.setattr(audit._hibp, "pwned_count", lambda *a, **k: 0)
    r = audit_password("correct-horse-battery-staple-9x!", check_breach=True)
    assert r.verdict in {Verdict.FAIR, Verdict.STRONG}


def test_reveal_flag_includes_plaintext(monkeypatch):
    monkeypatch.setattr(audit._hibp, "pwned_count", lambda *a, **k: 0)
    r = audit_password("Hunter2!xyz", check_breach=True, reveal=True)
    assert r.label == "Hunter2!xyz"
