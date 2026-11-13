import hashlib

import pytest
import requests

from password_auditor import hibp


class _FakeResponse:
    def __init__(self, text, status=200):
        self.text = text
        self._status = status

    def raise_for_status(self):
        if self._status >= 400:
            raise requests.HTTPError(f"status {self._status}")


def _range_body_for(password, count):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    suffix = digest[5:]
    # Mixed-case suffix plus unrelated rows and a padding (count 0) row.
    return f"0000000000000000000000000000000000A:3\r\n{suffix.lower()}:{count}\r\nFFFF:0\r\n"


def test_counts_a_known_hit(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        assert "User-Agent" in headers  # the 403-avoiding header
        assert headers.get("Add-Padding") == "true"
        return _FakeResponse(_range_body_for("hunter2", 42))

    monkeypatch.setattr(hibp.requests, "get", fake_get)
    assert hibp.pwned_count("hunter2") == 42


def test_miss_returns_zero(monkeypatch):
    monkeypatch.setattr(
        hibp.requests, "get", lambda *a, **k: _FakeResponse("ABCDE:1\r\n12345:2\r\n")
    )
    assert hibp.pwned_count("some-unique-pw") == 0


def test_network_error_raises_hibperror(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(hibp.requests, "get", boom)
    with pytest.raises(hibp.HIBPError):
        hibp.pwned_count("x")


def test_http_403_raises_hibperror(monkeypatch):
    monkeypatch.setattr(
        hibp.requests, "get", lambda *a, **k: _FakeResponse("", status=403)
    )
    with pytest.raises(hibp.HIBPError):
        hibp.pwned_count("x")
