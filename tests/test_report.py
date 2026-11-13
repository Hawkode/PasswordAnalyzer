import json

from password_auditor.audit import AuditResult, Verdict
from password_auditor.report import render, write_report


def _sample():
    return [
        AuditResult(
            label="p****d (len 8)",
            length=8,
            entropy_bits=37.6,
            score=1,
            score_label="Weak",
            verdict=Verdict.COMPROMISED,
            breach_count=12345,
            breach_checked=True,
            findings=["Seen 12,345 times in breach corpora; do not use."],
        )
    ]


def test_text_render_contains_verdict():
    out = render(_sample(), "text")
    assert "COMPROMISED" in out
    assert "p****d" in out


def test_json_render_is_valid():
    data = json.loads(render(_sample(), "json"))
    assert data[0]["verdict"] == "COMPROMISED"
    assert data[0]["breach_count"] == 12345


def test_csv_has_header():
    out = render(_sample(), "csv")
    assert out.splitlines()[0].startswith("label,verdict,length")


def test_write_report_roundtrip(tmp_path):
    path = tmp_path / "report.json"
    write_report(_sample(), str(path), "json")
    data = json.loads(path.read_text())
    assert data[0]["verdict"] == "COMPROMISED"
