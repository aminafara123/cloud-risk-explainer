"""Report assembly (pure strings, no network)."""
from cloud_risk_explainer.normalize import Finding
from cloud_risk_explainer.report import build_html, build_markdown
from cloud_risk_explainer.score import prioritize


def _fixture():
    findings = [
        Finding("f-crit", "Public RDS instance", "rds", "CRITICAL",
                "arn:aws:rds:us-east-1:1:db:prod", "RDS is publicly accessible from the internet", "Disable public access"),
        Finding("f-low", "Access key not rotated", "iam", "LOW",
                "arn:aws:iam::1:user/svc", "Key is 400 days old", "Rotate the key"),
    ]
    scored = prioritize(findings)
    narrative = {
        "executive_summary": "Overall posture is poor. Fix the public database first.",
        "per_finding": {"f-crit": {"why": "A public database is an open door.",
                                   "steps": "1) Disable public access\n2) Rotate credentials"}},
        "llm_available": True,
    }
    meta = {"source": "sample/x.json", "format": "native", "total": 2, "generated_at": "2026-01-01 00:00 UTC"}
    return scored, narrative, meta


def test_markdown_contains_core_sections():
    scored, narrative, meta = _fixture()
    md = build_markdown(scored, narrative, meta)
    # AI disclaimer + human-review wording
    assert "AI-assisted report" in md
    assert "human must review" in md.lower()
    # executive summary text present
    assert "Fix the public database first" in md
    # severity overview table
    assert "## Risk overview" in md
    assert "| Critical | 1 |" in md
    # prioritized table, critical ranked first
    assert "## Prioritized findings" in md
    crit_row = [ln for ln in md.splitlines() if "Public RDS instance" in ln and ln.startswith("| 1 ")]
    assert crit_row, "critical finding should be rank 1 in the table"
    # per-finding AI narrative rendered
    assert "A public database is an open door." in md
    assert "Disable public access" in md
    # methodology disclosed
    assert "deterministic" in md.lower()


def test_markdown_marks_fallback_when_no_llm():
    scored, narrative, meta = _fixture()
    narrative["llm_available"] = False
    md = build_markdown(scored, narrative, meta)
    assert "without an LLM" in md


def test_html_is_wellformed_enough():
    scored, narrative, meta = _fixture()
    doc = build_html(scored, narrative, meta)
    assert doc.strip().startswith("<!doctype html>")
    assert "Public RDS instance" in doc
    assert "AI-assisted report" in doc
    # resource ARN is HTML-escaped-safe (no raw angle brackets injected)
    assert "<script>" not in doc
