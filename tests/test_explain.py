"""Narrative generation: mocked LLM happy path + offline graceful degradation.

No network is ever touched: llm.complete is monkeypatched.
"""
from cloud_risk_explainer import explain, llm
from cloud_risk_explainer.normalize import Finding
from cloud_risk_explainer.score import prioritize


def _scored():
    return prioritize([
        Finding("c1", "Public RDS", "rds", "CRITICAL", "arn:db", "publicly accessible", "disable public"),
        Finding("h1", "Wildcard IAM", "iam", "HIGH", "arn:pol", "Action: * overly permissive", "scope it"),
        Finding("m1", "KMS rotation off", "kms", "MEDIUM", "arn:key", "rotation disabled", "enable rotation"),
    ])


def test_narrative_happy_path(monkeypatch):
    calls = {"n": 0}

    def fake_complete(prompt, system=None, **kw):
        calls["n"] += 1
        if "executive summary" in prompt.lower():
            return "This is the executive summary."
        return "WHY: It is bad.\nSTEPS:\n1) Fix it\n2) Verify"

    monkeypatch.setattr(llm, "complete", fake_complete)
    out = explain.generate_narrative(_scored(), use_llm=True)
    assert out["llm_available"] is True
    assert out["executive_summary"] == "This is the executive summary."
    # only CRITICAL + HIGH get per-finding narrative (not the MEDIUM)
    assert set(out["per_finding"]) == {"c1", "h1"}
    assert out["per_finding"]["c1"]["why"] == "It is bad."
    assert "Fix it" in out["per_finding"]["c1"]["steps"]
    # 1 summary call + 2 per-finding calls
    assert calls["n"] == 3


def test_degrades_when_llm_unreachable(monkeypatch):
    def boom(*a, **k):
        raise llm.LLMError("connection refused")

    monkeypatch.setattr(llm, "complete", boom)
    out = explain.generate_narrative(_scored(), use_llm=True)
    assert out["llm_available"] is False
    assert "fallback" in out["executive_summary"].lower()
    # fallback still provides per-finding content from the finding's own fields
    assert out["per_finding"]["c1"]["steps"] == "disable public"


def test_no_llm_flag_skips_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("llm.complete must not be called with use_llm=False")

    monkeypatch.setattr(llm, "complete", boom)
    out = explain.generate_narrative(_scored(), use_llm=False)
    assert out["llm_available"] is False
    assert out["per_finding"]["h1"]["why"]
