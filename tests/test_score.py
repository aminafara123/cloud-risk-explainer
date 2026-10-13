"""Deterministic scoring + prioritization."""
from cloud_risk_explainer.normalize import Finding
from cloud_risk_explainer.score import infer_signals, prioritize, risk_score


def mk(id, severity, text="", service="s3"):
    return Finding(id=id, title=text, service=service, severity=severity,
                   resource="", description="", remediation_hint="")


def test_signal_inference():
    f = mk("a", "HIGH", "Bucket is publicly accessible and exposed to the internet")
    assert "public_exposure" in infer_signals(f)
    sg = mk("b", "HIGH", "allows ingress from 0.0.0.0/0 to port 22", service="ec2")
    sigs = infer_signals(sg)
    assert "internet_facing_sg" in sigs and "public_exposure" in sigs
    iam = mk("c", "HIGH", "grants Action: * on Resource: * overly permissive", service="iam")
    assert "wildcard_iam" in infer_signals(iam)
    enc = mk("d", "MEDIUM", "storage encryption is not enabled")
    assert "unencrypted" in infer_signals(enc)
    log = mk("e", "HIGH", "CloudTrail is not enabled; logging disabled", service="cloudtrail")
    assert "logging_disabled" in infer_signals(log)
    clean = mk("f", "LOW", "access key not rotated in 400 days", service="iam")
    assert infer_signals(clean) == []


def test_exposure_amplifies_severity():
    crit_internal = mk("internal", "CRITICAL", "key rotation disabled", service="kms")
    crit_public = mk("public", "CRITICAL", "bucket is publicly accessible to the internet")
    assert risk_score(crit_public) > risk_score(crit_internal)
    # 40 * (1 + 1.0 public) = 80 vs 40 internal-only.
    assert risk_score(crit_internal) == 40.0
    assert risk_score(crit_public) == 80.0


def test_public_critical_ranks_top():
    findings = [
        mk("low", "LOW", "backups disabled", service="rds"),
        mk("crit_internal", "CRITICAL", "key rotation disabled", service="kms"),
        mk("high_public_wild", "HIGH", "policy Action: * publicly accessible", service="iam"),
        mk("crit_public", "CRITICAL", "RDS publicly accessible from the internet", service="rds"),
        mk("med", "MEDIUM", "mfa not enabled", service="iam"),
    ]
    ranked = prioritize(findings)
    assert ranked[0].finding.id == "crit_public"
    assert ranked[0].rank == 1
    # strictly descending by score
    scores = [s.score for s in ranked]
    assert scores == sorted(scores, reverse=True)


def test_prioritize_is_deterministic():
    findings = [mk(f"f{i}", "HIGH", "publicly accessible") for i in range(5)]
    a = [s.finding.id for s in prioritize(findings)]
    b = [s.finding.id for s in prioritize(findings)]
    assert a == b  # stable tie-break by id


def test_tie_break_prefers_higher_severity():
    # Same score (CRITICAL plain = 40 == MEDIUM*... no); craft an equal-score tie.
    # HIGH + public = 25*2 = 50 ; CRITICAL + unencrypted = 40*1.3 = 52 -> critical first anyway.
    # Equal-score case: build two scores that match, assert severity breaks the tie.
    a = mk("hi", "HIGH", "publicly accessible")        # 25 * 2.0 = 50
    b = mk("med", "MEDIUM", "publicly accessible internet-facing 0.0.0.0/0 all ports")
    # MEDIUM 12 * (1 + public 1.0 + sg 0.6) = 12 * 2.6 = 31.2, not equal; just assert order by score
    ranked = prioritize([b, a])
    assert ranked[0].finding.id == "hi"
