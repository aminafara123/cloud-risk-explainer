"""Importers: Prowler + ASFF + native -> the one normalized schema."""
import os

from cloud_risk_explainer.normalize import (
    Finding, detect_format, from_asff, from_prowler, load_findings, norm_severity, norm_service,
)

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample")
FIELDS = {"id", "title", "service", "severity", "resource", "description", "remediation_hint"}
CANON_SEV = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


def _all_normalized(findings):
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, Finding)
        assert set(f.to_dict()) == FIELDS
        assert f.severity in CANON_SEV
        assert f.service == f.service.lower()
        assert f.id and f.title


def test_prowler_import_and_detect():
    path = os.path.join(SAMPLE, "prowler_findings.json")
    assert detect_format(__import__("json").load(open(path))) == "prowler"
    findings = load_findings(path)
    _all_normalized(findings)
    # The one PASS record must be filtered out (17 records -> 16 actionable).
    assert len(findings) == 16
    ids = {f.id for f in findings}
    assert "s3_bucket_object_versioning" not in ids  # the PASS finding
    pub = next(f for f in findings if f.id == "s3_bucket_public_access")
    assert pub.service == "s3"
    assert pub.severity == "CRITICAL"
    assert pub.resource == "arn:aws:s3:::customer-exports"
    assert pub.remediation_hint  # pulled from Remediation.Recommendation.Text


def test_asff_import_and_detect():
    path = os.path.join(SAMPLE, "asff_findings.json")
    import json
    with open(path) as fh:
        data = json.load(fh)
    assert detect_format(data) == "asff"
    findings = load_findings(path)
    _all_normalized(findings)
    # 13 findings, one Compliance PASSED -> 12 actionable.
    assert len(findings) == 12
    rds = next(f for f in findings if "payments-db" in f.resource)
    assert rds.service == "rds"         # derived from AwsRdsDbInstance resource type
    assert rds.severity == "CRITICAL"   # derived from Severity.Label


def test_asff_service_from_arn_fallback():
    # AwsEc2Volume is not in the type map; service falls back to the ARN segment.
    findings = from_asff([{
        "Id": "x", "Title": "t", "Severity": {"Label": "LOW"},
        "Resources": [{"Type": "AwsEc2Volume", "Id": "arn:aws:ec2:us-east-1:1:volume/vol-1"}],
    }])
    assert findings[0].service == "ec2"


def test_native_round_trips():
    findings = load_findings(os.path.join(SAMPLE, "native_findings.json"))
    _all_normalized(findings)
    assert len(findings) == 4


def test_severity_normalization():
    assert norm_severity("critical") == "CRITICAL"
    assert norm_severity("Info") == "INFORMATIONAL"
    assert norm_severity({"Label": "HIGH"}) == "HIGH"
    assert norm_severity({"Normalized": 95}) == "CRITICAL"
    assert norm_severity(10) == "LOW"
    assert norm_severity("nonsense") == "MEDIUM"


def test_service_normalization():
    assert norm_service("AwsS3Bucket") == "s3"
    assert norm_service("S3") == "s3"
    assert norm_service(None) == "unknown"


def test_prowler_remediation_as_plain_string():
    # Some Prowler variants put remediation as a plain string.
    f = from_prowler([{"CheckID": "c", "Severity": "low", "Remediation": "do the thing"}])
    assert f[0].remediation_hint == "do the thing"
