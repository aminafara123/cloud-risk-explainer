"""Importers + the normalized finding schema.

Every supported input format is mapped to one `Finding` shape:
    {id, title, service, severity, resource, description, remediation_hint}

Supported inputs (auto-detected by `load_findings`):
  - Prowler-style JSON  (a list of check results: CheckID, CheckTitle, Severity, ...)
  - AWS Security Hub ASFF  ({"Findings": [...]} or a list: Id, Title, Severity.Label, Resources, ...)
  - Native  (already a list of normalized findings)

Only failing/actionable findings are kept. A finding explicitly marked PASS /
PASSED / ARCHIVED is dropped, because a risk report is about what is wrong.
"""
from dataclasses import asdict, dataclass

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MED": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "INFORMATIONAL",
    "INFO": "INFORMATIONAL",
    "INFORMATION": "INFORMATIONAL",
    "NONE": "INFORMATIONAL",
}

# ASFF resource type prefix -> AWS service short name.
_ASFF_SERVICE = {
    "AwsS3Bucket": "s3",
    "AwsIamRole": "iam",
    "AwsIamPolicy": "iam",
    "AwsIamUser": "iam",
    "AwsIamGroup": "iam",
    "AwsIamAccessKey": "iam",
    "AwsEc2SecurityGroup": "ec2",
    "AwsEc2Instance": "ec2",
    "AwsEc2Vpc": "ec2",
    "AwsRdsDbInstance": "rds",
    "AwsRdsDbSnapshot": "rds",
    "AwsCloudTrailTrail": "cloudtrail",
    "AwsKmsKey": "kms",
}


@dataclass
class Finding:
    """The one shape everything downstream (scoring, report) consumes."""
    id: str
    title: str
    service: str
    severity: str
    resource: str
    description: str
    remediation_hint: str

    def to_dict(self):
        return asdict(self)


def norm_severity(raw) -> str:
    """Coerce any provider severity into the canonical set.

    Accepts a string ("critical"), a number (ASFF 0-100 Normalized), or an
    ASFF Severity object ({"Label": ..., "Normalized": ...}).
    """
    if isinstance(raw, dict):
        if raw.get("Label"):
            return norm_severity(raw["Label"])
        if raw.get("Normalized") is not None:
            return norm_severity(raw["Normalized"])
        return "MEDIUM"
    if isinstance(raw, (int, float)):
        n = float(raw)
        if n >= 90:
            return "CRITICAL"
        if n >= 70:
            return "HIGH"
        if n >= 40:
            return "MEDIUM"
        if n >= 1:
            return "LOW"
        return "INFORMATIONAL"
    if raw:
        return _SEVERITY_ALIASES.get(str(raw).strip().upper(), "MEDIUM")
    return "MEDIUM"


def norm_service(raw) -> str:
    """Lower-case AWS service short name. Maps ASFF resource types too."""
    if not raw:
        return "unknown"
    s = str(raw).strip()
    if s in _ASFF_SERVICE:
        return _ASFF_SERVICE[s]
    return s.lower().replace("aws", "", 1) if s.lower().startswith("aws") else s.lower()


def _dig(d, *path, default=""):
    """Safe nested get: _dig(f, 'Remediation', 'Recommendation', 'Text')."""
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur not in (None, "") else default


def _service_from_arn(arn) -> str:
    """arn:aws:rds:us-east-1:123:db:mydb -> 'rds'. Empty string if not an ARN."""
    parts = str(arn).split(":")
    return parts[2] if len(parts) >= 3 and parts[0] == "arn" else ""


# --------------------------------------------------------------------------- #
# Importers
# --------------------------------------------------------------------------- #

def from_prowler(records) -> list[Finding]:
    """Prowler-style check results -> normalized findings."""
    out = []
    for i, r in enumerate(records):
        if str(r.get("Status", "FAIL")).upper() in ("PASS", "PASSED"):
            continue
        resource = r.get("ResourceArn") or r.get("ResourceId") or r.get("Resource") or ""
        fid = r.get("FindingUniqueId") or r.get("CheckID") or f"prowler-{i}"
        rem = r.get("Remediation")
        remediation = rem if isinstance(rem, str) else _dig(r, "Remediation", "Recommendation", "Text")
        out.append(Finding(
            id=str(fid),
            title=r.get("CheckTitle") or r.get("CheckID") or "Untitled check",
            service=norm_service(r.get("ServiceName") or r.get("Service")),
            severity=norm_severity(r.get("Severity")),
            resource=str(resource),
            description=(r.get("StatusExtended") or r.get("Risk")
                         or r.get("Description") or "").strip(),
            remediation_hint=remediation,
        ))
    return out


def from_asff(records) -> list[Finding]:
    """AWS Security Hub ASFF findings -> normalized findings."""
    if isinstance(records, dict):
        records = records.get("Findings", [])
    out = []
    for i, r in enumerate(records):
        if str(_dig(r, "Compliance", "Status")).upper() == "PASSED":
            continue
        if str(r.get("RecordState", "ACTIVE")).upper() == "ARCHIVED":
            continue
        resources = r.get("Resources") or []
        res0 = resources[0] if resources else {}
        # The ARN's service segment is authoritative; the resource Type is a fallback.
        service = _service_from_arn(res0.get("Id")) or norm_service(res0.get("Type"))
        out.append(Finding(
            id=str(r.get("Id") or f"asff-{i}"),
            title=r.get("Title") or "Untitled finding",
            service=service or "unknown",
            severity=norm_severity(r.get("Severity")),
            resource=str(res0.get("Id") or ""),
            description=(r.get("Description") or "").strip(),
            remediation_hint=_dig(r, "Remediation", "Recommendation", "Text"),
        ))
    return out


def from_native(records) -> list[Finding]:
    """Already-normalized findings -> validated Finding objects."""
    out = []
    for i, r in enumerate(records):
        out.append(Finding(
            id=str(r.get("id") or f"finding-{i}"),
            title=r.get("title") or "Untitled finding",
            service=norm_service(r.get("service")),
            severity=norm_severity(r.get("severity")),
            resource=str(r.get("resource") or ""),
            description=(r.get("description") or "").strip(),
            remediation_hint=r.get("remediation_hint") or "",
        ))
    return out


# --------------------------------------------------------------------------- #
# Format detection + loading
# --------------------------------------------------------------------------- #

def detect_format(data) -> str:
    """Return 'asff' | 'prowler' | 'native' for a parsed JSON document."""
    if isinstance(data, dict) and "Findings" in data:
        return "asff"
    records = data if isinstance(data, list) else []
    first = records[0] if records else {}
    if not isinstance(first, dict):
        return "native"
    if "SchemaVersion" in first or "ProductArn" in first or isinstance(first.get("Severity"), dict):
        return "asff"
    if "CheckID" in first or "CheckTitle" in first or "ServiceName" in first:
        return "prowler"
    return "native"


_IMPORTERS = {"asff": from_asff, "prowler": from_prowler, "native": from_native}


def load_findings(path, fmt="auto") -> list[Finding]:
    """Read a findings JSON file and return normalized Finding objects.

    `fmt` is one of 'auto' (default), 'prowler', 'asff', 'native'.
    Returns (findings, detected_format) is NOT done here to keep the call simple;
    use detect_format() if you need the label.
    """
    import json
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if fmt == "auto":
        fmt = detect_format(data)
    importer = _IMPORTERS.get(fmt)
    if importer is None:
        raise ValueError(f"unknown format {fmt!r}; expected one of {sorted(_IMPORTERS)}")
    # ASFF importer accepts the dict-with-Findings or a bare list.
    return importer(data)
