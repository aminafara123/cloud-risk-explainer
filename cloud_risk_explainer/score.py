"""Deterministic risk scoring + prioritization.

No LLM here, by design: ranking must be reproducible and defensible.

    risk score = severity_weight x exposure_multiplier

`exposure_multiplier` starts at 1.0 and each detected exposure signal
amplifies it. Exposure is what turns a theoretical misconfiguration into a
real incident, so a CRITICAL that is publicly reachable always outranks a
CRITICAL that is internal-only.

Signals are inferred deterministically by keyword from the finding's own text
(title + description + resource + service), so the same input always yields the
same ranking.
"""
from dataclasses import dataclass

from .normalize import Finding

SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5,
    "INFORMATIONAL": 1,
}

# Each signal adds this much to the exposure multiplier (which starts at 1.0).
SIGNAL_WEIGHT = {
    "public_exposure": 1.0,
    "internet_facing_sg": 0.6,
    "wildcard_iam": 0.6,
    "unencrypted": 0.3,
    "logging_disabled": 0.2,
}

SIGNAL_LABEL = {
    "public_exposure": "Public exposure",
    "internet_facing_sg": "Internet-facing SG",
    "wildcard_iam": "Wildcard IAM",
    "unencrypted": "Unencrypted",
    "logging_disabled": "Logging disabled",
}

_SIGNAL_KEYWORDS = {
    "public_exposure": [
        "public", "0.0.0.0/0", "::/0", "publicly accessible", "public-read",
        "public access", "anonymous", "exposed to the internet", "internet-facing",
    ],
    "internet_facing_sg": [
        "0.0.0.0/0", "::/0", "unrestricted", "open to the world", "all ports",
        "port 22", "port 3389", "ingress from 0.0.0.0",
    ],
    "wildcard_iam": [
        "wildcard", "action: *", "action *", '"*"', "*:*", "resource: *",
        "administratoraccess", "admin access", "full access", "overly permissive",
        "privilege escalation", "assumable by any",
    ],
    "unencrypted": [
        "unencrypted", "not encrypted", "encryption disabled", "without encryption",
        "no encryption", "encryption is not enabled", "encryption not enabled", "cleartext",
    ],
    "logging_disabled": [
        "logging disabled", "logging is not enabled", "logging not enabled", "no logging",
        "not logging", "cloudtrail is not enabled", "trail is not", "flow logs are not",
        "access logging", "audit logging disabled",
    ],
}


def infer_signals(finding: Finding) -> list[str]:
    """Deterministically detect exposure signals from the finding's text."""
    text = " ".join([
        finding.title, finding.description, finding.resource, finding.service,
    ]).lower()
    return [sig for sig, kws in _SIGNAL_KEYWORDS.items()
            if any(kw in text for kw in kws)]


def risk_score(finding: Finding, signals=None) -> float:
    """severity_weight x (1 + sum of signal weights). Rounded to 1 decimal."""
    if signals is None:
        signals = infer_signals(finding)
    base = SEVERITY_WEIGHT.get(finding.severity, 1)
    multiplier = 1.0 + sum(SIGNAL_WEIGHT.get(s, 0.0) for s in signals)
    return round(base * multiplier, 1)


def risk_band(score: float) -> str:
    """Human label for a score, independent of the source severity."""
    if score >= 60:
        return "Critical"
    if score >= 35:
        return "High"
    if score >= 18:
        return "Medium"
    return "Low"


@dataclass
class ScoredFinding:
    finding: Finding
    score: float
    signals: list
    rank: int = 0

    @property
    def band(self):
        return risk_band(self.score)


def prioritize(findings) -> list[ScoredFinding]:
    """Score every finding and return them ranked, highest risk first.

    Deterministic tie-break: score desc, then severity weight desc, then id asc.
    """
    scored = [
        ScoredFinding(f, risk_score(f, sig), sig)
        for f in findings
        for sig in [infer_signals(f)]
    ]
    scored.sort(key=lambda s: (
        -s.score,
        -SEVERITY_WEIGHT.get(s.finding.severity, 0),
        s.finding.id,
    ))
    for i, s in enumerate(scored, 1):
        s.rank = i
    return scored


def severity_counts(scored) -> dict:
    """Count findings per canonical severity, in CRITICAL..INFORMATIONAL order."""
    counts = {s: 0 for s in SEVERITY_WEIGHT}
    for item in scored:
        sev = item.finding.severity if isinstance(item, ScoredFinding) else item.severity
        counts[sev] = counts.get(sev, 0) + 1
    return counts
