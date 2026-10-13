"""LLM-written prose: executive summary + per-finding "why this matters" / steps.

The LLM is used for PROSE ONLY. All numbers, ranking and signal detection are
deterministic (see score.py). If the LLM is unreachable, every function degrades
to a plain deterministic fallback built from the finding's own fields, and the
report is marked accordingly, so the tool never crashes and never blocks offline.
"""
from . import llm
from .score import SIGNAL_LABEL, ScoredFinding

_SYSTEM = (
    "You are a senior cloud security analyst writing for a busy executive or "
    "client. Write in plain English, no jargon, concrete and calm. Never invent "
    "facts beyond what you are given. Do not use markdown headers."
)

# Only these severities get a per-finding AI write-up.
_NARRATE_SEVERITIES = {"CRITICAL", "HIGH"}


def _finding_line(s: ScoredFinding) -> str:
    sigs = ", ".join(SIGNAL_LABEL[x] for x in s.signals) or "none"
    return (f"- [{s.finding.severity}] {s.finding.service}: {s.finding.title} "
            f"(risk score {s.score}, exposure: {sigs})")


def executive_summary(scored) -> str:
    """One LLM call. Raises llm.LLMError if the endpoint is unreachable."""
    top = scored[: min(len(scored), 10)]
    lines = "\n".join(_finding_line(s) for s in top)
    crit = sum(1 for s in scored if s.finding.severity == "CRITICAL")
    high = sum(1 for s in scored if s.finding.severity == "HIGH")
    prompt = (
        f"Here are {len(scored)} AWS security findings, already prioritized by a "
        f"deterministic risk score ({crit} critical, {high} high). The highest-risk "
        f"ones:\n\n{lines}\n\n"
        "Write a 2-3 short paragraph executive summary. State the overall risk "
        "posture, the 2-3 themes that matter most, and what to fix first. "
        "Do not list every finding. Keep it under 180 words."
    )
    return llm.complete(prompt, system=_SYSTEM)


def explain_finding(s: ScoredFinding) -> dict:
    """One LLM call for a single finding. Returns {'why', 'steps'}.

    Raises llm.LLMError if the endpoint is unreachable.
    """
    sigs = ", ".join(SIGNAL_LABEL[x] for x in s.signals) or "none"
    prompt = (
        "Explain this AWS security finding for a decision-maker.\n\n"
        f"Title: {s.finding.title}\n"
        f"Service: {s.finding.service}\n"
        f"Severity: {s.finding.severity} (risk score {s.score})\n"
        f"Resource: {s.finding.resource}\n"
        f"Exposure signals: {sigs}\n"
        f"Detail: {s.finding.description}\n"
        f"Remediation hint: {s.finding.remediation_hint or 'none provided'}\n\n"
        "Respond in exactly this format:\n"
        "WHY: <2-3 sentences on the business/security risk in plain English>\n"
        "STEPS:\n1) <concrete remediation step>\n2) <...>\n3) <...>"
    )
    text = llm.complete(prompt, system=_SYSTEM)
    return _split_why_steps(text)


def _split_why_steps(text: str) -> dict:
    """Lenient parse of the WHY/STEPS format; never raises."""
    why, steps = text, ""
    upper = text.upper()
    if "STEPS:" in upper:
        idx = upper.index("STEPS:")
        why = text[:idx]
        steps = text[idx + len("STEPS:"):]
    why = why.replace("WHY:", "", 1).strip()
    return {"why": why, "steps": steps.strip()}


def _fallback_finding(s: ScoredFinding) -> dict:
    steps = s.finding.remediation_hint.strip() or "Review this finding and apply the vendor's recommended remediation."
    return {"why": s.finding.description or "(no description provided)", "steps": steps}


def _fallback_summary(scored) -> str:
    counts = {}
    for s in scored:
        counts[s.finding.severity] = counts.get(s.finding.severity, 0) + 1
    parts = ", ".join(f"{counts[k]} {k.lower()}" for k in
                      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] if counts.get(k))
    top = scored[0] if scored else None
    lead = (f" The highest-risk item is \"{top.finding.title}\" "
            f"(risk score {top.score})." if top else "")
    return (f"{len(scored)} findings were analyzed ({parts}).{lead} "
            "Address the highest-scoring items first. "
            "(LLM narrative unavailable; this is a deterministic fallback summary.)")


def generate_narrative(scored, use_llm=True) -> dict:
    """Produce the full narrative bundle for the report.

    Returns:
        {
          "executive_summary": str,
          "per_finding": {finding_id: {"why": str, "steps": str}},
          "llm_available": bool,
        }

    Never raises on LLM failure: it falls back to deterministic prose and sets
    llm_available=False.
    """
    if not use_llm:
        return {
            "executive_summary": _fallback_summary(scored),
            "per_finding": {s.finding.id: _fallback_finding(s) for s in scored
                            if s.finding.severity in _NARRATE_SEVERITIES},
            "llm_available": False,
        }

    try:
        summary = executive_summary(scored)
    except llm.LLMError:
        # One failure means the endpoint is down: fall back wholesale.
        return {
            "executive_summary": _fallback_summary(scored),
            "per_finding": {s.finding.id: _fallback_finding(s) for s in scored
                            if s.finding.severity in _NARRATE_SEVERITIES},
            "llm_available": False,
        }

    per_finding = {}
    for s in scored:
        if s.finding.severity not in _NARRATE_SEVERITIES:
            continue
        try:
            per_finding[s.finding.id] = explain_finding(s)
        except llm.LLMError:
            per_finding[s.finding.id] = _fallback_finding(s)
    return {"executive_summary": summary, "per_finding": per_finding, "llm_available": True}
