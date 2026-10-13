"""CLI: findings JSON -> prioritized, plain-English risk report.

    python -m cloud_risk_explainer --input sample/prowler_findings.json --out report.md
    python -m cloud_risk_explainer -i sample/asff_findings.json -o report.md --html report.html
    python -m cloud_risk_explainer -i sample/prowler_findings.json --no-llm   # offline, deterministic
"""
import argparse
import datetime
import json
import sys

from . import report
from .explain import generate_narrative
from .normalize import detect_format, load_findings
from .score import prioritize


def main(argv=None):
    p = argparse.ArgumentParser(prog="cloud-risk-explainer",
                                description="Turn raw AWS security findings into a prioritized risk report.")
    p.add_argument("-i", "--input", required=True, help="findings JSON file")
    p.add_argument("-o", "--out", default="report.md", help="Markdown output path (default report.md)")
    p.add_argument("--html", metavar="PATH", help="also write an HTML report to PATH")
    p.add_argument("--format", default="auto", choices=["auto", "prowler", "asff", "native"],
                   help="input format (default auto-detect)")
    p.add_argument("--no-llm", action="store_true",
                   help="skip the LLM and emit deterministic fallback narrative (fully offline)")
    args = p.parse_args(argv)

    with open(args.input, encoding="utf-8") as fh:
        fmt = args.format if args.format != "auto" else detect_format(json.load(fh))
    findings = load_findings(args.input, fmt=args.format)
    if not findings:
        print("No actionable findings found in input.", file=sys.stderr)
        return 1

    scored = prioritize(findings)
    narrative = generate_narrative(scored, use_llm=not args.no_llm)

    meta = {
        "source": args.input,
        "format": fmt,
        "total": len(scored),
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%d %H:%M UTC"),
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report.build_markdown(scored, narrative, meta))
    outputs = [args.out]
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.build_html(scored, narrative, meta))
        outputs.append(args.html)

    top = scored[0]
    llm_state = "LLM narrative" if narrative["llm_available"] else "deterministic fallback (no LLM)"
    print(f"Analyzed {len(scored)} findings from {args.input} ({fmt}).")
    print(f"Top risk: #{top.rank} [{top.score}] {top.finding.title}")
    print(f"Narrative: {llm_state}")
    print(f"Wrote: {', '.join(outputs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
