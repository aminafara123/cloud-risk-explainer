# 60-second demo script

Goal: show raw AWS findings becoming a ranked, plain-English report, with the ranking being deterministic and the prose clearly AI-labeled.

## Before recording

```bash
make install        # one dependency: pytest
make clean          # remove any old report.md / report.html
```

Have two terminal panes or a terminal plus a browser ready.

## The recording (target ~60s)

1) (0:00-0:08) Show the input. "Prowler dumps a few hundred findings as JSON. Nobody acts on that."
   ```bash
   head -40 sample/prowler_findings.json
   ```

2) (0:08-0:16) Prove the core is trustworthy. "Scoring and ranking are deterministic, so they are tested offline with no network."
   ```bash
   make test
   ```

3) (0:16-0:30) Generate the report, fully offline. "One command turns the dump into a ranked report."
   ```bash
   make demo
   ```
   Point at the console line: `Top risk: #1 [92.0] Ensure RDS instances are not publicly accessible`.

4) (0:30-0:48) Open `report.html` in the browser. Scroll the prioritized table.
   "A publicly reachable critical database sits at the top. A public plus unencrypted RDS beats a public S3 bucket beats an internal critical. Exposure amplifies severity, every run."

5) (0:48-0:60) Scroll to the AI disclaimer banner and a per-finding section.
   "The numbers are code. The summary and the why/how are AI-drafted and labeled as such, with a human-review notice. This is a triage aid, not a compliance sign-off."

## Optional (if a local Ollama is running)

```bash
make run        # same report, but the summary and per-finding prose are LLM-written
```

Show that the exec summary is now real narrative instead of the deterministic fallback line.
