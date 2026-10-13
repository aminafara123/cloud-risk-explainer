.PHONY: install test run run-asff demo clean

install:
	pip install -r requirements.txt

test:
	pytest -q

# Full run (tries the local LLM for narrative; falls back to deterministic text if offline).
run:
	python -m cloud_risk_explainer -i sample/prowler_findings.json -o report.md --html report.html

run-asff:
	python -m cloud_risk_explainer -i sample/asff_findings.json -o report.md --html report.html

# Deterministic, fully offline (no LLM): good for CI and demos.
demo:
	python -m cloud_risk_explainer -i sample/prowler_findings.json -o report.md --html report.html --no-llm

clean:
	rm -f report.md report.html
	rm -rf .pytest_cache __pycache__ cloud_risk_explainer/__pycache__ tests/__pycache__
