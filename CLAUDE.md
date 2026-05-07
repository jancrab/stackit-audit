# stackit-audit — Agent Instructions

## Project overview

Lightweight, local-only Python CLI that inventories STACKIT cloud resources via REST
APIs and audits them against CSA CCM v4 / BSI C5:2020 controls.  Read-only; no writes
to the STACKIT environment.  No telemetry; all data stays local.

## Key conventions

- Python 3.10+, Pydantic v2, httpx, ReportLab
- `UNKNOWN` status when an expected API field is absent — never `PASS` by assumption
- `automated_assurance_level` ∈ {automated, heuristic, manual} on every check
- Every `FAIL`/`PARTIAL` finding must populate `api_evidence`
- `redact()` applied before any data hits disk

## Module layout

```
stackit_audit/
├── auth/           Key Flow JWT auth
├── api_client/     HTTP clients per STACKIT service
├── discovery/      Orchestrates API calls → Inventory (parallelised across projects)
├── normalization/  Maps API responses → canonical Resource
├── checks/         21 MVP checks + engine  (CheckBase ABC, ALL_CHECKS registry)
├── frameworks/     CCM v4 + C5:2020 YAML mappings, EOL versions
├── scoring/        Aggregator (accepts active_checks) + prioritizer
├── reporting/      JSON writer + Markdown writer
├── pdf_rendering/  ReportLab PDF builder
├── cli/            argparse CLI dispatcher (--config flag supported)
├── config/         YAML config loader (AuditConfig)
├── models/         Pydantic: Resource, Check, Finding
└── utils/          logging, redact, exit codes
```

## Adding a new check

1. Add class to appropriate `stackit_audit/checks/*.py` following `CheckBase`
2. Register in `ALL_CHECKS` in `stackit_audit/checks/engine.py`
3. Write tests in `tests/checks/test_<domain>_checks.py`
4. Run `pytest tests/ -q` — must stay green

See `CONTRIBUTING.md` for the full guide with a working example.

## Running tests

```bash
pytest tests/ -q          # all 73 tests, no network required
pytest tests/ --cov=stackit_audit --cov-report=term-missing
```

## Commit messages

Every commit MUST include a "How to test" section in the body:

- Command to run to verify the change (preferably `pytest` or a CLI invocation)
- What to check in the output
- For check logic changes: which fixture reproduces the scenario
- For CLI changes: exact `stackit-audit` command + expected exit code / output

Example:

```
fix: --fail-on now triggers on severity >= threshold not exact match

How to test:
- pytest tests/test_arch_fixes.py::TestFailOnSeverityThreshold -v
- All 5 tests should pass; test_critical_finding_triggers_high_threshold
  was previously failing with the == bug
- CLI: stackit-audit audit --inventory sample/sample-findings.json
  --fail-on high → exit code 2 (critical findings present)
```
