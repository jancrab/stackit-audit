# STACKIT Audit — Build Progress

## Status: COMPLETE (all phases)

All 16 planned implementation tasks are done. 58 unit tests pass.

## Completed

| # | Task | Status |
|---|------|--------|
| 1 | Project skeleton (pyproject.toml, README, package layout) | ✅ |
| 2 | Pydantic models (Resource, Check, Finding) | ✅ |
| 3 | Auth module (Key Flow JWT signing + token cache) | ✅ |
| 4 | Config loader and schema | ✅ |
| 5 | Utils (logging, redact, exit codes) | ✅ |
| 6 | API client base + all service modules | ✅ |
| 7 | Discovery orchestrator and normalization | ✅ |
| 8 | Frameworks YAML (CCM v4, C5:2020 mappings, EOL versions) | ✅ |
| 9 | Check engine + base class | ✅ |
| 10 | All 20 MVP checks (IAM, NET, DB, K8S, CRYPTO, LOG, SECRET, ORG) | ✅ |
| 11 | Scoring/aggregation + prioritizer | ✅ |
| 12 | JSON + Markdown reporting | ✅ |
| 13 | PDF rendering (ReportLab) | ✅ |
| 14 | CLI dispatcher (discover / audit / report / run) | ✅ |
| 15 | Test fixtures and unit tests | ✅ |
| 16 | Full test run + PROGRESS.md + commit | ✅ |

## Test results (last run)

```
58 passed in 0.54s
```

## CLI usage

```bash
# Full pipeline
stackit-audit run \
  --service-account-key ./sa-key.json \
  --project-id proj-eu01-abc \
  --output-dir ./out \
  --formats json,md,pdf

# Step by step
stackit-audit discover --service-account-key ./sa-key.json --project-id proj-eu01-abc --output inventory.json
stackit-audit audit --inventory inventory.json --output findings.json --fail-on critical
stackit-audit report --findings findings.json --formats json,md,pdf --output-dir ./out
```

## Module layout

```
stackit_audit/
├── auth/           Key Flow JWT auth
├── api_client/     HTTP clients per STACKIT service
├── discovery/      Orchestrates API calls → Inventory
├── normalization/  Maps API responses → canonical Resource
├── checks/         20 MVP checks + engine
├── frameworks/     CCM v4 + C5:2020 YAML mappings
├── scoring/        Aggregator + prioritizer
├── reporting/      JSON writer + Markdown writer
├── pdf_rendering/  ReportLab PDF builder
├── cli/            argparse CLI dispatcher
├── config/         YAML config loader
├── models/         Pydantic: Resource, Check, Finding
└── utils/          logging, redact, exit codes
```

## Known limits

- Encryption-at-rest fields not consistently exposed by STACKIT API → PARTIAL/UNKNOWN
- MFA status not available via Authorization API → manual check only
- KMS beta API not integrated (stub)
- Discovery requires live STACKIT credentials; tests use resource/finding fixtures only
