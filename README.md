# stackit-audit

Lightweight Python audit tool for STACKIT cloud environments. Inventories
resources via the STACKIT REST APIs, applies a curated MVP catalog of
technically verifiable controls derived from CSA CCM v4 and BSI C5:2020,
and produces `findings.json`, `report.md`, and a managment-ready `report.pdf`.

## Scope

- Read-only. The tool never writes to your STACKIT environment.
- Local execution. No telemetry, no cloud backend.
- Honest about limits: every check carries an `assurance_level`
  (`automated` / `heuristic` / `manual`). Controls that cannot be
  verified via the STACKIT API are marked `UNKNOWN` or `MANUAL` —
  never `PASS` by assumption.

This is **not** a CSPM, **not** a certification statement, and **not**
a substitute for an auditor. It is a readiness / gap-assessment tool.

## Authentication

STACKIT Key Flow with a Service Account JSON key file (RSA-signed JWT
exchanged for a Bearer token at `https://service-account.api.stackit.cloud/token`).

```bash
stackit-audit run \
    --service-account-key ./sa-key.json \
    --project-id proj-eu01-abc \
    --output-dir ./out/ \
    --formats json,md,pdf
```

## Subcommands

```bash
stackit-audit discover --service-account-key ./sa-key.json --project-id <id> --output ./inventory.json
stackit-audit audit    --inventory ./inventory.json --output ./findings.json
stackit-audit report   --findings ./findings.json --formats json,md,pdf --output-dir ./out/
stackit-audit run      --service-account-key ./sa-key.json --project-id <id> --output-dir ./out/
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Successful, no findings above threshold |
| 2    | Successful, findings >= threshold (`--fail-on critical`/`high`/...) |
| 10   | Configuration / auth error |
| 20   | API error budget exceeded |
| 30   | Internal error |

## Layout

See `docs/architecture.md` (or the plan file) for the full architecture.
Frameworks mappings live in `stackit_audit/frameworks/*.yaml` and can be
edited without touching code.

## Limitations

- MFA on user accounts: not exposed by the STACKIT Authorization API. Marked `MANUAL`.
- Encryption-at-rest field names on Volumes / Object Storage / DB-Flex: not
  consistently documented; checks degrade to `PARTIAL`/`UNKNOWN` if absent.
- KMS API is currently beta; bindings per-resource may not be queryable.

## Generating a sample PDF without API access

```bash
python -m stackit_audit report --findings sample/sample-findings.json --formats md,pdf --output-dir out/
```

This uses the bundled fixture findings to render `report.md` and `report.pdf`
end-to-end, useful for reviewing the report layout without STACKIT credentials.
