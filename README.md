# stackit-audit

> Lightweight, local-only security audit tool for [STACKIT](https://www.stackit.de/) cloud environments.
> Maps your infrastructure against **CSA CCM v4** and **BSI C5:2020** controls and produces
> machine-readable findings plus management-ready reports.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What it does

```bash
stackit-audit run --service-account-key ./sa-key.json --project-id proj-eu01-abc --output-dir ./out/
```

Produces three artefacts in `./out/`:

| File | Audience | Description |
|---|---|---|
| `findings.json` | Pipelines / SIEM | Machine-readable, schema-versioned findings with full API evidence |
| `report.md` | Developers | Markdown with severity tables, framework cross-references, manual review list |
| `report.pdf` | Management / auditors | PDF with title page, executive summary, and prioritised findings |

**Properties:**
- **Read-only** — never writes to your STACKIT environment
- **Local-only** — no telemetry, no cloud backend, no external data upload
- **Honest** — checks that cannot be verified via the API produce `UNKNOWN` or `PARTIAL`, never a false `PASS`
- **CI/CD ready** — exit code `2` when findings at/above a configured severity are present

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/jancrab/stackit-audit.git
cd stackit-audit
pip install .
```

---

## Prerequisites — Service Account Key

1. In the STACKIT portal, create a Service Account for each project you want to audit.
2. Assign it the **reader** role on each project.
3. Download the key as JSON with **"Include private key"** enabled.
4. Save it locally (e.g. `./sa-key.json`) and keep it out of version control.

```json
{
  "id": "key-abc123",
  "iss": "audit-sa@proj.iam.stackit.cloud",
  "credentials": {
    "iss": "audit-sa@proj.iam.stackit.cloud",
    "privateKey": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
}
```

---

## Quick Start

### Full pipeline (one command)

```bash
stackit-audit run \
  --service-account-key ./sa-key.json \
  --project-id proj-eu01-abc \
  --output-dir ./out/ \
  --formats json,md,pdf \
  --fail-on critical
```

### Step by step

```bash
# Discover — snapshot all resources; re-use this without further API calls
stackit-audit discover \
  --service-account-key ./sa-key.json \
  --project-id proj-eu01-abc \
  --project-id proj-eu01-def \
  --output inventory.json

# Audit — run all checks against the cached snapshot
stackit-audit audit \
  --inventory inventory.json \
  --output findings.json \
  --fail-on high

# Report — render reports from findings (no API calls needed)
stackit-audit report \
  --findings findings.json \
  --formats json,md,pdf \
  --output-dir ./out/
```

### Preview without STACKIT credentials

```bash
stackit-audit report \
  --findings sample/sample-findings.json \
  --formats md,pdf \
  --output-dir ./out/
```

---

## Configuration file

Copy `audit-config.example.yaml` and adjust:

```yaml
auth:
  service_account_key_path: ./sa-key.json

scope:
  project_ids:
    - proj-eu01-abc
  region: eu01

checks:
  exclude: []          # e.g. [IAM-004, K8S-001]
  include_only: []     # run only these check IDs

reporting:
  formats: [json, md, pdf]
  output_dir: ./out
```

---

## Check catalogue

20 checks across 8 security domains:

| Check | Title | Severity | Assurance | CCM | C5 |
|---|---|---|---|---|---|
| IAM-001 | Service accounts with privileged project roles | High | Automated | IAM-09, IAM-16 | IDM-04 |
| IAM-002 | Service-account keys older than 90 days | Medium | Automated | IAM-04 | IDM-09, KRY-03 |
| IAM-003 | SA with multiple active keys | Low | Automated | IAM-04 | IDM-09 |
| IAM-004 | Privileged memberships without expiry | Medium | Heuristic | IAM-08 | IDM-06 |
| IAM-005 | MFA on privileged identities | High | Manual | IAM-13 | IDM-08 |
| NET-001 | SSH (port 22) open to internet | Critical | Automated | IVS-04 | KOS-04 |
| NET-002 | RDP (port 3389) open to internet | Critical | Automated | IVS-04 | KOS-04 |
| NET-003 | Database ports open to internet | Critical | Automated | IVS-04, IVS-09 | KOS-04 |
| NET-004 | Server with public IP and permissive SG | High | Heuristic | IVS-09 | KOS-05 |
| NET-005 | Object Storage bucket with public access | High | Heuristic | DSP-08, IVS-04 | AM-04, KOS-04 |
| NET-006 | Load balancer with HTTP-only listener | High | Automated | CEK-19 | KRY-04 |
| DB-001 | DB Flex instance with public access | Critical | Heuristic | IVS-09, DSP-08 | KOS-05 |
| DB-002 | DB Flex instance without backup config | Medium | Heuristic | BCR-08, BCR-11 | BCM-04 |
| DB-003 | DB engine version below supported floor | High | Automated | UEM-04, TVM-07 | OPS-07 |
| K8S-001 | SKE cluster control plane open to internet | Critical | Heuristic | IVS-04 | KOS-04 |
| K8S-002 | SKE cluster running unsupported K8s version | High | Automated | UEM-04 | OPS-07 |
| CRYPTO-001 | IaaS volume without encryption indicator | Medium | Heuristic | CEK-03 | KRY-01 |
| LOG-001 | No audit log activity in 30 days | Medium | Heuristic | LOG-02 | RB-12 |
| LOG-002 | No Observability/LogMe instance | Medium | Heuristic | LOG-03 | RB-09 |
| SECRET-001 | Active SA key never seen in audit logs | Medium | Heuristic | IAM-04 | IDM-09 |
| ORG-001 | Manual CCM/C5 controls checklist | Info | Manual | HRS-*, GRC-* | OIS-*, HR-* |

**Assurance levels:**
- `Automated` — API field is definitive; result is reliable
- `Heuristic` — inferred from available signals; review before acting
- `Manual` — not API-verifiable; produces `UNKNOWN` so it appears in the report

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed, no findings at/above threshold |
| `2` | Completed, findings ≥ `--fail-on` threshold |
| `10` | Configuration or authentication error |
| `20` | API errors prevented discovery |
| `30` | Internal error |

### GitHub Actions example

```yaml
- name: Run STACKIT audit
  run: |
    echo "${{ secrets.STACKIT_SA_KEY }}" > /tmp/sa-key.json
    stackit-audit run \
      --service-account-key /tmp/sa-key.json \
      --project-id ${{ vars.STACKIT_PROJECT_ID }} \
      --output-dir ./audit-out/ \
      --formats json,md \
      --fail-on critical
```

---

## Limitations

| Area | Limit | Status in report |
|---|---|---|
| MFA on user accounts | Not exposed by Authorization API | `UNKNOWN` (manual) |
| Volume encryption-at-rest | Field not consistently in STACKIT API | `PARTIAL` / `UNKNOWN` |
| Object Storage public ACL | Field availability varies | `UNKNOWN` if absent |
| DB Flex public access | Varies by engine and version | `UNKNOWN` if absent |
| KMS key bindings | KMS API is beta | Not checked |
| Audit log retention period | API returns entries, not config | `PARTIAL` |

These are reported in the **Manual Review** section of every report — nothing is silently skipped.

---

## Project layout

```
stackit_audit/
├── auth/           Key Flow JWT authentication
├── api_client/     HTTP clients per STACKIT service
├── discovery/      Orchestrates API calls → Inventory
├── normalization/  Maps API responses → canonical Resource
├── checks/         20 checks + engine
├── frameworks/     CCM v4 + C5:2020 YAML mappings, EOL versions
├── scoring/        Aggregator + prioritizer
├── reporting/      JSON + Markdown writers
├── pdf_rendering/  ReportLab PDF builder
├── cli/            CLI dispatcher
├── models/         Pydantic models (Resource, Check, Finding)
└── utils/          logging, redact, exit codes

docs/architecture.md   Full technical reference (18 sections)
sample/                Sample findings for offline report preview
tests/                 58 unit tests
```

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add checks, run tests, and submit changes.

---

## License

MIT — see [LICENSE](LICENSE).

---

> **Disclaimer:** This tool is a readiness assessment aid. It does not constitute a formal audit opinion, certification recommendation, or legal compliance statement. It does not replace a qualified auditor.
