# Changelog

All notable changes to stackit-audit are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2026-05

### Added

**Core pipeline**
- `stackit-audit discover` — inventories STACKIT resources across one or more projects via REST APIs
- `stackit-audit audit` — runs all checks against a cached inventory; no further API calls required
- `stackit-audit report` — renders `findings.json`, `report.md`, and `report.pdf` from findings
- `stackit-audit run` — convenience pipeline combining all three steps

**Authentication**
- Key Flow authentication (RSA-signed JWT exchanged for Bearer token at STACKIT token endpoint)
- In-memory token caching with 60-second safety margin before expiry

**Discovery**
- Resource collection across 12 STACKIT service APIs: Resource Manager, Authorization, Service Account, IaaS, Object Storage, SKE, DB Flex (6 engines), Load Balancer, DNS, Secrets Manager, Observability/LogMe, Audit Log
- Per-project error isolation — a 403 on one service does not abort collection of others
- `inventory.json` intermediate cache for fast iterative auditing

**Check engine — 20 MVP checks**

| Domain | Checks |
|---|---|
| IAM | IAM-001 through IAM-005 |
| Network | NET-001 through NET-006 |
| Database | DB-001 through DB-003 |
| Kubernetes | K8S-001, K8S-002 |
| Crypto | CRYPTO-001 |
| Logging | LOG-001, LOG-002 |
| Secrets | SECRET-001 |
| Organisational | ORG-001 (manual controls checklist) |

**Framework mappings**
- CCM v4 and BSI C5:2020 control references on every check
- `frameworks/eol_versions.yaml` for DB and Kubernetes version thresholds
- `frameworks/manual_controls.yaml` for the explicit list of controls the tool does not verify

**Reporting**
- `findings.json` with schema version, scan metadata, summary, and redacted API evidence
- `report.md` with executive summary, top-10 findings, findings by severity and framework, manual review section
- `report.pdf` via ReportLab with title page, severity colour coding, and all report sections

**CI/CD**
- Exit codes: `0` (clean), `2` (findings above threshold), `10` (config error), `20` (API error), `30` (internal error)
- `--fail-on critical|high|medium|low|info` threshold flag

**Tests**
- 58 unit tests covering all check modules, JSON/Markdown/PDF reporting, scoring, and redaction
- Tests run without network access using fixture-based resources

**Documentation**
- `docs/architecture.md` — 1,000+ line technical reference covering all 18 architectural aspects
- `CONTRIBUTING.md` — guide for adding checks and services
- `sample/sample-findings.json` — offline report preview without STACKIT credentials
