# STACKIT Audit — Technical Architecture & Reference

> **Version:** 0.1.0 | **Last updated:** 2026-05 | **Audience:** developers, security engineers, architects

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Design Goals and Non-Goals](#2-design-goals-and-non-goals)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Authentication — Key Flow](#4-authentication--key-flow)
5. [API Client Layer](#5-api-client-layer)
6. [Discovery Orchestrator](#6-discovery-orchestrator)
7. [Normalization Layer](#7-normalization-layer)
8. [Check Engine](#8-check-engine)
9. [MVP Check Catalogue](#9-mvp-check-catalogue)
10. [Framework Mappings](#10-framework-mappings)
11. [Scoring and Prioritization](#11-scoring-and-prioritization)
12. [Reporting (JSON, Markdown, PDF)](#12-reporting-json-markdown-pdf)
13. [CLI Dispatcher](#13-cli-dispatcher)
14. [Data Models Reference](#14-data-models-reference)
15. [Security Model](#15-security-model)
16. [Known Limits and Degradation Behaviour](#16-known-limits-and-degradation-behaviour)
17. [Extending the Tool](#17-extending-the-tool)
18. [Glossary](#18-glossary)

---

## 1. Executive Summary

`stackit-audit` is a local-only Python CLI that inventories a STACKIT cloud environment through its public REST APIs, applies a curated catalogue of security checks derived from **CSA CCM v4** and **BSI C5:2020**, and produces three report artefacts:

| Artefact | Audience | Content |
|---|---|---|
| `findings.json` | Pipelines, SIEM, automation | Machine-readable findings with full API evidence |
| `report.md` | Developers | Markdown with linked tables, framework cross-refs |
| `report.pdf` | Management, auditors | ReportLab PDF with title page, exec summary, severity tables |

**Key properties:**

- **Read-only.** The tool never writes to STACKIT APIs.
- **Local-only.** No data leaves your machine except outbound STACKIT API calls.
- **Honest about limits.** Checks that cannot be verified produce `UNKNOWN` or `PARTIAL`, never a false `PASS`.
- **CI-gate ready.** Exit code `2` when findings at or above a configured severity threshold are present.
- **20 checks across 8 domains** in v0.1.0; designed to be extended.

---

## 2. Design Goals and Non-Goals

### Goals

| Goal | Mechanism |
|---|---|
| Reproducibility | Same inventory → same findings (UUIDs aside) |
| Transparency | Every finding names the exact API field that triggered it |
| Honest coverage | `automated_assurance_level` on every check; manual controls explicitly reported |
| Local executability | No cloud backend, no external storage |
| Extensibility | Checks are plain Python classes; catalogue is a typed list |

### Non-Goals

- Not a CSPM (no drift detection, no ticketing)
- Not a certification tool (no "X% CCM-compliant" score)
- Not a remediation engine (reads only)
- Not a full CCM/C5 coverage claim (~15–20% of controls are API-automatable)

---

## 3. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CLI  (stackit_audit/cli/main.py)                                        │
│  discover │ audit │ report │ run                                         │
└──────┬────┴───────┴────────┴─────────────────────────────────────────────┘
       │
       ▼
┌──────────────┐        ┌────────────────────────────────────────────┐
│  Auth        │──JWT──▶│  STACKIT REST APIs                         │
│  key_flow.py │◀─token─│  (resource-manager, authorization, iaas,   │
└──────────────┘        │   ske, dbflex, object-storage, lb, dns,    │
                        │   secrets-manager, observability, audit-log)│
                        └───────────────┬────────────────────────────┘
                                        │  raw JSON
                                        ▼
                        ┌───────────────────────────┐
                        │  Discovery Orchestrator    │
                        │  orchestrator.py           │
                        │  (per-project, per-service)│
                        └───────────────┬────────────┘
                                        │  raw dicts
                                        ▼
                        ┌───────────────────────────┐
                        │  Normalization Layer       │
                        │  normalization/resources.py│
                        │  → Resource[]              │
                        └───────────────┬────────────┘
                                        │  Resource[]  (+ inventory.json cache)
                                        ▼
                        ┌───────────────────────────┐
                        │  Check Engine              │
                        │  checks/engine.py          │
                        │  ALL_CHECKS (20 checks)    │
                        └───────────────┬────────────┘
                                        │  Finding[]
                                        ▼
                   ┌────────────────────┼───────────────────┐
                   ▼                    ▼                    ▼
          findings.json           report.md            report.pdf
          (json_writer)       (markdown_writer)      (pdf_builder)
```

### Pipeline steps

The CLI exposes four subcommands that correspond to pipeline stages:

```
stackit-audit discover  →  inventory.json
stackit-audit audit     →  findings.json
stackit-audit report    →  report.md + report.pdf
stackit-audit run       →  all three in one step
```

`inventory.json` is an intermediate cache file. Running `audit` and `report` from a cached inventory makes the check/report loop fast and independent of live API access.

---

## 4. Authentication — Key Flow

**File:** `stackit_audit/auth/key_flow.py`

### Why Key Flow?

STACKIT's primary machine-to-machine authentication mechanism is *Key Flow*: instead of a static long-lived API key, the service account signs a short-lived JWT with its RSA private key and exchanges it for a Bearer token at the STACKIT token endpoint. This is safer than storing static tokens because:

1. The private key never leaves the signing machine.
2. Bearer tokens are short-lived (typically 30 minutes).
3. Token compromise can be limited by revoking the service account key.

### Data structures

```
ServiceAccountKey (dataclass)
├── key_id               — matches "id" or "kid" in the downloaded JSON
├── service_account_email
├── issuer               — "iss" claim; usually the SA email
├── audience             — "aud" claim for the token endpoint
├── private_key_pem      — RSA private key in PKCS#8 / PKCS#1 PEM
└── raw                  — original JSON dict (for future fields)
```

The key file is the JSON blob downloaded from the STACKIT portal. Its structure varies slightly between versions; the `from_dict` method tolerates multiple field name variants (`privateKey`, `credentials.privateKey`).

### Token exchange flow

```
1. Load key file from disk (KeyFlowAuth.from_key_file)
2. Build self-signed JWT:
   iss = sa_key.issuer
   sub = sa_key.issuer
   aud = token_endpoint
   iat = now
   exp = now + 600s
   jti = key_id + "-" + now   (replay protection)
   signed with RS512
3. POST to https://service-account.api.stackit.cloud/token
   grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
   assertion  = <signed JWT>
4. Cache returned access_token until expires_in - 60s
5. Return Bearer token for each API request
```

### Token caching

`KeyFlowAuth` caches the Bearer token in memory. Re-use is gated on:

```python
clock() < self._access_expires_at - TOKEN_REFRESH_SAFETY_S  # 60s safety margin
```

The `clock` parameter is injectable for testing (pass a fake `time.time`). The HTTP client is also injectable, enabling unit tests that don't touch the network.

### Error handling

`AuthError(RuntimeError)` is raised for:
- Key file not found / invalid JSON
- Missing required fields (`privateKey`, `id`, `iss`)
- Token endpoint unreachable
- Non-200 response from token endpoint
- `access_token` absent from response

Error messages deliberately **do not include the private key material** or the raw response body beyond 300 characters.

---

## 5. API Client Layer

**Files:** `stackit_audit/api_client/`

### Base client

`StackitApiClient` (`base.py`) is a thin wrapper around `httpx.Client` that:

- Prepends `base_url` to every path
- Injects `Authorization: Bearer <token>` on every request
- Retries on `429`, `502`, `503`, `504` with linear back-off (`0.5 × attempt` seconds)
- Automatically refreshes the token on `401`
- Surfaces errors as `StackitApiError(status_code, url)` so callers can record them without crashing
- Provides a `paginate()` generator that follows STACKIT's cursor-based pagination

### Service modules

Each service module is ~20–40 lines and has exactly one responsibility: translate Python method calls into HTTP calls against its base URL.

| Module | Base URL | Key methods |
|---|---|---|
| `resource_manager.py` | `resource-manager.api.stackit.cloud` | `get_project` |
| `authorization.py` | `authorization.api.stackit.cloud` | `list_memberships` |
| `service_account.py` | `service-account.api.stackit.cloud` | `list_service_accounts`, `list_keys` |
| `iaas.py` | `iaas.api.{region}.stackit.cloud` | `list_security_groups`, `list_security_group_rules`, `list_servers`, `list_volumes`, `list_public_ips` |
| `object_storage.py` | `object-storage.api.{region}.stackit.cloud` | `list_buckets` |
| `ske.py` | `ske.api.stackit.cloud` | `list_clusters` |
| `dbflex.py` | per-engine regional URL | `list_instances(engine, project_id)` |
| `load_balancer.py` | `load-balancer.api.{region}.stackit.cloud` | `list_load_balancers` |
| `dns.py` | `dns.api.stackit.cloud` | `list_zones` |
| `secrets_manager.py` | `secrets-manager.api.{region}.stackit.cloud` | `list_instances` |
| `observability.py` | regional | `list_observability_instances`, `list_logme_instances` |
| `audit_log.py` | `audit-log.api.{region}.stackit.cloud` | `list_entries(project_id, days)` |

### Endpoint constants

`endpoints.py` centralises all base URL templates:

```python
# Global (no region)
RESOURCE_MANAGER = "https://resource-manager.api.stackit.cloud"

# Regional (substitute {region})
IAAS = "https://iaas.api.{region}.stackit.cloud"
```

`regional(template, region)` is the single substitution function. This prevents typos and makes region changes a one-file edit.

### Design rationale — why not the official STACKIT Python SDK?

The official `stackit-*` PyPI packages wrap the same REST APIs but add significant dependency weight and SDK-specific abstractions. Using `httpx` directly keeps the tool lean, makes the HTTP calls transparent in logs, and avoids coupling to SDK version churn. If the SDK matures to cover all endpoints cleanly, service modules can be replaced one-by-one without touching the rest of the codebase.

---

## 6. Discovery Orchestrator

**File:** `stackit_audit/discovery/orchestrator.py`

### Responsibility

The orchestrator iterates over a list of project IDs, calls all service modules, and aggregates the results into an `Inventory` object. It is the only module that knows about the cross-service order of operations (e.g. service accounts must be listed before their keys can be fetched).

### Error isolation

Every API call is wrapped in a `safe(api_name, fn, *args)` closure:

```python
def safe(api_name, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except StackitApiError as exc:
        inv.errors.append(DiscoveryError(
            project_id=project_id, api=api_name,
            message=str(exc), status_code=exc.status_code
        ))
        return None
    except Exception as exc:
        inv.errors.append(DiscoveryError(...))
        return None
```

A `None` return causes the outer loop to skip that resource category and continue. This means a 403 on `ske.clusters` does not abort collection of IAM data. Errors are recorded in `inventory.errors` and surface in the report's "Limits" section.

The check engine treats a missing resource category as "no resources of that type" — checks that find nothing produce no FAIL findings, but the orchestrator's errors turn into `UNKNOWN` findings via a separate synthetic path in the manual checks module.

### Inventory model

```python
class Inventory(BaseModel):
    schema_version: str = "1.0"
    generated_at: datetime
    scope: dict          # {"project_ids": [...], "region": "eu01"}
    resources: list[Resource]
    errors: list[DiscoveryError]
```

`Inventory` is serialised to `inventory.json` by the `discover` subcommand. The `audit` subcommand reads it back, reconstructing `Resource` objects with Pydantic. This decoupling is intentional — the audit phase can be re-run against the same snapshot without any API calls, making check development fast.

### Resource collection order (per project)

```
1.  resource_manager.project        (project metadata)
2.  authorization.memberships       (IAM roles)
3.  service_account.accounts        (SA list)
4.  service_account.keys            (per SA — requires SA list from step 3)
5.  iaas.security_groups
6.  iaas.security_group_rules       (per SG — requires SG list from step 5)
7.  iaas.servers
8.  iaas.volumes
9.  iaas.public_ips
10. object_storage.buckets
11. ske.clusters
12. dbflex.{postgres,mariadb,mongodb,redis,opensearch,rabbitmq}
13. load_balancer.lbs
14. dns.zones
15. secrets_manager.instances
16. observability + logme instances
17. audit_log.entries (last 30 days)
```

Dependencies in steps 4 and 6 are the only sequential constraints; all other service calls are logically independent and could be parallelised in a future version.

---

## 7. Normalization Layer

**File:** `stackit_audit/normalization/resources.py`

### Purpose

STACKIT APIs use inconsistent field names across services (e.g. `projectId` vs `id` vs `containerId` for a project's ID). The normalization layer maps every API response shape into a single canonical `Resource` schema, so checks can read `r.attrs["created_at"]` without worrying about which service provided the resource.

### Canonical Resource schema

```python
class Resource(BaseModel):
    resource_type: str          # e.g. "service_account.key"
    resource_id:   str          # stable, service-specific ID
    resource_name: str | None
    scope: ResourceScope        # {organization_id, project_id, region}
    attrs: dict[str, Any]       # normalized field names
    raw: dict[str, Any]         # original API payload (for evidence)
```

`raw` is preserved so checks can access fields not extracted into `attrs`. This is important for heuristic checks that inspect non-standard fields.

### Tolerance strategy

All normalizers use `_pick(d, *keys, default=None)` — a utility that tries a list of candidate field names and returns the first non-None hit:

```python
def _pick(d, *keys, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default
```

This means a schema change in the STACKIT API produces a `Resource` with some `attrs` set to `None` rather than an exception. Checks that find `None` where they expect a value must produce `UNKNOWN`, not `PASS` — this is enforced by convention in each check's implementation.

### Resource type taxonomy

| `resource_type` | Source API | Key `attrs` |
|---|---|---|
| `resource_manager.project` | Resource Manager | `lifecycle_state` |
| `authorization.membership` | Authorization | `role`, `subject_type`, `subject_id`, `expires_at` |
| `service_account.account` | Service Account | `email`, `active` |
| `service_account.key` | Service Account | `service_account_email`, `active`, `created_at`, `valid_until` |
| `iaas.security_group` | IaaS | `name`, `stateful` |
| `iaas.security_group_rule` | IaaS | `direction`, `protocol`, `port_range_min`, `port_range_max`, `remote_ip_prefix`, `security_group_id` |
| `iaas.server` | IaaS | `status`, `public_ip_id`, `security_group_ids`, `network_interface_ids` |
| `iaas.volume` | IaaS | `status`, `size`, `encrypted` |
| `iaas.public_ip` | IaaS | `ip`, `server_id` |
| `object_storage.bucket` | Object Storage | `name`, `public_access`, `acl` |
| `ske.cluster` | SKE | `kubernetes_version`, `acl_enabled`, `acl_allowed_cidrs`, `status` |
| `dbflex.{engine}.instance` | DB Flex | `engine`, `version`, `is_public`, `acl`, `backup_enabled`, `backup_schedule` |
| `load_balancer.lb` | Load Balancer | `name`, `status`, `listeners[]` |
| `dns.zone` | DNS | `name`, `state` |
| `secrets_manager.instance` | Secrets Manager | `name`, `state` |
| `observability.instance` | Observability/LogMe | `name`, `plan_name`, `kind` |
| `audit_log.entry` | Audit Log | `action`, `resource_type`, `project_id`, `initiator`, `timestamp` |
| `org.manual_control` | (synthetic) | `area`, `framework_refs`, `rationale` |

---

## 8. Check Engine

**Files:** `stackit_audit/checks/engine.py`, `stackit_audit/checks/base.py`

### Check anatomy

Every check is a Python class:

```python
class NET001SshOpenWorld(CheckBase):
    META = Check(                       # static metadata (Pydantic model)
        check_id="NET-001",
        title="SSH (port 22) reachable from the internet",
        severity="critical",
        domain="Network",
        framework_refs=["CCM:IVS-04", "C5:KOS-04"],
        automated_assurance_level="automated",
        remediation="Restrict to a bastion CIDR or VPN range.",
        ...
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        # Filter, evaluate, return findings
        ...
```

`CheckBase` provides `make_finding(resource, status, rationale, ...)` which stamps all the metadata from `META` onto a `Finding` object, avoiding repetition.

### ALL_CHECKS registry

`engine.py` maintains an explicit list:

```python
ALL_CHECKS: list[type[CheckBase]] = [
    IAM001PrivilegedServiceAccounts,
    IAM002OldServiceAccountKeys,
    ...  # 20 entries
]
```

This is the single source of truth used by:
- `CheckEngine` when instantiating checks
- `aggregator.py` when computing coverage statistics
- The `--include-only` and `--exclude` CLI flags

### CheckEngine

```python
class CheckEngine:
    def __init__(
        self,
        check_classes=None,     # defaults to ALL_CHECKS
        include_only=None,      # filter by check_id
        exclude=None,           # filter by check_id
    ): ...

    def run(self, resources: list[Resource]) -> list[Finding]:
        findings = []
        for chk in self.checks:
            try:
                findings.extend(chk.run(resources))
            except Exception as exc:
                log.exception("Check %s crashed: %s", chk.META.check_id, exc)
        return findings
```

Individual check crashes are caught and logged; the engine continues with the remaining checks. This prevents a bug in one check from silently suppressing all subsequent findings.

### Finding status semantics

| Status | Meaning |
|---|---|
| `FAIL` | Evidence clearly shows non-compliance |
| `PARTIAL` | Partially compliant or evidence is incomplete but a problem is likely |
| `UNKNOWN` | Cannot determine — API field missing, endpoint unreachable, or manual-only control |
| `PASS` | Evidence confirms compliance |
| `NOT_APPLICABLE` | Check does not apply to this resource in this context |

**Critical rule:** a missing API field must never produce `PASS`. If the expected data is absent, the check must return `UNKNOWN` with `manual_review_required: true`.

---

## 9. MVP Check Catalogue

### IAM Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `IAM-001` | Service accounts assigned privileged project roles | High | Automated |
| `IAM-002` | Service-account keys older than 90 days | Medium | Automated |
| `IAM-003` | Service account with multiple active keys (rotation hygiene) | Low | Automated |
| `IAM-004` | Project memberships without expiry on privileged roles | Medium | Heuristic |
| `IAM-005` | MFA on privileged identities (manual check) | High | Manual |

**IAM-001 logic:**
```
For each authorization.membership:
  IF role ∈ {owner, project.owner, project.admin, admin, ...}
  AND subject looks like a service account (type="serviceAccount" or email contains @sa.)
  THEN FAIL
```

**IAM-002 logic:**
```
For each service_account.key:
  IF active == true
  AND (now - created_at) > 90 days
  THEN FAIL
```

**IAM-005** is a deliberate `UNKNOWN` emitter — it signals that MFA cannot be verified via the STACKIT Authorization API and must be checked in the IdP. It only fires for human (non-SA) privileged memberships.

### Network Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `NET-001` | SSH (port 22) reachable from the internet | Critical | Automated |
| `NET-002` | RDP (port 3389) reachable from the internet | Critical | Automated |
| `NET-003` | Database ports reachable from the internet | Critical | Automated |
| `NET-004` | Server with public IP and permissive security group | High | Heuristic |
| `NET-005` | Object Storage bucket with public access | High | Heuristic |
| `NET-006` | Load balancer with HTTP-only listener | High | Automated |

**NET-001/002/003 share the same helper logic:**

```python
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
DB_PORTS = {3306, 5432, 1433, 27017, 6379, 9200}

def _is_world_ingress_tcp(rule, port):
    return (
        rule.attrs["direction"] == "ingress"
        and rule.attrs["protocol"] in ("tcp", "any", "all", "")
        and rule.attrs["remote_ip_prefix"] in WORLD_CIDRS
        and port_range_covers(rule.attrs, port)
    )
```

**NET-004** is heuristic: it correlates `iaas.server` resources against their attached security groups. A server is flagged if it has a public IP **and** at least one attached SG has an ingress world-CIDR rule on a non-ICMP, sub-1024 port.

### Database Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `DB-001` | DB Flex instance with public network access | Critical | Heuristic |
| `DB-002` | DB Flex instance without observable backup config | Medium | Heuristic |
| `DB-003` | Database engine version below supported floor | High | Automated |

**DB-003** references `frameworks/eol_versions.yaml` for version thresholds:

```yaml
postgres: "13"
mariadb: "10.6"
mongodb: "5.0"
redis: "6.2"
opensearch: "2.0"
rabbitmq: "3.10"
```

Version comparison uses tuple-of-ints to handle `13` < `13.4` correctly.

### Kubernetes Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `K8S-001` | SKE cluster control plane accessible from the internet | Critical | Heuristic |
| `K8S-002` | SKE cluster running unsupported Kubernetes version | High | Automated |

**K8S-001** looks for `acl_enabled == false` or `acl_allowed_cidrs` containing `0.0.0.0/0`. Degraded to `UNKNOWN` if the ACL field is absent.

### Crypto Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `CRYPTO-001` | IaaS volume without encryption indicator | Medium | Heuristic |

This check is `PARTIAL` when the API does not expose the encryption field (which is the common case as of v0.1.0). It is `FAIL` only when the field is present and explicitly `false`.

### Logging Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `LOG-001` | Project with no audit log activity in 30 days | Medium | Heuristic |
| `LOG-002` | Project without Observability or LogMe instance | Medium | Heuristic |

Both are heuristic because absence of audit entries could mean "nothing happened" or "logging not configured".

### Secrets Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `SECRET-001` | Active SA key never seen in audit logs | Medium | Heuristic |

### Organisational Domain

| Check ID | Title | Severity | Assurance |
|---|---|---|---|
| `ORG-001` | Manual CCM/C5 controls checklist | Info | Manual |

`ORG-001` reads `frameworks/manual_controls.yaml` and emits one `UNKNOWN` finding per entry. This makes the report explicit about what was *not* checked, preventing a reader from assuming silence means compliance.

---

## 10. Framework Mappings

**Files:** `stackit_audit/frameworks/ccm_v4.yaml`, `stackit_audit/frameworks/c5_2020.yaml`, `stackit_audit/frameworks/mapping.py`

### N:M mapping model

A single check can satisfy multiple framework controls; a single framework control may require multiple checks:

```
NET-001  →  CCM:IVS-04, C5:KOS-04
NET-003  →  CCM:IVS-04, CCM:IVS-09, C5:KOS-04
IAM-002  →  CCM:IAM-04, C5:IDM-09, C5:KRY-03
```

`framework_refs` on each check carries the authoritative mapping. The YAML files contain the narrative descriptions; the Python class carries the machine-readable refs used in report tables.

### Important disclaimer

The CCM/C5 mapping reflects the authors' interpretation. It is:
- A readiness assessment aid, not a certification opinion
- Subject to interpretation differences between auditors
- Deliberately conservative — checks map only controls they directly address

### Manual controls YAML

`manual_controls.yaml` lists the CCM/C5 areas the tool deliberately skips:

```yaml
- area: "Personnel security & training"
  framework_refs: ["CCM:HRS-01", "CCM:HRS-04", "C5:HR-01", "C5:HR-03"]
  rationale: "HR processes, screening, training records — outside any cloud API."
```

This populates the **Manual Review** section in all three report formats.

---

## 11. Scoring and Prioritization

**Files:** `stackit_audit/scoring/aggregator.py`, `stackit_audit/scoring/prioritizer.py`

### Aggregation

`aggregate(findings)` returns an `AggregationSummary` Pydantic model:

```python
class AggregationSummary(BaseModel):
    totals_by_status:    dict[str, int]   # FAIL: 3, PARTIAL: 2, ...
    totals_by_severity:  dict[str, int]   # critical: 1, high: 4, ...
    totals_by_domain:    dict[str, int]   # IAM: 3, Network: 5, ...
    totals_by_framework: dict[str, int]   # CCM:IAM-04: 2, ...
    coverage:            dict[str, int]   # checks_run, automated, heuristic, manual
```

Coverage statistics are computed from `ALL_CHECKS` at aggregation time, not from findings. This means even a scan against an empty project correctly reports "21 checks run".

### Prioritization

`top_findings(findings, n=10)` sorts by `(severity_rank, status_rank, check_id)`:

```
critical/FAIL > critical/PARTIAL > high/FAIL > high/PARTIAL > ...
```

This appears in the "Top Findings" table in all three report formats.

### No compliance score

The tool deliberately produces no "X% CCM-compliant" percentage. Such a number would be:
1. Misleading (only 15–20% of CCM controls are API-checkable)
2. Not meaningful for certification purposes
3. Likely to be misread as a pass/fail certification gate

Reports instead state the raw counts and let the reader draw conclusions.

---

## 12. Reporting (JSON, Markdown, PDF)

### 12.1 findings.json

**File:** `stackit_audit/reporting/json_writer.py`

`build_findings_document()` assembles the canonical output document:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0",
  "scan": {
    "started_at": "2024-01-15T09:00:00Z",
    "finished_at": "2024-01-15T09:03:21Z",
    "scope": {"project_ids": ["proj-eu01-abc"], "region": "eu01"},
    "auth": {"method": "key_flow", "service_account_email": "audit@proj.iam.stackit.cloud"}
  },
  "summary": {
    "totals_by_status": {"FAIL": 4, "PARTIAL": 3, "UNKNOWN": 2, "PASS": 1},
    "totals_by_severity": {"critical": 2, "high": 3, "medium": 3, "low": 0, "info": 2},
    "totals_by_domain": {"IAM": 3, "Network": 4, ...},
    "coverage": {"checks_run": 21, "automated": 14, "heuristic": 5, "manual": 2}
  },
  "findings": [...]
}
```

Sensitive fields in `api_evidence` are redacted by `utils/redact.py` before serialisation. The `SENSITIVE_KEYS` set covers `private_key`, `password`, `token`, `access_token`, `api_key`, etc.

### 12.2 report.md

**File:** `stackit_audit/reporting/markdown_writer.py`

Sections:
1. Title block (tool version, scan times, service account, project IDs, region)
2. Executive Summary (severity/status counts, coverage)
3. Top 10 Findings (sorted table)
4. Findings by Severity (one sub-table per severity level, excluding PASS)
5. Findings by Framework (CCM and C5 separately)
6. Manual Review (items from `manual_controls.yaml`)
7. Limits of This Assessment

Pipe characters in cell values are escaped (`|` → `\|`) and newlines are collapsed to spaces to maintain valid Markdown table syntax.

### 12.3 report.pdf

**Files:** `stackit_audit/pdf_rendering/pdf_builder.py`, `sections.py`, `styles.py`

Built with **ReportLab** (pure Python, no external browser or TeX dependency).

#### Why ReportLab?

| Alternative | Problem |
|---|---|
| WeasyPrint | Requires GTK/cairo system libraries — complicates install |
| wkhtmltopdf | Requires a headless browser binary |
| Pandoc | External binary dependency, complex pipeline |
| ReportLab | Pure Python, `pip install reportlab`, batteries-included tables |

#### PDF structure

| Section | `sections.py` function |
|---|---|
| Title page | `title_page()` |
| 1. Executive Summary | `executive_summary()` |
| 2. Top Findings | `top_findings_section()` |
| 3. Findings by Severity | `findings_by_severity()` |
| 4. Findings by Framework | `findings_by_framework()` |
| 5. Manual Review | `manual_review_section()` |
| 6. Limits | `limitations_section()` |

#### Colour scheme

Severity colours are defined in `styles.py`:

```python
SEV_COLORS = {
    "critical": "#C0392B",   # red
    "high":     "#E67E22",   # orange
    "medium":   "#F1C40F",   # yellow
    "low":      "#3498DB",   # blue
    "info":     "#95A5A6",   # grey
}
```

The layout is designed to be readable when printed in black-and-white (severity names are also shown as text, not colour-only).

---

## 13. CLI Dispatcher

**File:** `stackit_audit/cli/main.py`

### Subcommands

#### `discover`

```bash
stackit-audit discover \
  --service-account-key ./sa-key.json \
  --project-id proj-eu01-abc \
  --project-id proj-eu01-def \
  --region eu01 \
  --output inventory.json
```

Runs the discovery orchestrator and writes `inventory.json`. Multiple `--project-id` flags collect resources across projects into a single inventory.

#### `audit`

```bash
stackit-audit audit \
  --inventory inventory.json \
  --output findings.json \
  --fail-on critical \
  --exclude IAM-004,K8S-001
```

Loads `inventory.json`, runs the check engine, writes `findings.json`. `--fail-on` sets the severity threshold for non-zero exit codes. `--include-only` and `--exclude` accept comma-separated check IDs.

#### `report`

```bash
stackit-audit report \
  --findings findings.json \
  --formats json,md,pdf \
  --output-dir ./out/
```

Renders the three report formats from an existing `findings.json`. Can be re-run without re-running discovery or audit.

#### `run`

```bash
stackit-audit run \
  --service-account-key ./sa-key.json \
  --project-id proj-eu01-abc \
  --output-dir ./out/ \
  --formats json,md,pdf \
  --fail-on high
```

Convenience pipeline: runs discover → audit → report in a temp directory. The temp directory is cleaned up on completion; only the final artefacts in `--output-dir` are kept.

### Exit codes

| Code | Constant | Meaning |
|---|---|---|
| `0` | `SUCCESS` | Run completed, no findings at/above threshold |
| `2` | `FINDINGS_ABOVE_THRESHOLD` | Run completed, actionable findings found |
| `10` | `CONFIG_OR_AUTH_ERROR` | Invalid config, missing key file, auth failure |
| `20` | `API_ERROR_BUDGET_EXCEEDED` | Discovery partially or fully failed |
| `30` | `INTERNAL_ERROR` | Unhandled exception |

Exit code `2` vs `0` is the CI/CD gate. A pipeline can fail a build on any critical finding:

```yaml
# GitHub Actions example
- run: stackit-audit run --service-account-key $SA_KEY_PATH --project-id $PROJECT_ID --fail-on critical
```

---

## 14. Data Models Reference

**Files:** `stackit_audit/models/`

### Finding

The central output unit. Every check produces zero or more `Finding` objects.

```python
class Finding(BaseModel):
    finding_id: str           # UUIDv4, generated at instantiation
    check_id: str             # e.g. "NET-001"
    title: str                # human-readable, includes resource name where possible
    status: FindingStatus     # PASS | FAIL | PARTIAL | UNKNOWN | NOT_APPLICABLE
    severity: Severity        # critical | high | medium | low | info
    framework_refs: list[str] # ["CCM:IVS-04", "C5:KOS-04"]
    framework_names: list[str]
    domain: str               # IAM | Network | Crypto | ...
    resource_type: str        # e.g. "iaas.security_group_rule"
    resource_id: str          # STACKIT-assigned ID
    resource_name: str | None
    resource_scope: dict      # {organization_id, project_id, region}
    api_evidence: dict        # exact fields from API that triggered the finding
    derived_evidence: dict    # computed values (e.g. age_days: 120)
    rationale: str            # why this is FAIL/PARTIAL/UNKNOWN
    risk: str                 # business/security impact
    remediation: str          # concrete steps
    assurance_level: AssuranceLevel  # automated | heuristic | manual
    manual_review_required: bool
    timestamp: datetime
    tool_version: str
```

The distinction between `rationale` and `risk`:
- `rationale` = why the check fired on this specific resource ("Key is 120 days old")
- `risk` = the broader security implication from `META.rationale` ("Stale keys widen blast radius")

### Check (metadata model)

```python
class Check(BaseModel):
    check_id: str
    title: str
    description: str
    framework_refs: list[str]
    framework_names: list[str]
    domain: Domain
    severity: Severity
    rationale: str               # risk description (becomes Finding.risk)
    resource_types: list[str]    # resource types this check targets
    required_data_points: list[str]
    automated_assurance_level: AssuranceLevel
    manual_review_required: bool = False
    evaluation_logic: str        # human-readable pseudo-code
    remediation: str
    version: str = "1.0"
```

### Resource

```python
class Resource(BaseModel):
    resource_type: str
    resource_id: str
    resource_name: str | None
    scope: ResourceScope     # {organization_id, project_id, region}
    attrs: dict[str, Any]    # normalized fields
    raw: dict[str, Any]      # original API payload
```

---

## 15. Security Model

### What the tool can see

The tool requires a STACKIT service account with **read** permissions on the target projects. It accesses:

- IAM configuration (memberships, SA keys)
- Network configuration (security groups, public IPs)
- Resource metadata (server names, DB instance names, cluster names)
- Audit log entries (who did what, when)
- Secrets Manager instance *list* (not secret values)

It does **not** access:
- Secret values from Secrets Manager
- Encryption key material from KMS
- VM image contents or running process state
- Credentials stored inside VMs

### Credential handling

- The private key is loaded into memory as a string and used only to sign JWTs.
- It is never written to disk, logged, or included in findings.
- The Bearer token is cached in memory and discarded when the process exits.
- `api_evidence` in findings is passed through `redact()` before writing to `findings.json`. The `SENSITIVE_KEYS` set (`private_key`, `password`, `token`, `access_token`, `api_key`, `client_secret`, `key_material`, `apiKey`) causes those values to be replaced with `***REDACTED***`.

### Findings data classification

`findings.json` and `report.pdf` contain:
- Resource names and IDs (treat as **internal/confidential**)
- Configuration details that reveal your attack surface
- Audit log metadata

These artefacts should be treated as security-sensitive documents and not stored in public repositories or unprotected shared drives.

### Network

All API calls go to `*.api.stackit.cloud` over HTTPS. SSL verification is not disabled anywhere. No data is sent to any third-party endpoint.

---

## 16. Known Limits and Degradation Behaviour

| Area | Limit | Reported as |
|---|---|---|
| Volume encryption-at-rest | `encrypted` field not consistently exposed | `PARTIAL` or `UNKNOWN` |
| Object Storage public ACL | ACL field naming varies; may not be exposed | `UNKNOWN` |
| DB Flex public access | `is_public`/`acl` field availability varies by engine | `UNKNOWN` if absent |
| MFA on user accounts | Authorization API has no MFA field | `UNKNOWN` (manual) |
| KMS key bindings | KMS API is beta; resource bindings not queryable | Not checked |
| Audit log retention | API returns entries but not the configured retention period | `PARTIAL` |
| SKE control-plane ACL | Field name varies by cluster version | `UNKNOWN` if absent |
| SA `last_used_at` | Not exposed; SECRET-001 falls back to audit-log heuristic | `PARTIAL` |

When a service returns a `403` or `404`, the discovery layer records a `DiscoveryError` and the relevant resource category is absent from the inventory. Checks that find no resources of their target type produce no findings — which is indistinguishable from "all resources of that type are compliant". This is why the `inventory.errors` list must be reviewed alongside findings.

---

## 17. Extending the Tool

### Adding a new check

1. Choose a check ID (e.g. `NET-007`)
2. Create the class in the appropriate `checks/*.py` file:

```python
class NET007MyNewCheck(CheckBase):
    META = Check(
        check_id="NET-007",
        title="...",
        description="...",
        framework_refs=["CCM:IVS-04"],
        framework_names=["CCM v4"],
        domain="Network",
        severity="high",
        rationale="...",
        resource_types=["iaas.security_group_rule"],
        required_data_points=["some_field"],
        automated_assurance_level="automated",
        remediation="...",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out = []
        for r in resources:
            if r.resource_type != "iaas.security_group_rule":
                continue
            val = r.attrs.get("some_field")
            if val is None:
                out.append(self.make_finding(r, status="UNKNOWN",
                    rationale="Field 'some_field' not present in API response."))
            elif val == "bad_value":
                out.append(self.make_finding(r, status="FAIL",
                    rationale=f"some_field is '{val}'.",
                    api_evidence={"some_field": val}))
        return out
```

3. Register it in `checks/engine.py`:

```python
from stackit_audit.checks.network_checks import ..., NET007MyNewCheck

ALL_CHECKS: list[type[CheckBase]] = [
    ...
    NET007MyNewCheck,
]
```

4. Write a test in `tests/checks/test_network_checks.py`.

### Adding a new API service

1. Add the base URL to `api_client/endpoints.py`
2. Create a client module in `api_client/` that subclasses or uses `StackitApiClient`
3. Add normalizer(s) in `normalization/resources.py`
4. Wire up collection in `discovery/orchestrator.py`
5. Register the resource type in the taxonomy table above

### Updating EOL version thresholds

Edit `frameworks/eol_versions.yaml` — no code change needed. `DB-003` and `K8S-002` load this file at check instantiation time.

### Updating manual controls

Edit `frameworks/manual_controls.yaml` — no code change needed. `ORG-001` loads this file at run time and emits one `UNKNOWN` finding per entry.

---

## 18. Glossary

| Term | Definition |
|---|---|
| **CCM** | Cloud Controls Matrix v4 — CSA's framework of ~197 cloud security controls across 17 domains |
| **C5** | BSI Cloud Computing Compliance Criteria Catalogue 2020 — 121 requirements across 17 areas |
| **Key Flow** | STACKIT's RSA-JWT-based machine authentication mechanism |
| **SA** | Service Account — a non-human STACKIT identity for programmatic access |
| **SG / SGR** | Security Group / Security Group Rule — virtual firewall constructs in STACKIT IaaS |
| **SKE** | STACKIT Kubernetes Engine |
| **DB Flex** | STACKIT's managed database services (Postgres, MariaDB, MongoDB, Redis, OpenSearch, RabbitMQ) |
| **Assurance level** | `automated` — API field is definitive; `heuristic` — inferred, may have false positives; `manual` — not API-verifiable |
| **Inventory** | The `inventory.json` file produced by `discover` — a snapshot of all discovered resources |
| **Finding** | A single check result tied to a specific resource |
| **Evidence** | The exact API fields (`api_evidence`) or computed values (`derived_evidence`) that justify the finding status |
| **Redaction** | Replacement of sensitive field values with `***REDACTED***` before writing to disk |
