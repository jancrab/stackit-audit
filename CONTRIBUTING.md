# Contributing to stackit-audit

Thank you for your interest in contributing. This document explains how to add checks,
run tests, and submit changes.

---

## Table of Contents

- [Development setup](#development-setup)
- [Project conventions](#project-conventions)
- [Adding a new check](#adding-a-new-check)
- [Adding a new API service](#adding-a-new-api-service)
- [Updating framework mappings](#updating-framework-mappings)
- [Running tests](#running-tests)
- [Submitting a pull request](#submitting-a-pull-request)

---

## Development setup

```bash
git clone https://github.com/jancrab/stackit-audit.git
cd stackit-audit
pip install -e ".[dev]"

# Verify everything works
pytest tests/ -q
```

Requirements: Python 3.10+, no other system dependencies.

---

## Project conventions

### Finding status rules

| Situation | Required status |
|---|---|
| Evidence clearly shows non-compliance | `FAIL` |
| Evidence is incomplete but a problem is likely | `PARTIAL` |
| Expected API field is absent | `UNKNOWN` with `manual_review_required=True` |
| Check doesn't apply to this resource | `NOT_APPLICABLE` |
| Evidence confirms compliance | `PASS` |

> **Critical rule:** a missing API field must never produce `PASS`. If the expected data
> is absent, produce `UNKNOWN`. Silence ≠ compliance.

### Assurance levels

- `automated` — the API field is authoritative; result is reliable
- `heuristic` — inferred from available signals; document the assumption in `rationale`
- `manual` — not API-verifiable; emit `UNKNOWN` to make it visible in the report

### Evidence fields

Every `FAIL` or `PARTIAL` finding must populate `api_evidence` with the exact API
field values that triggered the result. This makes findings auditable and reproducible.

```python
self.make_finding(
    r,
    status="FAIL",
    rationale="Key is 120 days old (threshold: 90).",
    api_evidence={"created_at": str(created), "active": active},
    derived_evidence={"age_days": 120},
)
```

---

## Adding a new check

### 1. Choose an ID

Follow the pattern `DOMAIN-NNN` where domain is one of:
`IAM`, `NET`, `DB`, `K8S`, `CRYPTO`, `LOG`, `SECRET`, `ORG`.

### 2. Implement the class

Place it in the appropriate `stackit_audit/checks/*.py` file:

```python
class NET007ExampleCheck(CheckBase):
    META = Check(
        check_id="NET-007",
        title="Short imperative title",
        description="One-to-three sentence description of what is checked and why.",
        framework_refs=["CCM:IVS-04", "C5:KOS-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="high",          # critical | high | medium | low | info
        rationale="Why this matters — becomes Finding.risk.",
        resource_types=["iaas.security_group_rule"],
        required_data_points=["some_field"],
        automated_assurance_level="automated",  # automated | heuristic | manual
        evaluation_logic="some_field == 'bad_value'",  # pseudo-code for humans
        remediation="Concrete steps to fix this in STACKIT.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out = []
        for r in resources:
            if r.resource_type != "iaas.security_group_rule":
                continue
            val = r.attrs.get("some_field")
            if val is None:
                out.append(self.make_finding(
                    r, status="UNKNOWN",
                    rationale="Field 'some_field' not present in API response.",
                ))
            elif val == "bad_value":
                out.append(self.make_finding(
                    r, status="FAIL",
                    rationale=f"some_field is '{val}'.",
                    api_evidence={"some_field": val},
                ))
        return out
```

### 3. Register the check

Add it to `ALL_CHECKS` in `stackit_audit/checks/engine.py`:

```python
from stackit_audit.checks.network_checks import ..., NET007ExampleCheck

ALL_CHECKS: list[type[CheckBase]] = [
    ...
    NET007ExampleCheck,
]
```

### 4. Write a test

Create or extend a test file in `tests/checks/`:

```python
class TestNET007:
    def test_fail_on_bad_value(self):
        r = Resource(
            resource_type="iaas.security_group_rule",
            resource_id="rule-001",
            scope=ResourceScope(project_id="proj-001"),
            attrs={"some_field": "bad_value"},
        )
        check = NET007ExampleCheck()
        assert any(f.status == "FAIL" for f in check.run([r]))

    def test_unknown_when_field_missing(self):
        r = Resource(
            resource_type="iaas.security_group_rule",
            resource_id="rule-001",
            scope=ResourceScope(project_id="proj-001"),
            attrs={},
        )
        check = NET007ExampleCheck()
        assert any(f.status == "UNKNOWN" for f in check.run([r]))

    def test_no_findings_for_other_resource_types(self):
        r = Resource(
            resource_type="iaas.server",
            resource_id="srv-001",
            scope=ResourceScope(project_id="proj-001"),
            attrs={"some_field": "bad_value"},
        )
        check = NET007ExampleCheck()
        assert check.run([r]) == []
```

---

## Adding a new API service

1. **Add the base URL** to `stackit_audit/api_client/endpoints.py`.
2. **Create a client module** in `stackit_audit/api_client/` using `StackitApiClient`:

```python
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client.endpoints import MY_NEW_SERVICE, regional
from stackit_audit.auth.key_flow import KeyFlowAuth

class MyNewServiceClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01") -> None:
        self._client = StackitApiClient(
            base_url=regional(MY_NEW_SERVICE, region),
            auth=auth,
        )

    def list_things(self, project_id: str) -> list[dict]:
        return list(self._client.paginate(
            f"/v1/projects/{project_id}/things",
            items_key="things",
        ))
```

3. **Add a normalizer** in `stackit_audit/normalization/resources.py`.
4. **Wire up collection** in `stackit_audit/discovery/orchestrator.py` inside `_discover_project`.

---

## Updating framework mappings

### EOL version thresholds

Edit `stackit_audit/frameworks/eol_versions.yaml` — no code change needed:

```yaml
postgres: "15"   # update when STACKIT drops support for older versions
```

### Manual controls list

Edit `stackit_audit/frameworks/manual_controls.yaml` to add or remove items
from the manual review checklist in reports.

---

## Running tests

```bash
# All tests
pytest tests/ -q

# With coverage
pytest tests/ --cov=stackit_audit --cov-report=term-missing

# Single module
pytest tests/checks/test_iam_checks.py -v
```

All tests run without network access. Fixtures and sample data live in `tests/conftest.py`.

---

## Submitting a pull request

1. Fork the repo and create a branch: `git checkout -b feat/NET-007-my-check`
2. Make your changes and add tests
3. Ensure `pytest tests/ -q` passes with no failures
4. Push and open a PR against `master`

Please include in the PR description:
- What the check/change does
- Which CCM/C5 controls it addresses (if a new check)
- Which STACKIT API fields it reads
- What `UNKNOWN` / `PARTIAL` degradation looks like when fields are absent
