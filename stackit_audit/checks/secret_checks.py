from __future__ import annotations

from datetime import datetime, timedelta, timezone

from stackit_audit.checks.base import CheckBase
from stackit_audit.checks.iam_checks import _parse_dt
from stackit_audit.models import Check, Finding, Resource


class SECRET001UnusedSaKeys(CheckBase):
    META = Check(
        check_id="SECRET-001",
        title="Active service-account keys with no observed usage",
        description="A key older than 30 days with no audit-log activity by its owner is likely orphaned.",
        framework_refs=["CCM:IAM-04", "C5:IDM-09"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Secrets",
        severity="medium",
        rationale="Unused credentials are pure liability — they cannot be reissued without disrupting nothing.",
        resource_types=["service_account.key", "audit_log.entry"],
        required_data_points=["service_account_email", "audit_log.initiator"],
        automated_assurance_level="heuristic",
        evaluation_logic="key.active AND age > 30d AND no audit_log_entry whose initiator == sa email",
        remediation="Disable the key; if a consumer breaks, rotate that consumer onto a fresh key.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        sa_to_initiators: dict[str, set[str]] = {}
        for r in resources:
            if r.resource_type != "audit_log.entry":
                continue
            init = r.attrs.get("initiator")
            if isinstance(init, dict):
                ident = init.get("email") or init.get("id") or init.get("name")
                if ident:
                    sa_to_initiators.setdefault(str(ident), set()).add(r.resource_id)
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=30)
        for r in resources:
            if r.resource_type != "service_account.key":
                continue
            if not bool(r.attrs.get("active", True)):
                continue
            sa_email = r.attrs.get("service_account_email") or ""
            created = _parse_dt(r.attrs.get("created_at"))
            if not created or created > cutoff:
                continue
            if sa_email and sa_email in sa_to_initiators and sa_to_initiators[sa_email]:
                continue
            out.append(
                self.make_finding(
                    r, status="FAIL",
                    rationale=f"Key is active, older than 30 days, and SA '{sa_email}' has no audit-log activity.",
                    api_evidence={"service_account_email": sa_email, "created_at": str(created)},
                )
            )
        return out
