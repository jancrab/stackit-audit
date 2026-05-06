from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from stackit_audit.checks.base import CheckBase
from stackit_audit.models import Check, Finding, Resource

PRIVILEGED_ROLES = {
    "owner", "project.owner", "organization.owner", "project.admin",
    "admin", "resource-manager.admin", "iam.admin",
}


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


class IAM001PrivilegedServiceAccounts(CheckBase):
    META = Check(
        check_id="IAM-001",
        title="Service accounts assigned privileged project roles",
        description="Service accounts holding owner/admin roles violate least privilege.",
        framework_refs=["CCM:IAM-09", "CCM:IAM-16", "C5:IDM-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="IAM",
        severity="high",
        rationale="Compromise of a single SA token grants full project control.",
        resource_types=["authorization.membership"],
        required_data_points=["role", "subject_type", "subject_id"],
        automated_assurance_level="automated",
        evaluation_logic="role IN PRIVILEGED_ROLES AND subject_type == 'service_account'",
        remediation="Reduce role to least-privileged equivalent; create dedicated SAs per duty.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "authorization.membership":
                continue
            role = (r.attrs.get("role") or "").lower()
            subj_type = (r.attrs.get("subject_type") or "").lower()
            subj_id = r.attrs.get("subject_id") or r.resource_name or ""
            looks_like_sa = "service" in subj_type or "service-account" in str(subj_id) or "@sa." in str(subj_id)
            if role in PRIVILEGED_ROLES and looks_like_sa:
                out.append(
                    self.make_finding(
                        r,
                        status="FAIL",
                        rationale=f"Service account '{subj_id}' holds privileged role '{role}'.",
                        api_evidence={"role": role, "subject": subj_id, "subject_type": subj_type},
                    )
                )
        return out


class IAM002OldServiceAccountKeys(CheckBase):
    META = Check(
        check_id="IAM-002",
        title="Service-account keys older than 90 days",
        description="Long-lived static credentials should be rotated regularly.",
        framework_refs=["CCM:IAM-04", "C5:IDM-09", "C5:KRY-03"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="IAM",
        severity="medium",
        rationale="Stale keys widen the blast radius of credential leaks.",
        resource_types=["service_account.key"],
        required_data_points=["created_at", "active"],
        automated_assurance_level="automated",
        evaluation_logic="now - created_at > 90d AND active == true",
        remediation="Rotate the key. Issue a new one, switch consumers, then disable the old.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=90)
        for r in resources:
            if r.resource_type != "service_account.key":
                continue
            created = _parse_dt(r.attrs.get("created_at"))
            active = bool(r.attrs.get("active", True))
            if active and created and created < cutoff:
                age_days = (datetime.now(tz=timezone.utc) - created).days
                out.append(
                    self.make_finding(
                        r,
                        status="FAIL",
                        rationale=f"Key is {age_days} days old (threshold: 90).",
                        api_evidence={"created_at": str(created), "active": active},
                        derived_evidence={"age_days": age_days},
                    )
                )
            elif active and not created:
                out.append(
                    self.make_finding(
                        r,
                        status="UNKNOWN",
                        rationale="Key has no observable createdAt; cannot evaluate age.",
                        api_evidence={"raw_keys": list(r.attrs.keys())},
                    )
                )
        return out


class IAM003MultipleActiveKeys(CheckBase):
    META = Check(
        check_id="IAM-003",
        title="Service account with multiple long-lived active keys",
        description="More than one active key (older than 30 days) per SA breaks key hygiene.",
        framework_refs=["CCM:IAM-04", "C5:IDM-09"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="IAM",
        severity="medium",
        rationale="Indicates incomplete rotation: leaked old keys remain usable.",
        resource_types=["service_account.key"],
        required_data_points=["service_account_email", "active", "created_at"],
        automated_assurance_level="automated",
        evaluation_logic="count(active keys per SA where age > 30d) > 1",
        remediation="Disable old keys after consumers migrate to the new one.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        per_sa: dict[str, list[Resource]] = {}
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=30)
        for r in resources:
            if r.resource_type != "service_account.key":
                continue
            if not bool(r.attrs.get("active", True)):
                continue
            created = _parse_dt(r.attrs.get("created_at"))
            if created and created > cutoff:
                continue
            sa = r.attrs.get("service_account_email") or "?"
            per_sa.setdefault(sa, []).append(r)
        for sa, keys in per_sa.items():
            if len(keys) > 1:
                first = keys[0]
                out.append(
                    self.make_finding(
                        first,
                        status="FAIL",
                        rationale=f"Service account '{sa}' has {len(keys)} active keys older than 30 days.",
                        api_evidence={"key_ids": [k.resource_id for k in keys], "service_account": sa},
                        derived_evidence={"active_long_lived_count": len(keys)},
                        title_override=f"SA '{sa}' has {len(keys)} long-lived active keys",
                    )
                )
        return out


class IAM004MembershipsWithoutExpiry(CheckBase):
    META = Check(
        check_id="IAM-004",
        title="Privileged memberships without expiry",
        description="Privileged role assignments should be time-bound and reviewed.",
        framework_refs=["CCM:IAM-08", "C5:IDM-06"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="IAM",
        severity="medium",
        rationale="Permanent privileged access escapes periodic review cycles.",
        resource_types=["authorization.membership"],
        required_data_points=["role", "expires_at"],
        automated_assurance_level="heuristic",
        manual_review_required=False,
        evaluation_logic="role IN PRIVILEGED_ROLES AND expires_at IS NULL",
        remediation="Use time-bound role grants; schedule access reviews quarterly.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "authorization.membership":
                continue
            role = (r.attrs.get("role") or "").lower()
            if role not in PRIVILEGED_ROLES:
                continue
            expires_at = r.attrs.get("expires_at")
            if expires_at:
                continue
            if "expires_at" not in r.attrs and "expiresAt" not in r.raw:
                out.append(
                    self.make_finding(
                        r,
                        status="PARTIAL",
                        rationale="Authorization API does not expose expires_at for this membership; cannot confirm time-bound access.",
                        api_evidence={"role": role, "subject_id": r.attrs.get("subject_id")},
                    )
                )
            else:
                out.append(
                    self.make_finding(
                        r,
                        status="FAIL",
                        rationale=f"Privileged membership '{role}' has no expires_at.",
                        api_evidence={"role": role, "subject_id": r.attrs.get("subject_id"), "expires_at": None},
                    )
                )
        return out


class IAM005MfaManualCheck(CheckBase):
    META = Check(
        check_id="IAM-005",
        title="MFA on privileged identities (manual)",
        description="STACKIT Authorization API does not expose MFA status; verify in your IdP/SSO.",
        framework_refs=["CCM:IAM-13", "C5:IDM-08"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="IAM",
        severity="high",
        rationale="Privileged accounts without MFA are the single highest credential-attack risk.",
        resource_types=["authorization.membership"],
        required_data_points=[],
        automated_assurance_level="manual",
        manual_review_required=True,
        evaluation_logic="N/A — verified via IdP/SSO outside STACKIT API",
        remediation="Enforce MFA at the IdP for any user holding a privileged STACKIT role.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "authorization.membership":
                continue
            role = (r.attrs.get("role") or "").lower()
            subj_type = (r.attrs.get("subject_type") or "").lower()
            if role in PRIVILEGED_ROLES and "service" not in subj_type:
                out.append(
                    self.make_finding(
                        r,
                        status="UNKNOWN",
                        rationale="MFA cannot be verified via STACKIT API; manual review required.",
                        api_evidence={"role": role, "subject_id": r.attrs.get("subject_id")},
                    )
                )
        return out
