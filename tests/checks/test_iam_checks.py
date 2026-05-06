"""Unit tests for IAM checks."""
from __future__ import annotations

import pytest

from stackit_audit.checks.iam_checks import (
    IAM001PrivilegedServiceAccounts,
    IAM002OldServiceAccountKeys,
    IAM003MultipleActiveKeys,
    IAM005MfaManualCheck,
)
from stackit_audit.models.resource import Resource, ResourceScope


def _scope():
    return ResourceScope(project_id="proj-001", region="eu01")


def _membership(role: str, subject_type: str = "serviceAccount") -> Resource:
    return Resource(
        resource_type="authorization.membership",
        resource_id="mem-001",
        scope=_scope(),
        attrs={"subject": "sa@proj.iam.stackit.cloud", "role": role, "subject_type": subject_type},
    )


def _key(days_old: int, active: bool = True) -> Resource:
    from datetime import datetime, timedelta, timezone
    created = (datetime.now(tz=timezone.utc) - timedelta(days=days_old)).isoformat()
    return Resource(
        resource_type="service_account.key",
        resource_id="key-001",
        scope=_scope(),
        attrs={
            "service_account_id": "sa-001",
            "service_account_email": "sa@proj.iam.stackit.cloud",
            "created_at": created,
            "active": active,
        },
    )


class TestIAM001:
    def test_fail_on_owner_role(self):
        check = IAM001PrivilegedServiceAccounts()
        findings = check.run([_membership("project.owner")])
        assert any(f.status == "FAIL" for f in findings)

    def test_pass_on_reader_role(self):
        check = IAM001PrivilegedServiceAccounts()
        findings = check.run([_membership("reader")])
        assert not any(f.status == "FAIL" for f in findings)

    def test_no_memberships(self):
        check = IAM001PrivilegedServiceAccounts()
        findings = check.run([])
        assert all(f.status != "FAIL" for f in findings)


class TestIAM002:
    def test_fail_on_old_key(self):
        check = IAM002OldServiceAccountKeys()
        findings = check.run([_key(days_old=100)])
        assert any(f.status == "FAIL" for f in findings)

    def test_pass_on_fresh_key(self):
        check = IAM002OldServiceAccountKeys()
        findings = check.run([_key(days_old=10)])
        assert not any(f.status == "FAIL" for f in findings)

    def test_inactive_key_not_flagged(self):
        check = IAM002OldServiceAccountKeys()
        findings = check.run([_key(days_old=200, active=False)])
        assert not any(f.status == "FAIL" for f in findings)


class TestIAM003:
    def test_fail_on_multiple_old_keys(self):
        from datetime import datetime, timedelta, timezone
        old_date = (datetime.now(tz=timezone.utc) - timedelta(days=40)).isoformat()
        keys = [
            Resource(
                resource_type="service_account.key",
                resource_id=f"key-{i}",
                scope=_scope(),
                attrs={
                    "service_account_id": "sa-001",
                    "service_account_email": "sa@proj",
                    "created_at": old_date,
                    "active": True,
                },
            )
            for i in range(2)
        ]
        check = IAM003MultipleActiveKeys()
        findings = check.run(keys)
        assert any(f.status == "FAIL" for f in findings)


class TestIAM005:
    def test_produces_unknown_finding_for_human_user(self):
        # IAM-005 only fires for human (non-service-account) privileged identities
        human_membership = Resource(
            resource_type="authorization.membership",
            resource_id="mem-human",
            scope=_scope(),
            attrs={"subject": "user@example.com", "role": "project.owner", "subject_type": "user"},
        )
        check = IAM005MfaManualCheck()
        findings = check.run([human_membership])
        assert findings
        assert all(f.status == "UNKNOWN" for f in findings)
        assert all(f.manual_review_required for f in findings)

    def test_does_not_fire_for_service_account(self):
        check = IAM005MfaManualCheck()
        findings = check.run([_membership("project.owner", subject_type="serviceAccount")])
        assert not findings
