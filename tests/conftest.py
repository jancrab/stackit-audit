"""Shared pytest fixtures."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from stackit_audit.models.finding import Finding
from stackit_audit.models.resource import Resource, ResourceScope


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _scope(project_id: str = "proj-test-001") -> ResourceScope:
    return ResourceScope(project_id=project_id, region="eu01")


def _finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="TEST-001",
        title="Test finding",
        status="FAIL",
        severity="high",
        domain="IAM",
        resource_type="test.resource",
        resource_id="res-001",
        assurance_level="automated",
        framework_refs=["CCM:IAM-01"],
        framework_names=["CCM v4.0"],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Resource factories
# ---------------------------------------------------------------------------

@pytest.fixture()
def sa_key_resource():
    return Resource(
        resource_type="service_account.key",
        resource_id="key-001",
        resource_name="my-key",
        scope=_scope(),
        attrs={
            "service_account_id": "sa-001",
            "service_account_email": "sa@proj.iam.stackit.cloud",
            "created_at": "2020-01-01T00:00:00Z",
            "active": True,
        },
    )


@pytest.fixture()
def security_group_rule_ssh():
    return Resource(
        resource_type="iaas.security_group_rule",
        resource_id="rule-ssh-001",
        scope=_scope(),
        attrs={
            "security_group_id": "sg-001",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range_min": 22,
            "port_range_max": 22,
            "remote_ip_prefix": "0.0.0.0/0",
            "ethertype": "IPv4",
        },
    )


@pytest.fixture()
def security_group_rule_rdp():
    return Resource(
        resource_type="iaas.security_group_rule",
        resource_id="rule-rdp-001",
        scope=_scope(),
        attrs={
            "security_group_id": "sg-001",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range_min": 3389,
            "port_range_max": 3389,
            "remote_ip_prefix": "0.0.0.0/0",
            "ethertype": "IPv4",
        },
    )


@pytest.fixture()
def db_resource():
    return Resource(
        resource_type="dbflex.postgres.instance",
        resource_id="db-001",
        resource_name="my-db",
        scope=_scope(),
        attrs={
            "engine": "postgres",
            "version": "9.6",
            "public_access": True,
            "backup_schedule": None,
        },
    )


@pytest.fixture()
def ske_cluster():
    return Resource(
        resource_type="ske.cluster",
        resource_id="cluster-001",
        resource_name="my-cluster",
        scope=_scope(),
        attrs={
            "kubernetes_version": "1.25.0",
            "acl_enabled": False,
            "acl_allowed_cidrs": [],
        },
    )


@pytest.fixture()
def membership_owner():
    return Resource(
        resource_type="authorization.membership",
        resource_id="mem-001",
        scope=_scope(),
        attrs={
            "subject": "sa-deploy@proj.iam.stackit.cloud",
            "role": "project.owner",
            "subject_type": "serviceAccount",
        },
    )


@pytest.fixture()
def sample_findings_doc():
    return {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "scan": {
            "started_at": "2024-01-01T10:00:00Z",
            "finished_at": "2024-01-01T10:05:00Z",
            "scope": {"project_ids": ["proj-test-001"], "region": "eu01"},
            "auth": {"method": "key_flow", "service_account_email": "audit@proj.iam.stackit.cloud"},
        },
        "summary": {
            "totals_by_status": {"FAIL": 2, "PARTIAL": 1, "UNKNOWN": 0, "PASS": 1, "NOT_APPLICABLE": 0},
            "totals_by_severity": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 1},
            "totals_by_domain": {"IAM": 2, "Network": 1, "Logging": 1},
            "totals_by_framework": {"CCM:IAM-01": 2},
            "coverage": {"checks_run": 21, "automated": 14, "heuristic": 5, "manual": 2},
        },
        "findings": [
            {
                "finding_id": "a1b2c3d4-0000-0000-0000-000000000001",
                "check_id": "IAM-001",
                "title": "SA has owner role",
                "status": "FAIL",
                "severity": "high",
                "domain": "IAM",
                "resource_type": "authorization.membership",
                "resource_id": "mem-001",
                "resource_name": "sa-deploy",
                "resource_scope": {"project_id": "proj-test-001"},
                "framework_refs": ["CCM:IAM-09", "C5:IDM-04"],
                "framework_names": ["CCM v4.0", "BSI C5:2020"],
                "assurance_level": "automated",
                "manual_review_required": False,
                "rationale": "SA has owner role",
                "risk": "Excessive privilege",
                "remediation": "Reduce to reader role",
                "timestamp": "2024-01-01T10:00:01Z",
                "tool_version": "0.1.0",
            },
            {
                "finding_id": "a1b2c3d4-0000-0000-0000-000000000002",
                "check_id": "NET-001",
                "title": "SSH open to world",
                "status": "FAIL",
                "severity": "high",
                "domain": "Network",
                "resource_type": "iaas.security_group_rule",
                "resource_id": "rule-ssh-001",
                "resource_name": None,
                "resource_scope": {"project_id": "proj-test-001"},
                "framework_refs": ["CCM:IVS-04", "C5:KOS-04"],
                "framework_names": ["CCM v4.0", "BSI C5:2020"],
                "assurance_level": "automated",
                "manual_review_required": False,
                "rationale": "Ingress TCP/22 from 0.0.0.0/0",
                "risk": "Remote access exposure",
                "remediation": "Restrict to known IP ranges",
                "timestamp": "2024-01-01T10:00:02Z",
                "tool_version": "0.1.0",
            },
            {
                "finding_id": "a1b2c3d4-0000-0000-0000-000000000003",
                "check_id": "LOG-001",
                "title": "No audit log activity",
                "status": "PARTIAL",
                "severity": "medium",
                "domain": "Logging",
                "resource_type": "audit_log.project",
                "resource_id": "proj-test-001",
                "resource_name": None,
                "resource_scope": {"project_id": "proj-test-001"},
                "framework_refs": ["CCM:LOG-02", "C5:RB-12"],
                "framework_names": ["CCM v4.0", "BSI C5:2020"],
                "assurance_level": "heuristic",
                "manual_review_required": True,
                "rationale": "No audit log entries found",
                "risk": "Audit trail gap",
                "remediation": "Enable audit logging",
                "timestamp": "2024-01-01T10:00:03Z",
                "tool_version": "0.1.0",
            },
            {
                "finding_id": "a1b2c3d4-0000-0000-0000-000000000004",
                "check_id": "ORG-001",
                "title": "Manual: MFA for privileged users",
                "status": "UNKNOWN",
                "severity": "info",
                "domain": "IAM",
                "resource_type": "org.manual_control",
                "resource_id": "manual-mfa",
                "resource_name": None,
                "resource_scope": {},
                "framework_refs": ["CCM:IAM-13", "C5:IDM-08"],
                "framework_names": ["CCM v4.0", "BSI C5:2020"],
                "assurance_level": "manual",
                "manual_review_required": True,
                "rationale": "Cannot be verified via API",
                "risk": "Privileged account compromise",
                "remediation": "Verify MFA in IdP",
                "derived_evidence": {"area": "MFA on privileged accounts"},
                "timestamp": "2024-01-01T10:00:04Z",
                "tool_version": "0.1.0",
            },
        ],
    }
