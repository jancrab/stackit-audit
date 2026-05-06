"""Unit tests for database checks."""
from __future__ import annotations

import pytest

from stackit_audit.checks.db_checks import (
    DB001PublicDbInstances, DB002BackupConfiguration, DB003UnsupportedDbVersion,
)
from stackit_audit.models.resource import Resource, ResourceScope


def _scope():
    return ResourceScope(project_id="proj-001", region="eu01")


def _db(engine: str = "postgres", version: str = "15.2",
        is_public=False, backup_schedule="0 3 * * *") -> Resource:
    return Resource(
        resource_type=f"dbflex.{engine}.instance",
        resource_id="db-001",
        resource_name="mydb",
        scope=_scope(),
        attrs={
            "engine": engine,
            "version": version,
            "is_public": is_public,
            "backup_schedule": backup_schedule,
        },
    )


class TestDB001:
    def test_fail_public(self):
        check = DB001PublicDbInstances()
        assert any(f.status == "FAIL" for f in check.run([_db(is_public=True)]))

    def test_pass_private(self):
        check = DB001PublicDbInstances()
        assert not any(f.status == "FAIL" for f in check.run([_db(is_public=False)]))

    def test_unknown_when_field_missing(self):
        r = Resource(
            resource_type="dbflex.postgres.instance",
            resource_id="db-001",
            scope=_scope(),
            attrs={"engine": "postgres", "version": "15.2"},
            # is_public and acl deliberately omitted
        )
        check = DB001PublicDbInstances()
        findings = check.run([r])
        assert any(f.status in ("UNKNOWN", "PARTIAL") for f in findings)


class TestDB002:
    def test_partial_when_no_backup_fields(self):
        r = Resource(
            resource_type="dbflex.postgres.instance",
            resource_id="db-001",
            scope=_scope(),
            attrs={"engine": "postgres", "version": "15.2"},
        )
        check = DB002BackupConfiguration()
        findings = check.run([r])
        assert any(f.status == "PARTIAL" for f in findings)

    def test_fail_when_backup_disabled(self):
        r = Resource(
            resource_type="dbflex.postgres.instance",
            resource_id="db-001",
            scope=_scope(),
            attrs={"engine": "postgres", "version": "15.2", "backup_enabled": False},
        )
        check = DB002BackupConfiguration()
        assert any(f.status == "FAIL" for f in check.run([r]))

    def test_pass_with_backup_schedule(self):
        check = DB002BackupConfiguration()
        assert not any(f.status == "FAIL" for f in check.run([_db()]))


class TestDB003:
    def test_fail_eol_postgres(self):
        check = DB003UnsupportedDbVersion()
        findings = check.run([_db(engine="postgres", version="9.6")])
        assert any(f.status == "FAIL" for f in findings)

    def test_pass_recent_postgres(self):
        check = DB003UnsupportedDbVersion()
        findings = check.run([_db(engine="postgres", version="16.0")])
        assert not any(f.status == "FAIL" for f in findings)
