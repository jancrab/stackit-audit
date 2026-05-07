"""Tests verifying the ARCH-001..ARCH-010 fixes from the architect review."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import patch

from stackit_audit.checks.engine import CheckEngine, ALL_CHECKS, _crash_finding
from stackit_audit.checks.base import CheckBase
from stackit_audit.models import Check, Finding, Resource
from stackit_audit.models.resource import ResourceScope
from stackit_audit.scoring.aggregator import aggregate
from stackit_audit.reporting.json_writer import build_findings_document


# ---------------------------------------------------------------------------
# ARCH-003 — fail_on severity threshold is >= not ==
# ---------------------------------------------------------------------------

class TestFailOnSeverityThreshold:
    """cli/_at_or_above() must treat fail_on as a >= threshold."""

    def _finding(self, severity: str, status: str = "FAIL") -> Finding:
        return Finding(
            check_id="T-001",
            title="t",
            status=status,
            severity=severity,
            domain="IAM",
            resource_type="x",
            resource_id="r",
            assurance_level="automated",
        )

    def test_at_or_above_helper_critical_above_high(self):
        from stackit_audit.cli.main import _at_or_above
        assert _at_or_above("critical", "high") is True

    def test_at_or_above_helper_exact_match(self):
        from stackit_audit.cli.main import _at_or_above
        assert _at_or_above("high", "high") is True

    def test_at_or_above_helper_below_threshold(self):
        from stackit_audit.cli.main import _at_or_above
        assert _at_or_above("medium", "high") is False

    def test_at_or_above_helper_info_below_critical(self):
        from stackit_audit.cli.main import _at_or_above
        assert _at_or_above("info", "critical") is False

    def test_critical_finding_triggers_high_threshold(self):
        """A critical FAIL should cause exit when --fail-on=high."""
        from stackit_audit.cli.main import _at_or_above
        findings = [self._finding("critical"), self._finding("medium")]
        threshold = "high"
        triggered = any(
            f for f in findings
            if f.status in ("FAIL", "PARTIAL") and _at_or_above(f.severity, threshold)
        )
        assert triggered  # was False with the == bug


# ---------------------------------------------------------------------------
# ARCH-004 — coverage stats reflect active check list, not ALL_CHECKS
# ---------------------------------------------------------------------------

class TestAggregatorActivatedChecks:
    def test_coverage_uses_all_checks_by_default(self):
        summary = aggregate([])
        assert summary.coverage["checks_run"] == len(ALL_CHECKS)

    def test_coverage_uses_provided_active_checks(self):
        # Simulate running with include_only=["IAM-001"]
        engine = CheckEngine(include_only=["IAM-001"])
        active = [type(c) for c in engine.checks]
        summary = aggregate([], active_checks=active)
        assert summary.coverage["checks_run"] == 1

    def test_coverage_reflects_exclude(self):
        # All but IAM-001 excluded
        engine = CheckEngine(exclude=["IAM-001"])
        active = [type(c) for c in engine.checks]
        summary = aggregate([], active_checks=active)
        assert summary.coverage["checks_run"] == len(ALL_CHECKS) - 1

    def test_build_findings_document_passes_active_checks(self):
        """build_findings_document active_checks kwarg flows into coverage."""
        engine = CheckEngine(include_only=["NET-001", "NET-002"])
        active = [type(c) for c in engine.checks]
        doc = build_findings_document(
            findings=[],
            scope={},
            started_at=datetime.now(tz=timezone.utc),
            active_checks=active,
        )
        assert doc["summary"]["coverage"]["checks_run"] == 2


# ---------------------------------------------------------------------------
# ARCH-007 — crashed check emits synthetic UNKNOWN, not silence
# ---------------------------------------------------------------------------

class _BrokenCheck(CheckBase):
    META = Check(
        check_id="TEST-CRASH",
        title="Always crashes",
        description="Intentionally broken for testing.",
        framework_refs=[],
        framework_names=[],
        domain="IAM",
        severity="info",
        rationale="test",
        resource_types=[],
        required_data_points=[],
        automated_assurance_level="automated",
        evaluation_logic="raises",
        remediation="n/a",
    )

    def run(self, resources):
        raise RuntimeError("Simulated crash in check")


class TestCheckCrashHandling:
    def test_crash_produces_unknown_finding_not_silence(self):
        engine = CheckEngine(check_classes=[_BrokenCheck])
        findings = engine.run([])
        assert len(findings) == 1
        f = findings[0]
        assert f.status == "UNKNOWN"
        assert f.check_id == "TEST-CRASH"
        assert f.manual_review_required is True

    def test_crash_finding_helper_captures_exception_type(self):
        exc = ValueError("bad field")
        f = _crash_finding("IAM-001", exc)
        assert "ValueError" in f.rationale
        assert f.status == "UNKNOWN"

    def test_crash_does_not_suppress_other_check_findings(self):
        """Checks after the crashing one still produce findings."""
        from stackit_audit.checks.iam_checks import IAM001PrivilegedServiceAccounts

        r = Resource(
            resource_type="authorization.membership",
            resource_id="m-1",
            scope=ResourceScope(project_id="p"),
            attrs={"role": "project.owner", "subject_type": "serviceAccount", "subject_id": "sa@x"},
        )
        engine = CheckEngine(check_classes=[_BrokenCheck, IAM001PrivilegedServiceAccounts])
        findings = engine.run([r])
        statuses = {f.status for f in findings}
        assert "UNKNOWN" in statuses   # crash synthetic finding
        assert "FAIL" in statuses      # IAM-001 still ran


# ---------------------------------------------------------------------------
# ARCH-009 — tool_version derives from __version__
# ---------------------------------------------------------------------------

class TestToolVersionDynamic:
    def test_finding_tool_version_matches_package_version(self):
        from stackit_audit import __version__
        f = Finding(
            check_id="T-001",
            title="t",
            status="PASS",
            severity="info",
            domain="IAM",
            resource_type="x",
            resource_id="r",
            assurance_level="automated",
        )
        assert f.tool_version == __version__

    def test_tool_version_not_hardcoded_0_1_0(self):
        """If someone bumps __version__, tool_version reflects it."""
        import stackit_audit
        original = stackit_audit.__version__
        try:
            stackit_audit.__version__ = "9.9.9"
            f = Finding(
                check_id="T-001",
                title="t",
                status="PASS",
                severity="info",
                domain="IAM",
                resource_type="x",
                resource_id="r",
                assurance_level="automated",
            )
            assert f.tool_version == "9.9.9"
        finally:
            stackit_audit.__version__ = original


# ---------------------------------------------------------------------------
# ARCH-010 — NET-006 domain is "Network" not "Crypto"
# ---------------------------------------------------------------------------

class TestNet006Domain:
    def test_net006_domain_is_network(self):
        from stackit_audit.checks.network_checks import NET006LoadBalancerHttpListener
        assert NET006LoadBalancerHttpListener.META.domain == "Network"
