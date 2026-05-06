"""Tests for scoring/aggregation."""
from __future__ import annotations

from stackit_audit.models.finding import Finding
from stackit_audit.scoring.aggregator import aggregate
from stackit_audit.scoring.prioritizer import top_findings


def _f(**kw) -> Finding:
    defaults = dict(
        check_id="TEST-001",
        title="t",
        status="FAIL",
        severity="high",
        domain="IAM",
        resource_type="test",
        resource_id="r-001",
        assurance_level="automated",
        framework_refs=[],
        framework_names=[],
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_aggregate_counts():
    findings = [
        _f(status="FAIL", severity="critical"),
        _f(status="FAIL", severity="high"),
        _f(status="PASS", severity="low"),
    ]
    s = aggregate(findings)
    assert s.totals_by_status["FAIL"] == 2
    assert s.totals_by_status["PASS"] == 1
    assert s.totals_by_severity["critical"] == 1
    assert s.totals_by_severity["high"] == 1


def test_aggregate_framework_refs():
    f = _f(framework_refs=["CCM:IAM-01", "C5:IDM-04"])
    s = aggregate([f])
    assert s.totals_by_framework["CCM:IAM-01"] == 1
    assert s.totals_by_framework["C5:IDM-04"] == 1


def test_top_findings_ordering():
    findings = [
        _f(check_id="B", severity="high", status="FAIL"),
        _f(check_id="A", severity="critical", status="FAIL"),
        _f(check_id="C", severity="medium", status="PARTIAL"),
        _f(check_id="D", severity="low", status="PASS"),  # excluded
    ]
    top = top_findings(findings, n=3)
    assert len(top) == 3
    assert top[0].severity == "critical"
    assert top[1].severity == "high"


def test_top_findings_excludes_pass():
    findings = [_f(status="PASS") for _ in range(5)]
    assert top_findings(findings) == []


def test_top_findings_respects_n():
    findings = [_f(check_id=f"C-{i}", severity="high") for i in range(20)]
    assert len(top_findings(findings, n=5)) == 5


def test_coverage_includes_all_checks():
    s = aggregate([])
    assert s.coverage["checks_run"] > 0
    assert s.coverage["automated"] + s.coverage["heuristic"] + s.coverage["manual"] == s.coverage["checks_run"]
