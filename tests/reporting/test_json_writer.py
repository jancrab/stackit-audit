"""Tests for JSON reporting."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from stackit_audit.reporting.json_writer import build_findings_document, write_json
from stackit_audit.models.finding import Finding


def _make_finding(**kw) -> Finding:
    defaults = dict(
        check_id="IAM-001",
        title="Test",
        status="FAIL",
        severity="high",
        domain="IAM",
        resource_type="test",
        resource_id="res-001",
        assurance_level="automated",
        framework_refs=["CCM:IAM-01"],
        framework_names=["CCM v4.0"],
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_build_findings_document_structure():
    f = _make_finding()
    doc = build_findings_document(
        findings=[f],
        scope={"project_ids": ["proj-001"], "region": "eu01"},
        started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    assert doc["schema_version"] == "1.0"
    assert "summary" in doc
    assert "findings" in doc
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["check_id"] == "IAM-001"


def test_build_findings_document_summary_counts():
    findings = [
        _make_finding(status="FAIL", severity="high"),
        _make_finding(status="PASS", severity="low"),
        _make_finding(status="PARTIAL", severity="medium"),
    ]
    doc = build_findings_document(
        findings=findings,
        scope={},
        started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    sev = doc["summary"]["totals_by_severity"]
    sta = doc["summary"]["totals_by_status"]
    assert sta["FAIL"] == 1
    assert sta["PASS"] == 1
    assert sta["PARTIAL"] == 1
    assert sev["high"] == 1
    assert sev["medium"] == 1


def test_write_json_creates_file(tmp_path):
    f = _make_finding()
    doc = build_findings_document(
        findings=[f],
        scope={},
        started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    out = tmp_path / "findings.json"
    write_json(doc, out)
    assert out.exists()
    loaded = json.loads(out.read_text())
    assert loaded["schema_version"] == "1.0"


def test_write_json_creates_parent_dirs(tmp_path):
    f = _make_finding()
    doc = build_findings_document(
        findings=[f],
        scope={},
        started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    out = tmp_path / "sub" / "dir" / "findings.json"
    write_json(doc, out)
    assert out.exists()
