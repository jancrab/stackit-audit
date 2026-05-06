"""Tests for PDF generation."""
from __future__ import annotations

import pytest

from stackit_audit.pdf_rendering.pdf_builder import build_pdf


def test_build_pdf_creates_file(tmp_path, sample_findings_doc):
    out = tmp_path / "report.pdf"
    result = build_pdf(sample_findings_doc, out)
    assert result == out
    assert out.exists()
    assert out.stat().st_size > 1000  # non-trivial PDF


def test_build_pdf_empty_findings(tmp_path):
    doc = {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "scan": {
            "started_at": "2024-01-01T10:00:00Z",
            "finished_at": "2024-01-01T10:05:00Z",
            "scope": {"project_ids": [], "region": "eu01"},
            "auth": {"method": "key_flow", "service_account_email": ""},
        },
        "summary": {
            "totals_by_status": {},
            "totals_by_severity": {},
            "totals_by_domain": {},
            "totals_by_framework": {},
            "coverage": {"checks_run": 0, "automated": 0, "heuristic": 0, "manual": 0},
        },
        "findings": [],
    }
    out = tmp_path / "empty.pdf"
    result = build_pdf(doc, out)
    assert out.exists()


def test_build_pdf_creates_parent_dirs(tmp_path, sample_findings_doc):
    out = tmp_path / "nested" / "output" / "report.pdf"
    build_pdf(sample_findings_doc, out)
    assert out.exists()
