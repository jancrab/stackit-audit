"""Tests for Markdown reporting."""
from __future__ import annotations

import pytest

from stackit_audit.reporting.markdown_writer import render_markdown, write_markdown


def test_render_markdown_contains_title(sample_findings_doc):
    md = render_markdown(sample_findings_doc)
    assert "# STACKIT Cloud Audit" in md


def test_render_markdown_executive_summary(sample_findings_doc):
    md = render_markdown(sample_findings_doc)
    assert "Executive summary" in md
    assert "FAIL" in md


def test_render_markdown_top_findings_table(sample_findings_doc):
    md = render_markdown(sample_findings_doc)
    assert "## Top findings" in md
    assert "IAM-001" in md


def test_render_markdown_framework_section(sample_findings_doc):
    md = render_markdown(sample_findings_doc)
    assert "CSA CCM v4" in md
    assert "BSI C5:2020" in md


def test_render_markdown_manual_review(sample_findings_doc):
    md = render_markdown(sample_findings_doc)
    assert "Manual review" in md


def test_render_markdown_limits(sample_findings_doc):
    md = render_markdown(sample_findings_doc)
    assert "Limits of this assessment" in md


def test_write_markdown_creates_file(tmp_path, sample_findings_doc):
    p = write_markdown(sample_findings_doc, tmp_path / "report.md")
    assert p.exists()
    content = p.read_text(encoding="utf-8")
    assert "# STACKIT Cloud Audit" in content


def test_escape_pipe_in_table(sample_findings_doc):
    doc = dict(sample_findings_doc)
    doc["findings"] = [
        {
            **sample_findings_doc["findings"][0],
            "title": "Title with | pipe",
        }
    ]
    md = render_markdown(doc)
    assert "\\|" in md
