"""ReportLab PDF builder — takes a findings document dict and writes a PDF."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, SimpleDocTemplate, Spacer

from stackit_audit.pdf_rendering.sections import (
    executive_summary,
    findings_by_framework,
    findings_by_severity,
    limitations_section,
    manual_review_section,
    title_page,
    top_findings_section,
)
from stackit_audit.pdf_rendering.styles import BODY, SMALL

_MARGIN = 2 * cm


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColorRGB(0.5, 0.5, 0.5)
    canvas.drawString(_MARGIN, 1 * cm, "STACKIT Cloud Audit — Confidential")
    canvas.drawRightString(A4[0] - _MARGIN, 1 * cm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(document: dict[str, Any], output_path: Path | str) -> Path:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(p),
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=_MARGIN,
        bottomMargin=1.5 * cm,
        title="STACKIT Cloud Audit",
        author="stackit-audit",
    )

    story = []
    story.extend(title_page(document))
    story.append(PageBreak())
    story.extend(executive_summary(document))
    story.append(PageBreak())
    story.extend(top_findings_section(document))
    story.append(PageBreak())
    story.extend(findings_by_severity(document))
    story.append(PageBreak())
    story.extend(findings_by_framework(document))
    story.append(PageBreak())
    story.extend(manual_review_section(document))
    story.append(PageBreak())
    story.extend(limitations_section())

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return p
