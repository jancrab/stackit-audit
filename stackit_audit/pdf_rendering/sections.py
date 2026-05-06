"""Flowable-producing functions for each PDF section."""
from __future__ import annotations

from typing import Any

from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, Spacer, Table, TableStyle,
)

from stackit_audit.pdf_rendering.styles import (
    BODY, CODE, HEADING1, HEADING2, SEV_COLORS, SMALL, STATUS_COLORS,
    TABLE_STYLE_BASE, TITLE,
)


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _para(text: str, style=BODY) -> Paragraph:
    return Paragraph(_esc(text), style)


def _heading(text: str, level: int = 1) -> Paragraph:
    return Paragraph(_esc(text), HEADING1 if level == 1 else HEADING2)


def _hr() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.5, color="#BDC3C7", spaceAfter=4)


def _table(headers: list[str], rows: list[list[str]], col_widths=None) -> Table:
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(TABLE_STYLE_BASE))
    return t


# ---------------------------------------------------------------------------
# Title page
# ---------------------------------------------------------------------------

def title_page(doc: dict[str, Any]) -> list:
    scan = doc.get("scan", {})
    scope = scan.get("scope", {})
    sa = scan.get("auth", {}).get("service_account_email", "")
    project_ids = ", ".join(scope.get("project_ids", []) or [])
    region = scope.get("region", "")
    started = scan.get("started_at", "")
    finished = scan.get("finished_at", "")
    version = doc.get("tool_version", "")

    story = [
        Spacer(1, 3 * cm),
        Paragraph("STACKIT Cloud Audit", TITLE),
        _hr(),
        Spacer(1, 0.5 * cm),
        _para(f"<b>Tool version:</b> {_esc(version)}"),
        _para(f"<b>Scan started:</b> {_esc(started)}"),
        _para(f"<b>Scan finished:</b> {_esc(finished)}"),
        _para(f"<b>Service account:</b> {_esc(sa)}"),
        _para(f"<b>Project IDs:</b> {_esc(project_ids)}"),
        _para(f"<b>Region:</b> {_esc(region)}"),
    ]
    return story


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def executive_summary(doc: dict[str, Any]) -> list:
    summary = doc.get("summary", {})
    sev = summary.get("totals_by_severity", {})
    sta = summary.get("totals_by_status", {})
    cov = summary.get("coverage", {})

    story = [
        _heading("1. Executive Summary"),
        _hr(),
        _para(
            f"Findings — <b>critical:</b> {sev.get('critical',0)}, "
            f"<b>high:</b> {sev.get('high',0)}, "
            f"<b>medium:</b> {sev.get('medium',0)}, "
            f"<b>low:</b> {sev.get('low',0)}, "
            f"<b>info:</b> {sev.get('info',0)}."
        ),
        _para(
            f"Status — <b>FAIL:</b> {sta.get('FAIL',0)}, "
            f"<b>PARTIAL:</b> {sta.get('PARTIAL',0)}, "
            f"<b>UNKNOWN:</b> {sta.get('UNKNOWN',0)}, "
            f"<b>PASS:</b> {sta.get('PASS',0)}."
        ),
        _para(
            f"Coverage — {cov.get('checks_run',0)} checks "
            f"({cov.get('automated',0)} automated, "
            f"{cov.get('heuristic',0)} heuristic, "
            f"{cov.get('manual',0)} manual)."
        ),
        Spacer(1, 0.3 * cm),
    ]

    # severity bar table
    sev_rows = [
        [k.capitalize(), str(sev.get(k, 0))]
        for k in ("critical", "high", "medium", "low", "info")
    ]
    t = Table([["Severity", "Count"]] + sev_rows, colWidths=[4 * cm, 2 * cm])
    from reportlab.platypus import TableStyle
    style_cmds = list(TABLE_STYLE_BASE)
    for i, k in enumerate(("critical", "high", "medium", "low", "info"), start=1):
        c = SEV_COLORS.get(k)
        if c:
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), c))
            style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    return story


# ---------------------------------------------------------------------------
# Top findings
# ---------------------------------------------------------------------------

def top_findings_section(doc: dict[str, Any]) -> list:
    findings = doc.get("findings", [])
    actionable = [f for f in findings if f.get("status") in ("FAIL", "PARTIAL")]
    actionable.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity"), 9),
            {"FAIL": 0, "PARTIAL": 1}.get(f.get("status"), 9),
        )
    )
    top = actionable[:10]

    story = [
        _heading("2. Top Findings"),
        _hr(),
    ]
    if not top:
        story.append(_para("No actionable findings."))
        return story

    rows = [
        [
            _esc(f.get("severity", "")),
            _esc(f.get("status", "")),
            _esc(f.get("check_id", "")),
            _esc(f.get("title", "")),
            _esc(f.get("resource_name") or f.get("resource_id", "")),
        ]
        for f in top
    ]
    widths = [2 * cm, 2 * cm, 2.5 * cm, 6 * cm, 4 * cm]
    t = _table(["Severity", "Status", "Check", "Title", "Resource"], rows, widths)
    from reportlab.platypus import TableStyle
    style_cmds = list(TABLE_STYLE_BASE)
    for i, f in enumerate(top, start=1):
        sc = SEV_COLORS.get(f.get("severity", ""))
        if sc:
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), sc))
            style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
        stc = STATUS_COLORS.get(f.get("status", ""))
        if stc:
            style_cmds.append(("TEXTCOLOR", (1, i), (1, i), stc))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    return story


# ---------------------------------------------------------------------------
# Findings by severity
# ---------------------------------------------------------------------------

def findings_by_severity(doc: dict[str, Any]) -> list:
    findings = doc.get("findings", [])
    story = [_heading("3. Findings by Severity"), _hr()]

    for sev_key in ("critical", "high", "medium", "low", "info"):
        group = [f for f in findings if f.get("severity") == sev_key and f.get("status") != "PASS"]
        if not group:
            continue
        story.append(_heading(f"{sev_key.capitalize()} ({len(group)})", level=2))
        rows = [
            [
                _esc(f.get("status", "")),
                _esc(f.get("check_id", "")),
                _esc(f.get("title", "")),
                _esc(f.get("resource_name") or f.get("resource_id", "")),
                _esc(", ".join(f.get("framework_refs", []))),
            ]
            for f in group
        ]
        widths = [2 * cm, 2.5 * cm, 5 * cm, 4 * cm, 3 * cm]
        story.append(_table(["Status", "Check", "Title", "Resource", "Frameworks"], rows, widths))
        story.append(Spacer(1, 0.2 * cm))

    return story


# ---------------------------------------------------------------------------
# Findings by framework
# ---------------------------------------------------------------------------

def findings_by_framework(doc: dict[str, Any]) -> list:
    findings = doc.get("findings", [])
    story = [_heading("4. Findings by Framework"), _hr()]

    for prefix, label in (("CCM:", "CSA CCM v4"), ("C5:", "BSI C5:2020")):
        story.append(_heading(label, level=2))
        rows = []
        for f in findings:
            refs = [r for r in f.get("framework_refs", []) if r.startswith(prefix)]
            if not refs:
                continue
            rows.append([
                _esc(", ".join(refs)),
                _esc(f.get("severity", "")),
                _esc(f.get("status", "")),
                _esc(f.get("check_id", "")),
                _esc(f.get("title", "")),
                _esc(f.get("resource_name") or f.get("resource_id", "")),
            ])
        if rows:
            widths = [3 * cm, 2 * cm, 2 * cm, 2 * cm, 5 * cm, 3 * cm]
            story.append(_table(["Refs", "Severity", "Status", "Check", "Title", "Resource"], rows, widths))
        else:
            story.append(_para("No findings mapped."))
        story.append(Spacer(1, 0.2 * cm))

    return story


# ---------------------------------------------------------------------------
# Manual review
# ---------------------------------------------------------------------------

def manual_review_section(doc: dict[str, Any]) -> list:
    findings = doc.get("findings", [])
    manual = [f for f in findings if f.get("resource_type") == "org.manual_control"]
    story = [_heading("5. Manual Review"), _hr()]

    if not manual:
        story.append(_para("No manual review items."))
        return story

    rows = [
        [
            _esc(f.get("derived_evidence", {}).get("area") or f.get("title", "")),
            _esc(", ".join(f.get("framework_refs", []))),
            _esc(f.get("rationale", "")),
        ]
        for f in manual
    ]
    widths = [4 * cm, 4 * cm, 9 * cm]
    story.append(_table(["Area", "Frameworks", "Rationale"], rows, widths))
    return story


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------

def limitations_section() -> list:
    items = [
        "Encryption-at-rest fields on Volumes / Object Storage / DB Flex are not consistently exposed by the STACKIT API; affected checks degrade to PARTIAL/UNKNOWN.",
        "MFA on user identities is not exposed by the Authorization API; verify in your IdP.",
        "The Manual Review section lists CCM/C5 areas that this tool deliberately does not verify.",
        "API field availability may vary by STACKIT region and account tier. UNKNOWN findings indicate missing data, not PASS.",
        "This report is not a certification-ready audit opinion and does not constitute legal compliance evidence.",
    ]
    story = [_heading("6. Limits of This Assessment"), _hr()]
    for item in items:
        story.append(_para(f"• {item}"))
    return story
