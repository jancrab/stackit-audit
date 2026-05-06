from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Any


def _escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    out = StringIO()
    out.write("| " + " | ".join(headers) + " |\n")
    out.write("|" + "|".join(["---"] * len(headers)) + "|\n")
    for row in rows:
        out.write("| " + " | ".join(_escape(str(c)) for c in row) + " |\n")
    return out.getvalue()


def render_markdown(doc: dict[str, Any]) -> str:
    findings = doc.get("findings", [])
    summary = doc.get("summary", {})
    scan = doc.get("scan", {})
    out = StringIO()
    out.write(f"# STACKIT Cloud Audit\n\n")
    out.write(f"- **Tool version:** {doc.get('tool_version', '')}\n")
    out.write(f"- **Scan started:** {scan.get('started_at', '')}\n")
    out.write(f"- **Scan finished:** {scan.get('finished_at', '')}\n")
    out.write(f"- **Service account:** {scan.get('auth', {}).get('service_account_email', '')}\n")
    scope = scan.get("scope", {})
    out.write(f"- **Project IDs:** {', '.join(scope.get('project_ids', []) or [])}\n")
    out.write(f"- **Region:** {scope.get('region', '')}\n\n")

    out.write("## Executive summary\n\n")
    sev = summary.get("totals_by_severity", {})
    sta = summary.get("totals_by_status", {})
    cov = summary.get("coverage", {})
    out.write(
        f"Findings — critical: {sev.get('critical', 0)}, high: {sev.get('high', 0)}, "
        f"medium: {sev.get('medium', 0)}, low: {sev.get('low', 0)}, info: {sev.get('info', 0)}.\n"
    )
    out.write(
        f"Status — FAIL: {sta.get('FAIL', 0)}, PARTIAL: {sta.get('PARTIAL', 0)}, "
        f"UNKNOWN: {sta.get('UNKNOWN', 0)}, PASS: {sta.get('PASS', 0)}.\n\n"
    )
    out.write(
        f"Coverage — {cov.get('checks_run', 0)} checks "
        f"({cov.get('automated', 0)} automated, "
        f"{cov.get('heuristic', 0)} heuristic, "
        f"{cov.get('manual', 0)} manual).\n\n"
    )

    actionable = [f for f in findings if f.get("status") in ("FAIL", "PARTIAL")]
    actionable.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity"), 9),
            {"FAIL": 0, "PARTIAL": 1}.get(f.get("status"), 9),
        )
    )
    out.write("## Top findings\n\n")
    rows = [
        [f.get("severity"), f.get("status"), f.get("check_id"), f.get("title"), f.get("resource_name") or f.get("resource_id")]
        for f in actionable[:10]
    ]
    out.write(_table(["Severity", "Status", "Check", "Title", "Resource"], rows))
    out.write("\n")

    out.write("## Findings by severity\n\n")
    for sev_key in ("critical", "high", "medium", "low", "info"):
        group = [f for f in findings if f.get("severity") == sev_key and f.get("status") != "PASS"]
        if not group:
            continue
        out.write(f"### {sev_key.capitalize()} ({len(group)})\n\n")
        rows = [
            [f.get("status"), f.get("check_id"), f.get("title"),
             f.get("resource_name") or f.get("resource_id"),
             ", ".join(f.get("framework_refs", []))]
            for f in group
        ]
        out.write(_table(["Status", "Check", "Title", "Resource", "Frameworks"], rows))
        out.write("\n")

    out.write("## Findings by framework\n\n")
    for prefix, label in (("CCM:", "CSA CCM v4"), ("C5:", "BSI C5:2020")):
        out.write(f"### {label}\n\n")
        rows: list[list[str]] = []
        for f in findings:
            refs = [r for r in f.get("framework_refs", []) if r.startswith(prefix)]
            if not refs:
                continue
            rows.append([
                ", ".join(refs), f.get("severity"), f.get("status"), f.get("check_id"),
                f.get("title"), f.get("resource_name") or f.get("resource_id"),
            ])
        if rows:
            out.write(_table(["Refs", "Severity", "Status", "Check", "Title", "Resource"], rows))
        else:
            out.write("_No findings mapped._\n")
        out.write("\n")

    out.write("## Manual review (non-API-introspectable areas)\n\n")
    manual = [f for f in findings if f.get("resource_type") == "org.manual_control"]
    if not manual:
        out.write("_None._\n\n")
    else:
        rows = [
            [f.get("derived_evidence", {}).get("area") or f.get("title"),
             ", ".join(f.get("framework_refs", [])),
             f.get("rationale")]
            for f in manual
        ]
        out.write(_table(["Area", "Frameworks", "Rationale"], rows))
        out.write("\n")

    out.write("## Limits of this assessment\n\n")
    out.write(
        "- Encryption-at-rest fields on Volumes / Object Storage / DB Flex are not\n"
        "  consistently exposed by the STACKIT API; affected checks degrade to PARTIAL/UNKNOWN.\n"
        "- MFA on user identities is not exposed by the Authorization API; verify in your IdP.\n"
        "- The `Manual review` section above lists CCM/C5 areas that this tool deliberately does not verify.\n"
    )
    return out.getvalue()


def write_markdown(doc: dict[str, Any], path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_markdown(doc), encoding="utf-8")
    return p
