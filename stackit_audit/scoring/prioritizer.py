from __future__ import annotations

from stackit_audit.models import Finding

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_RANK = {"FAIL": 0, "PARTIAL": 1, "UNKNOWN": 2, "PASS": 3, "NOT_APPLICABLE": 4}


def _key(f: Finding) -> tuple[int, int, str]:
    return (
        SEV_RANK.get(f.severity, 9),
        STATUS_RANK.get(f.status, 9),
        f.check_id,
    )


def top_findings(findings: list[Finding], n: int = 10) -> list[Finding]:
    actionable = [f for f in findings if f.status in ("FAIL", "PARTIAL")]
    actionable.sort(key=_key)
    return actionable[:n]
