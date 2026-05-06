from __future__ import annotations

from typing import Iterable
from pydantic import BaseModel, Field

from stackit_audit.checks import ALL_CHECKS
from stackit_audit.models import Finding


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
STATUS_ORDER = ["FAIL", "PARTIAL", "UNKNOWN", "PASS", "NOT_APPLICABLE"]


class AggregationSummary(BaseModel):
    totals_by_status: dict[str, int] = Field(default_factory=dict)
    totals_by_severity: dict[str, int] = Field(default_factory=dict)
    totals_by_domain: dict[str, int] = Field(default_factory=dict)
    totals_by_framework: dict[str, int] = Field(default_factory=dict)
    coverage: dict[str, int] = Field(default_factory=dict)


def aggregate(findings: Iterable[Finding]) -> AggregationSummary:
    findings = list(findings)
    by_status: dict[str, int] = {s: 0 for s in STATUS_ORDER}
    by_sev: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    by_domain: dict[str, int] = {}
    by_fw: dict[str, int] = {}
    for f in findings:
        if f.status in by_status:
            by_status[f.status] += 1
        if f.severity in by_sev:
            by_sev[f.severity] += 1
        by_domain[f.domain] = by_domain.get(f.domain, 0) + 1
        for ref in f.framework_refs:
            by_fw[ref] = by_fw.get(ref, 0) + 1

    auto = sum(1 for c in ALL_CHECKS if c.META.automated_assurance_level == "automated")
    heur = sum(1 for c in ALL_CHECKS if c.META.automated_assurance_level == "heuristic")
    manu = sum(1 for c in ALL_CHECKS if c.META.automated_assurance_level == "manual")

    return AggregationSummary(
        totals_by_status=by_status,
        totals_by_severity=by_sev,
        totals_by_domain=by_domain,
        totals_by_framework=by_fw,
        coverage={
            "checks_run": len(ALL_CHECKS),
            "automated": auto,
            "heuristic": heur,
            "manual": manu,
        },
    )
