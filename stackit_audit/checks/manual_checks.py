from __future__ import annotations

from stackit_audit.checks.base import CheckBase
from stackit_audit.frameworks.mapping import load_manual_controls
from stackit_audit.models import Check, Finding, Resource
from stackit_audit.models.resource import ResourceScope


class ORG001ManualControls(CheckBase):
    META = Check(
        check_id="ORG-001",
        title="Manual review required for non-API-introspectable controls",
        description="CCM/C5 areas that this tool cannot verify automatically.",
        framework_refs=[],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Org",
        severity="info",
        rationale="Honesty about the limits of automated cloud auditing.",
        resource_types=[],
        required_data_points=[],
        automated_assurance_level="manual",
        manual_review_required=True,
        evaluation_logic="static list from frameworks/manual_controls.yaml",
        remediation="Address each area through the indicated organizational/contractual evidence.",
    )

    def __init__(self) -> None:
        try:
            self.entries = load_manual_controls() or []
        except Exception:
            self.entries = []

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for entry in self.entries:
            f = self.make_finding(
                None, status="UNKNOWN",
                rationale=entry.get("rationale", ""),
                api_evidence={},
                derived_evidence={"area": entry.get("area")},
                title_override=f"Manual review: {entry.get('area')}",
            )
            f.framework_refs = list(entry.get("framework_refs", []))
            f.resource_type = "org.manual_control"
            f.resource_id = entry.get("area", "manual")
            f.resource_name = entry.get("area")
            out.append(f)
        return out
