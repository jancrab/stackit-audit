"""Base class for all checks.

Each check is a Python class that declares static metadata (the `Check`
model) and implements `run(resources)` returning a list of `Finding`s.
This is the procedural side of the hybrid declarative/procedural model
described in the plan; YAML-only checks could be added later by wrapping
a generic predicate evaluator into the same interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from stackit_audit.models import Check, Finding, Resource


class CheckBase(ABC):
    META: Check  # set on subclass

    @classmethod
    def get_meta(cls) -> Check:
        return cls.META

    @abstractmethod
    def run(self, resources: list[Resource]) -> list[Finding]: ...

    def make_finding(
        self,
        resource: Resource | None,
        status: str,
        rationale: str,
        api_evidence: dict | None = None,
        derived_evidence: dict | None = None,
        title_override: str | None = None,
    ) -> Finding:
        m = self.META
        if resource is not None:
            rt = resource.resource_type
            rid = resource.resource_id
            rname = resource.resource_name
            rscope = resource.scope.model_dump()
        else:
            rt = "n/a"
            rid = "n/a"
            rname = None
            rscope = {}
        return Finding(
            check_id=m.check_id,
            title=title_override or m.title,
            status=status,
            severity=m.severity,
            framework_refs=list(m.framework_refs),
            framework_names=list(m.framework_names),
            domain=m.domain,
            resource_type=rt,
            resource_id=rid,
            resource_name=rname,
            resource_scope=rscope,
            api_evidence=api_evidence or {},
            derived_evidence=derived_evidence or {},
            rationale=rationale,
            risk=m.rationale,
            remediation=m.remediation,
            assurance_level=m.automated_assurance_level,
            manual_review_required=m.manual_review_required,
        )
