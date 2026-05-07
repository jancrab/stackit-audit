from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4
from pydantic import BaseModel, Field

from stackit_audit.models.check import AssuranceLevel, Severity

FindingStatus = Literal["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN"]


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _tool_version() -> str:
    # ARCH-009: derive from package __version__ so it stays in sync with releases
    from stackit_audit import __version__
    return __version__


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    check_id: str
    title: str
    status: FindingStatus
    severity: Severity
    framework_refs: list[str] = Field(default_factory=list)
    framework_names: list[str] = Field(default_factory=list)
    domain: str
    resource_type: str
    resource_id: str
    resource_name: str | None = None
    resource_scope: dict[str, Any] = Field(default_factory=dict)
    api_evidence: dict[str, Any] = Field(default_factory=dict)
    derived_evidence: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    risk: str = ""
    remediation: str = ""
    assurance_level: AssuranceLevel
    manual_review_required: bool = False
    timestamp: datetime = Field(default_factory=_now)
    tool_version: str = Field(default_factory=_tool_version)
