from typing import Literal
from pydantic import BaseModel, Field

AssuranceLevel = Literal["automated", "heuristic", "manual"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Domain = Literal[
    "IAM", "Network", "Crypto", "Logging", "Backup", "Config", "Secrets", "Org"
]


class Check(BaseModel):
    check_id: str
    title: str
    description: str
    framework_refs: list[str] = Field(default_factory=list)
    framework_names: list[str] = Field(default_factory=list)
    domain: Domain
    severity: Severity
    rationale: str
    resource_types: list[str] = Field(default_factory=list)
    required_data_points: list[str] = Field(default_factory=list)
    automated_assurance_level: AssuranceLevel
    manual_review_required: bool = False
    evaluation_logic: str = ""
    remediation: str = ""
    version: str = "1.0"
