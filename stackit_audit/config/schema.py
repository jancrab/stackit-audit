from pathlib import Path
from pydantic import BaseModel, Field

from stackit_audit.auth.key_flow import DEFAULT_TOKEN_ENDPOINT


class AuthConfig(BaseModel):
    service_account_key_path: Path | None = None
    token_endpoint: str = DEFAULT_TOKEN_ENDPOINT


class ScopeConfig(BaseModel):
    organization_ids: list[str] = Field(default_factory=list)
    project_ids: list[str] = Field(default_factory=list)
    region: str = "eu01"


class ChecksConfig(BaseModel):
    exclude: list[str] = Field(default_factory=list)
    include_only: list[str] = Field(default_factory=list)
    custom_dirs: list[Path] = Field(default_factory=list)


class ReportingConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "md", "pdf"])
    output_dir: Path = Path("./out")
    pdf_title: str = "STACKIT Cloud Audit"


class RuntimeConfig(BaseModel):
    parallelism: int = 8
    request_timeout_s: int = 30
    api_retry_attempts: int = 3


class AuditConfig(BaseModel):
    auth: AuthConfig = Field(default_factory=AuthConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    checks: ChecksConfig = Field(default_factory=ChecksConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
