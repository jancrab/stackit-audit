from typing import Any
from pydantic import BaseModel, Field


class ResourceScope(BaseModel):
    organization_id: str | None = None
    project_id: str | None = None
    region: str | None = None


class Resource(BaseModel):
    """Canonical normalized representation of a STACKIT resource.

    `raw` keeps the original API payload for evidence; `attrs` carries
    fields the normalization layer extracted into stable names.
    """

    resource_type: str
    resource_id: str
    resource_name: str | None = None
    scope: ResourceScope = Field(default_factory=ResourceScope)
    attrs: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
