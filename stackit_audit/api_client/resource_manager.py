from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class ResourceManagerClient:
    def __init__(self, auth: KeyFlowAuth, base_url: str = endpoints.RESOURCE_MANAGER):
        self.api = StackitApiClient(base_url, auth)

    def list_projects(self) -> list[dict[str, Any]]:
        return list(self.api.paginate("/v2/projects", items_key="items"))

    def get_project(self, project_id: str) -> dict[str, Any]:
        return self.api.get(f"/v2/projects/{project_id}")

    def list_organizations(self) -> list[dict[str, Any]]:
        return list(self.api.paginate("/v2/organizations", items_key="items"))
