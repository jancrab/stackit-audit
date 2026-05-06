from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class SecretsManagerClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.api = StackitApiClient(endpoints.regional(endpoints.SECRETS_MANAGER, region), auth)

    def list_instances(self, project_id: str) -> list[dict[str, Any]]:
        body = self.api.get(f"/v1/projects/{project_id}/instances")
        if isinstance(body, dict):
            return list(body.get("instances") or body.get("items") or [])
        return list(body or [])
