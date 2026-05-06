from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class SkeClient:
    def __init__(self, auth: KeyFlowAuth, base_url: str = endpoints.SKE):
        self.api = StackitApiClient(base_url, auth)

    def list_clusters(self, project_id: str) -> list[dict[str, Any]]:
        body = self.api.get(f"/v1/projects/{project_id}/clusters")
        if isinstance(body, dict):
            return list(body.get("items") or body.get("clusters") or [])
        return list(body or [])

    def get_cluster(self, project_id: str, cluster_name: str) -> dict[str, Any]:
        return self.api.get(f"/v1/projects/{project_id}/clusters/{cluster_name}")
