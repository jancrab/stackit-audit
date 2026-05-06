from typing import Any
from stackit_audit.api_client.base import StackitApiClient, StackitApiError
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class ObservabilityClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.observability = StackitApiClient(
            endpoints.regional(endpoints.OBSERVABILITY, region), auth
        )
        self.logme = StackitApiClient(endpoints.regional(endpoints.LOGME, region), auth)

    def list_observability_instances(self, project_id: str) -> list[dict[str, Any]]:
        try:
            body = self.observability.get(f"/v1/projects/{project_id}/instances")
        except StackitApiError:
            return []
        if isinstance(body, dict):
            return list(body.get("instances") or body.get("items") or [])
        return list(body or [])

    def list_logme_instances(self, project_id: str) -> list[dict[str, Any]]:
        try:
            body = self.logme.get(f"/v1/projects/{project_id}/instances")
        except StackitApiError:
            return []
        if isinstance(body, dict):
            return list(body.get("instances") or body.get("items") or [])
        return list(body or [])
