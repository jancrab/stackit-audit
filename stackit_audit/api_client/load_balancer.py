from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class LoadBalancerClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.api = StackitApiClient(endpoints.regional(endpoints.LOAD_BALANCER, region), auth)

    def list_load_balancers(self, project_id: str) -> list[dict[str, Any]]:
        body = self.api.get(f"/v1/projects/{project_id}/load-balancers")
        if isinstance(body, dict):
            return list(body.get("loadBalancers") or body.get("items") or [])
        return list(body or [])
