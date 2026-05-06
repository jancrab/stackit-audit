from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class DnsClient:
    def __init__(self, auth: KeyFlowAuth, base_url: str = endpoints.DNS):
        self.api = StackitApiClient(base_url, auth)

    def list_zones(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v1/projects/{project_id}/zones", items_key="zones"))

    def list_records(self, project_id: str, zone_id: str) -> list[dict[str, Any]]:
        return list(
            self.api.paginate(
                f"/v1/projects/{project_id}/zones/{zone_id}/rrsets",
                items_key="rrSets",
            )
        )
