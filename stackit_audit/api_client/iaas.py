from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class IaasClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.api = StackitApiClient(endpoints.regional(endpoints.IAAS, region), auth)

    def list_servers(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v1alpha1/projects/{project_id}/servers", items_key="items"))

    def list_volumes(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v1alpha1/projects/{project_id}/volumes", items_key="items"))

    def list_security_groups(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v1alpha1/projects/{project_id}/security-groups", items_key="items"))

    def list_security_group_rules(self, project_id: str, sg_id: str) -> list[dict[str, Any]]:
        return list(
            self.api.paginate(
                f"/v1alpha1/projects/{project_id}/security-groups/{sg_id}/rules",
                items_key="items",
            )
        )

    def list_public_ips(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v1alpha1/projects/{project_id}/public-ips", items_key="items"))

    def list_networks(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v1alpha1/projects/{project_id}/networks", items_key="items"))
