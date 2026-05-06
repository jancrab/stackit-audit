from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class AuthorizationClient:
    def __init__(self, auth: KeyFlowAuth, base_url: str = endpoints.AUTHORIZATION):
        self.api = StackitApiClient(base_url, auth)

    def list_memberships(self, resource_id: str) -> list[dict[str, Any]]:
        return list(
            self.api.paginate(
                f"/v2/{resource_id}/members",
                items_key="members",
            )
        )

    def list_roles(self, resource_id: str) -> list[dict[str, Any]]:
        return list(self.api.paginate(f"/v2/{resource_id}/roles", items_key="roles"))
