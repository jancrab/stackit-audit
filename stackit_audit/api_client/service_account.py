from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class ServiceAccountClient:
    def __init__(self, auth: KeyFlowAuth, base_url: str = endpoints.SERVICE_ACCOUNT):
        self.api = StackitApiClient(base_url, auth)

    def list_service_accounts(self, project_id: str) -> list[dict[str, Any]]:
        return list(
            self.api.paginate(
                f"/v2/projects/{project_id}/service-accounts",
                items_key="items",
            )
        )

    def list_keys(self, project_id: str, sa_email: str) -> list[dict[str, Any]]:
        return list(
            self.api.paginate(
                f"/v2/projects/{project_id}/service-accounts/{sa_email}/keys",
                items_key="items",
            )
        )
