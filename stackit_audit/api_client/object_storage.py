from typing import Any
from stackit_audit.api_client.base import StackitApiClient
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class ObjectStorageClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.api = StackitApiClient(endpoints.regional(endpoints.OBJECT_STORAGE, region), auth)

    def list_buckets(self, project_id: str) -> list[dict[str, Any]]:
        return list(
            self.api.paginate(
                f"/v1/project/{project_id}/buckets", items_key="buckets"
            )
        )
