from typing import Any
from datetime import datetime, timedelta, timezone
from stackit_audit.api_client.base import StackitApiClient, StackitApiError
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth


class AuditLogClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.api = StackitApiClient(endpoints.regional(endpoints.AUDIT_LOG, region), auth)

    def list_entries(
        self, project_id: str, days: int = 30, limit: int = 1000
    ) -> list[dict[str, Any]]:
        end = datetime.now(tz=timezone.utc)
        start = end - timedelta(days=days)
        params = {
            "from": start.isoformat(),
            "to": end.isoformat(),
            "limit": limit,
        }
        try:
            body = self.api.get(f"/v1/projects/{project_id}/audit-logs", params=params)
        except StackitApiError:
            return []
        if isinstance(body, dict):
            return list(body.get("items") or body.get("entries") or [])
        return list(body or [])
