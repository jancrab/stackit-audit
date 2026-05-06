"""Unified client for STACKIT DB Flex services (Postgres, MariaDB, MongoDB).

The three services share a similar API shape but distinct hosts. We
expose them via one class so discovery can iterate them uniformly.
"""

from typing import Any
from stackit_audit.api_client.base import StackitApiClient, StackitApiError
from stackit_audit.api_client import endpoints
from stackit_audit.auth.key_flow import KeyFlowAuth

ENGINES = {
    "postgres": endpoints.POSTGRES_FLEX,
    "mariadb": endpoints.MARIADB_FLEX,
    "mongodb": endpoints.MONGODB_FLEX,
    "redis": endpoints.REDIS,
    "opensearch": endpoints.OPENSEARCH,
    "rabbitmq": endpoints.RABBITMQ,
}


class DbFlexClient:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01"):
        self.region = region
        self.auth = auth
        self.clients = {
            engine: StackitApiClient(endpoints.regional(template, region), auth)
            for engine, template in ENGINES.items()
        }

    def list_instances(self, engine: str, project_id: str) -> list[dict[str, Any]]:
        if engine not in self.clients:
            return []
        try:
            body = self.clients[engine].get(f"/v1/projects/{project_id}/instances")
        except StackitApiError:
            return []
        if isinstance(body, dict):
            return list(body.get("items") or body.get("instances") or [])
        return list(body or [])
