"""STACKIT API base URLs.

Patterns observed from stackit-sdk-go OpenAPI specifications. Region is
substituted via `.format(region=...)`. Base URLs and paths are subject
to change; if a request returns 404 the discovery layer translates
that into an UNKNOWN finding rather than a hard failure.

Some services are global (no region prefix); those are listed without
a `{region}` placeholder.
"""

# Global services
RESOURCE_MANAGER = "https://resource-manager.api.stackit.cloud"
AUTHORIZATION = "https://authorization.api.stackit.cloud"
SERVICE_ACCOUNT = "https://service-account.api.stackit.cloud"
SKE = "https://ske.api.stackit.cloud"
DNS = "https://dns.api.stackit.cloud"

# Regional services (use .format(region=...))
IAAS = "https://iaas.api.{region}.stackit.cloud"
OBJECT_STORAGE = "https://object-storage.api.{region}.stackit.cloud"
LOAD_BALANCER = "https://load-balancer.api.{region}.stackit.cloud"
SECRETS_MANAGER = "https://secrets-manager.api.{region}.stackit.cloud"
AUDIT_LOG = "https://audit-log.api.{region}.stackit.cloud"
OBSERVABILITY = "https://observability.api.{region}.stackit.cloud"
LOGME = "https://logme.api.{region}.stackit.cloud"
POSTGRES_FLEX = "https://postgres-flex-service.api.{region}.stackit.cloud"
MARIADB_FLEX = "https://mariadb-service.api.{region}.stackit.cloud"
MONGODB_FLEX = "https://mongodbflex-service.api.{region}.stackit.cloud"
REDIS = "https://redis-service.api.{region}.stackit.cloud"
OPENSEARCH = "https://opensearch-service.api.{region}.stackit.cloud"
RABBITMQ = "https://rabbitmq-service.api.{region}.stackit.cloud"


def regional(template: str, region: str) -> str:
    return template.format(region=region)
