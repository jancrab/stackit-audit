"""HTTP clients for STACKIT REST APIs.

Each service module wraps a single STACKIT API and exposes list-style
methods that return raw JSON. Endpoints are configurable via the
`base_url` argument so tests and ad-hoc deployments can override.

Where API field names are not consistently documented (e.g. encryption
flags on volumes, public-access flags on buckets), the discovery layer
preserves the full payload as `raw` and check logic must treat missing
fields as `UNKNOWN`, never `PASS`.
"""

from stackit_audit.api_client.base import StackitApiClient, StackitApiError
