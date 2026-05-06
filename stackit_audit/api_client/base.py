"""Generic HTTP client used by all STACKIT service modules.

Each service module instantiates a `StackitApiClient` with its own
`base_url` and uses it to make authenticated GET requests. Errors are
surfaced as `StackitApiError` with the HTTP status preserved, so the
discovery orchestrator can convert them into UNKNOWN findings rather
than crashing the run.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Iterator

import httpx

from stackit_audit.auth.key_flow import KeyFlowAuth

log = logging.getLogger(__name__)


class StackitApiError(Exception):
    def __init__(self, message: str, status_code: int | None = None, url: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.url = url


class StackitApiClient:
    def __init__(
        self,
        base_url: str,
        auth: KeyFlowAuth,
        timeout_s: int = 30,
        retry_attempts: int = 3,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.timeout_s = timeout_s
        self.retry_attempts = max(1, retry_attempts)
        self._client = http_client or httpx.Client(timeout=timeout_s)

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(self.retry_attempts):
            try:
                resp = self._client.get(
                    url, params=params or {}, headers=self.auth.auth_header()
                )
            except httpx.HTTPError as exc:
                last_exc = exc
                log.warning("HTTP error on %s (attempt %d): %s", url, attempt + 1, exc)
                time.sleep(0.5 * (attempt + 1))
                continue
            if resp.status_code == 401:
                self.auth.get_access_token(force_refresh=True)
                continue
            if resp.status_code in (429, 502, 503, 504):
                time.sleep(0.5 * (attempt + 1))
                continue
            if resp.status_code >= 400:
                raise StackitApiError(
                    f"GET {url} failed: HTTP {resp.status_code} {resp.text[:200]}",
                    status_code=resp.status_code,
                    url=url,
                )
            try:
                return resp.json()
            except ValueError as exc:
                raise StackitApiError(
                    f"GET {url} returned non-JSON body: {exc}", url=url
                ) from exc
        raise StackitApiError(
            f"GET {url} failed after {self.retry_attempts} attempts: {last_exc}", url=url
        )

    def paginate(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        items_key: str = "items",
        page_size: int = 100,
    ) -> Iterator[dict[str, Any]]:
        """Generic cursor/page parameter iteration.

        STACKIT services use varying pagination conventions; callers can
        override `items_key`. If no pagination metadata is present we
        emit one page and stop.
        """
        params = dict(params or {})
        params.setdefault("limit", page_size)
        cursor: str | None = None
        while True:
            page_params = dict(params)
            if cursor:
                page_params["cursor"] = cursor
            body = self.get(path, page_params)
            items = body.get(items_key) if isinstance(body, dict) else None
            if items is None and isinstance(body, list):
                items = body
            if not items:
                return
            for item in items:
                yield item
            cursor = body.get("nextCursor") or body.get("next_cursor") if isinstance(body, dict) else None
            if not cursor:
                return

    def close(self) -> None:
        self._client.close()
