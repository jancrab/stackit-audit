"""STACKIT Key Flow authentication.

Implements the Service-Account-Key based authentication described at
https://docs.stackit.cloud/stackit/en/authentication-key-flow:
locally sign a JWT with the RSA private key, exchange it at the token
endpoint for a short-lived Bearer token, cache it until shortly before
expiry.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt

DEFAULT_TOKEN_ENDPOINT = "https://service-account.api.stackit.cloud/token"
TOKEN_REFRESH_SAFETY_S = 60


class AuthError(RuntimeError):
    pass


@dataclass
class ServiceAccountKey:
    """In-memory representation of a STACKIT Service Account Key JSON file.

    The file (downloaded from the STACKIT portal) contains the key id,
    the service-account-key id, the credentials block (with the RSA
    private key in PEM), and metadata. We only require the fields needed
    for Key Flow signing.
    """

    key_id: str
    service_account_email: str
    issuer: str
    audience: str
    private_key_pem: str
    raw: dict[str, Any]

    @classmethod
    def from_file(cls, path: Path | str) -> "ServiceAccountKey":
        path = Path(path)
        if not path.is_file():
            raise AuthError(f"Service account key file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AuthError(f"Service account key is not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServiceAccountKey":
        credentials = data.get("credentials") or {}
        private_key = credentials.get("privateKey") or data.get("privateKey")
        if not private_key:
            raise AuthError(
                "Service account key file is missing 'credentials.privateKey'. "
                "Re-download the key with the private-key option enabled."
            )
        key_id = data.get("id") or credentials.get("kid") or data.get("kid") or ""
        sa_email = (
            credentials.get("iss")
            or data.get("iss")
            or data.get("serviceAccountEmail")
            or ""
        )
        issuer = credentials.get("iss") or data.get("iss") or sa_email
        audience = data.get("aud") or credentials.get("aud") or ""
        if not key_id or not issuer:
            raise AuthError(
                "Service account key is missing required fields (id / iss). "
                "File seems malformed."
            )
        return cls(
            key_id=key_id,
            service_account_email=sa_email,
            issuer=issuer,
            audience=audience,
            private_key_pem=private_key,
            raw=data,
        )


class KeyFlowAuth:
    """Authenticator implementing STACKIT Key Flow.

    Usage:
        auth = KeyFlowAuth(ServiceAccountKey.from_file("sa-key.json"))
        token = auth.get_access_token()
    """

    def __init__(
        self,
        sa_key: ServiceAccountKey,
        token_endpoint: str = DEFAULT_TOKEN_ENDPOINT,
        http_client: httpx.Client | None = None,
        clock: callable = time.time,  # type: ignore[type-arg]
    ) -> None:
        self.sa_key = sa_key
        self.token_endpoint = token_endpoint
        self._client = http_client or httpx.Client(timeout=30)
        self._clock = clock
        self._access_token: str | None = None
        self._access_expires_at: float = 0.0

    def _build_self_signed_jwt(self) -> str:
        now = int(self._clock())
        payload = {
            "iss": self.sa_key.issuer,
            "sub": self.sa_key.issuer,
            "aud": self.token_endpoint,
            "iat": now,
            "exp": now + 600,
            "jti": f"{self.sa_key.key_id}-{now}",
        }
        headers = {"kid": self.sa_key.key_id, "typ": "JWT"}
        return jwt.encode(
            payload,
            self.sa_key.private_key_pem,
            algorithm="RS512",
            headers=headers,
        )

    def get_access_token(self, force_refresh: bool = False) -> str:
        if (
            not force_refresh
            and self._access_token
            and self._clock() < self._access_expires_at - TOKEN_REFRESH_SAFETY_S
        ):
            return self._access_token

        assertion = self._build_self_signed_jwt()
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        try:
            resp = self._client.post(
                self.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise AuthError(f"Token endpoint unreachable: {exc}") from exc

        if resp.status_code != 200:
            raise AuthError(
                f"Token exchange failed (HTTP {resp.status_code}): {resp.text[:300]}"
            )
        try:
            body = resp.json()
        except json.JSONDecodeError as exc:
            raise AuthError(f"Token endpoint returned non-JSON: {exc}") from exc

        access_token = body.get("access_token")
        if not access_token:
            raise AuthError(f"Token response missing 'access_token': {body}")

        expires_in = body.get("expires_in") or 1800
        self._access_token = access_token
        self._access_expires_at = self._clock() + float(expires_in)
        return access_token

    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_access_token()}"}

    def close(self) -> None:
        self._client.close()
