from typing import Any

REDACTED = "***REDACTED***"
SENSITIVE_KEYS = {
    "private_key",
    "privateKey",
    "secret",
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "key_material",
    "apiKey",
    "api_key",
}


def redact(obj: Any) -> Any:
    """Recursively redact sensitive fields in a dict/list structure."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if k in SENSITIVE_KEYS else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj
