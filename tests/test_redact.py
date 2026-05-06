"""Tests for the redact utility."""
from stackit_audit.utils.redact import redact


def test_redact_private_key():
    d = {"private_key": "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"}
    result = redact(d)
    assert result["private_key"] == "***REDACTED***"


def test_redact_nested():
    d = {"credentials": {"password": "secret123"}}
    result = redact(d)
    assert result["credentials"]["password"] == "***REDACTED***"


def test_redact_preserves_other_fields():
    d = {"name": "test", "secret": "abc", "api_key": "key123"}
    result = redact(d)
    assert result["name"] == "test"
    assert result["secret"] == "***REDACTED***"
    assert result["api_key"] == "***REDACTED***"


def test_redact_does_not_mutate_original():
    d = {"password": "sensitive"}
    original = dict(d)
    redact(d)
    assert d == original
