"""Unit tests for KakoroGuard custom error classes."""

from kakoroguard.errors import (
    AgentKeyError,
    AgentSignatureInvalid,
    AgentSigningError,
    AgentTimestampExpiredError,
    KakoroGuardError,
    SerializationError,
)


def test_kakoro_guard_error_without_details() -> None:
    err = KakoroGuardError("Something failed")
    assert str(err) == "Something failed"
    assert err.message == "Something failed"
    assert err.details == {}


def test_kakoro_guard_error_with_details() -> None:
    err = KakoroGuardError("Failed", {"code": 401, "reason": "bad_key"})
    assert "Failed" in str(err)
    assert "bad_key" in str(err)
    assert err.details["code"] == 401


def test_error_hierarchy() -> None:
    assert issubclass(AgentKeyError, KakoroGuardError)
    assert issubclass(AgentSigningError, KakoroGuardError)
    assert issubclass(AgentSignatureInvalid, KakoroGuardError)
    assert issubclass(AgentTimestampExpiredError, KakoroGuardError)
    assert issubclass(SerializationError, KakoroGuardError)
