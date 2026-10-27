"""Unit tests for AgentGuard custom error classes."""

from agentguard.errors import (
    AgentGuardError,
    AgentKeyError,
    AgentSignatureInvalid,
    AgentSigningError,
    AgentTimestampExpiredError,
    SerializationError,
)


def test_agent_guard_error_without_details() -> None:
    err = AgentGuardError("Something failed")
    assert str(err) == "Something failed"
    assert err.message == "Something failed"
    assert err.details == {}


def test_agent_guard_error_with_details() -> None:
    err = AgentGuardError("Failed", {"code": 401, "reason": "bad_key"})
    assert "Failed" in str(err)
    assert "bad_key" in str(err)
    assert err.details["code"] == 401


def test_error_hierarchy() -> None:
    assert issubclass(AgentKeyError, AgentGuardError)
    assert issubclass(AgentSigningError, AgentGuardError)
    assert issubclass(AgentSignatureInvalid, AgentGuardError)
    assert issubclass(AgentTimestampExpiredError, AgentGuardError)
    assert issubclass(SerializationError, AgentGuardError)
