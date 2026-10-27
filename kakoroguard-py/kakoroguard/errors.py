"""Custom exception classes for the KakoroGuard Python SDK."""

from __future__ import annotations


class KakoroGuardError(Exception):
    """Base exception for all KakoroGuard SDK errors."""

    def __init__(self, message: str, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class AgentKeyError(KakoroGuardError):
    """Raised when an Ed25519 key cannot be generated, parsed, or decoded."""


class AgentSigningError(KakoroGuardError):
    """Raised when signing a request or canonicalizing payload fails."""


class AgentSignatureInvalid(KakoroGuardError):
    """Raised when an Ed25519 signature fails verification against a public key."""


class AgentTimestampExpiredError(KakoroGuardError):
    """Raised when a request timestamp violates replay attack protection limits."""


class SerializationError(KakoroGuardError):
    """Raised when a payload cannot be canonically serialized to JSON."""
