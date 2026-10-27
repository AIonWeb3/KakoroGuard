"""AgentGuard Python SDK for AI Agent Key Management and Cryptographic Request Signing."""

from __future__ import annotations

from agentguard.errors import (
    AgentGuardError,
    AgentKeyError,
    AgentSignatureInvalid,
    AgentSigningError,
    AgentTimestampExpiredError,
    SerializationError,
)
from agentguard.keys import AgentKeypair
from agentguard.signer import (
    MAX_TIMESTAMP_AGE_MS,
    AgentAuthHeader,
    canonicalize_payload,
    create_auth_headers,
    generate_auth_header,
    get_current_timestamp_ms,
    sign_request,
    validate_timestamp,
)

__version__ = "0.1.0"

__all__ = [
    "MAX_TIMESTAMP_AGE_MS",
    "AgentAuthHeader",
    "AgentGuardError",
    "AgentKeyError",
    "AgentKeypair",
    "AgentSignatureInvalid",
    "AgentSigningError",
    "AgentTimestampExpiredError",
    "SerializationError",
    "canonicalize_payload",
    "create_auth_headers",
    "generate_auth_header",
    "get_current_timestamp_ms",
    "sign_request",
    "validate_timestamp",
]
