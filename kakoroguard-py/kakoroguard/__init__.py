"""KakoroGuard Python SDK for AI Agent Key Management and Cryptographic Request Signing."""

from __future__ import annotations

from kakoroguard.errors import (
    AgentKeyError,
    AgentSignatureInvalid,
    AgentSigningError,
    AgentTimestampExpiredError,
    KakoroGuardError,
    SerializationError,
)
from kakoroguard.keys import AgentKeypair
from kakoroguard.signer import (
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
    "AgentKeyError",
    "AgentKeypair",
    "AgentSignatureInvalid",
    "AgentSigningError",
    "AgentTimestampExpiredError",
    "KakoroGuardError",
    "SerializationError",
    "canonicalize_payload",
    "create_auth_headers",
    "generate_auth_header",
    "get_current_timestamp_ms",
    "sign_request",
    "validate_timestamp",
]
