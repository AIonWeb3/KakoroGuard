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
from kakoroguard.fastapi import (
    KakoroGuardProviderConfig,
    SorobanRpcClient,
    get_provider_config,
    require_agent_role,
    set_provider_config,
)
from kakoroguard.keys import AgentKeypair
from kakoroguard.schema import AgentRequestPayload, PaymentIntent
from kakoroguard.signer import (
    MAX_TIMESTAMP_AGE_MS,
    AgentAuthHeader,
    AgentSigner,
    attach_payment,
    build_synergistic_signing_message,
    canonicalize_payload,
    create_auth_headers,
    generate_auth_header,
    get_current_timestamp_ms,
    hash_synergistic_payload,
    serialize_synergistic_payload,
    sign_request,
    validate_timestamp,
)

__version__ = "0.1.0"

__all__ = [
    "MAX_TIMESTAMP_AGE_MS",
    "AgentAuthHeader",
    "AgentKeyError",
    "AgentKeypair",
    "AgentRequestPayload",
    "AgentSignatureInvalid",
    "AgentSigner",
    "AgentSigningError",
    "AgentTimestampExpiredError",
    "KakoroGuardError",
    "KakoroGuardProviderConfig",
    "PaymentIntent",
    "SerializationError",
    "SorobanRpcClient",
    "attach_payment",
    "build_synergistic_signing_message",
    "canonicalize_payload",
    "create_auth_headers",
    "generate_auth_header",
    "get_current_timestamp_ms",
    "get_provider_config",
    "hash_synergistic_payload",
    "require_agent_role",
    "serialize_synergistic_payload",
    "set_provider_config",
    "sign_request",
    "validate_timestamp",
]
