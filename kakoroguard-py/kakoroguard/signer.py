"""Request signing module for KakoroGuard AI agents.

Provides deterministic canonical JSON serialization and Ed25519 request signing
with standardized AgentAuthHeader generation for replay-protected authentication.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from kakoroguard.errors import (
    AgentSigningError,
    AgentTimestampExpiredError,
    SerializationError,
)
from kakoroguard.keys import AgentKeypair

# Replay protection constant: 5 minutes in milliseconds
MAX_TIMESTAMP_AGE_MS: int = 5 * 60 * 1000


def canonicalize_payload(payload: Any) -> str:
    """Deterministically serialize any JSON-compatible payload to canonical JSON.

    Rules:
    - Dict keys sorted alphabetically.
    - Compact separators without whitespace (',' and ':').
    - UTF-8 characters preserved (ensure_ascii=False).
    - Consistent representation across Python and JavaScript.

    Args:
        payload: The Python object (dict, list, primitive) to serialize.

    Returns:
        Canonical JSON string.

    Raises:
        SerializationError: If the payload cannot be serialized to JSON.
    """
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SerializationError(
            f"Failed to canonically serialize payload: {exc}"
        ) from exc


def get_current_timestamp_ms() -> int:
    """Return the current unix epoch timestamp in milliseconds."""
    return int(time.time() * 1000)


def build_signing_message(canonical_json: str, timestamp: int | None = None) -> bytes:
    """Build the binary message to be signed.

    If a timestamp is provided, the message binds the timestamp to the payload:
        "{timestamp}.{canonical_json}"
    Otherwise:
        "{canonical_json}"
    """
    if timestamp is not None:
        message_str = f"{timestamp}.{canonical_json}"
    else:
        message_str = canonical_json
    return message_str.encode("utf-8")


def sign_request(
    payload: Mapping[str, Any] | Any,
    keypair: AgentKeypair,
    timestamp: int | None = None,
) -> str:
    """Sign a request payload using an AgentKeypair.

    Args:
        payload: The request body / payload dictionary.
        keypair: The AgentKeypair containing the agent's private signing key.
        timestamp: Optional unix timestamp in milliseconds. If provided, binds
                   the timestamp to the signed payload for replay protection.

    Returns:
        Hex-encoded Ed25519 signature string.

    Raises:
        AgentSigningError: If signing fails.
        SerializationError: If payload cannot be serialized.
    """
    try:
        canonical = canonicalize_payload(payload)
        message = build_signing_message(canonical, timestamp)
        signature_bytes = keypair.sign(message)
        return signature_bytes.hex()
    except SerializationError:
        raise
    except Exception as exc:
        raise AgentSigningError(f"Failed to sign request: {exc}") from exc


@dataclass(frozen=True)
class AgentAuthHeader:
    """Standardized KakoroGuard Authentication Header representation."""

    public_key: str
    timestamp: int
    signature: str

    def to_headers(self) -> dict[str, str]:
        """Generate standardized HTTP request headers.

        Includes both individual headers (`X-Agent-*`) and composite `Authorization` header.
        """
        return {
            "x-agent-public-key": self.public_key,
            "x-agent-timestamp": str(self.timestamp),
            "x-agent-signature": self.signature,
            "authorization": (
                f'KakoroGuard key="{self.public_key}",ts="{self.timestamp}",sig="{self.signature}"'
            ),
        }

    def to_dict(self) -> dict[str, str]:
        """Return headers as a dictionary."""
        return self.to_headers()


def generate_auth_header(
    payload: Mapping[str, Any] | Any,
    keypair: AgentKeypair,
    timestamp: int | None = None,
) -> AgentAuthHeader:
    """Generate an AgentAuthHeader for an agent request.

    Args:
        payload: The request body / payload dictionary.
        keypair: The AgentKeypair holding the private key.
        timestamp: Optional timestamp in ms (defaults to current time).

    Returns:
        An AgentAuthHeader containing public key, timestamp, and signature.
    """
    if timestamp is None:
        timestamp = get_current_timestamp_ms()

    signature = sign_request(payload, keypair, timestamp=timestamp)
    return AgentAuthHeader(
        public_key=keypair.public_key,
        timestamp=timestamp,
        signature=signature,
    )


def create_auth_headers(
    payload: Mapping[str, Any] | Any,
    keypair: AgentKeypair,
    timestamp: int | None = None,
) -> dict[str, str]:
    """Create HTTP request headers for an agent request.

    Args:
        payload: The request body / payload dictionary.
        keypair: The AgentKeypair holding the private key.
        timestamp: Optional timestamp in ms (defaults to current time).

    Returns:
        Dictionary of HTTP headers with x-agent-public-key, x-agent-timestamp, x-agent-signature.
    """
    auth = generate_auth_header(payload, keypair, timestamp=timestamp)
    return auth.to_headers()


def validate_timestamp(
    timestamp: int,
    max_age_ms: int = MAX_TIMESTAMP_AGE_MS,
    clock_skew_ms: int = 60_000,
    current_time_ms: int | None = None,
) -> bool:
    """Validate a timestamp for replay attack prevention.

    Args:
        timestamp: The timestamp in milliseconds (or seconds if < 1e11).
        max_age_ms: Maximum age allowed (default 5 minutes = 300,000 ms).
        clock_skew_ms: Allowable forward clock skew.
        current_time_ms: Optional injected current time (for testing).

    Returns:
        True if the timestamp is fresh and within bounds.

    Raises:
        AgentTimestampExpiredError: If expired or too far in the future.
    """
    now = current_time_ms if current_time_ms is not None else get_current_timestamp_ms()
    ts_ms = timestamp * 1000 if timestamp < 100_000_000_000 else timestamp

    diff = now - ts_ms
    if diff > max_age_ms:
        raise AgentTimestampExpiredError(
            f"Timestamp expired: age is {diff}ms (allowed: {max_age_ms}ms)"
        )
    if diff < -clock_skew_ms:
        raise AgentTimestampExpiredError(
            f"Timestamp is in the future: ahead by {-diff}ms (allowed clock skew: {clock_skew_ms}ms)"
        )
    return True
