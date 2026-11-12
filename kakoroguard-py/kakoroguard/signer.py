"""Request signing module for KakoroGuard AI agents.

Provides deterministic canonical JSON serialization and Ed25519 request signing
with standardized AgentAuthHeader generation for replay-protected authentication.
"""

from __future__ import annotations

import hashlib
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
from kakoroguard.schema import AgentRequestPayload, PaymentIntent

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


def serialize_synergistic_payload(
    payload: Any,
    payment_intent: PaymentIntent | Mapping[str, Any] | None = None,
) -> str:
    """Deterministically serialize synergistic payload + payment intent to canonical JSON.

    Combines application payload with payment intent to bind financial authorization
    with KakoroGuard identity, preventing tampering of amounts or destination.

    Args:
        payload: Application request payload (or AgentRequestPayload).
        payment_intent: Optional PaymentIntent or payment intent mapping.

    Returns:
        Canonical JSON string.
    """
    app_payload: Any = payload
    intent_data: dict[str, Any] | None = None

    if isinstance(payload, AgentRequestPayload):
        app_payload = payload.payload
        intent_data = {
            "amount": payload.payment_intent.amount,
            "asset": payload.payment_intent.asset,
            "destination": payload.payment_intent.destination,
            "max_fee": payload.payment_intent.max_fee,
        }
    elif isinstance(payload, Mapping) and "payment_intent" in payload:
        app_payload = payload.get("payload", {})
        raw_intent = payload["payment_intent"]
        if isinstance(raw_intent, PaymentIntent):
            intent_data = {
                "amount": raw_intent.amount,
                "asset": raw_intent.asset,
                "destination": raw_intent.destination,
                "max_fee": raw_intent.max_fee,
            }
        elif isinstance(raw_intent, Mapping):
            intent_data = {
                "amount": str(raw_intent.get("amount", "")),
                "asset": str(raw_intent.get("asset", "XLM")),
                "destination": raw_intent.get("destination"),
                "max_fee": int(raw_intent.get("max_fee", 100_000)),
            }

    if intent_data is None and payment_intent is not None:
        if isinstance(payment_intent, PaymentIntent):
            intent_data = {
                "amount": payment_intent.amount,
                "asset": payment_intent.asset,
                "destination": payment_intent.destination,
                "max_fee": payment_intent.max_fee,
            }
        elif isinstance(payment_intent, Mapping):
            intent_data = {
                "amount": str(payment_intent.get("amount", "")),
                "asset": str(payment_intent.get("asset", "XLM")),
                "destination": payment_intent.get("destination"),
                "max_fee": int(payment_intent.get("max_fee", 100_000)),
            }

    combined: dict[str, Any] = {
        "payment_intent": intent_data if intent_data is not None else {},
        "payload": app_payload if app_payload is not None else {},
    }
    return canonicalize_payload(combined)


def hash_synergistic_payload(
    payload: Any,
    payment_intent: PaymentIntent | Mapping[str, Any] | None = None,
) -> str:
    """Compute deterministic SHA-256 hex digest of the synergistic payload.

    Args:
        payload: Canonical JSON string, application payload, or AgentRequestPayload.
        payment_intent: Optional PaymentIntent if payload is not already combined.

    Returns:
        64-character lowercase hexadecimal string of SHA-256 digest.
    """
    if isinstance(payload, str) and payment_intent is None:
        canonical = payload
    else:
        canonical = serialize_synergistic_payload(payload, payment_intent)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_synergistic_signing_message(
    canonical_json_or_hash: str,
    timestamp: int | None = None,
) -> bytes:
    """Build binary message to sign for synergistic request."""
    return build_signing_message(canonical_json_or_hash, timestamp)


class AgentSigner:
    """High-level signer for an AI Agent to construct signed requests and attach AgentPay authorization."""

    def __init__(self, keypair: AgentKeypair) -> None:
        self.keypair = keypair

    def sign(self, payload: Any, timestamp: int | None = None) -> AgentAuthHeader:
        """Sign a payload and return an AgentAuthHeader."""
        return generate_auth_header(payload, self.keypair, timestamp=timestamp)

    def attach_payment(
        self,
        cost: str,
        asset: str = "XLM",
        payload: Any = None,
        max_fee: int = 100_000,
        destination: str | None = None,
        timestamp: int | None = None,
    ) -> AgentRequestPayload:
        """Attach an AgentPay payment intent to a request and cryptographically sign the combination.

        Args:
            cost: Payment amount (e.g. "5_XLM" or "5.0").
            asset: Stellar asset identifier (default: "XLM").
            payload: Optional application request payload (defaults to empty dict).
            max_fee: Maximum fee in stroops.
            destination: Optional provider destination address.
            timestamp: Optional timestamp in ms (defaults to current time).

        Returns:
            An AgentRequestPayload instance containing identity, signature, payment intent, and payload.
        """
        return attach_payment(
            cost=cost,
            asset=asset,
            payload=payload,
            keypair=self.keypair,
            max_fee=max_fee,
            destination=destination,
            timestamp=timestamp,
        )


def attach_payment(
    cost: str,
    asset: str = "XLM",
    payload: Any = None,
    keypair: AgentKeypair | None = None,
    max_fee: int = 100_000,
    destination: str | None = None,
    timestamp: int | None = None,
) -> AgentRequestPayload:
    """Attach an AgentPay payment intent to a request and cryptographically sign the combination.

    Args:
        cost: Payment amount (e.g. "5_XLM" or "5.0").
        asset: Stellar asset identifier (default: "XLM").
        payload: Optional application request payload (defaults to empty dict).
        keypair: AgentKeypair for signing. If omitted, a temporary keypair is generated.
        max_fee: Maximum fee in stroops.
        destination: Optional provider destination address.
        timestamp: Optional timestamp in ms (defaults to current time).

    Returns:
        An AgentRequestPayload instance containing identity, signature, payment intent, and payload.
    """
    if keypair is None:
        keypair = AgentKeypair.generate()

    if timestamp is None:
        timestamp = get_current_timestamp_ms()

    intent = PaymentIntent(
        amount=cost,
        asset=asset,
        max_fee=max_fee,
        destination=destination,
    )

    app_dict: dict[str, Any]
    if payload is None:
        app_dict = {}
    elif isinstance(payload, Mapping):
        app_dict = dict(payload)
    else:
        app_dict = {"data": payload}

    canonical = serialize_synergistic_payload(app_dict, intent)
    message = build_signing_message(canonical, timestamp)
    signature_bytes = keypair.sign(message)
    signature_hex = signature_bytes.hex()

    return AgentRequestPayload(
        agent_id=keypair.public_key,
        timestamp=timestamp,
        signature=signature_hex,
        payment_intent=intent,
        payload=app_dict,
    )


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
