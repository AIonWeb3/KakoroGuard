"""Unit tests for request signing and canonicalization module."""

from unittest.mock import patch

import pytest

from kakoroguard.errors import (
    AgentSigningError,
    AgentTimestampExpiredError,
    SerializationError,
)
from kakoroguard.keys import AgentKeypair
from kakoroguard.signer import (
    AgentAuthHeader,
    build_signing_message,
    canonicalize_payload,
    create_auth_headers,
    generate_auth_header,
    get_current_timestamp_ms,
    sign_request,
    validate_timestamp,
)


def test_canonicalize_payload_sorting() -> None:
    # Keys out of order
    payload = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    canonical = canonicalize_payload(payload)
    assert canonical == '{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_canonicalize_payload_types() -> None:
    payload = {
        "string": "hello",
        "number": 42,
        "bool": True,
        "null": None,
        "list": [3, 2, 1],
    }
    canonical = canonicalize_payload(payload)
    assert (
        canonical
        == '{"bool":true,"list":[3,2,1],"null":null,"number":42,"string":"hello"}'
    )


def test_canonicalize_payload_non_serializable() -> None:
    class Unserializable:
        pass

    with pytest.raises(
        SerializationError, match="Failed to canonically serialize payload"
    ):
        canonicalize_payload({"obj": Unserializable()})

    with pytest.raises(
        SerializationError, match="Failed to canonically serialize payload"
    ):
        canonicalize_payload({"invalid_float": float("nan")})


def test_build_signing_message() -> None:
    msg_without_ts = build_signing_message('{"a":1}', timestamp=None)
    assert msg_without_ts == b'{"a":1}'

    msg_with_ts = build_signing_message('{"a":1}', timestamp=1700000000000)
    assert msg_with_ts == b'1700000000000.{"a":1}'


def test_sign_request_deterministic() -> None:
    kp = AgentKeypair.generate()
    payload = {"action": "execute", "amount": 100}

    sig1 = sign_request(payload, kp)
    sig2 = sign_request(payload, kp)
    assert sig1 == sig2
    assert len(sig1) == 128  # 64 bytes in hex

    # Verify signature
    msg = build_signing_message(canonicalize_payload(payload))
    assert kp.verify(msg, bytes.fromhex(sig1)) is True


def test_sign_request_with_timestamp() -> None:
    kp = AgentKeypair.generate()
    payload = {"action": "query"}
    ts = 1710000000000

    sig = sign_request(payload, kp, timestamp=ts)
    msg = build_signing_message(canonicalize_payload(payload), timestamp=ts)
    assert kp.verify(msg, bytes.fromhex(sig)) is True


def test_sign_request_signing_error() -> None:
    kp = AgentKeypair.generate()
    with (
        patch.object(
            kp, "sign", side_effect=RuntimeError("Signing device disconnected")
        ),
        pytest.raises(AgentSigningError, match="Failed to sign request"),
    ):
        sign_request({"test": 1}, kp)


def test_sign_request_unserializable_payload() -> None:
    kp = AgentKeypair.generate()
    with pytest.raises(SerializationError):
        sign_request({"bad": {1, 2, 3}}, kp)


def test_agent_auth_header() -> None:
    auth = AgentAuthHeader(
        public_key="GAVJD7E63JZUJAHI4KWFOTWJWDIL7E6S2K4ZZAQIX5UNCON4A5NJTUNJ",
        timestamp=1710000000000,
        signature="abcdef123456",
    )
    headers = auth.to_headers()
    assert headers["x-agent-public-key"] == auth.public_key
    assert headers["x-agent-timestamp"] == "1710000000000"
    assert headers["x-agent-signature"] == "abcdef123456"
    assert "KakoroGuard" in headers["authorization"]
    assert auth.to_dict() == headers


def test_generate_auth_header() -> None:
    kp = AgentKeypair.generate()
    payload = {"command": "deploy"}

    auth = generate_auth_header(payload, kp, timestamp=1700000000000)
    assert auth.public_key == kp.public_key
    assert auth.timestamp == 1700000000000
    assert len(auth.signature) == 128

    # Test auto timestamp
    auth_auto = generate_auth_header(payload, kp)
    assert auth_auto.timestamp > 0
    now_ms = get_current_timestamp_ms()
    assert abs(auth_auto.timestamp - now_ms) < 2000


def test_create_auth_headers() -> None:
    kp = AgentKeypair.generate()
    payload = {"service": "model-gateway"}
    headers = create_auth_headers(payload, kp, timestamp=1700000000000)

    assert headers["x-agent-public-key"] == kp.public_key
    assert headers["x-agent-timestamp"] == "1700000000000"
    assert len(headers["x-agent-signature"]) == 128
    assert "KakoroGuard" in headers["authorization"]


def test_validate_timestamp_fresh() -> None:
    now = 1710000000000
    # Exactly current
    assert validate_timestamp(now, current_time_ms=now) is True

    # 1 minute ago (within 5 minutes)
    assert validate_timestamp(now - 60_000, current_time_ms=now) is True

    # Given in seconds (< 1e11)
    now_sec = 1710000000
    assert validate_timestamp(now_sec - 60, current_time_ms=now) is True

    # With default current_time_ms
    current_real = get_current_timestamp_ms()
    assert validate_timestamp(current_real - 5000) is True


def test_validate_timestamp_expired() -> None:
    now = 1710000000000
    # 6 minutes ago (exceeds 5 minutes)
    with pytest.raises(AgentTimestampExpiredError, match="Timestamp expired"):
        validate_timestamp(now - (6 * 60 * 1000), current_time_ms=now)


def test_validate_timestamp_future_clock_skew() -> None:
    now = 1710000000000
    # 2 minutes in the future (default skew tolerance is 1 minute)
    with pytest.raises(AgentTimestampExpiredError, match="in the future"):
        validate_timestamp(now + 120_000, current_time_ms=now)
