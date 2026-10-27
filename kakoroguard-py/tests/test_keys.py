"""Unit tests for AgentKeypair key management module."""

from unittest.mock import patch

import pytest

from kakoroguard.errors import AgentKeyError, AgentSignatureInvalid
from kakoroguard.keys import AgentKeypair


def test_agent_keypair_generate() -> None:
    kp = AgentKeypair.generate()
    assert kp.public_key.startswith("G")
    assert len(kp.public_key) == 56
    assert kp.secret_seed.startswith("S")
    assert len(kp.secret_seed) == 56
    assert kp.can_sign is True
    assert len(kp.raw_public_key) == 32
    assert len(kp.raw_secret_seed) == 32
    assert "signing" in repr(kp)
    assert kp.public_key in repr(kp)


def test_agent_keypair_from_secret_stellar_seed() -> None:
    original = AgentKeypair.generate()
    loaded = AgentKeypair.from_secret(original.secret_seed)
    assert loaded.public_key == original.public_key
    assert loaded.secret_seed == original.secret_seed
    assert loaded.can_sign is True


def test_agent_keypair_from_secret_raw_bytes() -> None:
    original = AgentKeypair.generate()
    raw_seed = original.raw_secret_seed
    assert len(raw_seed) == 32

    loaded = AgentKeypair.from_secret(raw_seed)
    assert loaded.public_key == original.public_key
    assert loaded.secret_seed == original.secret_seed


def test_agent_keypair_from_secret_hex_string() -> None:
    original = AgentKeypair.generate()
    hex_seed = original.raw_secret_seed.hex()
    assert len(hex_seed) == 64

    loaded = AgentKeypair.from_secret(hex_seed)
    assert loaded.public_key == original.public_key
    assert loaded.secret_seed == original.secret_seed


def test_agent_keypair_from_secret_invalid_inputs() -> None:
    with pytest.raises(AgentKeyError, match="cannot be empty"):
        AgentKeypair.from_secret("")

    with pytest.raises(AgentKeyError, match="must be exactly 32 bytes"):
        AgentKeypair.from_secret(b"short_bytes")

    with pytest.raises(AgentKeyError, match="must be exactly 32 bytes"):
        AgentKeypair.from_secret(b"too_long_bytes_over_32_bytes_length_1234")

    with pytest.raises(AgentKeyError, match="Invalid hex string"):
        # 64 chars of non-hex
        AgentKeypair.from_secret("Z" * 64)

    with pytest.raises(AgentKeyError, match="Invalid Ed25519 secret seed"):
        # Malformed S-seed
        AgentKeypair.from_secret("SBADSEEDINVALIDCHECKSUM1234567890")

    with pytest.raises(AgentKeyError, match="Invalid Ed25519 secret seed"):
        # Malformed seed not starting with S and not 64 hex chars
        AgentKeypair.from_secret("bad_seed_not_s_prefix")


def test_agent_keypair_from_public_key() -> None:
    original = AgentKeypair.generate()
    pub_only = AgentKeypair.from_public_key(original.public_key)

    assert pub_only.public_key == original.public_key
    assert pub_only.can_sign is False
    assert len(pub_only.raw_public_key) == 32
    assert "public-only" in repr(pub_only)

    with pytest.raises(AgentKeyError, match="does not have a private key"):
        _ = pub_only.secret_seed

    with pytest.raises(AgentKeyError, match="does not have a private key"):
        _ = pub_only.raw_secret_seed

    with pytest.raises(AgentKeyError, match="Cannot sign"):
        pub_only.sign(b"data")


def test_agent_keypair_from_public_key_invalid() -> None:
    with pytest.raises(AgentKeyError, match="must be a non-empty string"):
        AgentKeypair.from_public_key("")

    with pytest.raises(AgentKeyError, match="must be a non-empty string"):
        AgentKeypair.from_public_key(12345)  # type: ignore[arg-type]

    with pytest.raises(AgentKeyError, match="Invalid Stellar public key"):
        AgentKeypair.from_public_key("GBADPUBLICKEYNOTCORRECT123456789")


def test_agent_keypair_sign_and_verify() -> None:
    kp = AgentKeypair.generate()
    data = b"Hello, Soroban AI Agent!"
    signature = kp.sign(data)

    assert isinstance(signature, bytes)
    assert len(signature) == 64

    # Verification on original keypair
    assert kp.verify(data, signature) is True

    # Verification on public-only keypair
    pub_only = AgentKeypair.from_public_key(kp.public_key)
    assert pub_only.verify(data, signature) is True

    # Verification failure on modified data
    with pytest.raises(AgentSignatureInvalid, match="Signature verification failed"):
        kp.verify(b"Tampered data", signature)

    # Verification failure on corrupted signature
    corrupt_sig = bytes([b ^ 0xFF for b in signature])
    with pytest.raises(AgentSignatureInvalid):
        kp.verify(data, corrupt_sig)


def test_agent_keypair_generate_exception() -> None:
    with (
        patch(
            "stellar_sdk.Keypair.random", side_effect=RuntimeError("Entropy failure")
        ),
        pytest.raises(AgentKeyError, match="Failed to generate secure random keypair"),
    ):
        AgentKeypair.generate()


def test_agent_keypair_from_secret_unexpected_exception() -> None:
    with (
        patch(
            "stellar_sdk.Keypair.from_secret",
            side_effect=RuntimeError("Unexpected OS error"),
        ),
        pytest.raises(
            AgentKeyError, match="Unexpected error loading keypair from secret"
        ),
    ):
        AgentKeypair.from_secret("SBADSTRINGNOTSTRKEY")


def test_agent_keypair_from_public_key_unexpected_exception() -> None:
    with (
        patch(
            "stellar_sdk.Keypair.from_public_key",
            side_effect=RuntimeError("Memory error"),
        ),
        pytest.raises(AgentKeyError, match="Unexpected error loading public key"),
    ):
        AgentKeypair.from_public_key(
            "GAVJD7E63JZUJAHI4KWFOTWJWDIL7E6S2K4ZZAQIX5UNCON4A5NJTUNJ"
        )


def test_agent_keypair_verify_unexpected_exception() -> None:
    kp = AgentKeypair.generate()
    with (
        patch.object(kp._keypair, "verify", side_effect=RuntimeError("Crypto crash")),
        pytest.raises(
            AgentSignatureInvalid, match="Error during signature verification"
        ),
    ):
        kp.verify(b"data", b"x" * 64)
