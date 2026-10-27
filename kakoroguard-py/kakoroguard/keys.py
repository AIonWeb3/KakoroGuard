"""Key management module for Ed25519 Agent Keypairs compatible with Stellar/Soroban."""

from __future__ import annotations

import binascii

from stellar_sdk import Keypair as StellarKeypair
from stellar_sdk import StrKey
from stellar_sdk.exceptions import (
    BadSignatureError,
    Ed25519PublicKeyInvalidError,
    Ed25519SecretSeedInvalidError,
)

from kakoroguard.errors import AgentKeyError, AgentSignatureInvalid


class AgentKeypair:
    """Manages an Ed25519 keypair for an AI agent on Stellar/Soroban.

    Public keys are represented as Stellar StrKey G-addresses (e.g. `G...`),
    and private seeds as Stellar StrKey S-seeds (e.g. `S...`).
    """

    def __init__(self, internal_keypair: StellarKeypair) -> None:
        self._keypair = internal_keypair

    @classmethod
    def generate(cls) -> AgentKeypair:
        """Generate a cryptographically secure random Ed25519 keypair."""
        try:
            kp = StellarKeypair.random()
            return cls(kp)
        except Exception as exc:
            raise AgentKeyError(
                f"Failed to generate secure random keypair: {exc}"
            ) from exc

    @classmethod
    def from_secret(cls, secret_seed: str | bytes) -> AgentKeypair:
        """Create an AgentKeypair from a Stellar secret seed or raw 32-byte seed.

        Args:
            secret_seed: A Stellar StrKey secret seed (e.g. 'S...'),
                         a 64-character hex string representing 32 bytes,
                         or raw 32 bytes.

        Returns:
            An initialized AgentKeypair instance.

        Raises:
            AgentKeyError: If the seed is invalid, malformed, or has bad checksum.
        """
        if not secret_seed:
            raise AgentKeyError("Secret seed cannot be empty")

        try:
            if isinstance(secret_seed, bytes):
                if len(secret_seed) == 32:
                    encoded_seed = StrKey.encode_ed25519_secret_seed(secret_seed)
                    kp = StellarKeypair.from_secret(encoded_seed)
                    return cls(kp)
                raise AgentKeyError(
                    f"Raw secret seed must be exactly 32 bytes, received {len(secret_seed)} bytes"
                )

            # String input
            secret_str = secret_seed.strip()

            # Check if it's already a Stellar S-seed
            if secret_str.startswith("S"):
                kp = StellarKeypair.from_secret(secret_str)
                return cls(kp)

            # Check if it's a 64-char hex string (32 bytes)
            if len(secret_str) == 64:
                try:
                    seed_bytes = bytes.fromhex(secret_str)
                    encoded_seed = StrKey.encode_ed25519_secret_seed(seed_bytes)
                    kp = StellarKeypair.from_secret(encoded_seed)
                    return cls(kp)
                except ValueError as err:
                    raise AgentKeyError(
                        f"Invalid hex string for secret seed: {err}"
                    ) from err

            # Otherwise not an S-seed and not a 64-char hex string
            raise AgentKeyError(
                "Invalid Ed25519 secret seed format (expected Stellar S-seed or 64-char hex string)"
            )
        except (Ed25519SecretSeedInvalidError, binascii.Error, ValueError) as exc:
            raise AgentKeyError(f"Invalid Ed25519 secret seed: {exc}") from exc
        except AgentKeyError:
            raise
        except Exception as exc:
            raise AgentKeyError(
                f"Unexpected error loading keypair from secret: {exc}"
            ) from exc

    @classmethod
    def from_public_key(cls, public_key: str) -> AgentKeypair:
        """Create an AgentKeypair with only a public key (for signature verification).

        Args:
            public_key: A Stellar StrKey G-address (e.g. 'G...').

        Returns:
            An initialized AgentKeypair instance without signing capabilities.

        Raises:
            AgentKeyError: If the public key is invalid, malformed, or has bad checksum.
        """
        if not public_key or not isinstance(public_key, str):
            raise AgentKeyError("Public key must be a non-empty string")

        public_str = public_key.strip()
        try:
            kp = StellarKeypair.from_public_key(public_str)
            return cls(kp)
        except (Ed25519PublicKeyInvalidError, binascii.Error, ValueError) as exc:
            raise AgentKeyError(
                f"Invalid Stellar public key (G-address): {exc}"
            ) from exc
        except Exception as exc:
            raise AgentKeyError(f"Unexpected error loading public key: {exc}") from exc

    @property
    def public_key(self) -> str:
        """The agent's public key as a Stellar StrKey G-address (e.g. 'G...')."""
        return self._keypair.public_key

    @property
    def secret_seed(self) -> str:
        """The agent's secret seed as a Stellar StrKey S-seed (e.g. 'S...').

        Raises:
            AgentKeyError: If this keypair only has a public key.
        """
        if not self.can_sign:
            raise AgentKeyError(
                "Keypair does not have a private key (public-key only instance)"
            )
        return self._keypair.secret

    @property
    def raw_public_key(self) -> bytes:
        """The raw 32 bytes of the Ed25519 public key."""
        return self._keypair.raw_public_key()

    @property
    def raw_secret_seed(self) -> bytes:
        """The raw 32 bytes of the Ed25519 secret seed.

        Raises:
            AgentKeyError: If this keypair only has a public key.
        """
        if not self.can_sign:
            raise AgentKeyError(
                "Keypair does not have a private key (public-key only instance)"
            )
        return self._keypair.raw_secret_key()

    @property
    def can_sign(self) -> bool:
        """Whether this keypair has the private key needed to sign data."""
        return self._keypair.signing_key is not None

    def sign(self, data: bytes) -> bytes:
        """Sign binary data using Ed25519.

        Args:
            data: Raw bytes to sign.

        Returns:
            64-byte Ed25519 signature.

        Raises:
            AgentKeyError: If the keypair lacks a private key.
        """
        if not self.can_sign:
            raise AgentKeyError("Cannot sign: keypair has no private key")
        return self._keypair.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature against this keypair's public key.

        Args:
            data: The original raw bytes that were signed.
            signature: The 64-byte Ed25519 signature.

        Returns:
            True if the signature is valid.

        Raises:
            AgentSignatureInvalid: If the signature is forged, corrupt, or invalid.
        """
        try:
            self._keypair.verify(data, signature)
            return True
        except BadSignatureError as exc:
            raise AgentSignatureInvalid(
                f"Signature verification failed for agent {self.public_key}"
            ) from exc
        except Exception as exc:
            raise AgentSignatureInvalid(
                f"Error during signature verification: {exc}"
            ) from exc

    def __repr__(self) -> str:
        status = "signing" if self.can_sign else "public-only"
        return f"<AgentKeypair public_key='{self.public_key}' mode='{status}'>"
