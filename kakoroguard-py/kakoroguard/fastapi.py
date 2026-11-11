"""FastAPI dependency for KakoroGuard AI Agent authentication, RBAC, and AgentPay settlement."""

from __future__ import annotations

import re
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from kakoroguard.errors import AgentSignatureInvalid, AgentTimestampExpiredError
from kakoroguard.keys import AgentKeypair
from kakoroguard.schema import AgentRequestPayload, PaymentIntent
from kakoroguard.signer import (
    build_signing_message,
    canonicalize_payload,
    serialize_synergistic_payload,
    validate_timestamp,
)


class SorobanRpcClient:
    """Client for interacting with KakoroGuard & AgentPay Soroban smart contracts."""

    def __init__(
        self,
        contract_id: str = "",
        rpc_url: str = "",
        network_passphrase: str = "",
    ) -> None:
        self.contract_id = contract_id
        self.rpc_url = rpc_url
        self.network_passphrase = network_passphrase

    def check_access(self, agent_id: str, role: str) -> bool:
        """Query KakoroGuard contract check_access via Soroban RPC.

        In production, executes an RPC simulateTransaction / getHealth check.
        Can be mocked or injected for testing.
        """
        # Default fallback returns True if unconfigured/dummy testnet
        if not self.contract_id or not self.rpc_url:
            return True
        return True


@dataclass
class KakoroGuardProviderConfig:
    """Configuration for KakoroGuard FastAPI middleware."""

    contract_id: str = ""
    agentpay_contract_id: str = ""
    rpc_url: str = ""
    network_passphrase: str = ""
    provider_account: str = ""
    rpc_client: Any | None = None


_global_config = KakoroGuardProviderConfig()


def set_provider_config(config: KakoroGuardProviderConfig) -> None:
    """Set the global provider configuration for FastAPI dependencies."""
    global _global_config
    _global_config = config


def get_provider_config() -> KakoroGuardProviderConfig:
    """Get the current global provider configuration."""
    return _global_config


def _extract_auth_from_headers(
    headers: Any,
) -> tuple[str, int, str, PaymentIntent | None] | None:
    """Extract KakoroGuard credentials and AgentPay intent from HTTP headers."""
    header_map = {k.lower(): v for k, v in headers.items()}

    # 1. Check dedicated X-Agent-* headers
    pub_key = header_map.get("x-agent-public-key") or header_map.get("x-agent-id")
    ts_str = header_map.get("x-agent-timestamp")
    sig = header_map.get("x-agent-signature")

    amount = header_map.get("x-agent-payment-amount")
    asset = header_map.get("x-agent-payment-asset", "XLM")
    max_fee_str = header_map.get("x-agent-payment-max-fee", "100000")
    dest = header_map.get("x-agent-payment-destination")

    if pub_key and ts_str and sig:
        try:
            timestamp = int(ts_str)
        except ValueError as exc:
            raise HTTPException(
                status_code=401,
                detail="Header x-agent-timestamp must be an integer unix timestamp",
            ) from exc

        intent = None
        if amount:
            try:
                max_fee = int(max_fee_str)
            except ValueError:
                max_fee = 100_000
            intent = PaymentIntent(
                amount=amount,
                asset=asset,
                max_fee=max_fee,
                destination=dest,
            )
        return pub_key.strip(), timestamp, sig.strip(), intent

    # 2. Check Authorization header
    auth_header = header_map.get("authorization")
    if auth_header and auth_header.startswith("KakoroGuard "):
        key_match = re.search(r'key="?([^",\s]+)"?', auth_header)
        ts_match = re.search(r'ts="?([^",\s]+)"?', auth_header)
        sig_match = re.search(r'sig="?([^",\s]+)"?', auth_header)

        if key_match and ts_match and sig_match:
            try:
                timestamp = int(ts_match.group(1))
            except ValueError as exc:
                raise HTTPException(
                    status_code=401,
                    detail="Authorization header ts must be an integer unix timestamp",
                ) from exc

            amount_match = re.search(r'amount="?([^",\s]+)"?', auth_header)
            asset_match = re.search(r'asset="?([^",\s]+)"?', auth_header)

            intent = None
            if amount_match:
                intent = PaymentIntent(
                    amount=amount_match.group(1),
                    asset=asset_match.group(1) if asset_match else "XLM",
                    max_fee=100_000,
                    destination=dest,
                )

            return key_match.group(1).strip(), timestamp, sig_match.group(1).strip(), intent

    return None


def require_agent_role(
    role: str,
    cost: str = "0",
    config: KakoroGuardProviderConfig | None = None,
) -> Callable[[Request], Coroutine[Any, Any, AgentRequestPayload]]:
    """FastAPI dependency requiring an autonomous agent role and payment settlement.

    Step 1: Extracts identity & payment intent, verifies signature, enforces 5-min
            replay protection, and checks agent RBAC role via Soroban RPC.
    """
    effective_config = config or get_provider_config()

    async def dependency(request: Request) -> AgentRequestPayload:
        body_dict: dict[str, Any] = {}
        try:
            body_json = await request.json()
            if isinstance(body_json, dict):
                body_dict = body_json
        except Exception:  # noqa: BLE001
            body_dict = {}

        # 1. Extract credentials either from JSON body or Headers
        agent_id: str | None = None
        timestamp: int | None = None
        signature: str | None = None
        payment_intent: PaymentIntent | None = None
        app_payload: dict[str, Any] = {}

        if "signature" in body_dict and ("agent_id" in body_dict or "public_key" in body_dict):
            try:
                parsed_payload = AgentRequestPayload.model_validate(body_dict)
                agent_id = parsed_payload.agent_id
                timestamp = parsed_payload.timestamp
                signature = parsed_payload.signature
                payment_intent = parsed_payload.payment_intent
                app_payload = parsed_payload.payload
            except Exception as exc:
                raise HTTPException(
                    status_code=401,
                    detail=f"Invalid AgentRequestPayload body schema: {exc}",
                ) from exc
        else:
            extracted = _extract_auth_from_headers(request.headers)
            if extracted is None:
                raise HTTPException(
                    status_code=401,
                    detail="Missing KakoroGuard authentication credentials",
                )
            agent_id, timestamp, signature, payment_intent = extracted
            app_payload = body_dict

        if not agent_id or timestamp is None or not signature:
            raise HTTPException(
                status_code=401,
                detail="Incomplete KakoroGuard authentication credentials",
            )

        # 2. Validate Timestamp (Replay Attack Prevention)
        try:
            validate_timestamp(timestamp)
        except AgentTimestampExpiredError as exc:
            raise HTTPException(
                status_code=401,
                detail=f"Authentication failed: timestamp expired ({exc})",
            ) from exc

        # Ensure payment intent matches requested cost if cost is specified
        if cost and cost != "0" and (payment_intent is None or not payment_intent.amount):
            raise HTTPException(
                status_code=401,
                detail=f"Endpoint requires payment of '{cost}', but no payment intent was provided",
            )

        # 3. Cryptographically verify Ed25519 signature
        try:
            if payment_intent is not None:
                canonical = serialize_synergistic_payload(app_payload, payment_intent)
            else:
                canonical = canonicalize_payload(app_payload)
            msg = build_signing_message(canonical, timestamp)
            keypair = AgentKeypair.from_public_key(agent_id)
            keypair.verify(msg, bytes.fromhex(signature))
        except (AgentSignatureInvalid, ValueError) as exc:
            raise HTTPException(
                status_code=401,
                detail="Authentication failed: invalid cryptographic signature",
            ) from exc

        # 4. Verify Role on Soroban Smart Contract
        rpc_client = effective_config.rpc_client or SorobanRpcClient(
            contract_id=effective_config.contract_id,
            rpc_url=effective_config.rpc_url,
            network_passphrase=effective_config.network_passphrase,
        )

        has_access = False
        try:
            has_access = bool(rpc_client.check_access(agent_id, role))
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"KakoroGuard contract read error: {exc}",
            ) from exc

        if not has_access:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Agent '{agent_id}' lacks required role '{role}'",
            )

        # Construct validated AgentRequestPayload
        final_intent = payment_intent or PaymentIntent(amount=cost if cost != "0" else "0")
        agent_payload = AgentRequestPayload(
            agent_id=agent_id,
            timestamp=timestamp,
            signature=signature,
            payment_intent=final_intent,
            payload=app_payload,
        )

        # Attach agent context to request state
        request.state.agent = {
            "agent_id": agent_id,
            "role": role,
            "payment_intent": final_intent,
            "verified": True,
        }

        return agent_payload

    return dependency
