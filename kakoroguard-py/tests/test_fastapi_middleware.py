"""Unit tests for FastAPI KakoroGuard + AgentPay middleware dependency."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from kakoroguard.errors import AgentPaySettlementError
from kakoroguard.fastapi import (
    KakoroGuardProviderConfig,
    require_agent_role,
    set_provider_config,
)
from kakoroguard.keys import AgentKeypair
from kakoroguard.schema import AgentRequestPayload, PaymentIntent
from kakoroguard.signer import (
    AgentSigner,
    build_signing_message,
    get_current_timestamp_ms,
    serialize_synergistic_payload,
)


def create_test_app(mock_rpc: Any, mock_settler: Any) -> FastAPI:
    app = FastAPI()
    config = KakoroGuardProviderConfig(
        contract_id="CAKAKOROGUARD123",
        agentpay_contract_id="CAAGENTPAY456",
        provider_account="GPROVIDER789",
        rpc_client=mock_rpc,
        agentpay_client=mock_settler,
    )
    set_provider_config(config)

    @app.post("/api/premium-data")
    async def premium_endpoint(
        request: Request,
        agent: AgentRequestPayload = Depends(require_agent_role("PREMIUM_API", "5_XLM")),  # noqa: B008
    ) -> dict[str, Any]:
        return {
            "success": True,
            "data": "confidential_intelligence_stream",
            "agent_id": agent.agent_id,
            "settlement": request.state.agent.get("settlement"),
        }

    @app.post("/api/free-data")
    async def free_endpoint(
        agent: AgentRequestPayload = Depends(require_agent_role("BASIC_API", "0")),  # noqa: B008
    ) -> dict[str, Any]:
        return {"success": True, "data": "public_data", "agent_id": agent.agent_id}

    return app


def test_fastapi_middleware_valid_request() -> None:
    mock_rpc = MagicMock()
    mock_rpc.check_access.return_value = True

    mock_settler = MagicMock()
    mock_settler.settle_payment.return_value = {
        "status": "SETTLED",
        "tx_hash": "0x1234abcd",
        "settled": True,
    }

    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    signer = AgentSigner(kp)
    req_payload = signer.attach_payment(
        cost="5_XLM",
        asset="XLM",
        payload={"query": "test"},
        destination="GPROVIDER789",
    )

    response = client.post("/api/premium-data", json=req_payload.to_dict())
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["agent_id"] == kp.public_key
    assert data["settlement"]["status"] == "SETTLED"
    assert data["settlement"]["tx_hash"] == "0x1234abcd"

    mock_rpc.check_access.assert_called_once_with(kp.public_key, "PREMIUM_API")
    mock_settler.settle_payment.assert_called_once()


def test_fastapi_middleware_missing_auth() -> None:
    mock_rpc = MagicMock()
    mock_settler = MagicMock()
    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    response = client.post("/api/premium-data", json={"query": "unauthenticated"})
    assert response.status_code == 401
    assert "Missing KakoroGuard authentication" in response.json()["detail"]


def test_fastapi_middleware_expired_timestamp() -> None:
    mock_rpc = MagicMock()
    mock_settler = MagicMock()
    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    signer = AgentSigner(kp)
    # Stale timestamp: 10 minutes ago
    stale_ts = get_current_timestamp_ms() - (10 * 60 * 1000)
    req_payload = signer.attach_payment(cost="5_XLM", timestamp=stale_ts)

    response = client.post("/api/premium-data", json=req_payload.to_dict())
    assert response.status_code == 401
    assert "timestamp expired" in response.json()["detail"]


def test_fastapi_middleware_invalid_signature() -> None:
    mock_rpc = MagicMock()
    mock_settler = MagicMock()
    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    signer = AgentSigner(kp)
    req_payload = signer.attach_payment(cost="5_XLM")

    # Corrupt the signature
    corrupted_data = req_payload.to_dict()
    corrupted_data["signature"] = "00" * 64

    response = client.post("/api/premium-data", json=corrupted_data)
    assert response.status_code == 401
    assert "invalid cryptographic signature" in response.json()["detail"]


def test_fastapi_middleware_role_forbidden() -> None:
    mock_rpc = MagicMock()
    # Agent does not have PREMIUM_API role
    mock_rpc.check_access.return_value = False

    mock_settler = MagicMock()
    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    signer = AgentSigner(kp)
    req_payload = signer.attach_payment(cost="5_XLM")

    response = client.post("/api/premium-data", json=req_payload.to_dict())
    assert response.status_code == 403
    assert "lacks required role" in response.json()["detail"]
    mock_settler.settle_payment.assert_not_called()


def test_fastapi_middleware_agentpay_failure() -> None:
    mock_rpc = MagicMock()
    mock_rpc.check_access.return_value = True

    mock_settler = MagicMock()
    # Simulate AgentPay insufficient balance failure
    mock_settler.settle_payment.side_effect = AgentPaySettlementError("Insufficient XLM balance on ledger")

    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    signer = AgentSigner(kp)
    req_payload = signer.attach_payment(cost="5_XLM")

    response = client.post("/api/premium-data", json=req_payload.to_dict())
    assert response.status_code == 402
    assert "Payment Required" in response.json()["detail"]
    assert "Insufficient XLM balance" in response.json()["detail"]


def test_fastapi_middleware_header_authentication() -> None:
    mock_rpc = MagicMock()
    mock_rpc.check_access.return_value = True

    mock_settler = MagicMock()
    mock_settler.settle_payment.return_value = {"status": "SETTLED", "tx_hash": "0x5678", "settled": True}

    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    intent = PaymentIntent(amount="5_XLM", destination="GPROVIDER789")
    ts = get_current_timestamp_ms()
    body = {"data": "from_headers"}

    canonical = serialize_synergistic_payload(body, intent)
    sig = kp.sign(build_signing_message(canonical, ts)).hex()

    headers = {
        "x-agent-public-key": kp.public_key,
        "x-agent-timestamp": str(ts),
        "x-agent-signature": sig,
        "x-agent-payment-amount": "5_XLM",
        "x-agent-payment-destination": "GPROVIDER789",
    }

    response = client.post("/api/premium-data", json=body, headers=headers)
    assert response.status_code == 200
    assert response.json()["agent_id"] == kp.public_key


def test_fastapi_middleware_contract_read_error() -> None:
    mock_rpc = MagicMock()
    mock_rpc.check_access.side_effect = RuntimeError("RPC node unreachable")

    mock_settler = MagicMock()
    app = create_test_app(mock_rpc, mock_settler)
    client = TestClient(app)

    kp = AgentKeypair.generate()
    signer = AgentSigner(kp)
    req_payload = signer.attach_payment(cost="5_XLM")

    response = client.post("/api/premium-data", json=req_payload.to_dict())
    assert response.status_code == 503
    assert "KakoroGuard contract read error" in response.json()["detail"]
