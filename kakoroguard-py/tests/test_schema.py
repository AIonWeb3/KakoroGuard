import pytest
from pydantic import ValidationError

from kakoroguard.schema import AgentRequestPayload, PaymentIntent


def test_payment_intent_valid() -> None:
    intent = PaymentIntent(amount="5_XLM", asset="XLM", max_fee=100_000, destination="GABC")
    assert intent.amount == "5_XLM"
    assert intent.asset == "XLM"
    assert intent.max_fee == 100_000
    assert intent.destination == "GABC"


def test_payment_intent_defaults() -> None:
    intent = PaymentIntent(amount="10")
    assert intent.amount == "10"
    assert intent.asset == "XLM"
    assert intent.max_fee == 100_000
    assert intent.destination is None


def test_payment_intent_invalid() -> None:
    with pytest.raises(ValidationError):
        PaymentIntent(amount="5", max_fee=-1)


def test_agent_request_payload_valid() -> None:
    intent = PaymentIntent(amount="5_XLM")
    payload = AgentRequestPayload(
        agent_id="GAGENT123",
        timestamp=1700000000000,
        signature="deadbeef",
        payment_intent=intent,
        payload={"action": "query"},
    )
    assert payload.agent_id == "GAGENT123"
    assert payload.public_key == "GAGENT123"
    assert payload.timestamp == 1700000000000
    assert payload.signature == "deadbeef"
    assert payload.payment_intent.amount == "5_XLM"
    assert payload.payload == {"action": "query"}


def test_agent_request_payload_public_key_alias() -> None:
    raw = {
        "public_key": "GAGENT123",
        "timestamp": 1700000000000,
        "signature": "deadbeef",
        "amount": "5_XLM",
    }
    payload = AgentRequestPayload.model_validate(raw)
    assert payload.agent_id == "GAGENT123"
    assert payload.public_key == "GAGENT123"
    assert payload.payment_intent.amount == "5_XLM"
    assert payload.payload == {}


def test_agent_request_payload_missing_required() -> None:
    with pytest.raises(ValidationError):
        AgentRequestPayload.model_validate({"agent_id": "G123"})
