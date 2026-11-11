"""Synergistic payload schema defining the interaction between KakoroGuard and AgentPay."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator


class PaymentIntent(BaseModel):
    """AgentPay transaction authorization intent."""

    amount: str = Field(..., description="Payment amount (e.g. '5_XLM' or '5.0')")
    asset: str = Field(default="XLM", description="Stellar asset code or identifier")
    max_fee: int = Field(default=100_000, ge=0, description="Maximum fee in stroops")
    destination: str | None = Field(default=None, description="Optional destination public key")

    model_config = {"frozen": True}


class AgentRequestPayload(BaseModel):
    """Synergistic request payload combining KakoroGuard identity with AgentPay transaction intent."""

    agent_id: str = Field(..., description="Stellar public key of the autonomous agent")
    timestamp: int = Field(..., gt=0, description="Unix timestamp in milliseconds")
    signature: str = Field(..., description="Cryptographic signature of the agent")
    payment_intent: PaymentIntent = Field(..., description="AgentPay payment authorization intent")
    payload: dict[str, Any] = Field(default_factory=dict, description="Application request body")

    model_config = {"frozen": True}

    @model_validator(mode="before")
    @classmethod
    def handle_public_key_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            mutable_data = dict(data)
            if "agent_id" not in mutable_data and "public_key" in mutable_data:
                mutable_data["agent_id"] = mutable_data["public_key"]
            if "payment_intent" not in mutable_data and "amount" in mutable_data:
                mutable_data["payment_intent"] = {
                    "amount": mutable_data.get("amount"),
                    "asset": mutable_data.get("asset", "XLM"),
                    "max_fee": mutable_data.get("max_fee", 100_000),
                    "destination": mutable_data.get("destination"),
                }
            return mutable_data
        return data

    @property
    def public_key(self) -> str:
        return self.agent_id
