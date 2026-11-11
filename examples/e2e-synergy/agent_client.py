"""Autonomous AI Agent Client demonstrating KakoroGuard RBAC and AgentPay settlement.

Simulates an autonomous AI agent:
1. Generates Ed25519 cryptographic keypair (Stellar G-address identity).
2. Holds the authorized PREMIUM_API role in KakoroGuard.
3. Constructs an AgentPay transaction intent authorizing 5 XLM.
4. Cryptographically signs the synergistic request.
5. Invokes the resource provider's /api/premium-data endpoint.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

from kakoroguard.keys import AgentKeypair
from kakoroguard.signer import AgentSigner, get_current_timestamp_ms


def run_agent(
    endpoint_url: str = "http://localhost:3000/api/premium-data",
    cost: str = "5_XLM",
    asset: str = "XLM",
    simulate_failure: str | None = None,
) -> dict[str, Any]:
    print("[Agent] Initializing Autonomous AI Agent...")

    # 1. Generate autonomous Ed25519 keypair
    keypair = AgentKeypair.generate()
    print(f"[Agent] Identity generated: {keypair.public_key}")

    # 2. Prepare request and payment intent
    signer = AgentSigner(keypair)
    payload_data = {
        "service": "deep-reasoning-inference",
        "prompt": "Analyze optimal Stellar liquidity path for agentic micropayments",
        "parameters": {"depth": 3, "temperature": 0.2},
    }

    effective_cost = cost
    timestamp = get_current_timestamp_ms()

    if simulate_failure == "insufficient_funds":
        effective_cost = "INSUFFICIENT_FUNDS"
    elif simulate_failure == "expired":
        timestamp = timestamp - (10 * 60 * 1000)  # 10 minutes ago

    print(f"[Agent] Constructing synergistic payload with {effective_cost} payment intent...")
    signed_req = signer.attach_payment(
        cost=effective_cost,
        asset=asset,
        payload=payload_data,
        timestamp=timestamp,
    )

    req_dict = signed_req.to_dict()

    if simulate_failure == "tampered":
        print("[Agent] Simulating malicious tampering of payment amount...")
        req_dict["payment_intent"]["amount"] = "0_XLM"

    print(f"[Agent] Sending signed request to Resource Provider at {endpoint_url}...")
    req_body = json.dumps(req_dict).encode("utf-8")
    req = urllib.request.Request(
        endpoint_url,
        data=req_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            status_code = resp.getcode()
            response_data = json.loads(resp.read().decode("utf-8"))
            print(f"[Agent] HTTP {status_code} Response received!")
            print(f"[Agent] Response Data: {response_data.get('data')}")
            print(f"[Agent] Settlement Receipt: {response_data.get('settlement')}")
            return {
                "status_code": status_code,
                "agent_id": keypair.public_key,
                "response": response_data,
            }
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8")
        print(f"[Agent] Provider returned error HTTP {exc.code}: {err_body}")
        try:
            parsed_err = json.loads(err_body)
        except (ValueError, json.JSONDecodeError):
            parsed_err = {"raw": err_body}
        return {
            "status_code": exc.code,
            "agent_id": keypair.public_key,
            "error": parsed_err,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="KakoroGuard + AgentPay AI Agent Client")
    parser.add_argument("--url", default="http://localhost:3000/api/premium-data")
    parser.add_argument("--cost", default="5_XLM")
    parser.add_argument(
        "--simulate-failure",
        choices=["insufficient_funds", "expired", "tampered"],
        default=None,
    )

    args = parser.parse_args()
    res = run_agent(
        endpoint_url=args.url,
        cost=args.cost,
        simulate_failure=args.simulate_failure,
    )

    if res["status_code"] == 200:
        print("[Agent] SUCCESS: Service booked and settled successfully!")
        sys.exit(0)
    else:
        print(f"[Agent] FAILED with status {res['status_code']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
