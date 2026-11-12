import assert from "node:assert/strict";
import test, { describe } from "node:test";
import {
  AgentRequestPayloadSchema,
  PaymentIntentSchema,
} from "../dist/esm/schema.js";

describe("PaymentIntentSchema", () => {
  test("parses valid payment intent with all fields", () => {
    const parsed = PaymentIntentSchema.parse({
      amount: "5_XLM",
      asset: "USDC",
      max_fee: 50_000,
      destination: "GPROVIDER",
    });
    assert.equal(parsed.amount, "5_XLM");
    assert.equal(parsed.asset, "USDC");
    assert.equal(parsed.max_fee, 50_000);
    assert.equal(parsed.destination, "GPROVIDER");
  });

  test("uses default values for asset and max_fee", () => {
    const parsed = PaymentIntentSchema.parse({
      amount: "5",
    });
    assert.equal(parsed.amount, "5");
    assert.equal(parsed.asset, "XLM");
    assert.equal(parsed.max_fee, 100_000);
    assert.equal(parsed.destination, undefined);
  });

  test("throws on invalid max_fee or missing amount", () => {
    assert.throws(() => PaymentIntentSchema.parse({ max_fee: -10 }), /amount/);
    assert.throws(() => PaymentIntentSchema.parse({ amount: "5", max_fee: -10 }));
  });
});

describe("AgentRequestPayloadSchema", () => {
  test("parses full AgentRequestPayload", () => {
    const input = {
      agent_id: "GAGENT123",
      timestamp: 1700000000000,
      signature: "0xdeadbeef",
      payment_intent: {
        amount: "5_XLM",
        asset: "XLM",
        max_fee: 100_000,
      },
      payload: { service: "data" },
    };
    const parsed = AgentRequestPayloadSchema.parse(input);
    assert.equal(parsed.agent_id, "GAGENT123");
    assert.equal(parsed.public_key, "GAGENT123");
    assert.equal(parsed.timestamp, 1700000000000);
    assert.equal(parsed.signature, "0xdeadbeef");
    assert.equal(parsed.payment_intent.amount, "5_XLM");
    assert.deepEqual(parsed.payload, { service: "data" });
  });

  test("handles public_key alias and flat payment fields", () => {
    const input = {
      public_key: "GAGENT456",
      timestamp: 1700000000000,
      signature: "0xdeadbeef",
      amount: "10_XLM",
    };
    const parsed = AgentRequestPayloadSchema.parse(input);
    assert.equal(parsed.agent_id, "GAGENT456");
    assert.equal(parsed.public_key, "GAGENT456");
    assert.equal(parsed.payment_intent.amount, "10_XLM");
    assert.equal(parsed.payment_intent.asset, "XLM");
    assert.deepEqual(parsed.payload, {});
  });

  test("throws on missing required identity fields", () => {
    assert.throws(() =>
      AgentRequestPayloadSchema.parse({
        timestamp: 1700000000000,
        signature: "sig",
        amount: "5",
      })
    );
  });
});
