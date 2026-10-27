import { describe, it } from "node:test";
import assert from "node:assert";
import {
  AgentPermissionDeniedError,
  AgentSignatureInvalid,
  AgentTimestampExpiredError,
  AgentUnauthorizedError,
  ContractReadError,
  KakoroGuardError,
  NetworkRetryExhaustedError,
} from "../dist/esm/errors.js";

describe("errors.ts", () => {
  it("creates KakoroGuardError with default code and custom details", () => {
    const err = new KakoroGuardError("Something failed", "CUSTOM_CODE", { key: 123 });
    assert.strictEqual(err.message, "Something failed");
    assert.strictEqual(err.code, "CUSTOM_CODE");
    assert.deepStrictEqual(err.details, { key: 123 });
    assert.strictEqual(err.name, "KakoroGuardError");
  });

  it("creates KakoroGuardError with default code when omitted", () => {
    const err = new KakoroGuardError("Default error");
    assert.strictEqual(err.code, "KAKORO_GUARD_ERROR");
  });

  it("creates AgentSignatureInvalid with and without reason", () => {
    const errWithout = new AgentSignatureInvalid("GBADKEY");
    assert.strictEqual(errWithout.name, "AgentSignatureInvalid");
    assert.strictEqual(errWithout.code, "AGENT_SIGNATURE_INVALID");
    assert.ok(errWithout.message.includes("GBADKEY"));

    const errWith = new AgentSignatureInvalid("GBADKEY", "bad length");
    assert.ok(errWith.message.includes("bad length"));
  });

  it("creates AgentTimestampExpiredError with and without reason", () => {
    const err = new AgentTimestampExpiredError(1700000000, 400000);
    assert.strictEqual(err.name, "AgentTimestampExpiredError");
    assert.strictEqual(err.code, "AGENT_TIMESTAMP_EXPIRED");
    assert.strictEqual(err.timestamp, 1700000000);
    assert.strictEqual(err.ageMs, 400000);

    const customErr = new AgentTimestampExpiredError(1700000000, 400000, "Custom reason");
    assert.strictEqual(customErr.message, "Custom reason");
  });

  it("creates ContractReadError with and without cause", () => {
    const errNoCause = new ContractReadError("RPC timeout");
    assert.strictEqual(errNoCause.name, "ContractReadError");
    assert.strictEqual(errNoCause.code, "CONTRACT_READ_ERROR");
    assert.strictEqual(errNoCause.causeError, undefined);

    const cause = new Error("Connection reset");
    const errWithCause = new ContractReadError("RPC failed", cause, { rpc: "http://localhost" });
    assert.strictEqual(errWithCause.causeError, cause);
    assert.strictEqual(errWithCause.details?.cause, "Connection reset");
    assert.strictEqual(errWithCause.details?.rpc, "http://localhost");
  });

  it("creates NetworkRetryExhaustedError", () => {
    const cause = new Error("504 Gateway Timeout");
    const err = new NetworkRetryExhaustedError("Host unreachable", 3, cause);
    assert.strictEqual(err.name, "NetworkRetryExhaustedError");
    assert.strictEqual(err.attempts, 3);
    assert.ok(err.message.includes("3 attempts"));
    assert.strictEqual(err.details?.cause, "504 Gateway Timeout");
  });

  it("creates AgentUnauthorizedError with default message", () => {
    const errDefault = new AgentUnauthorizedError();
    assert.strictEqual(errDefault.message, "Agent authentication required");
    assert.strictEqual(errDefault.code, "UNAUTHORIZED");

    const errCustom = new AgentUnauthorizedError("Missing token", { header: "x-token" });
    assert.strictEqual(errCustom.message, "Missing token");
    assert.deepStrictEqual(errCustom.details, { header: "x-token" });
  });

  it("creates AgentPermissionDeniedError with and without resourceId", () => {
    const errWith = new AgentPermissionDeniedError("GAGENT123", "Premium", "vault_api");
    assert.strictEqual(errWith.name, "AgentPermissionDeniedError");
    assert.strictEqual(errWith.code, "PERMISSION_DENIED");
    assert.strictEqual(errWith.agentId, "GAGENT123");
    assert.strictEqual(errWith.requiredRole, "Premium");
    assert.strictEqual(errWith.resourceId, "vault_api");
    assert.ok(errWith.message.includes("vault_api"));

    const errWithout = new AgentPermissionDeniedError("GAGENT123", "Admin");
    assert.strictEqual(errWithout.resourceId, undefined);
    assert.ok(!errWithout.message.includes("on resource"));
  });
});
