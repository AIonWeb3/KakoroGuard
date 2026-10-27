import { describe, it } from "node:test";
import assert from "node:assert";
import { Keypair } from "@stellar/stellar-sdk";
import {
  assertSignatureValid,
  canonicalizePayload,
  parseSignature,
  validateTimestamp,
  verifySignature,
} from "../dist/esm/verifier.js";
import { AgentSignatureInvalid, AgentTimestampExpiredError } from "../dist/esm/errors.js";

describe("verifier.ts", () => {
  describe("canonicalizePayload", () => {
    it("handles undefined, null, and primitive values", () => {
      assert.strictEqual(canonicalizePayload(undefined), "");
      assert.strictEqual(canonicalizePayload(null), "null");
      assert.strictEqual(canonicalizePayload("hello"), '"hello"');
      assert.strictEqual(canonicalizePayload(123), "123");
      assert.strictEqual(canonicalizePayload(true), "true");
    });

    it("sorts object keys alphabetically", () => {
      const payload = { z: 1, a: 2, m: 3 };
      assert.strictEqual(canonicalizePayload(payload), '{"a":2,"m":3,"z":1}');
    });

    it("recursively handles nested objects and arrays", () => {
      const payload = {
        b: [3, { y: "nested", x: "nested" }, 1],
        a: { beta: true, alpha: false },
        c: undefined, // omitted
      };
      assert.strictEqual(
        canonicalizePayload(payload),
        '{"a":{"alpha":false,"beta":true},"b":[3,{"x":"nested","y":"nested"},1]}'
      );
    });
  });

  describe("validateTimestamp", () => {
    it("validates fresh timestamps in ms and seconds", () => {
      const now = 1710000000000;
      assert.strictEqual(validateTimestamp(now, { currentTimeMs: now }), true);
      assert.strictEqual(validateTimestamp(now - 60_000, { currentTimeMs: now }), true);

      // in seconds (< 1e11)
      const nowSec = 1710000000;
      assert.strictEqual(validateTimestamp(nowSec - 30, { currentTimeMs: now }), true);
    });

    it("rejects non-finite, zero, or negative timestamps", () => {
      assert.throws(
        () => validateTimestamp(0),
        (err: Error) => err instanceof AgentTimestampExpiredError
      );
      assert.throws(
        () => validateTimestamp(NaN),
        (err: Error) => err instanceof AgentTimestampExpiredError
      );
    });

    it("rejects expired timestamps (> 5 min)", () => {
      const now = 1710000000000;
      assert.throws(
        () => validateTimestamp(now - 301_000, { currentTimeMs: now }),
        (err: Error) => err instanceof AgentTimestampExpiredError && err.message.includes("expired")
      );
    });

    it("rejects future timestamps exceeding clock skew", () => {
      const now = 1710000000000;
      assert.throws(
        () => validateTimestamp(now + 65_000, { currentTimeMs: now }),
        (err: Error) => err instanceof AgentTimestampExpiredError && err.message.includes("in the future")
      );
    });

    it("uses default current time when omitted", () => {
      assert.strictEqual(validateTimestamp(Date.now() - 5000), true);
    });
  });

  describe("parseSignature", () => {
    it("parses 128-character hex string", () => {
      const hex = "ab".repeat(64);
      const buf = parseSignature(hex);
      assert.strictEqual(buf.length, 64);
      assert.strictEqual(buf[0], 0xab);
    });

    it("parses base64 string", () => {
      const raw = Buffer.alloc(64, 42);
      const b64 = raw.toString("base64");
      const buf = parseSignature(b64);
      assert.strictEqual(buf.length, 64);
      assert.strictEqual(buf[0], 42);
    });

    it("throws on invalid string or length", () => {
      assert.throws(() => parseSignature(""));
      assert.throws(() => parseSignature(123 as unknown as string));
      assert.throws(() => parseSignature("invalid_short_signature"));
    });
  });

  describe("verifySignature & assertSignatureValid", () => {
    it("successfully verifies valid bound signature", () => {
      const keypair = Keypair.random();
      const payload = { prompt: "test prompt", max_tokens: 100 };
      const timestamp = 1710000000000;

      const canonical = canonicalizePayload(payload);
      const msg = Buffer.from(`${timestamp}.${canonical}`, "utf-8");
      const sigBuffer = keypair.sign(msg);
      const sigHex = sigBuffer.toString("hex");

      const valid = verifySignature(keypair.publicKey(), payload, sigHex, timestamp, {
        currentTimeMs: timestamp,
      });
      assert.strictEqual(valid, true);

      // assertSignatureValid does not throw
      assert.doesNotThrow(() =>
        assertSignatureValid(keypair.publicKey(), payload, sigHex, timestamp, {
          currentTimeMs: timestamp,
        })
      );
    });

    it("successfully verifies unbounded fallback signature", () => {
      const keypair = Keypair.random();
      const payload = { prompt: "fallback" };
      const timestamp = 1710000000000;

      const canonical = canonicalizePayload(payload);
      const msg = Buffer.from(canonical, "utf-8");
      const sigBuffer = keypair.sign(msg);

      const valid = verifySignature(keypair.publicKey(), payload, sigBuffer.toString("hex"), timestamp, {
        currentTimeMs: timestamp,
      });
      assert.strictEqual(valid, true);
    });

    it("fails verification on corrupted signature", () => {
      const keypair = Keypair.random();
      const payload = { amount: 50 };
      const timestamp = 1710000000000;

      const corruptSigHex = "00".repeat(64);
      assert.strictEqual(
        verifySignature(keypair.publicKey(), payload, corruptSigHex, timestamp, {
          currentTimeMs: timestamp,
        }),
        false
      );

      assert.throws(
        () =>
          assertSignatureValid(keypair.publicKey(), payload, corruptSigHex, timestamp, {
            currentTimeMs: timestamp,
          }),
        (err: Error) => err instanceof AgentSignatureInvalid
      );
    });

    it("fails verification on tampered payload", () => {
      const keypair = Keypair.random();
      const payload = { amount: 50 };
      const timestamp = 1710000000000;

      const canonical = canonicalizePayload(payload);
      const msg = Buffer.from(`${timestamp}.${canonical}`, "utf-8");
      const sigHex = keypair.sign(msg).toString("hex");

      const tamperedPayload = { amount: 500 };
      assert.strictEqual(
        verifySignature(keypair.publicKey(), tamperedPayload, sigHex, timestamp, {
          currentTimeMs: timestamp,
        }),
        false
      );
    });

    it("fails verification on invalid public key", () => {
      const sigHex = "00".repeat(64);
      const testNow = 1710000000000;
      assert.strictEqual(
        verifySignature("INVALID_PUB_KEY", {}, sigHex, testNow, { currentTimeMs: testNow }),
        false
      );

      assert.throws(
        () => assertSignatureValid("INVALID_PUB_KEY", {}, sigHex, testNow, { currentTimeMs: testNow }),
        (err: Error) => err instanceof AgentSignatureInvalid && err.message.includes("Invalid Stellar")
      );
    });

    it("fails verification on expired timestamp", () => {
      const keypair = Keypair.random();
      const sigHex = "00".repeat(64);
      const expiredTs = 1000;

      assert.strictEqual(verifySignature(keypair.publicKey(), {}, sigHex, expiredTs), false);

      assert.throws(
        () => assertSignatureValid(keypair.publicKey(), {}, sigHex, expiredTs),
        (err: Error) => err instanceof AgentTimestampExpiredError
      );
    });

    it("fails verification on malformed signature string", () => {
      const keypair = Keypair.random();
      assert.strictEqual(
        verifySignature(keypair.publicKey(), {}, "not-a-sig", 1710000000000, { currentTimeMs: 1710000000000 }),
        false
      );

      assert.throws(
        () =>
          assertSignatureValid(keypair.publicKey(), {}, "not-a-sig", 1710000000000, {
            currentTimeMs: 1710000000000,
          }),
        (err: Error) => err instanceof AgentSignatureInvalid
      );
    });
  });
});
