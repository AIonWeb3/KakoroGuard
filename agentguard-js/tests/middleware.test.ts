import { describe, it } from "node:test";
import assert from "node:assert";
import { Keypair, nativeToScVal } from "@stellar/stellar-sdk";
import { AgentGuardContract } from "../dist/esm/contract.js";
import { AgentUnauthorizedError } from "../dist/esm/errors.js";
import { extractAuthHeader, requireAgentRole } from "../dist/esm/middleware.js";
import type { AgentGuardRequest, AgentGuardResponse } from "../dist/esm/types.js";
import { canonicalizePayload } from "../dist/esm/verifier.js";

const VALID_CONTRACT_ID = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";

function createMockResponse(): {
  res: AgentGuardResponse;
  statusCode: number;
  body: unknown;
} {
  const state = {
    statusCode: 200,
    body: undefined as unknown,
  };

  const res: AgentGuardResponse = {
    status(code: number) {
      state.statusCode = code;
      return res;
    },
    json(data: unknown) {
      state.body = data;
      return data;
    },
  };

  return {
    res,
    get statusCode() {
      return state.statusCode;
    },
    get body() {
      return state.body;
    },
  };
}

describe("middleware.ts", () => {
  const keypair = Keypair.random();
  const validAgent = keypair.publicKey();

  describe("extractAuthHeader", () => {
    it("extracts from x-agent-* headers (case-insensitive and array headers)", () => {
      const req: AgentGuardRequest = {
        headers: {
          "X-Agent-Public-Key": validAgent,
          "x-agent-timestamp": ["1710000000000"],
          "x-agent-signature": "abcdef123456",
        },
      };

      const auth = extractAuthHeader(req);
      assert.strictEqual(auth.publicKey, validAgent);
      assert.strictEqual(auth.timestamp, 1710000000000);
      assert.strictEqual(auth.signature, "abcdef123456");
    });

    it("throws on non-numeric x-agent-timestamp", () => {
      const req: AgentGuardRequest = {
        headers: {
          "x-agent-public-key": validAgent,
          "x-agent-timestamp": "not-a-number",
          "x-agent-signature": "abcdef",
        },
      };

      assert.throws(
        () => extractAuthHeader(req),
        (err: Error) => err instanceof AgentUnauthorizedError && err.message.includes("valid numeric")
      );
    });

    it("extracts from Authorization AgentGuard header", () => {
      const req: AgentGuardRequest = {
        headers: {
          authorization: `AgentGuard key="${validAgent}",ts="1710000000000",sig="abcdef123456"`,
        },
      };

      const auth = extractAuthHeader(req);
      assert.strictEqual(auth.publicKey, validAgent);
      assert.strictEqual(auth.timestamp, 1710000000000);
      assert.strictEqual(auth.signature, "abcdef123456");
    });

    it("throws on non-numeric timestamp in Authorization header", () => {
      const req: AgentGuardRequest = {
        headers: {
          authorization: `AgentGuard key="${validAgent}",ts="bad_ts",sig="abcdef"`,
        },
      };

      assert.throws(
        () => extractAuthHeader(req),
        (err: Error) => err instanceof AgentUnauthorizedError
      );
    });

    it("throws when headers are missing", () => {
      assert.throws(
        () => extractAuthHeader({ headers: {} }),
        (err: Error) => err instanceof AgentUnauthorizedError
      );
    });
  });

  describe("requireAgentRole middleware execution", () => {
    it("returns 500 CONFIGURATION_ERROR if no contract is configured", async () => {
      AgentGuardContract.setDefault(undefined as unknown as AgentGuardContract);
      const middleware = requireAgentRole("Premium");

      const req: AgentGuardRequest = { headers: {} };
      const mock = createMockResponse();

      let nextCalled = false;
      await middleware(req, mock.res, () => {
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(mock.statusCode, 500);
      assert.strictEqual((mock.body as { code: string }).code, "CONFIGURATION_ERROR");
    });

    it("returns 401 UNAUTHORIZED if authentication headers are missing", async () => {
      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        { simulateTransaction: async () => ({}) }
      );

      const middleware = requireAgentRole("Premium", { contract });
      const req: AgentGuardRequest = { headers: {} };
      const mock = createMockResponse();

      let nextCalled = false;
      await middleware(req, mock.res, () => {
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, false);
      assert.strictEqual(mock.statusCode, 401);
      assert.strictEqual((mock.body as { code: string }).code, "UNAUTHORIZED");
    });

    it("returns 401 TIMESTAMP_EXPIRED if request timestamp is stale", async () => {
      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        { simulateTransaction: async () => ({}) }
      );

      const middleware = requireAgentRole("Premium", { contract });
      const req: AgentGuardRequest = {
        headers: {
          "x-agent-public-key": validAgent,
          "x-agent-timestamp": "1000", // ancient timestamp
          "x-agent-signature": "00".repeat(64),
        },
        body: { test: true },
      };
      const mock = createMockResponse();

      await middleware(req, mock.res, () => {});

      assert.strictEqual(mock.statusCode, 401);
      assert.strictEqual((mock.body as { code: string }).code, "TIMESTAMP_EXPIRED");
    });

    it("returns 401 INVALID_SIGNATURE if cryptographic signature fails", async () => {
      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        { simulateTransaction: async () => ({}) }
      );

      const now = Date.now();
      const middleware = requireAgentRole("Premium", {
        contract,
        verifyOptions: { currentTimeMs: now },
      });

      const req: AgentGuardRequest = {
        headers: {
          "x-agent-public-key": validAgent,
          "x-agent-timestamp": String(now),
          "x-agent-signature": "00".repeat(64), // invalid signature
        },
        body: { amount: 100 },
      };
      const mock = createMockResponse();

      await middleware(req, mock.res, () => {});

      assert.strictEqual(mock.statusCode, 401);
      assert.strictEqual((mock.body as { code: string }).code, "INVALID_SIGNATURE");
    });

    it("returns 403 FORBIDDEN if on-chain role check fails", async () => {
      const mockSimulator = {
        simulateTransaction: async () => ({
          result: { retval: nativeToScVal(false, { type: "bool" }) },
        }),
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        mockSimulator
      );

      const now = 1710000000000;
      const payload = { action: "transfer" };
      const canonical = canonicalizePayload(payload);
      const msg = Buffer.from(`${now}.${canonical}`, "utf-8");
      const sigHex = keypair.sign(msg).toString("hex");

      const middleware = requireAgentRole("Admin", {
        contract,
        verifyOptions: { currentTimeMs: now },
      });

      const req: AgentGuardRequest = {
        headers: {
          "x-agent-public-key": validAgent,
          "x-agent-timestamp": String(now),
          "x-agent-signature": sigHex,
        },
        body: payload,
      };
      const mock = createMockResponse();

      await middleware(req, mock.res, () => {});

      assert.strictEqual(mock.statusCode, 403);
      assert.strictEqual((mock.body as { code: string }).code, "FORBIDDEN");
    });

    it("returns 503 CONTRACT_READ_ERROR if contract query fails", async () => {
      const mockSimulator = {
        simulateTransaction: async () => {
          throw new Error("RPC Network error");
        },
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
          maxRetries: 1,
        },
        mockSimulator
      );

      const now = 1710000000000;
      const payload = {};
      const canonical = canonicalizePayload(payload);
      const msg = Buffer.from(`${now}.${canonical}`, "utf-8");
      const sigHex = keypair.sign(msg).toString("hex");

      const middleware = requireAgentRole("Basic", {
        contract,
        verifyOptions: { currentTimeMs: now },
      });

      const req: AgentGuardRequest = {
        headers: {
          "x-agent-public-key": validAgent,
          "x-agent-timestamp": String(now),
          "x-agent-signature": sigHex,
        },
        body: payload,
      };
      const mock = createMockResponse();

      await middleware(req, mock.res, () => {});

      assert.strictEqual(mock.statusCode, 503);
      assert.strictEqual((mock.body as { code: string }).code, "CONTRACT_READ_ERROR");
    });

    it("authorizes request and calls next() on valid credentials and role", async () => {
      const mockSimulator = {
        simulateTransaction: async () => ({
          result: { retval: nativeToScVal(true, { type: "bool" }) },
        }),
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        mockSimulator
      );

      const now = 1710000000000;
      const payload = { query: "SELECT 1" };
      const canonical = canonicalizePayload(payload);
      const msg = Buffer.from(`${now}.${canonical}`, "utf-8");
      const sigHex = keypair.sign(msg).toString("hex");

      const middleware = requireAgentRole("Premium", {
        contract,
        resourceId: (r) => `resource_${String(r.url)}`,
        getPayload: (r) => r.body,
        verifyOptions: { currentTimeMs: now },
      });

      const req: AgentGuardRequest = {
        url: "/v1/sql",
        headers: {
          "x-agent-public-key": validAgent,
          "x-agent-timestamp": String(now),
          "x-agent-signature": sigHex,
        },
        body: payload,
      };
      const mock = createMockResponse();

      let nextCalled = false;
      await middleware(req, mock.res, () => {
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
      assert.strictEqual(mock.statusCode, 200);
      assert.strictEqual(req.agentId, validAgent);
      assert.strictEqual(req.agentPublicKey, validAgent);
      assert.strictEqual(req.agentTimestamp, now);
    });
  });
});
