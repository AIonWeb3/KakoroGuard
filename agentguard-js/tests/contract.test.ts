import { describe, it } from "node:test";
import assert from "node:assert";
import { Keypair, nativeToScVal } from "@stellar/stellar-sdk";
import { AgentGuardContract, type RpcSimulator } from "../dist/esm/contract.js";
import { ContractReadError, NetworkRetryExhaustedError } from "../dist/esm/errors.js";
import { parseRole, Role } from "../dist/esm/types.js";

const VALID_CONTRACT_ID = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";

describe("contract.ts", () => {
  describe("parseRole", () => {
    it("parses Role enum directly", () => {
      assert.strictEqual(parseRole(Role.Basic), Role.Basic);
      assert.strictEqual(parseRole(Role.Premium), Role.Premium);
      assert.strictEqual(parseRole(Role.Admin), Role.Admin);
    });

    it("parses valid strings case-insensitively and numbers", () => {
      assert.strictEqual(parseRole("basic"), Role.Basic);
      assert.strictEqual(parseRole("Premium"), Role.Premium);
      assert.strictEqual(parseRole("ADMIN"), Role.Admin);
      assert.strictEqual(parseRole("0"), Role.Basic);
      assert.strictEqual(parseRole("1"), Role.Premium);
      assert.strictEqual(parseRole("2"), Role.Admin);
    });

    it("throws on invalid role string", () => {
      assert.throws(() => parseRole("Superuser"));
      assert.throws(() => parseRole("unknown"));
    });
  });

  describe("AgentGuardContract constructor & configuration", () => {
    it("throws if required config fields are missing", () => {
      assert.throws(
        () => new AgentGuardContract({ contractId: "", rpcUrl: "http://localhost", networkPassphrase: "test" }),
        (err: Error) => err instanceof ContractReadError
      );
      assert.throws(
        () => new AgentGuardContract({ contractId: VALID_CONTRACT_ID, rpcUrl: "", networkPassphrase: "test" }),
        (err: Error) => err instanceof ContractReadError
      );
      assert.throws(
        () => new AgentGuardContract({ contractId: VALID_CONTRACT_ID, rpcUrl: "http://localhost", networkPassphrase: "" }),
        (err: Error) => err instanceof ContractReadError
      );
    });

    it("manages global default instance", () => {
      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        { simulateTransaction: async () => ({}) }
      );

      AgentGuardContract.setDefault(contract);
      assert.strictEqual(AgentGuardContract.getDefault(), contract);
    });
  });

  describe("checkAccess & verifyAgent", () => {
    const validAgent = Keypair.random().publicKey();

    it("successfully checks access when contract returns true", async () => {
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => ({
          result: {
            retval: nativeToScVal(true, { type: "bool" }),
          },
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

      const hasAccess = await contract.checkAccess(validAgent, "Premium", "api_gateway");
      assert.strictEqual(hasAccess, true);

      const verifyRes = await contract.verifyAgent(validAgent, Role.Basic);
      assert.strictEqual(verifyRes, true);
    });

    it("returns false when contract returns false", async () => {
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => ({
          result: {
            retval: nativeToScVal(false, { type: "bool" }),
          },
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

      const hasAccess = await contract.checkAccess(validAgent, Role.Admin, "vault");
      assert.strictEqual(hasAccess, false);

      const verifyRes = await contract.verifyAgent(validAgent, "Admin");
      assert.strictEqual(verifyRes, false);
    });

    it("retries on network failures and recovers on second attempt", async () => {
      let attempts = 0;
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => {
          attempts++;
          if (attempts === 1) {
            throw new Error("ECONNRESET: Socket closed");
          }
          return {
            result: {
              retval: nativeToScVal(true, { type: "bool" }),
            },
          };
        },
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
          maxRetries: 3,
          retryDelayMs: 10,
        },
        mockSimulator
      );

      const res = await contract.checkAccess(validAgent, "Basic", "default");
      assert.strictEqual(res, true);
      assert.strictEqual(attempts, 2);
    });

    it("throws NetworkRetryExhaustedError after max retries fail", async () => {
      let attempts = 0;
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => {
          attempts++;
          throw new Error("503 Service Unavailable");
        },
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
          maxRetries: 3,
          retryDelayMs: 10,
        },
        mockSimulator
      );

      await assert.rejects(
        () => contract.checkAccess(validAgent, "Premium", "data_lake"),
        (err: Error) => err instanceof NetworkRetryExhaustedError && err.attempts === 3
      );
      assert.strictEqual(attempts, 3);
    });

    it("aborts retry immediately on permanent simulation logic error", async () => {
      let attempts = 0;
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => {
          attempts++;
          throw new ContractReadError("Contract simulation failed: HostError(Error(Contract, #1))");
        },
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
          maxRetries: 3,
        },
        mockSimulator
      );

      await assert.rejects(
        () => contract.checkAccess(validAgent, "Premium", "res"),
        (err: Error) => err instanceof ContractReadError
      );
      assert.strictEqual(attempts, 1);
    });

    it("throws ContractReadError if simulation result is empty or missing retval", async () => {
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => ({
          result: {},
        }),
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

      await assert.rejects(
        () => contract.checkAccess(validAgent, "Basic", "res"),
        (err: Error) => err instanceof NetworkRetryExhaustedError || err instanceof ContractReadError
      );
    });

    it("handles invalid agent ID in checkAccess and verifyAgent", async () => {
      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
        },
        { simulateTransaction: async () => ({}) }
      );

      await assert.rejects(
        () => contract.checkAccess("INVALID_AGENT_KEY", "Basic", "res"),
        (err: Error) => err instanceof ContractReadError
      );

      await assert.rejects(
        () => contract.verifyAgent("INVALID_AGENT_KEY", "Basic"),
        (err: Error) => err instanceof ContractReadError
      );
    });

    it("throws NetworkRetryExhaustedError when verifyAgent exhausts retries", async () => {
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => {
          throw new Error("RPC unreachable");
        },
      };

      const contract = new AgentGuardContract(
        {
          contractId: VALID_CONTRACT_ID,
          rpcUrl: "https://soroban-testnet.stellar.org",
          networkPassphrase: "Test SDF Network ; September 2015",
          maxRetries: 2,
          retryDelayMs: 5,
        },
        mockSimulator
      );

      await assert.rejects(
        () => contract.verifyAgent(validAgent, "Premium"),
        (err: Error) => err instanceof NetworkRetryExhaustedError && err.attempts === 2
      );
    });

    it("handles StellarRpc.Api simulation error response", async () => {
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => ({
          error: "Contract execution failed due to panic",
        }),
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

      await assert.rejects(
        () => contract.checkAccess(validAgent, "Basic", "res"),
        (err: Error) => err instanceof ContractReadError && err.message.includes("Contract simulation failed:")
      );
    });

    it("handles StellarRpc.Api simulation success response", async () => {
      const mockSimulator: RpcSimulator = {
        simulateTransaction: async () => ({
          transactionData: "AAAAAQ==",
          result: {
            retval: nativeToScVal(true, { type: "bool" }),
          },
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

      const res = await contract.checkAccess(validAgent, "Basic", "res");
      assert.strictEqual(res, true);
    });
  });
});
