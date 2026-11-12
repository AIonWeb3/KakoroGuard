/**
 * Express Resource Provider Server protected by KakoroGuard + AgentPay middleware.
 */

import express from "express";
import { KakoroGuardContract, requireAgentRole } from "kakoroguard-js";
import { nativeToScVal } from "@stellar/stellar-sdk";

export function createApp(options = {}) {
  const app = express();
  app.use(express.json());

  // Configure Soroban contract
  const contractId =
    options.contractId ||
    process.env.KAKOROGUARD_CONTRACT_ID ||
    "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";
  const rpcUrl =
    options.rpcUrl ||
    process.env.SOROBAN_RPC_URL ||
    "https://soroban-testnet.stellar.org";
  const networkPassphrase =
    options.networkPassphrase ||
    process.env.STELLAR_NETWORK_PASSPHRASE ||
    "Test SDF Network ; September 2015";

  // In test / demo mode without live blockchain, use mock simulation if specified
  const simulator = options.simulator || {
    simulateTransaction: async () => ({
      result: { retval: nativeToScVal(true, { type: "bool" }) },
    }),
  };

  const contract = new KakoroGuardContract(
    {
      contractId,
      rpcUrl,
      networkPassphrase,
    },
    simulator
  );

  // Health check endpoint
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", service: "e2e-synergy-provider" });
  });

  // Protected premium intelligence endpoint: requires role PREMIUM_API and payment of 5 XLM
  app.post(
    "/api/premium-data",
    requireAgentRole("PREMIUM_API", "5_XLM", {
      contract,
      providerAccount: options.providerAccount || "GPROVIDER_STELLAR_ADDRESS_12345",
      agentPaySettler: options.agentPaySettler,
    }),
    (req, res) => {
      res.json({
        success: true,
        data: "CONFIDENTIAL_INTELLIGENCE_DATA_STREAM_ALPHA",
        agent_id: req.agentId,
        settlement: req.paymentReceipt,
      });
    }
  );

  return app;
}

if (process.argv[1] && process.argv[1].endsWith("server.js")) {
  const port = process.env.PORT || 3000;
  const app = createApp();
  app.listen(port, () => {
    console.log(`Resource Provider Server listening on http://localhost:${port}`);
  });
}
