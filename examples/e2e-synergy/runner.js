/**
 * Automated End-to-End Integration Test Runner for Phase 4 Synergy.
 *
 * 1. Simulates/executes setup network script.
 * 2. Starts Express server with live KakoroGuard + AgentPay middleware.
 * 3. Tracks Stellar ledger balances for provider and agent.
 * 4. Executes python agent_client.py.
 * 5. Asserts provider balance increased by 5 XLM and agent received premium data.
 */

import { spawn } from "node:child_process";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./server.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Ledger State Tracker
const ledgerBalances = {
  provider: 100.0,
  agent: 50.0,
};

const mockSettler = {
  async settlePayment(params) {
    const amountNum = parseFloat(params.amount.replace("_XLM", ""));
    if (isNaN(amountNum) || amountNum <= 0) {
      throw new Error(`Invalid payment amount: ${params.amount}`);
    }

    if (ledgerBalances.agent < amountNum) {
      throw new Error(`Insufficient agent balance: ${ledgerBalances.agent} XLM available, ${amountNum} XLM required`);
    }

    // Execute ledger state update
    ledgerBalances.agent -= amountNum;
    ledgerBalances.provider += amountNum;

    const txHash = `0x${Buffer.from(`${params.agentId}:${params.amount}:${Date.now()}`).toString("hex").slice(0, 64)}`;

    return {
      status: "SETTLED",
      txHash,
      settled: true,
      amount: params.amount,
      asset: params.asset || "XLM",
      providerBalance: ledgerBalances.provider,
      agentBalance: ledgerBalances.agent,
    };
  },
};

async function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const pySdkPath = path.resolve(__dirname, "../../kakoroguard-py");
    const proc = spawn(command, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      shell: true,
      env: {
        ...process.env,
        PYTHONPATH: `${pySdkPath}${path.delimiter}${process.env.PYTHONPATH || ""}`,
      },
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    proc.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });

    proc.on("error", (err) => {
      reject(err);
    });
  });
}

async function main() {
  console.log("==================================================================");
  console.log("   KakoroGuard + AgentPay End-to-End Synergy Integration Runner   ");
  console.log("==================================================================\n");

  console.log(`[Ledger] Initial Provider Balance: ${ledgerBalances.provider} XLM`);
  console.log(`[Ledger] Initial Agent Balance:    ${ledgerBalances.agent} XLM\n`);

  // 1. Run local network setup script
  console.log("--- Step 1: Executing setup_local_network.sh ---");
  try {
    const setupRes = await runCommand("bash", ["setup_local_network.sh"], __dirname);
    console.log(setupRes.stdout || "Setup completed successfully.");
  } catch (err) {
    console.log("Note: bash not found or failed, using native environment configuration.");
  }

  // 2. Start Express Provider Server
  console.log("\n--- Step 2: Starting Express Resource Provider Server ---");
  const app = createApp({
    agentPaySettler: mockSettler,
    providerAccount: "GPROVIDER_STELLAR_ADDRESS_12345",
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = address.port;
  const baseUrl = `http://127.0.0.1:${port}/api/premium-data`;
  console.log(`[Server] Express listening on ${baseUrl}`);

  try {
    // 3. Fire Python AI Agent Client (Successful Flow)
    console.log("\n--- Step 3: Executing Autonomous AI Agent Client ---");
    const agentRes = await runCommand(
      "python",
      ["agent_client.py", "--url", baseUrl, "--cost", "5_XLM"],
      __dirname
    );

    console.log(agentRes.stdout);
    if (agentRes.code !== 0) {
      console.error(agentRes.stderr);
      throw new Error(`AI Agent script failed with exit code ${agentRes.code}`);
    }

    // 4. Assert Financial Settlement and Data Delivery
    console.log("--- Step 4: Verifying Financial Settlement & Ledger State ---");
    console.log(`[Ledger] New Provider Balance: ${ledgerBalances.provider} XLM`);
    console.log(`[Ledger] New Agent Balance:    ${ledgerBalances.agent} XLM`);

    assert.strictEqual(
      ledgerBalances.provider,
      105.0,
      "Provider balance must have increased by exactly 5 XLM"
    );
    assert.strictEqual(
      ledgerBalances.agent,
      45.0,
      "Agent balance must have decreased by exactly 5 XLM"
    );
    assert.ok(
      agentRes.stdout.includes("CONFIDENTIAL_INTELLIGENCE_DATA_STREAM_ALPHA"),
      "Agent must have received the premium confidential intelligence payload"
    );

    // 5. Verify Edge Case: Malicious Tampering
    console.log("\n--- Step 5: Testing Edge Case - Malicious Payment Tampering ---");
    const tamperRes = await runCommand(
      "python",
      ["agent_client.py", "--url", baseUrl, "--simulate-failure", "tampered"],
      __dirname
    );
    assert.strictEqual(tamperRes.code, 1, "Tampered request must fail with non-zero exit code");
    assert.ok(
      tamperRes.stdout.includes("401") || tamperRes.stdout.includes("INVALID_SIGNATURE"),
      "Tampered request must return HTTP 401 Invalid Signature"
    );
    console.log("[PASS] Tampered request rejected by KakoroGuard middleware.");

    console.log("\n==================================================================");
    console.log("  SUCCESS: All End-to-End Synergy Assertions Passed Completely!  ");
    console.log("==================================================================");
  } finally {
    server.close();
  }
}

main().catch((err) => {
  console.error("\n[E2E ERROR]:", err);
  process.exit(1);
});
