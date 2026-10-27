# agentguard-js

TypeScript / Node.js SDK for Web2 Resource Providers (e.g. Express, Fastify, Next.js backends) to cryptographically verify AI agent Ed25519 signatures, defend against replay attacks, and query on-chain Role-Based Access Control (RBAC) via Soroban smart contracts on Stellar.

---

## 🚀 Quickstart: Mounting Middleware in Express

```typescript
import express from "express";
import { AgentGuardContract, requireAgentRole } from "agentguard-js";

const app = express();
app.use(express.json());

// 1. Initialize the Soroban contract client (configurable, no hardcoded URLs)
const contract = new AgentGuardContract({
  contractId: process.env.AGENTGUARD_CONTRACT_ID!,
  rpcUrl: process.env.SOROBAN_RPC_URL ?? "https://soroban-testnet.stellar.org",
  networkPassphrase: process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015",
  maxRetries: 3, // Auto-retry with backoff on network failures
});

// 2. Set default contract instance for global middleware usage
AgentGuardContract.setDefault(contract);

// 3. Mount requireAgentRole on protected endpoints
app.post(
  "/v1/settle",
  requireAgentRole("Premium", { resourceId: "settlement_api" }),
  (req, res) => {
    // Verified Agent identity is attached to req
    res.json({
      success: true,
      agentId: req.agentId,
      timestamp: req.agentTimestamp,
      data: "Authorized settlement window open",
    });
  }
);

app.listen(8080, () => console.log("Provider API listening on port 8080"));
```

---

## 🔒 Verification & Replay Protection

### 1. Replay-Attack Prevention
The SDK enforces a strict 5-minute validity window on all signed requests. Requests with timestamps older than 5 minutes or ahead of server clock drift (> 1 minute) are immediately rejected with `401 Unauthorized` (`TIMESTAMP_EXPIRED`).

### 2. Standalone Signature Verification
You can also verify agent signatures directly outside of Express:

```typescript
import { verifySignature, assertSignatureValid } from "agentguard-js";

const payload = { prompt: "Run model inference", tokens: 100 };
const signature = "c3ab4f..."; // 64-byte Ed25519 signature in hex
const timestamp = 1710000000000;
const agentPublicKey = "GAVJD7E63JZUJAHI4KWFOTWJWDIL7E6S2K4ZZAQIX5UNCON4A5NJTUNJ";

// Boolean check:
const isValid = verifySignature(agentPublicKey, payload, signature, timestamp);

// Or strict assertion (throws detailed Error on failure):
assertSignatureValid(agentPublicKey, payload, signature, timestamp);
```

---

## ⛓️ Soroban Contract RBAC Queries

Query the on-chain registry with built-in retry resilience:

```typescript
import { AgentGuardContract, Role } from "agentguard-js";

const guard = new AgentGuardContract({
  contractId: "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526",
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
});

// Check if agent holds an unexpired role on a specific resource:
const allowed = await guard.checkAccess(agentPublicKey, "Premium", "inference_api");

// Check global role:
const hasAdmin = await guard.verifyAgent(agentPublicKey, Role.Admin);
```

---

## 🛡️ Error Classes

All exceptions inherit from `AgentGuardError`:
- `AgentSignatureInvalid`: Cryptographic Ed25519 signature check failed or signature corrupt.
- `AgentTimestampExpiredError`: Timestamp failed the 5-minute replay attack threshold.
- `ContractReadError`: Smart contract RPC simulation error.
- `NetworkRetryExhaustedError`: Network connection failed after 3 automatic retries.
- `AgentUnauthorizedError`: Missing required authentication headers.
- `AgentPermissionDeniedError`: Agent does not hold the required on-chain role.

---

## 🧪 Testing & Builds

```bash
# Compile to both ESM and CommonJS
npm run build

# Run unit tests with line coverage report
npm test
```
