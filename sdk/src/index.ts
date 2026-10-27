/**
 * @kakoroguard/sdk
 *
 * Identity and RBAC client for the KakoroGuard Soroban contract.
 *
 * @example
 * ```typescript
 * import { KakoroGuardClient, Role } from "@kakoroguard/sdk";
 * import { Networks } from "@stellar/stellar-sdk";
 *
 * const guard = new KakoroGuardClient({
 *   contractId: "CABC...XYZ",
 *   rpcUrl: "https://soroban-testnet.stellar.org",
 *   networkPassphrase: Networks.TESTNET,
 * });
 *
 * const authorized = await guard.verifyAgent(agentPublicKey, Role.Premium);
 * ```
 */

export {
  KakoroGuardClient,
  AgentUnauthorizedError,
  AgentPermissionDeniedError,
  SimulationError,
  TransactionError,
} from "./kakoro-guard-client.js";
export {
  Role,
  AgentStatus,
  ROLE_LABELS,
  STATUS_LABELS,
  type AgentRecord,
  type AgentMetadata,
  type AgentProfile,
  type KakoroGuardConfig,
  type TransactionSigner,
  type SubmittedTransaction,
  type Permission,
} from "./types.js";
export {
  AGENT_HEADER,
  enforceAgentRole,
  enforceAgentPermission,
  requireRole,
  requirePermission,
  type GuardRequest,
  type GuardFailure,
  type GuardResult,
} from "./middleware.js";
