/**
 * AgentGuard TypeScript SDK for Web2 Resource Providers.
 *
 * Provides cryptographic signature verification, replay-attack prevention,
 * Soroban contract RBAC integration, and Express.js middleware.
 */
export { AgentGuardContract, type RpcSimulator } from "./contract.js";
export { assertSignatureValid, canonicalizePayload, DEFAULT_CLOCK_SKEW_MS, DEFAULT_MAX_AGE_MS, parseSignature, validateTimestamp, verifySignature, } from "./verifier.js";
export { extractAuthHeader, requireAgentRole, type RequireRoleOptions, } from "./middleware.js";
export { AgentGuardError, AgentPermissionDeniedError, AgentSignatureInvalid, AgentTimestampExpiredError, AgentUnauthorizedError, ContractReadError, NetworkRetryExhaustedError, } from "./errors.js";
export { type AgentAuthHeader, type AgentGuardConfig, type AgentGuardRequest, type AgentGuardResponse, AgentStatus, type NextFunction, parseRole, Role, ROLE_NAMES, type VerifyOptions, } from "./types.js";
//# sourceMappingURL=index.d.ts.map