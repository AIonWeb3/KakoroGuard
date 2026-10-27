/**
 * KakoroGuard TypeScript SDK for Web2 Resource Providers.
 *
 * Provides cryptographic signature verification, replay-attack prevention,
 * Soroban contract RBAC integration, and Express.js middleware.
 */
export { KakoroGuardContract } from "./contract.js";
export { assertSignatureValid, canonicalizePayload, DEFAULT_CLOCK_SKEW_MS, DEFAULT_MAX_AGE_MS, parseSignature, validateTimestamp, verifySignature, } from "./verifier.js";
export { extractAuthHeader, requireAgentRole, } from "./middleware.js";
export { AgentPermissionDeniedError, AgentSignatureInvalid, AgentTimestampExpiredError, AgentUnauthorizedError, ContractReadError, KakoroGuardError, NetworkRetryExhaustedError, } from "./errors.js";
export { AgentStatus, parseRole, Role, ROLE_NAMES, } from "./types.js";
//# sourceMappingURL=index.js.map