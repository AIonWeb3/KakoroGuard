"use strict";
/**
 * Custom error classes for the AgentGuard TypeScript SDK.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentPermissionDeniedError = exports.AgentUnauthorizedError = exports.NetworkRetryExhaustedError = exports.ContractReadError = exports.AgentTimestampExpiredError = exports.AgentSignatureInvalid = exports.AgentGuardError = void 0;
class AgentGuardError extends Error {
    code;
    details;
    constructor(message, code = "AGENT_GUARD_ERROR", details) {
        super(message);
        this.name = "AgentGuardError";
        this.code = code;
        this.details = details;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
exports.AgentGuardError = AgentGuardError;
/**
 * Raised when an Ed25519 signature is cryptographically invalid or forged.
 */
class AgentSignatureInvalid extends AgentGuardError {
    publicKey;
    constructor(publicKey, reason) {
        const detailMsg = reason ? ` (${reason})` : "";
        super(`Cryptographic signature verification failed for agent public key ${publicKey}${detailMsg}`, "AGENT_SIGNATURE_INVALID", { publicKey, reason });
        this.name = "AgentSignatureInvalid";
        this.publicKey = publicKey;
    }
}
exports.AgentSignatureInvalid = AgentSignatureInvalid;
/**
 * Raised when a request timestamp fails the 5-minute replay-attack prevention check.
 */
class AgentTimestampExpiredError extends AgentGuardError {
    timestamp;
    ageMs;
    constructor(timestamp, ageMs, reason) {
        const msg = reason ?? `Timestamp ${timestamp} expired or outside acceptable window (skew: ${ageMs}ms)`;
        super(msg, "AGENT_TIMESTAMP_EXPIRED", { timestamp, ageMs });
        this.name = "AgentTimestampExpiredError";
        this.timestamp = timestamp;
        this.ageMs = ageMs;
    }
}
exports.AgentTimestampExpiredError = AgentTimestampExpiredError;
/**
 * Raised when an RPC or Soroban smart contract simulation/read fails.
 */
class ContractReadError extends AgentGuardError {
    causeError;
    constructor(message, cause, details) {
        super(message, "CONTRACT_READ_ERROR", { ...details, cause: cause?.message });
        this.name = "ContractReadError";
        this.causeError = cause;
    }
}
exports.ContractReadError = ContractReadError;
/**
 * Raised when all automatic retries against the Soroban RPC are exhausted.
 */
class NetworkRetryExhaustedError extends AgentGuardError {
    attempts;
    constructor(message, attempts, cause) {
        super(`Network operation failed after ${attempts} attempts: ${message}`, "NETWORK_RETRY_EXHAUSTED", { attempts, cause: cause?.message });
        this.name = "NetworkRetryExhaustedError";
        this.attempts = attempts;
    }
}
exports.NetworkRetryExhaustedError = NetworkRetryExhaustedError;
/**
 * Raised when an agent request lacks required credentials or authentication headers.
 */
class AgentUnauthorizedError extends AgentGuardError {
    constructor(message = "Agent authentication required", details) {
        super(message, "UNAUTHORIZED", details);
        this.name = "AgentUnauthorizedError";
    }
}
exports.AgentUnauthorizedError = AgentUnauthorizedError;
/**
 * Raised when an agent lacks the required role or permissions on-chain.
 */
class AgentPermissionDeniedError extends AgentGuardError {
    agentId;
    requiredRole;
    resourceId;
    constructor(agentId, requiredRole, resourceId) {
        const resMsg = resourceId ? ` on resource "${resourceId}"` : "";
        super(`Agent ${agentId} is denied access. Required role: "${requiredRole}"${resMsg}`, "PERMISSION_DENIED", { agentId, requiredRole, resourceId });
        this.name = "AgentPermissionDeniedError";
        this.agentId = agentId;
        this.requiredRole = requiredRole;
        this.resourceId = resourceId;
    }
}
exports.AgentPermissionDeniedError = AgentPermissionDeniedError;
//# sourceMappingURL=errors.js.map