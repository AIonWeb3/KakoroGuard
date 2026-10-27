/**
 * Custom error classes for the AgentGuard TypeScript SDK.
 */
export declare class AgentGuardError extends Error {
    readonly code: string;
    readonly details?: Record<string, unknown>;
    constructor(message: string, code?: string, details?: Record<string, unknown>);
}
/**
 * Raised when an Ed25519 signature is cryptographically invalid or forged.
 */
export declare class AgentSignatureInvalid extends AgentGuardError {
    readonly publicKey: string;
    constructor(publicKey: string, reason?: string);
}
/**
 * Raised when a request timestamp fails the 5-minute replay-attack prevention check.
 */
export declare class AgentTimestampExpiredError extends AgentGuardError {
    readonly timestamp: number;
    readonly ageMs: number;
    constructor(timestamp: number, ageMs: number, reason?: string);
}
/**
 * Raised when an RPC or Soroban smart contract simulation/read fails.
 */
export declare class ContractReadError extends AgentGuardError {
    readonly causeError?: Error;
    constructor(message: string, cause?: Error, details?: Record<string, unknown>);
}
/**
 * Raised when all automatic retries against the Soroban RPC are exhausted.
 */
export declare class NetworkRetryExhaustedError extends AgentGuardError {
    readonly attempts: number;
    constructor(message: string, attempts: number, cause?: Error);
}
/**
 * Raised when an agent request lacks required credentials or authentication headers.
 */
export declare class AgentUnauthorizedError extends AgentGuardError {
    constructor(message?: string, details?: Record<string, unknown>);
}
/**
 * Raised when an agent lacks the required role or permissions on-chain.
 */
export declare class AgentPermissionDeniedError extends AgentGuardError {
    readonly agentId: string;
    readonly requiredRole: string;
    readonly resourceId?: string;
    constructor(agentId: string, requiredRole: string, resourceId?: string);
}
//# sourceMappingURL=errors.d.ts.map