/**
 * Type definitions for KakoroGuard TypeScript SDK.
 */
/**
 * Role hierarchy matching the on-chain Soroban contract:
 * Basic = 0 < Premium = 1 < Admin = 2
 */
export declare enum Role {
    Basic = 0,
    Premium = 1,
    Admin = 2
}
export declare const ROLE_NAMES: Record<Role, string>;
/**
 * Parse a role string or enum into a canonical Role enum value.
 */
export declare function parseRole(role: string | Role): Role;
/**
 * On-chain operational status of an agent.
 */
export declare enum AgentStatus {
    Active = 0,
    Suspended = 1,
    Revoked = 2
}
/**
 * Standard AgentPay settlement client interface.
 */
export interface AgentPaySettler {
    settlePayment(params: {
        agentId: string;
        amount: string;
        asset?: string;
        maxFee?: number;
        destination?: string;
    }): Promise<{
        status: string;
        txHash: string;
        settled: boolean;
        [key: string]: unknown;
    }>;
}
/**
 * Standard KakoroGuard authentication header payload.
 */
export interface AgentAuthHeader {
    publicKey: string;
    timestamp: number;
    signature: string;
    paymentIntent?: {
        amount: string;
        asset: string;
        max_fee: number;
        destination?: string | null;
    };
}
/**
 * Configuration options for KakoroGuardContract.
 */
export interface KakoroGuardConfig {
    /** Soroban contract ID (e.g. "CA...") */
    contractId: string;
    /** Soroban RPC endpoint URL (no hardcoded defaults in production) */
    rpcUrl: string;
    /** Stellar network passphrase (e.g. Networks.TESTNET or Networks.PUBLIC) */
    networkPassphrase: string;
    /** Maximum retry attempts on network failures (default: 3) */
    maxRetries?: number;
    /** Initial delay between retries in milliseconds (default: 300) */
    retryDelayMs?: number;
}
/**
 * Options for signature verification and replay prevention.
 */
export interface VerifyOptions {
    /** Maximum allowable age of the timestamp in milliseconds (default: 300,000 = 5 minutes) */
    maxAgeMs?: number;
    /** Allowable forward clock skew in milliseconds (default: 60,000 = 1 minute) */
    clockSkewMs?: number;
    /** Current time override in milliseconds (useful for testing) */
    currentTimeMs?: number;
}
/**
 * HTTP Request interface compatible with Express, Fastify, Next.js, and Node http.
 */
export interface KakoroGuardRequest {
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    agentId?: string;
    agentPublicKey?: string;
    agentTimestamp?: number;
    paymentIntent?: unknown;
    paymentReceipt?: unknown;
    [key: string]: unknown;
}
/**
 * HTTP Response interface compatible with Express.
 */
export interface KakoroGuardResponse {
    status(statusCode: number): KakoroGuardResponse;
    json(data: unknown): unknown;
}
/**
 * Next function callback for Express middleware.
 */
export type NextFunction = (err?: unknown) => void;
//# sourceMappingURL=types.d.ts.map