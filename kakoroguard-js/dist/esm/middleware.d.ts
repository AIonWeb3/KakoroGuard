/**
 * Express.js compatible middleware for KakoroGuard AI agent authentication & RBAC.
 */
import { KakoroGuardContract } from "./contract.js";
import { AgentAuthHeader, AgentPaySettler, KakoroGuardRequest, KakoroGuardResponse, NextFunction, VerifyOptions } from "./types.js";
export interface RequireRoleOptions {
    /** The KakoroGuardContract instance (defaults to KakoroGuardContract.getDefault()) */
    contract?: KakoroGuardContract;
    /** Protected resource ID (defaults to route path or "default_resource") */
    resourceId?: string | ((req: KakoroGuardRequest) => string);
    /** Custom payload extractor (defaults to req.body) */
    getPayload?: (req: KakoroGuardRequest) => unknown;
    /** Verification options for timestamp skew and age */
    verifyOptions?: VerifyOptions;
    /** Custom AgentPay settlement client */
    agentPaySettler?: AgentPaySettler;
    /** Provider destination account to receive funds */
    providerAccount?: string;
}
/**
 * Extract AgentAuthHeader credentials from incoming HTTP request headers.
 *
 * Supports:
 * - Dedicated headers: `x-agent-public-key`, `x-agent-timestamp`, `x-agent-signature`
 * - Standard Authorization header: `Authorization: KakoroGuard key="G...",ts="...",sig="..."`
 */
export declare function extractAuthHeader(req: KakoroGuardRequest): AgentAuthHeader;
/**
 * Express-compatible middleware factory that requires an agent to possess a specific role
 * and settles required AgentPay transaction intents.
 *
 * Steps:
 * 1. Extracts AgentAuthHeader and payment intent from body or headers.
 * 2. Cryptographically verifies the Ed25519 signature and enforces 5-min replay attack protection.
 * 3. Queries the Soroban contract via `checkAccess` to verify time-bound roles.
 * 4. Executes AgentPay financial settlement and awaits ledger confirmation.
 * 5. Calls `next()` on success, or returns 401, 402, or 403 on failure.
 */
export declare function requireAgentRole(role: string, cost: string, options?: RequireRoleOptions): (req: KakoroGuardRequest, res: KakoroGuardResponse, next: NextFunction) => Promise<unknown>;
export declare function requireAgentRole(role: string, options?: RequireRoleOptions): (req: KakoroGuardRequest, res: KakoroGuardResponse, next: NextFunction) => Promise<unknown>;
//# sourceMappingURL=middleware.d.ts.map