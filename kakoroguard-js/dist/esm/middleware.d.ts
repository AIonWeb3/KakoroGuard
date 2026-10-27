/**
 * Express.js compatible middleware for KakoroGuard AI agent authentication & RBAC.
 */
import { KakoroGuardContract } from "./contract.js";
import { AgentAuthHeader, KakoroGuardRequest, KakoroGuardResponse, NextFunction, VerifyOptions } from "./types.js";
export interface RequireRoleOptions {
    /** The KakoroGuardContract instance (defaults to KakoroGuardContract.getDefault()) */
    contract?: KakoroGuardContract;
    /** Protected resource ID (defaults to route path or "default_resource") */
    resourceId?: string | ((req: KakoroGuardRequest) => string);
    /** Custom payload extractor (defaults to req.body) */
    getPayload?: (req: KakoroGuardRequest) => unknown;
    /** Verification options for timestamp skew and age */
    verifyOptions?: VerifyOptions;
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
 * Express-compatible middleware factory that requires an agent to possess a specific role.
 *
 * Steps:
 * 1. Extracts AgentAuthHeader (public key, timestamp, signature).
 * 2. Cryptographically verifies the Ed25519 signature and enforces 5-min replay attack protection.
 * 3. Queries the Soroban contract via `checkAccess`.
 * 4. Returns 401 Unauthorized or 403 Forbidden with detailed JSON error messages on failure.
 *
 * @param role Required role name ("Basic", "Premium", "Admin").
 * @param options Contract instance, resource identifier, or verification options.
 *
 * @example
 * ```ts
 * app.post("/v1/settle", requireAgentRole("Premium", { contract: myContract }), handler);
 * ```
 */
export declare function requireAgentRole(role: string, options?: RequireRoleOptions): (req: KakoroGuardRequest, res: KakoroGuardResponse, next: NextFunction) => Promise<unknown>;
//# sourceMappingURL=middleware.d.ts.map