/**
 * Express.js compatible middleware for AgentGuard AI agent authentication & RBAC.
 */
import { AgentGuardContract } from "./contract.js";
import { AgentAuthHeader, AgentGuardRequest, AgentGuardResponse, NextFunction, VerifyOptions } from "./types.js";
export interface RequireRoleOptions {
    /** The AgentGuardContract instance (defaults to AgentGuardContract.getDefault()) */
    contract?: AgentGuardContract;
    /** Protected resource ID (defaults to route path or "default_resource") */
    resourceId?: string | ((req: AgentGuardRequest) => string);
    /** Custom payload extractor (defaults to req.body) */
    getPayload?: (req: AgentGuardRequest) => unknown;
    /** Verification options for timestamp skew and age */
    verifyOptions?: VerifyOptions;
}
/**
 * Extract AgentAuthHeader credentials from incoming HTTP request headers.
 *
 * Supports:
 * - Dedicated headers: `x-agent-public-key`, `x-agent-timestamp`, `x-agent-signature`
 * - Standard Authorization header: `Authorization: AgentGuard key="G...",ts="...",sig="..."`
 */
export declare function extractAuthHeader(req: AgentGuardRequest): AgentAuthHeader;
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
export declare function requireAgentRole(role: string, options?: RequireRoleOptions): (req: AgentGuardRequest, res: AgentGuardResponse, next: NextFunction) => Promise<unknown>;
//# sourceMappingURL=middleware.d.ts.map