/**
 * Express.js compatible middleware for AgentGuard AI agent authentication & RBAC.
 */

import { AgentGuardContract } from "./contract.js";
import {
  AgentPermissionDeniedError,
  AgentSignatureInvalid,
  AgentTimestampExpiredError,
  AgentUnauthorizedError,
} from "./errors.js";
import {
  AgentAuthHeader,
  AgentGuardRequest,
  AgentGuardResponse,
  NextFunction,
  VerifyOptions,
} from "./types.js";
import { assertSignatureValid } from "./verifier.js";

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
export function extractAuthHeader(req: AgentGuardRequest): AgentAuthHeader {
  const headerMap: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(req.headers || {})) {
    headerMap[k.toLowerCase()] = v;
  }

  const getHeader = (name: string): string | undefined => {
    const val = headerMap[name.toLowerCase()];
    if (Array.isArray(val)) return val[0];
    return val;
  };

  // 1. Check dedicated X-Agent-* headers
  const pubKey = getHeader("x-agent-public-key") ?? getHeader("x-agent-id");
  const tsStr = getHeader("x-agent-timestamp");
  const sig = getHeader("x-agent-signature");

  if (pubKey && tsStr && sig) {
    const timestamp = Number(tsStr);
    if (!Number.isFinite(timestamp)) {
      throw new AgentUnauthorizedError("Header x-agent-timestamp must be a valid numeric unix epoch", {
        raw: tsStr,
      });
    }
    return {
      publicKey: pubKey.trim(),
      timestamp,
      signature: sig.trim(),
    };
  }

  // 2. Check Authorization header
  const authHeader = getHeader("authorization");
  if (authHeader && authHeader.startsWith("AgentGuard ")) {
    const keyMatch = authHeader.match(/key="?([^",\s]+)"?/);
    const tsMatch = authHeader.match(/ts="?([^",\s]+)"?/);
    const sigMatch = authHeader.match(/sig="?([^",\s]+)"?/);

    if (keyMatch && tsMatch && sigMatch) {
      const timestamp = Number(tsMatch[1]);
      if (!Number.isFinite(timestamp)) {
        throw new AgentUnauthorizedError("Authorization header ts must be a valid numeric unix epoch");
      }
      return {
        publicKey: keyMatch[1].trim(),
        timestamp,
        signature: sigMatch[1].trim(),
      };
    }
  }

  throw new AgentUnauthorizedError(
    "Missing AgentGuard authentication headers (required: x-agent-public-key, x-agent-timestamp, x-agent-signature)"
  );
}

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
export function requireAgentRole(role: string, options?: RequireRoleOptions) {
  return async (req: AgentGuardRequest, res: AgentGuardResponse, next: NextFunction): Promise<unknown> => {
    const contract = options?.contract ?? AgentGuardContract.getDefault();
    if (!contract) {
      return res.status(500).json({
        error: "AgentGuard contract instance is not configured. Pass contract in options or call AgentGuardContract.setDefault().",
        code: "CONFIGURATION_ERROR",
      });
    }

    // Step 1: Extract credentials
    let auth: AgentAuthHeader;
    try {
      auth = extractAuthHeader(req);
    } catch (err) {
      const authErr = err as AgentUnauthorizedError;
      return res.status(401).json({
        error: authErr.message,
        code: "UNAUTHORIZED",
      });
    }

    // Step 2: Cryptographic signature & replay protection verification
    const payload = options?.getPayload ? options.getPayload(req) : (req.body ?? {});

    try {
      assertSignatureValid(auth.publicKey, payload, auth.signature, auth.timestamp, options?.verifyOptions);
    } catch (err) {
      if (err instanceof AgentTimestampExpiredError) {
        return res.status(401).json({
          error: err.message,
          code: "TIMESTAMP_EXPIRED",
          details: { timestamp: err.timestamp, ageMs: err.ageMs },
        });
      }
      const sigErr = err as AgentSignatureInvalid;
      return res.status(401).json({
        error: sigErr.message,
        code: "INVALID_SIGNATURE",
        details: sigErr.details,
      });
    }

    // Step 3: Query Soroban contract via checkAccess
    const resourceId =
      typeof options?.resourceId === "function"
        ? options.resourceId(req)
        : (options?.resourceId ?? "default_resource");

    try {
      const hasAccess = await contract.checkAccess(auth.publicKey, role, resourceId);
      if (!hasAccess) {
        const deniedErr = new AgentPermissionDeniedError(auth.publicKey, role, resourceId);
        return res.status(403).json({
          error: deniedErr.message,
          code: "FORBIDDEN",
          details: deniedErr.details,
        });
      }
    } catch (err) {
      return res.status(503).json({
        error: `Failed to query AgentGuard contract: ${(err as Error).message}`,
        code: "CONTRACT_READ_ERROR",
      });
    }

    // Step 4: Success — attach verified identity to request object
    req.agentId = auth.publicKey;
    req.agentPublicKey = auth.publicKey;
    req.agentTimestamp = auth.timestamp;

    return next();
  };
}
