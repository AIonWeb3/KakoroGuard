"use strict";
/**
 * Express.js compatible middleware for KakoroGuard AI agent authentication & RBAC.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractAuthHeader = extractAuthHeader;
exports.requireAgentRole = requireAgentRole;
const contract_js_1 = require("./contract.js");
const errors_js_1 = require("./errors.js");
const verifier_js_1 = require("./verifier.js");
/**
 * Extract AgentAuthHeader credentials from incoming HTTP request headers.
 *
 * Supports:
 * - Dedicated headers: `x-agent-public-key`, `x-agent-timestamp`, `x-agent-signature`
 * - Standard Authorization header: `Authorization: KakoroGuard key="G...",ts="...",sig="..."`
 */
function extractAuthHeader(req) {
    const headerMap = {};
    for (const [k, v] of Object.entries(req.headers || {})) {
        headerMap[k.toLowerCase()] = v;
    }
    const getHeader = (name) => {
        const val = headerMap[name.toLowerCase()];
        if (Array.isArray(val))
            return val[0];
        return val;
    };
    // 1. Check dedicated X-Agent-* headers
    const pubKey = getHeader("x-agent-public-key") ?? getHeader("x-agent-id");
    const tsStr = getHeader("x-agent-timestamp");
    const sig = getHeader("x-agent-signature");
    if (pubKey && tsStr && sig) {
        const timestamp = Number(tsStr);
        if (!Number.isFinite(timestamp)) {
            throw new errors_js_1.AgentUnauthorizedError("Header x-agent-timestamp must be a valid numeric unix epoch", {
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
    if (authHeader && authHeader.startsWith("KakoroGuard ")) {
        const keyMatch = authHeader.match(/key="?([^",\s]+)"?/);
        const tsMatch = authHeader.match(/ts="?([^",\s]+)"?/);
        const sigMatch = authHeader.match(/sig="?([^",\s]+)"?/);
        if (keyMatch && tsMatch && sigMatch) {
            const timestamp = Number(tsMatch[1]);
            if (!Number.isFinite(timestamp)) {
                throw new errors_js_1.AgentUnauthorizedError("Authorization header ts must be a valid numeric unix epoch");
            }
            return {
                publicKey: keyMatch[1].trim(),
                timestamp,
                signature: sigMatch[1].trim(),
            };
        }
    }
    throw new errors_js_1.AgentUnauthorizedError("Missing KakoroGuard authentication headers (required: x-agent-public-key, x-agent-timestamp, x-agent-signature)");
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
function requireAgentRole(role, options) {
    return async (req, res, next) => {
        const contract = options?.contract ?? contract_js_1.KakoroGuardContract.getDefault();
        if (!contract) {
            return res.status(500).json({
                error: "KakoroGuard contract instance is not configured. Pass contract in options or call KakoroGuardContract.setDefault().",
                code: "CONFIGURATION_ERROR",
            });
        }
        // Step 1: Extract credentials
        let auth;
        try {
            auth = extractAuthHeader(req);
        }
        catch (err) {
            const authErr = err;
            return res.status(401).json({
                error: authErr.message,
                code: "UNAUTHORIZED",
            });
        }
        // Step 2: Cryptographic signature & replay protection verification
        const payload = options?.getPayload ? options.getPayload(req) : (req.body ?? {});
        try {
            (0, verifier_js_1.assertSignatureValid)(auth.publicKey, payload, auth.signature, auth.timestamp, options?.verifyOptions);
        }
        catch (err) {
            if (err instanceof errors_js_1.AgentTimestampExpiredError) {
                return res.status(401).json({
                    error: err.message,
                    code: "TIMESTAMP_EXPIRED",
                    details: { timestamp: err.timestamp, ageMs: err.ageMs },
                });
            }
            const sigErr = err;
            return res.status(401).json({
                error: sigErr.message,
                code: "INVALID_SIGNATURE",
                details: sigErr.details,
            });
        }
        // Step 3: Query Soroban contract via checkAccess
        const resourceId = typeof options?.resourceId === "function"
            ? options.resourceId(req)
            : (options?.resourceId ?? "default_resource");
        try {
            const hasAccess = await contract.checkAccess(auth.publicKey, role, resourceId);
            if (!hasAccess) {
                const deniedErr = new errors_js_1.AgentPermissionDeniedError(auth.publicKey, role, resourceId);
                return res.status(403).json({
                    error: deniedErr.message,
                    code: "FORBIDDEN",
                    details: deniedErr.details,
                });
            }
        }
        catch (err) {
            return res.status(503).json({
                error: `Failed to query KakoroGuard contract: ${err.message}`,
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
//# sourceMappingURL=middleware.js.map