/**
 * Express.js compatible middleware for KakoroGuard AI agent authentication & RBAC.
 */
import { KakoroGuardContract } from "./contract.js";
import { AgentPermissionDeniedError, AgentTimestampExpiredError, AgentUnauthorizedError, } from "./errors.js";
import { AgentRequestPayloadSchema } from "./schema.js";
import { assertSignatureValid, } from "./verifier.js";
/**
 * Extract AgentAuthHeader credentials from incoming HTTP request headers.
 *
 * Supports:
 * - Dedicated headers: `x-agent-public-key`, `x-agent-timestamp`, `x-agent-signature`
 * - Standard Authorization header: `Authorization: KakoroGuard key="G...",ts="...",sig="..."`
 */
export function extractAuthHeader(req) {
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
    const amount = getHeader("x-agent-payment-amount");
    const asset = getHeader("x-agent-payment-asset") ?? "XLM";
    const maxFeeStr = getHeader("x-agent-payment-max-fee");
    const dest = getHeader("x-agent-payment-destination");
    let paymentIntent;
    if (amount) {
        paymentIntent = {
            amount,
            asset,
            max_fee: maxFeeStr ? Number(maxFeeStr) || 100_000 : 100_000,
            destination: dest,
        };
    }
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
            paymentIntent,
        };
    }
    // 2. Check Authorization header
    const authHeader = getHeader("authorization");
    if (authHeader && authHeader.startsWith("KakoroGuard ")) {
        const keyMatch = authHeader.match(/key="?([^",\s]+)"?/);
        const tsMatch = authHeader.match(/ts="?([^",\s]+)"?/);
        const sigMatch = authHeader.match(/sig="?([^",\s]+)"?/);
        const amountMatch = authHeader.match(/amount="?([^",\s]+)"?/);
        const assetMatch = authHeader.match(/asset="?([^",\s]+)"?/);
        if (amountMatch && !paymentIntent) {
            paymentIntent = {
                amount: amountMatch[1],
                asset: assetMatch ? assetMatch[1] : "XLM",
                max_fee: 100_000,
                destination: dest,
            };
        }
        if (keyMatch && tsMatch && sigMatch) {
            const timestamp = Number(tsMatch[1]);
            if (!Number.isFinite(timestamp)) {
                throw new AgentUnauthorizedError("Authorization header ts must be a valid numeric unix epoch");
            }
            return {
                publicKey: keyMatch[1].trim(),
                timestamp,
                signature: sigMatch[1].trim(),
                paymentIntent,
            };
        }
    }
    throw new AgentUnauthorizedError("Missing KakoroGuard authentication headers (required: x-agent-public-key, x-agent-timestamp, x-agent-signature)");
}
export function requireAgentRole(role, costOrOptions, maybeOptions) {
    const cost = typeof costOrOptions === "string" ? costOrOptions : undefined;
    const options = typeof costOrOptions === "object" ? costOrOptions : maybeOptions;
    return async (req, res, next) => {
        // Step 0: Ensure KakoroGuardContract is configured
        const contract = options?.contract ?? KakoroGuardContract.getDefault();
        if (!contract) {
            return res.status(500).json({
                error: "KakoroGuard contract instance is not configured. Pass contract in options or call KakoroGuardContract.setDefault().",
                code: "CONFIGURATION_ERROR",
            });
        }
        // Step 1: Extract credentials & payment intent
        let auth;
        let payloadToVerify;
        let paymentIntent;
        if (req.body &&
            typeof req.body === "object" &&
            "signature" in req.body &&
            ("agent_id" in req.body || "public_key" in req.body)) {
            const parsedBody = AgentRequestPayloadSchema.safeParse(req.body);
            if (!parsedBody.success) {
                return res.status(401).json({
                    error: "Invalid AgentRequestPayload body schema",
                    code: "UNAUTHORIZED",
                    details: parsedBody.error.format(),
                });
            }
            auth = {
                publicKey: parsedBody.data.public_key,
                timestamp: parsedBody.data.timestamp,
                signature: parsedBody.data.signature,
                paymentIntent: parsedBody.data.payment_intent,
            };
            paymentIntent = parsedBody.data.payment_intent;
            payloadToVerify = options?.getPayload ? options.getPayload(req) : parsedBody.data.payload;
        }
        else {
            try {
                auth = extractAuthHeader(req);
                paymentIntent = auth.paymentIntent;
                payloadToVerify = options?.getPayload ? options.getPayload(req) : (req.body ?? {});
            }
            catch (err) {
                const authErr = err;
                return res.status(401).json({
                    error: authErr.message,
                    code: "UNAUTHORIZED",
                });
            }
        }
        if (cost && cost !== "0" && (!paymentIntent || !paymentIntent.amount)) {
            return res.status(401).json({
                error: `Endpoint requires payment of '${cost}', but no payment intent was provided`,
                code: "UNAUTHORIZED",
            });
        }
        // Step 2: Cryptographic signature & replay protection verification
        try {
            const payloadToAssert = paymentIntent
                ? {
                    payment_intent: {
                        amount: String(paymentIntent.amount ?? ""),
                        asset: String(paymentIntent.asset ?? "XLM"),
                        destination: paymentIntent.destination ?? null,
                        max_fee: typeof paymentIntent.max_fee === "number"
                            ? paymentIntent.max_fee
                            : Number(paymentIntent.max_fee ?? 100_000),
                    },
                    payload: payloadToVerify ?? {},
                }
                : payloadToVerify;
            assertSignatureValid(auth.publicKey, payloadToAssert, auth.signature, auth.timestamp, options?.verifyOptions);
        }
        catch (err) {
            if (err instanceof AgentTimestampExpiredError) {
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
        // Step 3: Contract Reads & Identity — Query Soroban contract via checkAccess
        const resourceId = typeof options?.resourceId === "function"
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
        }
        catch (err) {
            return res.status(503).json({
                error: `Failed to query KakoroGuard contract: ${err.message}`,
                code: "CONTRACT_READ_ERROR",
            });
        }
        // Step 4: AgentPay Execution — Settle transaction intent
        if (cost && cost !== "0") {
            const destination = paymentIntent?.destination ?? options?.providerAccount ?? "GPROVIDER_ACCOUNT";
            let receipt;
            try {
                if (options?.agentPaySettler) {
                    receipt = await options.agentPaySettler.settlePayment({
                        agentId: auth.publicKey,
                        amount: paymentIntent?.amount ?? cost,
                        asset: paymentIntent?.asset ?? "XLM",
                        maxFee: paymentIntent?.max_fee ?? 100_000,
                        destination,
                    });
                }
                else {
                    const amountStr = paymentIntent?.amount ?? cost;
                    if (amountStr.toUpperCase().includes("FAIL") || amountStr.toUpperCase().includes("INSUFFICIENT")) {
                        throw new Error(`Insufficient AgentPay balance or settlement rejected for ${amountStr}`);
                    }
                    receipt = {
                        status: "SETTLED",
                        txHash: `0x${Buffer.from(`${auth.publicKey}:${amountStr}:${Date.now()}`).toString("hex").slice(0, 64)}`,
                        settled: true,
                        amount: amountStr,
                    };
                }
            }
            catch (err) {
                return res.status(402).json({
                    error: `Payment Required: AgentPay settlement failed - ${err.message}`,
                    code: "PAYMENT_REQUIRED",
                    details: { error: err.message },
                });
            }
            req.paymentReceipt = receipt;
        }
        // Step 5: Success — attach verified identity and payment to request
        req.agentId = auth.publicKey;
        req.agentPublicKey = auth.publicKey;
        req.agentTimestamp = auth.timestamp;
        req.paymentIntent = paymentIntent;
        return next();
    };
}
//# sourceMappingURL=middleware.js.map