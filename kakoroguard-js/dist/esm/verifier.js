/**
 * Verification module for KakoroGuard cryptographic request signatures & replay protection.
 */
import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { createHash } from "node:crypto";
import { AgentSignatureInvalid, AgentTimestampExpiredError } from "./errors.js";
/** Default replay attack threshold: 5 minutes in milliseconds */
export const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000;
/** Default forward clock skew tolerance: 1 minute in milliseconds */
export const DEFAULT_CLOCK_SKEW_MS = 60 * 1000;
/**
 * Deterministically serializes an arbitrary payload into canonical JSON.
 *
 * Ensures identical byte representations across Python and JavaScript by:
 * - Sorting dictionary/object keys alphabetically.
 * - Recursively sorting nested objects and arrays.
 * - Removing whitespace between keys and values.
 */
export function canonicalizePayload(payload) {
    if (payload === undefined) {
        return "";
    }
    if (payload === null || typeof payload !== "object") {
        return JSON.stringify(payload);
    }
    if (Array.isArray(payload)) {
        const elements = payload.map((item) => canonicalizePayload(item));
        return `[${elements.join(",")}]`;
    }
    const record = payload;
    const sortedKeys = Object.keys(record).sort();
    const entries = [];
    for (const key of sortedKeys) {
        const val = record[key];
        if (val !== undefined) {
            entries.push(`${JSON.stringify(key)}:${canonicalizePayload(val)}`);
        }
    }
    return `{${entries.join(",")}}`;
}
/**
 * Deterministically serializes a synergistic payload and payment intent into canonical JSON.
 *
 * Combines application payload with payment intent to bind financial authorization
 * with KakoroGuard identity, preventing tampering of amounts or destination.
 */
export function serializeSynergisticPayload(payload, paymentIntent) {
    let appPayload = payload;
    let intentData = null;
    if (payload && typeof payload === "object") {
        const obj = payload;
        if ("payment_intent" in obj && obj.payment_intent && typeof obj.payment_intent === "object") {
            appPayload = obj.payload ?? {};
            const rawIntent = obj.payment_intent;
            intentData = {
                amount: String(rawIntent.amount ?? ""),
                asset: String(rawIntent.asset ?? "XLM"),
                destination: rawIntent.destination ?? null,
                max_fee: typeof rawIntent.max_fee === "number" ? rawIntent.max_fee : Number(rawIntent.max_fee ?? 100_000),
            };
        }
    }
    if (!intentData && paymentIntent) {
        const rawIntent = paymentIntent;
        intentData = {
            amount: String(rawIntent.amount ?? ""),
            asset: String(rawIntent.asset ?? "XLM"),
            destination: rawIntent.destination ?? null,
            max_fee: typeof rawIntent.max_fee === "number" ? rawIntent.max_fee : Number(rawIntent.max_fee ?? 100_000),
        };
    }
    const combined = {
        payment_intent: intentData ?? {},
        payload: appPayload ?? {},
    };
    return canonicalizePayload(combined);
}
/**
 * Computes deterministic SHA-256 hex digest of the synergistic payload.
 */
export function hashSynergisticPayload(payload, paymentIntent) {
    const canonical = typeof payload === "string" && !paymentIntent
        ? payload
        : serializeSynergisticPayload(payload, paymentIntent);
    return createHash("sha256").update(canonical, "utf8").digest("hex");
}
/**
 * Builds binary message to verify/sign for synergistic request.
 */
export function buildSynergisticSigningMessage(canonicalJsonOrHash, timestamp) {
    const msgStr = timestamp !== undefined ? `${timestamp}.${canonicalJsonOrHash}` : canonicalJsonOrHash;
    return Buffer.from(msgStr, "utf8");
}
/**
 * Validates timestamp for replay-attack prevention.
 *
 * @param timestamp Timestamp in milliseconds (or seconds if < 1e11).
 * @param options Timing thresholds and optional clock override.
 * @throws AgentTimestampExpiredError if the timestamp is too old or in the future.
 */
export function validateTimestamp(timestamp, options) {
    if (!Number.isFinite(timestamp) || timestamp <= 0) {
        throw new AgentTimestampExpiredError(timestamp, 0, "Timestamp must be a positive finite number");
    }
    const now = options?.currentTimeMs ?? Date.now();
    const tsMs = timestamp < 100_000_000_000 ? timestamp * 1000 : timestamp;
    const maxAgeMs = options?.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
    const clockSkewMs = options?.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    const age = now - tsMs;
    if (age > maxAgeMs) {
        throw new AgentTimestampExpiredError(timestamp, age, `Request timestamp expired: age ${age}ms exceeds maximum allowed ${maxAgeMs}ms (5 minutes)`);
    }
    if (age < -clockSkewMs) {
        throw new AgentTimestampExpiredError(timestamp, age, `Request timestamp is in the future: clock skew ${-age}ms exceeds tolerance ${clockSkewMs}ms`);
    }
    return true;
}
/**
 * Parses a signature string into a raw Buffer.
 * Supports hex encoding (128 chars) and base64 encoding (86-88 chars).
 */
export function parseSignature(signature) {
    if (!signature || typeof signature !== "string") {
        throw new Error("Signature must be a non-empty string");
    }
    const clean = signature.trim();
    // 128 hex chars = 64 bytes
    if (/^[0-9a-fA-F]{128}$/.test(clean)) {
        return Buffer.from(clean, "hex");
    }
    // Base64 (86-88 chars)
    if (/^[A-Za-z0-9+/=]{86,88}$/.test(clean)) {
        const buf = Buffer.from(clean, "base64");
        if (buf.length === 64) {
            return buf;
        }
    }
    throw new Error(`Invalid signature format: expected 64 bytes in hex or base64, received length ${clean.length}`);
}
/**
 * Verify an Ed25519 request signature from an AI agent.
 *
 * Checks:
 * 1. Replay attack prevention: timestamp must be within 5 minutes of current time.
 * 2. Cryptographic validity: validates signature against the agent's Stellar G-address public key.
 *
 * @param publicKey The agent's Stellar public key (G-address).
 * @param payload The request body or payload dictionary.
 * @param signature The 64-byte Ed25519 signature in hex or base64.
 * @param timestamp The request timestamp in milliseconds.
 * @param options Optional verification options.
 * @returns true if signature and timestamp are valid, false otherwise.
 */
export function verifySignature(publicKey, payload, signature, timestamp, options) {
    try {
        assertSignatureValid(publicKey, payload, signature, timestamp, options);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Strict signature assertion that throws detailed errors on failure.
 *
 * @throws AgentTimestampExpiredError if the timestamp fails replay attack protection.
 * @throws AgentSignatureInvalid if the cryptographic signature is invalid or forged.
 */
export function assertSignatureValid(publicKey, payload, signature, timestamp, options) {
    // Step 1: Replay protection check
    validateTimestamp(timestamp, options);
    // Step 2: Public key validation
    if (!publicKey || typeof publicKey !== "string" || !StrKey.isValidEd25519PublicKey(publicKey.trim())) {
        throw new AgentSignatureInvalid(String(publicKey), "Invalid Stellar Ed25519 public key (G-address)");
    }
    const cleanPubKey = publicKey.trim();
    const keypair = Keypair.fromPublicKey(cleanPubKey);
    // Step 3: Parse signature
    let signatureBytes;
    try {
        signatureBytes = parseSignature(signature);
    }
    catch (err) {
        throw new AgentSignatureInvalid(cleanPubKey, err.message);
    }
    // Step 4: Verify against canonical payload binding
    const canonical = canonicalizePayload(payload);
    const boundMessage = Buffer.from(`${timestamp}.${canonical}`, "utf-8");
    if (keypair.verify(boundMessage, signatureBytes)) {
        return;
    }
    // Fallback: verify unbounded message (just canonical payload)
    const rawMessage = Buffer.from(canonical, "utf-8");
    if (keypair.verify(rawMessage, signatureBytes)) {
        return;
    }
    throw new AgentSignatureInvalid(cleanPubKey, "Cryptographic signature does not match payload and timestamp");
}
//# sourceMappingURL=verifier.js.map