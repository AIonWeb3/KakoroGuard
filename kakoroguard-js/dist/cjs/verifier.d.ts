/**
 * Verification module for KakoroGuard cryptographic request signatures & replay protection.
 */
import { VerifyOptions } from "./types.js";
/** Default replay attack threshold: 5 minutes in milliseconds */
export declare const DEFAULT_MAX_AGE_MS: number;
/** Default forward clock skew tolerance: 1 minute in milliseconds */
export declare const DEFAULT_CLOCK_SKEW_MS: number;
/**
 * Deterministically serializes an arbitrary payload into canonical JSON.
 *
 * Ensures identical byte representations across Python and JavaScript by:
 * - Sorting dictionary/object keys alphabetically.
 * - Recursively sorting nested objects and arrays.
 * - Removing whitespace between keys and values.
 */
export declare function canonicalizePayload(payload: unknown): string;
/**
 * Validates timestamp for replay-attack prevention.
 *
 * @param timestamp Timestamp in milliseconds (or seconds if < 1e11).
 * @param options Timing thresholds and optional clock override.
 * @throws AgentTimestampExpiredError if the timestamp is too old or in the future.
 */
export declare function validateTimestamp(timestamp: number, options?: VerifyOptions): boolean;
/**
 * Parses a signature string into a raw Buffer.
 * Supports hex encoding (128 chars) and base64 encoding (86-88 chars).
 */
export declare function parseSignature(signature: string): Buffer;
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
export declare function verifySignature(publicKey: string, payload: unknown, signature: string, timestamp: number, options?: VerifyOptions): boolean;
/**
 * Strict signature assertion that throws detailed errors on failure.
 *
 * @throws AgentTimestampExpiredError if the timestamp fails replay attack protection.
 * @throws AgentSignatureInvalid if the cryptographic signature is invalid or forged.
 */
export declare function assertSignatureValid(publicKey: string, payload: unknown, signature: string, timestamp: number, options?: VerifyOptions): void;
//# sourceMappingURL=verifier.d.ts.map