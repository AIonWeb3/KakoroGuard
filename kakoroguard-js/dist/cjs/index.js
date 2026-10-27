"use strict";
/**
 * KakoroGuard TypeScript SDK for Web2 Resource Providers.
 *
 * Provides cryptographic signature verification, replay-attack prevention,
 * Soroban contract RBAC integration, and Express.js middleware.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ROLE_NAMES = exports.Role = exports.parseRole = exports.AgentStatus = exports.NetworkRetryExhaustedError = exports.KakoroGuardError = exports.ContractReadError = exports.AgentUnauthorizedError = exports.AgentTimestampExpiredError = exports.AgentSignatureInvalid = exports.AgentPermissionDeniedError = exports.requireAgentRole = exports.extractAuthHeader = exports.verifySignature = exports.validateTimestamp = exports.parseSignature = exports.DEFAULT_MAX_AGE_MS = exports.DEFAULT_CLOCK_SKEW_MS = exports.canonicalizePayload = exports.assertSignatureValid = exports.KakoroGuardContract = void 0;
var contract_js_1 = require("./contract.js");
Object.defineProperty(exports, "KakoroGuardContract", { enumerable: true, get: function () { return contract_js_1.KakoroGuardContract; } });
var verifier_js_1 = require("./verifier.js");
Object.defineProperty(exports, "assertSignatureValid", { enumerable: true, get: function () { return verifier_js_1.assertSignatureValid; } });
Object.defineProperty(exports, "canonicalizePayload", { enumerable: true, get: function () { return verifier_js_1.canonicalizePayload; } });
Object.defineProperty(exports, "DEFAULT_CLOCK_SKEW_MS", { enumerable: true, get: function () { return verifier_js_1.DEFAULT_CLOCK_SKEW_MS; } });
Object.defineProperty(exports, "DEFAULT_MAX_AGE_MS", { enumerable: true, get: function () { return verifier_js_1.DEFAULT_MAX_AGE_MS; } });
Object.defineProperty(exports, "parseSignature", { enumerable: true, get: function () { return verifier_js_1.parseSignature; } });
Object.defineProperty(exports, "validateTimestamp", { enumerable: true, get: function () { return verifier_js_1.validateTimestamp; } });
Object.defineProperty(exports, "verifySignature", { enumerable: true, get: function () { return verifier_js_1.verifySignature; } });
var middleware_js_1 = require("./middleware.js");
Object.defineProperty(exports, "extractAuthHeader", { enumerable: true, get: function () { return middleware_js_1.extractAuthHeader; } });
Object.defineProperty(exports, "requireAgentRole", { enumerable: true, get: function () { return middleware_js_1.requireAgentRole; } });
var errors_js_1 = require("./errors.js");
Object.defineProperty(exports, "AgentPermissionDeniedError", { enumerable: true, get: function () { return errors_js_1.AgentPermissionDeniedError; } });
Object.defineProperty(exports, "AgentSignatureInvalid", { enumerable: true, get: function () { return errors_js_1.AgentSignatureInvalid; } });
Object.defineProperty(exports, "AgentTimestampExpiredError", { enumerable: true, get: function () { return errors_js_1.AgentTimestampExpiredError; } });
Object.defineProperty(exports, "AgentUnauthorizedError", { enumerable: true, get: function () { return errors_js_1.AgentUnauthorizedError; } });
Object.defineProperty(exports, "ContractReadError", { enumerable: true, get: function () { return errors_js_1.ContractReadError; } });
Object.defineProperty(exports, "KakoroGuardError", { enumerable: true, get: function () { return errors_js_1.KakoroGuardError; } });
Object.defineProperty(exports, "NetworkRetryExhaustedError", { enumerable: true, get: function () { return errors_js_1.NetworkRetryExhaustedError; } });
var types_js_1 = require("./types.js");
Object.defineProperty(exports, "AgentStatus", { enumerable: true, get: function () { return types_js_1.AgentStatus; } });
Object.defineProperty(exports, "parseRole", { enumerable: true, get: function () { return types_js_1.parseRole; } });
Object.defineProperty(exports, "Role", { enumerable: true, get: function () { return types_js_1.Role; } });
Object.defineProperty(exports, "ROLE_NAMES", { enumerable: true, get: function () { return types_js_1.ROLE_NAMES; } });
//# sourceMappingURL=index.js.map