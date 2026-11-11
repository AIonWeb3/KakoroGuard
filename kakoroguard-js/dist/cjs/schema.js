"use strict";
/**
 * Synergistic payload schema defining the interaction between KakoroGuard and AgentPay.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentRequestPayloadSchema = exports.PaymentIntentSchema = void 0;
const zod_1 = require("zod");
exports.PaymentIntentSchema = zod_1.z.object({
    amount: zod_1.z.string().min(1, "Payment amount is required"),
    asset: zod_1.z.string().default("XLM"),
    max_fee: zod_1.z.number().int().nonnegative().default(100_000),
    destination: zod_1.z.string().nullable().optional(),
});
exports.AgentRequestPayloadSchema = zod_1.z
    .object({
    agent_id: zod_1.z.string().optional(),
    public_key: zod_1.z.string().optional(),
    timestamp: zod_1.z.number().int().positive("Timestamp must be a positive integer"),
    signature: zod_1.z.string().min(1, "Signature is required"),
    payment_intent: exports.PaymentIntentSchema.optional(),
    amount: zod_1.z.string().optional(),
    asset: zod_1.z.string().optional(),
    max_fee: zod_1.z.number().optional(),
    destination: zod_1.z.string().nullable().optional(),
    payload: zod_1.z.record(zod_1.z.string(), zod_1.z.unknown()).optional().default({}),
})
    .transform((data) => {
    const agentId = data.agent_id || data.public_key;
    if (!agentId) {
        throw new Error("Missing required field: agent_id or public_key");
    }
    let paymentIntent = data.payment_intent;
    if (!paymentIntent) {
        if (!data.amount) {
            throw new Error("Missing required field: payment_intent or amount");
        }
        paymentIntent = exports.PaymentIntentSchema.parse({
            amount: data.amount,
            asset: data.asset ?? "XLM",
            max_fee: data.max_fee ?? 100_000,
            destination: data.destination,
        });
    }
    return {
        agent_id: agentId,
        public_key: agentId,
        timestamp: data.timestamp,
        signature: data.signature,
        payment_intent: paymentIntent,
        payload: data.payload ?? {},
    };
});
//# sourceMappingURL=schema.js.map