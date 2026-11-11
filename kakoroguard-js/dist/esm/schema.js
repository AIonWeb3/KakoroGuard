/**
 * Synergistic payload schema defining the interaction between KakoroGuard and AgentPay.
 */
import { z } from "zod";
export const PaymentIntentSchema = z.object({
    amount: z.string().min(1, "Payment amount is required"),
    asset: z.string().default("XLM"),
    max_fee: z.number().int().nonnegative().default(100_000),
    destination: z.string().optional(),
});
export const AgentRequestPayloadSchema = z
    .object({
    agent_id: z.string().optional(),
    public_key: z.string().optional(),
    timestamp: z.number().int().positive("Timestamp must be a positive integer"),
    signature: z.string().min(1, "Signature is required"),
    payment_intent: PaymentIntentSchema.optional(),
    amount: z.string().optional(),
    asset: z.string().optional(),
    max_fee: z.number().optional(),
    destination: z.string().optional(),
    payload: z.record(z.string(), z.unknown()).optional().default({}),
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
        paymentIntent = PaymentIntentSchema.parse({
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