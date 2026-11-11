/**
 * Synergistic payload schema defining the interaction between KakoroGuard and AgentPay.
 */
import { z } from "zod";
export declare const PaymentIntentSchema: z.ZodObject<{
    amount: z.ZodString;
    asset: z.ZodDefault<z.ZodString>;
    max_fee: z.ZodDefault<z.ZodNumber>;
    destination: z.ZodOptional<z.ZodString>;
}, z.core.$strip>;
export type PaymentIntent = z.infer<typeof PaymentIntentSchema>;
export declare const AgentRequestPayloadSchema: z.ZodPipe<z.ZodObject<{
    agent_id: z.ZodOptional<z.ZodString>;
    public_key: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodNumber;
    signature: z.ZodString;
    payment_intent: z.ZodOptional<z.ZodObject<{
        amount: z.ZodString;
        asset: z.ZodDefault<z.ZodString>;
        max_fee: z.ZodDefault<z.ZodNumber>;
        destination: z.ZodOptional<z.ZodString>;
    }, z.core.$strip>>;
    amount: z.ZodOptional<z.ZodString>;
    asset: z.ZodOptional<z.ZodString>;
    max_fee: z.ZodOptional<z.ZodNumber>;
    destination: z.ZodOptional<z.ZodString>;
    payload: z.ZodDefault<z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>>;
}, z.core.$strip>, z.ZodTransform<{
    agent_id: string;
    public_key: string;
    timestamp: number;
    signature: string;
    payment_intent: {
        amount: string;
        asset: string;
        max_fee: number;
        destination?: string | undefined;
    };
    payload: Record<string, unknown>;
}, {
    timestamp: number;
    signature: string;
    payload: Record<string, unknown>;
    agent_id?: string | undefined;
    public_key?: string | undefined;
    payment_intent?: {
        amount: string;
        asset: string;
        max_fee: number;
        destination?: string | undefined;
    } | undefined;
    amount?: string | undefined;
    asset?: string | undefined;
    max_fee?: number | undefined;
    destination?: string | undefined;
}>>;
export type AgentRequestPayload = z.output<typeof AgentRequestPayloadSchema>;
export type AgentRequestPayloadInput = z.input<typeof AgentRequestPayloadSchema>;
//# sourceMappingURL=schema.d.ts.map