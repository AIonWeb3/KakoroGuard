/**
 * Soroban Smart Contract interaction module for AgentGuard RBAC.
 */
import { AgentGuardConfig, Role } from "./types.js";
/** Interface allowing simulation engine injection for testing and offline mocking */
export interface RpcSimulator {
    simulateTransaction(tx: unknown): Promise<unknown>;
}
export declare class AgentGuardContract {
    readonly contractId: string;
    readonly rpcUrl: string;
    readonly networkPassphrase: string;
    readonly maxRetries: number;
    readonly retryDelayMs: number;
    private readonly contract;
    private readonly server;
    private readonly simulationKeypair;
    private static defaultInstance?;
    constructor(config: AgentGuardConfig, customSimulator?: RpcSimulator);
    /**
     * Set the default global contract instance for middleware use.
     */
    static setDefault(instance: AgentGuardContract): void;
    /**
     * Get the default global contract instance.
     */
    static getDefault(): AgentGuardContract | undefined;
    /**
     * Check whether an agent holds an active, unexpired role on a resource.
     *
     * @param agentId The agent's Stellar G-address.
     * @param role Required role ("Basic", "Premium", "Admin" or Role enum).
     * @param resourceId Target protected resource identifier (Symbol).
     * @returns true if authorized, false otherwise.
     */
    checkAccess(agentId: string, role: string | Role, resourceId: string): Promise<boolean>;
    /**
     * Verify an agent's global role against the on-chain registry.
     *
     * @param agentId The agent's Stellar G-address.
     * @param role Required role ("Basic", "Premium", "Admin" or Role enum).
     * @returns true if agent exists, is Active, and holds the role; false otherwise.
     */
    verifyAgent(agentId: string, role: string | Role): Promise<boolean>;
    /**
     * Execute a read-only transaction simulation with automatic network retry.
     */
    private executeWithRetry;
    /**
     * Build and simulate a Soroban contract call transaction.
     */
    private simulateCall;
}
//# sourceMappingURL=contract.d.ts.map