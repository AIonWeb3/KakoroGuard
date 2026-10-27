/**
 * Soroban Smart Contract interaction module for KakoroGuard RBAC.
 */
import { Account, Address, Contract, Keypair, nativeToScVal, rpc as StellarRpc, scValToNative, TransactionBuilder, } from "@stellar/stellar-sdk";
import { ContractReadError, NetworkRetryExhaustedError } from "./errors.js";
import { parseRole } from "./types.js";
export class KakoroGuardContract {
    contractId;
    rpcUrl;
    networkPassphrase;
    maxRetries;
    retryDelayMs;
    contract;
    server;
    simulationKeypair;
    static defaultInstance;
    constructor(config, customSimulator) {
        if (!config.contractId || !config.rpcUrl || !config.networkPassphrase) {
            throw new ContractReadError("KakoroGuardConfig must provide contractId, rpcUrl, and networkPassphrase (no hardcoded URLs allowed)");
        }
        this.contractId = config.contractId.trim();
        this.rpcUrl = config.rpcUrl.trim();
        this.networkPassphrase = config.networkPassphrase;
        this.maxRetries = config.maxRetries ?? 3;
        this.retryDelayMs = config.retryDelayMs ?? 200;
        this.contract = new Contract(this.contractId);
        this.server = customSimulator ?? new StellarRpc.Server(this.rpcUrl);
        this.simulationKeypair = Keypair.random();
    }
    /**
     * Set the default global contract instance for middleware use.
     */
    static setDefault(instance) {
        KakoroGuardContract.defaultInstance = instance;
    }
    /**
     * Get the default global contract instance.
     */
    static getDefault() {
        return KakoroGuardContract.defaultInstance;
    }
    /**
     * Check whether an agent holds an active, unexpired role on a resource.
     *
     * @param agentId The agent's Stellar G-address.
     * @param role Required role ("Basic", "Premium", "Admin" or Role enum).
     * @param resourceId Target protected resource identifier (Symbol).
     * @returns true if authorized, false otherwise.
     */
    async checkAccess(agentId, role, resourceId) {
        const roleEnum = parseRole(role);
        try {
            const args = [
                new Address(agentId.trim()).toScVal(),
                nativeToScVal(resourceId.trim(), { type: "symbol" }),
                nativeToScVal(roleEnum, { type: "u32" }),
            ];
            const retVal = await this.executeWithRetry("check_access", args);
            return Boolean(scValToNative(retVal));
        }
        catch (error) {
            if (error instanceof NetworkRetryExhaustedError || error instanceof ContractReadError) {
                throw error;
            }
            throw new ContractReadError(`Failed to check access for agent ${agentId}: ${error.message}`, error, { agentId, role, resourceId });
        }
    }
    /**
     * Verify an agent's global role against the on-chain registry.
     *
     * @param agentId The agent's Stellar G-address.
     * @param role Required role ("Basic", "Premium", "Admin" or Role enum).
     * @returns true if agent exists, is Active, and holds the role; false otherwise.
     */
    async verifyAgent(agentId, role) {
        const roleEnum = parseRole(role);
        try {
            const args = [
                new Address(agentId.trim()).toScVal(),
                nativeToScVal(roleEnum, { type: "u32" }),
            ];
            const retVal = await this.executeWithRetry("verify_agent", args);
            return Boolean(scValToNative(retVal));
        }
        catch (error) {
            if (error instanceof NetworkRetryExhaustedError || error instanceof ContractReadError) {
                throw error;
            }
            throw new ContractReadError(`Failed to verify agent ${agentId}: ${error.message}`, error, { agentId, role });
        }
    }
    /**
     * Execute a read-only transaction simulation with automatic network retry.
     */
    async executeWithRetry(method, args) {
        let lastError;
        for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
            try {
                return await this.simulateCall(method, args);
            }
            catch (err) {
                lastError = err;
                // If it's a permanent contract simulation error (e.g. logic error, not network), don't retry endlessly
                if (lastError.message.includes("Contract simulation failed:")) {
                    throw new ContractReadError(lastError.message, lastError);
                }
                // On last attempt, do not sleep
                if (attempt < this.maxRetries) {
                    const delay = this.retryDelayMs * Math.pow(1.5, attempt - 1);
                    await new Promise((resolve) => setTimeout(resolve, delay));
                }
            }
        }
        throw new NetworkRetryExhaustedError(`RPC query to ${this.rpcUrl} failed after ${this.maxRetries} attempts: ${lastError?.message}`, this.maxRetries, lastError);
    }
    /**
     * Build and simulate a Soroban contract call transaction.
     */
    async simulateCall(method, args) {
        const operation = this.contract.call(method, ...args);
        const sourcePublicKey = this.simulationKeypair.publicKey();
        const account = new Account(sourcePublicKey, "0");
        const transaction = new TransactionBuilder(account, {
            fee: "100",
            networkPassphrase: this.networkPassphrase,
        })
            .addOperation(operation)
            .setTimeout(30)
            .build();
        const simulation = (await this.server.simulateTransaction(transaction));
        if (StellarRpc.Api.isSimulationError(simulation)) {
            const errResponse = simulation;
            throw new ContractReadError(`Contract simulation failed: ${errResponse.error}`);
        }
        if (StellarRpc.Api.isSimulationSuccess(simulation)) {
            const successResponse = simulation;
            if (successResponse.result?.retval) {
                return successResponse.result.retval;
            }
        }
        // Support mocked or plain simulation structures
        const plainSim = simulation;
        if (plainSim.result && typeof plainSim.result === "object") {
            const resObj = plainSim.result;
            if (resObj.retval) {
                return resObj.retval;
            }
        }
        throw new ContractReadError(`Soroban simulation returned no return value for method "${method}"`);
    }
}
//# sourceMappingURL=contract.js.map