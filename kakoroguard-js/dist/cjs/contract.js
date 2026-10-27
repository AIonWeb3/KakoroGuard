"use strict";
/**
 * Soroban Smart Contract interaction module for KakoroGuard RBAC.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.KakoroGuardContract = void 0;
const stellar_sdk_1 = require("@stellar/stellar-sdk");
const errors_js_1 = require("./errors.js");
const types_js_1 = require("./types.js");
class KakoroGuardContract {
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
            throw new errors_js_1.ContractReadError("KakoroGuardConfig must provide contractId, rpcUrl, and networkPassphrase (no hardcoded URLs allowed)");
        }
        this.contractId = config.contractId.trim();
        this.rpcUrl = config.rpcUrl.trim();
        this.networkPassphrase = config.networkPassphrase;
        this.maxRetries = config.maxRetries ?? 3;
        this.retryDelayMs = config.retryDelayMs ?? 200;
        this.contract = new stellar_sdk_1.Contract(this.contractId);
        this.server = customSimulator ?? new stellar_sdk_1.rpc.Server(this.rpcUrl);
        this.simulationKeypair = stellar_sdk_1.Keypair.random();
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
        const roleEnum = (0, types_js_1.parseRole)(role);
        try {
            const args = [
                new stellar_sdk_1.Address(agentId.trim()).toScVal(),
                (0, stellar_sdk_1.nativeToScVal)(resourceId.trim(), { type: "symbol" }),
                (0, stellar_sdk_1.nativeToScVal)(roleEnum, { type: "u32" }),
            ];
            const retVal = await this.executeWithRetry("check_access", args);
            return Boolean((0, stellar_sdk_1.scValToNative)(retVal));
        }
        catch (error) {
            if (error instanceof errors_js_1.NetworkRetryExhaustedError || error instanceof errors_js_1.ContractReadError) {
                throw error;
            }
            throw new errors_js_1.ContractReadError(`Failed to check access for agent ${agentId}: ${error.message}`, error, { agentId, role, resourceId });
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
        const roleEnum = (0, types_js_1.parseRole)(role);
        try {
            const args = [
                new stellar_sdk_1.Address(agentId.trim()).toScVal(),
                (0, stellar_sdk_1.nativeToScVal)(roleEnum, { type: "u32" }),
            ];
            const retVal = await this.executeWithRetry("verify_agent", args);
            return Boolean((0, stellar_sdk_1.scValToNative)(retVal));
        }
        catch (error) {
            if (error instanceof errors_js_1.NetworkRetryExhaustedError || error instanceof errors_js_1.ContractReadError) {
                throw error;
            }
            throw new errors_js_1.ContractReadError(`Failed to verify agent ${agentId}: ${error.message}`, error, { agentId, role });
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
                    throw new errors_js_1.ContractReadError(lastError.message, lastError);
                }
                // On last attempt, do not sleep
                if (attempt < this.maxRetries) {
                    const delay = this.retryDelayMs * Math.pow(1.5, attempt - 1);
                    await new Promise((resolve) => setTimeout(resolve, delay));
                }
            }
        }
        throw new errors_js_1.NetworkRetryExhaustedError(`RPC query to ${this.rpcUrl} failed after ${this.maxRetries} attempts: ${lastError?.message}`, this.maxRetries, lastError);
    }
    /**
     * Build and simulate a Soroban contract call transaction.
     */
    async simulateCall(method, args) {
        const operation = this.contract.call(method, ...args);
        const sourcePublicKey = this.simulationKeypair.publicKey();
        const account = new stellar_sdk_1.Account(sourcePublicKey, "0");
        const transaction = new stellar_sdk_1.TransactionBuilder(account, {
            fee: "100",
            networkPassphrase: this.networkPassphrase,
        })
            .addOperation(operation)
            .setTimeout(30)
            .build();
        const simulation = (await this.server.simulateTransaction(transaction));
        if (stellar_sdk_1.rpc.Api.isSimulationError(simulation)) {
            const errResponse = simulation;
            throw new errors_js_1.ContractReadError(`Contract simulation failed: ${errResponse.error}`);
        }
        if (stellar_sdk_1.rpc.Api.isSimulationSuccess(simulation)) {
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
        throw new errors_js_1.ContractReadError(`Soroban simulation returned no return value for method "${method}"`);
    }
}
exports.KakoroGuardContract = KakoroGuardContract;
//# sourceMappingURL=contract.js.map