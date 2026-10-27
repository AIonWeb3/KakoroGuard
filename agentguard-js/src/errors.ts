/**
 * Custom error classes for the AgentGuard TypeScript SDK.
 */

export class AgentGuardError extends Error {
  public readonly code: string;
  public readonly details?: Record<string, unknown>;

  constructor(message: string, code: string = "AGENT_GUARD_ERROR", details?: Record<string, unknown>) {
    super(message);
    this.name = "AgentGuardError";
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when an Ed25519 signature is cryptographically invalid or forged.
 */
export class AgentSignatureInvalid extends AgentGuardError {
  public readonly publicKey: string;

  constructor(publicKey: string, reason?: string) {
    const detailMsg = reason ? ` (${reason})` : "";
    super(
      `Cryptographic signature verification failed for agent public key ${publicKey}${detailMsg}`,
      "AGENT_SIGNATURE_INVALID",
      { publicKey, reason }
    );
    this.name = "AgentSignatureInvalid";
    this.publicKey = publicKey;
  }
}

/**
 * Raised when a request timestamp fails the 5-minute replay-attack prevention check.
 */
export class AgentTimestampExpiredError extends AgentGuardError {
  public readonly timestamp: number;
  public readonly ageMs: number;

  constructor(timestamp: number, ageMs: number, reason?: string) {
    const msg = reason ?? `Timestamp ${timestamp} expired or outside acceptable window (skew: ${ageMs}ms)`;
    super(msg, "AGENT_TIMESTAMP_EXPIRED", { timestamp, ageMs });
    this.name = "AgentTimestampExpiredError";
    this.timestamp = timestamp;
    this.ageMs = ageMs;
  }
}

/**
 * Raised when an RPC or Soroban smart contract simulation/read fails.
 */
export class ContractReadError extends AgentGuardError {
  public readonly causeError?: Error;

  constructor(message: string, cause?: Error, details?: Record<string, unknown>) {
    super(message, "CONTRACT_READ_ERROR", { ...details, cause: cause?.message });
    this.name = "ContractReadError";
    this.causeError = cause;
  }
}

/**
 * Raised when all automatic retries against the Soroban RPC are exhausted.
 */
export class NetworkRetryExhaustedError extends AgentGuardError {
  public readonly attempts: number;

  constructor(message: string, attempts: number, cause?: Error) {
    super(
      `Network operation failed after ${attempts} attempts: ${message}`,
      "NETWORK_RETRY_EXHAUSTED",
      { attempts, cause: cause?.message }
    );
    this.name = "NetworkRetryExhaustedError";
    this.attempts = attempts;
  }
}

/**
 * Raised when an agent request lacks required credentials or authentication headers.
 */
export class AgentUnauthorizedError extends AgentGuardError {
  constructor(message: string = "Agent authentication required", details?: Record<string, unknown>) {
    super(message, "UNAUTHORIZED", details);
    this.name = "AgentUnauthorizedError";
  }
}

/**
 * Raised when an agent lacks the required role or permissions on-chain.
 */
export class AgentPermissionDeniedError extends AgentGuardError {
  public readonly agentId: string;
  public readonly requiredRole: string;
  public readonly resourceId?: string;

  constructor(agentId: string, requiredRole: string, resourceId?: string) {
    const resMsg = resourceId ? ` on resource "${resourceId}"` : "";
    super(
      `Agent ${agentId} is denied access. Required role: "${requiredRole}"${resMsg}`,
      "PERMISSION_DENIED",
      { agentId, requiredRole, resourceId }
    );
    this.name = "AgentPermissionDeniedError";
    this.agentId = agentId;
    this.requiredRole = requiredRole;
    this.resourceId = resourceId;
  }
}
