"use strict";
/**
 * Type definitions for AgentGuard TypeScript SDK.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentStatus = exports.ROLE_NAMES = exports.Role = void 0;
exports.parseRole = parseRole;
/**
 * Role hierarchy matching the on-chain Soroban contract:
 * Basic = 0 < Premium = 1 < Admin = 2
 */
var Role;
(function (Role) {
    Role[Role["Basic"] = 0] = "Basic";
    Role[Role["Premium"] = 1] = "Premium";
    Role[Role["Admin"] = 2] = "Admin";
})(Role || (exports.Role = Role = {}));
exports.ROLE_NAMES = {
    [Role.Basic]: "Basic",
    [Role.Premium]: "Premium",
    [Role.Admin]: "Admin",
};
/**
 * Parse a role string or enum into a canonical Role enum value.
 */
function parseRole(role) {
    if (typeof role === "number" && role in Role) {
        return role;
    }
    const normalized = String(role).trim().toLowerCase();
    switch (normalized) {
        case "basic":
        case "0":
            return Role.Basic;
        case "premium":
        case "1":
            return Role.Premium;
        case "admin":
        case "2":
            return Role.Admin;
        default:
            throw new Error(`Invalid role: "${role}". Must be one of: Basic, Premium, Admin.`);
    }
}
/**
 * On-chain operational status of an agent.
 */
var AgentStatus;
(function (AgentStatus) {
    AgentStatus[AgentStatus["Active"] = 0] = "Active";
    AgentStatus[AgentStatus["Suspended"] = 1] = "Suspended";
    AgentStatus[AgentStatus["Revoked"] = 2] = "Revoked";
})(AgentStatus || (exports.AgentStatus = AgentStatus = {}));
//# sourceMappingURL=types.js.map