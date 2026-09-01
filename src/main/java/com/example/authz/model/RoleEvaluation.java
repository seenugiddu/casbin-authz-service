package com.example.authz.model;

import java.util.List;

/**
 * Result of enforcing one (resource, action) request against a single role.
 *
 * @param role            role that was evaluated
 * @param inheritedRoles  roles this role transitively inherits via "g" rules
 * @param decision        Casbin's verdict for this role alone
 * @param matchedPolicies every policy (own or inherited) whose resource/action patterns
 *                        matched the request, regardless of effect
 */
public record RoleEvaluation(String role,
                             List<String> inheritedRoles,
                             Decision decision,
                             List<PolicyRule> matchedPolicies) {
}
