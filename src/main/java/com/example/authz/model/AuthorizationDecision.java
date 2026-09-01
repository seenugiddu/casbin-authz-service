package com.example.authz.model;

import java.util.List;

/**
 * Endpoint 1 payload: final decision plus the policy information that produced it.
 *
 * @param decision        ALLOW if at least one of the caller's roles is allowed
 * @param reason          human-readable explanation
 * @param decidingPolicies the policies that decided the outcome: the matching allow rules
 *                        for an ALLOW, or the matching deny rules for a DENY
 * @param roleEvaluations per-role breakdown for auditing / debugging
 */
public record AuthorizationDecision(String principal,
                                    List<String> roles,
                                    String resource,
                                    String action,
                                    Decision decision,
                                    String reason,
                                    List<PolicyRule> decidingPolicies,
                                    List<RoleEvaluation> roleEvaluations) {
}
