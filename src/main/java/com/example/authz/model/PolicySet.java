package com.example.authz.model;

import java.util.List;

/**
 * Endpoint 4 payload: everything currently loaded in the enforcer.
 */
public record PolicySet(List<PolicyRule> policies, List<RoleLink> roleLinks) {
}
