package com.example.authz.model;

import java.util.List;

/**
 * Endpoint 5 payload, one entry per requested role.
 *
 * @param known          false when the role appears in neither "p" nor "g" rules
 * @param inheritedRoles roles reachable through the role hierarchy
 * @param permissions    effective (resource, action, effect) triples; {@code grantedBy}
 *                       tells which role in the hierarchy actually owns the rule
 */
public record RolePermissions(String role,
                              boolean known,
                              List<String> inheritedRoles,
                              List<Permission> permissions) {

    public record Permission(String resource, String action, String effect, String grantedBy) {
        public static Permission of(PolicyRule rule) {
            return new Permission(rule.resource(), rule.action(), rule.effect(), rule.role());
        }
    }
}
