package com.example.authz.model;

import java.util.List;

/**
 * One Casbin "p" rule: (role, resource-pattern, action-pattern, effect).
 */
public record PolicyRule(String role, String resource, String action, String effect) {

    public static final String ALLOW = "allow";
    public static final String DENY = "deny";

    public static PolicyRule fromTokens(List<String> tokens) {
        if (tokens.size() < 3) {
            throw new IllegalStateException("Malformed policy rule: " + tokens);
        }
        String effect = tokens.size() > 3 && !tokens.get(3).isBlank() ? tokens.get(3) : ALLOW;
        return new PolicyRule(tokens.get(0), tokens.get(1), tokens.get(2), effect);
    }

    public boolean isAllow() {
        return ALLOW.equalsIgnoreCase(effect);
    }

    public boolean isDeny() {
        return DENY.equalsIgnoreCase(effect);
    }
}
