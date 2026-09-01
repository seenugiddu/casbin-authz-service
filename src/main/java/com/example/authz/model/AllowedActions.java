package com.example.authz.model;

import java.util.List;

/**
 * Endpoint 3 payload.
 *
 * @param actions        concrete actions (from authz.known-actions) allowed on the resource
 * @param actionPatterns raw action patterns from matching allow-policies
 * @param deniedActions  concrete actions explicitly denied on the resource
 */
public record AllowedActions(String principal,
                             List<String> roles,
                             String resource,
                             List<String> actions,
                             List<String> actionPatterns,
                             List<String> deniedActions) {
}
