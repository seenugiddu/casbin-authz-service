package com.example.authz.model;

import java.util.List;

/**
 * Endpoint 2 payload.
 *
 * @param resources        concrete resources (from authz.known-resources) for which at least
 *                         one action is allowed
 * @param resourcePatterns raw resource patterns from every allow-policy the roles hold
 */
public record AllowedResources(String principal,
                               List<String> roles,
                               List<String> resources,
                               List<String> resourcePatterns) {
}
