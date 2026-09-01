package com.example.authz.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.util.List;

/**
 * Binds the {@code authz.*} block of application.yml.
 */
@ConfigurationProperties(prefix = "authz")
public record AuthzProperties(Casbin casbin,
                              List<String> knownResources,
                              List<String> knownActions) {

    public AuthzProperties {
        knownResources = knownResources == null ? List.of() : List.copyOf(knownResources);
        knownActions = knownActions == null ? List.of() : List.copyOf(knownActions);
    }

    public record Casbin(Resource model, Resource policy) {
    }
}
