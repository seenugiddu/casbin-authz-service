package com.example.authz.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Maps Spring Security authorities to Casbin role names.
 * {@code ROLE_ADMIN} becomes {@code admin}, matching the subjects used in policy.csv.
 */
public final class RoleExtractor {

    private static final String PREFIX = "ROLE_";

    private RoleExtractor() {
    }

    public static Set<String> rolesOf(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith(PREFIX))
                .map(RoleExtractor::normalize)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    public static String normalize(String authorityOrRole) {
        String r = authorityOrRole.trim();
        if (r.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            r = r.substring(PREFIX.length());
        }
        return r.toLowerCase(Locale.ROOT);
    }
}
