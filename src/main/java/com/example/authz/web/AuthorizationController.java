package com.example.authz.web;

import com.example.authz.model.AllowedActions;
import com.example.authz.model.AllowedResources;
import com.example.authz.model.AuthorizationDecision;
import com.example.authz.model.PolicySet;
import com.example.authz.model.RolePermissions;
import com.example.authz.service.AuthorizationService;
import com.example.authz.service.RoleExtractor;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/authz")
public class AuthorizationController {

    private final AuthorizationService service;

    public AuthorizationController(AuthorizationService service) {
        this.service = service;
    }

    /** 1. Allow / deny for the authenticated user, with the policies that decided it. */
    @PostMapping("/check")
    public AuthorizationDecision check(@Valid @RequestBody CheckRequest request, Authentication auth) {
        return service.check(auth.getName(), RoleExtractor.rolesOf(auth),
                request.resource().trim(), request.action().trim());
    }

    /** 2. Resources the authenticated user may access (at least one action allowed). */
    @GetMapping("/resources")
    public AllowedResources resources(Authentication auth) {
        return service.allowedResources(auth.getName(), RoleExtractor.rolesOf(auth));
    }

    /** 3. Actions the authenticated user may perform on a resource. */
    @GetMapping("/actions")
    public AllowedActions actions(@RequestParam String resource, Authentication auth) {
        if (resource.isBlank()) {
            throw new IllegalArgumentException("'resource' must not be blank");
        }
        return service.allowedActions(auth.getName(), RoleExtractor.rolesOf(auth), resource.trim());
    }

    /** 4. Every policy and role link currently loaded. */
    @GetMapping("/policies")
    public PolicySet policies() {
        return service.policies();
    }

    /** 5. Resources + actions for an arbitrary list of roles (POST body). */
    @PostMapping("/roles/permissions")
    public List<RolePermissions> rolePermissions(@Valid @RequestBody RolesRequest request) {
        return service.permissionsForRoles(normalize(request.roles()));
    }

    /** 5. Same as above via query string: {@code ?roles=admin,auditor}. */
    @GetMapping("/roles/permissions")
    public List<RolePermissions> rolePermissions(@RequestParam List<String> roles) {
        Set<String> normalized = normalize(roles);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("'roles' must contain at least one role");
        }
        return service.permissionsForRoles(normalized);
    }

    private static Set<String> normalize(List<String> roles) {
        return roles.stream()
                .filter(r -> r != null && !r.isBlank())
                .map(RoleExtractor::normalize)
                .collect(Collectors.toCollection(TreeSet::new));
    }
}
