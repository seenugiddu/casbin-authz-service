package com.example.authz.service;

import com.example.authz.config.AuthzProperties;
import com.example.authz.model.AllowedActions;
import com.example.authz.model.AllowedResources;
import com.example.authz.model.AuthorizationDecision;
import com.example.authz.model.Decision;
import com.example.authz.model.PolicyRule;
import com.example.authz.model.PolicySet;
import com.example.authz.model.RoleEvaluation;
import com.example.authz.model.RoleLink;
import com.example.authz.model.RolePermissions;
import org.casbin.jcasbin.main.Enforcer;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Policy decision point backed by jCasbin.
 *
 * <p>Casbin requests are made with the <em>role</em> as subject, so the caller's
 * identity never has to be present in the policy store. A caller with several roles is
 * evaluated with exactly the semantics of the model's policy effect
 * {@code some(allow) && !some(deny)} applied across all of those roles: one matching
 * allow from any role grants access unless any role carries a matching deny.</p>
 */
@Service
public class AuthorizationService {

    private final Enforcer enforcer;
    private final List<String> knownResources;
    private final List<String> knownActions;

    public AuthorizationService(Enforcer enforcer, AuthzProperties properties) {
        this.enforcer = enforcer;
        this.knownResources = properties.knownResources();
        this.knownActions = properties.knownActions();
    }

    // ------------------------------------------------------------------ 1. allow / deny

    public AuthorizationDecision check(String principal, Collection<String> roles,
                                       String resource, String action) {
        List<RoleEvaluation> evaluations = roles.stream()
                .map(role -> evaluateRole(role, resource, action))
                .toList();

        List<PolicyRule> allows = evaluations.stream()
                .flatMap(e -> e.matchedPolicies().stream())
                .filter(PolicyRule::isAllow)
                .distinct()
                .toList();
        List<PolicyRule> denies = evaluations.stream()
                .flatMap(e -> e.matchedPolicies().stream())
                .filter(PolicyRule::isDeny)
                .distinct()
                .toList();

        boolean anyRoleAllowed = evaluations.stream().anyMatch(e -> e.decision() == Decision.ALLOW);
        boolean allowed = anyRoleAllowed && denies.isEmpty();

        Decision decision = allowed ? Decision.ALLOW : Decision.DENY;
        String reason;
        List<PolicyRule> deciding;
        if (allowed) {
            reason = "Allowed by " + allows.size() + " matching allow policy(ies)";
            deciding = allows;
        } else if (!denies.isEmpty()) {
            reason = "Explicit deny policy matched"
                    + (allows.isEmpty() ? "" : " and overrides " + allows.size() + " allow policy(ies)");
            deciding = denies;
        } else {
            reason = "No policy grants '" + action + "' on '" + resource + "' for roles " + roles;
            deciding = List.of();
        }

        return new AuthorizationDecision(principal, List.copyOf(roles), resource, action,
                decision, reason, deciding, evaluations);
    }

    private RoleEvaluation evaluateRole(String role, String resource, String action) {
        boolean allowed = enforcer.enforce(role, resource, action);
        List<PolicyRule> matched = effectivePolicies(role).stream()
                .filter(rule -> matches(rule, resource, action))
                .toList();
        return new RoleEvaluation(role, inheritedRoles(role),
                allowed ? Decision.ALLOW : Decision.DENY, matched);
    }

    /** Plain boolean helper used by the resources / actions endpoints. */
    private boolean isAllowed(Collection<String> roles, String resource, String action) {
        return check("-", roles, resource, action).decision() == Decision.ALLOW;
    }

    // ------------------------------------------------------------------ 2. allowed resources

    public AllowedResources allowedResources(String principal, Collection<String> roles) {
        List<String> concrete = knownResources.stream()
                .filter(res -> knownActions.stream().anyMatch(act -> isAllowed(roles, res, act)))
                .toList();

        Set<String> patterns = new TreeSet<>();
        for (String role : roles) {
            effectivePolicies(role).stream()
                    .filter(PolicyRule::isAllow)
                    .map(PolicyRule::resource)
                    .forEach(patterns::add);
        }
        return new AllowedResources(principal, List.copyOf(roles), concrete, List.copyOf(patterns));
    }

    // ------------------------------------------------------------------ 3. allowed actions

    public AllowedActions allowedActions(String principal, Collection<String> roles, String resource) {
        List<String> allowed = new ArrayList<>();
        List<String> denied = new ArrayList<>();
        for (String act : knownActions) {
            AuthorizationDecision d = check(principal, roles, resource, act);
            if (d.decision() == Decision.ALLOW) {
                allowed.add(act);
            } else if (d.decidingPolicies().stream().anyMatch(PolicyRule::isDeny)) {
                denied.add(act);
            }
        }

        Set<String> patterns = new TreeSet<>();
        for (String role : roles) {
            effectivePolicies(role).stream()
                    .filter(PolicyRule::isAllow)
                    .filter(rule -> BuiltInFunctions.keyMatch(resource, rule.resource()))
                    .map(PolicyRule::action)
                    .forEach(patterns::add);
        }
        return new AllowedActions(principal, List.copyOf(roles), resource,
                allowed, List.copyOf(patterns), denied);
    }

    // ------------------------------------------------------------------ 4. policy listing

    public PolicySet policies() {
        List<PolicyRule> rules = enforcer.getPolicy().stream()
                .map(PolicyRule::fromTokens)
                .toList();
        List<RoleLink> links = enforcer.getGroupingPolicy().stream()
                .map(g -> new RoleLink(g.get(0), g.get(1)))
                .toList();
        return new PolicySet(rules, links);
    }

    // ------------------------------------------------------------------ 5. permissions per role

    public List<RolePermissions> permissionsForRoles(Collection<String> roles) {
        return roles.stream().map(this::permissionsForRole).toList();
    }

    public RolePermissions permissionsForRole(String role) {
        List<String> inherited = inheritedRoles(role);
        List<RolePermissions.Permission> permissions = effectivePolicies(role).stream()
                .map(RolePermissions.Permission::of)
                .toList();
        boolean known = !permissions.isEmpty() || !inherited.isEmpty()
                || enforcer.getAllSubjects().contains(role)
                || enforcer.getAllRoles().contains(role);
        return new RolePermissions(role, known, inherited, permissions);
    }

    // ------------------------------------------------------------------ helpers

    /** All "p" rules the role holds directly or through the role hierarchy. */
    private List<PolicyRule> effectivePolicies(String role) {
        Set<PolicyRule> rules = new LinkedHashSet<>();
        enforcer.getImplicitPermissionsForUser(role).stream()
                .map(PolicyRule::fromTokens)
                .forEach(rules::add);
        return List.copyOf(rules);
    }

    private List<String> inheritedRoles(String role) {
        return List.copyOf(enforcer.getImplicitRolesForUser(role));
    }

    /**
     * Mirrors the [matchers] section of model.conf (minus the g() role check, which
     * {@link #effectivePolicies} already accounts for). Keep the two in sync.
     */
    private boolean matches(PolicyRule rule, String resource, String action) {
        return BuiltInFunctions.keyMatch(resource, rule.resource())
                && BuiltInFunctions.regexMatch(action, rule.action());
    }
}
