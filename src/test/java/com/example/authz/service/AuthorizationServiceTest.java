package com.example.authz.service;

import com.example.authz.config.AuthzProperties;
import com.example.authz.config.CasbinConfig;
import com.example.authz.model.AllowedActions;
import com.example.authz.model.AuthorizationDecision;
import com.example.authz.model.Decision;
import com.example.authz.model.PolicyRule;
import com.example.authz.model.RolePermissions;
import org.casbin.jcasbin.main.Enforcer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationServiceTest {

    private static AuthorizationService service;

    @BeforeAll
    static void setUp() throws Exception {
        AuthzProperties props = new AuthzProperties(
                new AuthzProperties.Casbin(
                        new ClassPathResource("casbin/model.conf"),
                        new ClassPathResource("casbin/policy.csv")),
                List.of("document", "report", "invoice", "user", "audit-log"),
                List.of("read", "write", "delete", "approve"));
        Enforcer enforcer = new CasbinConfig().enforcer(props);
        service = new AuthorizationService(enforcer, props);
    }

    @Test
    void viewerCanReadButNotWriteDocuments() {
        assertEquals(Decision.ALLOW, service.check("carol", Set.of("viewer"), "document", "read").decision());
        assertEquals(Decision.DENY, service.check("carol", Set.of("viewer"), "document", "write").decision());
    }

    @Test
    void editorInheritsViewerPolicies() {
        AuthorizationDecision d = service.check("bob", Set.of("editor"), "report", "read");
        assertEquals(Decision.ALLOW, d.decision());
        assertTrue(d.decidingPolicies().contains(new PolicyRule("viewer", "report", "read", "allow")));
        assertTrue(d.roleEvaluations().get(0).inheritedRoles().contains("viewer"));
    }

    @Test
    void adminWildcardMatchesEverything() {
        assertEquals(Decision.ALLOW, service.check("alice", Set.of("admin"), "anything", "purge").decision());
    }

    @Test
    void denyFromOneRoleOverridesAllowFromAnother() {
        // auditor allows report/read, contractor explicitly denies it
        AuthorizationDecision d = service.check("dave", Set.of("auditor", "contractor"), "report", "read");
        assertEquals(Decision.DENY, d.decision());
        assertTrue(d.decidingPolicies().stream().allMatch(PolicyRule::isDeny));
    }

    @Test
    void allowedActionsUsesKnownActionVocabulary() {
        AllowedActions a = service.allowedActions("bob", Set.of("editor"), "document");
        assertEquals(List.of("read", "write"), a.actions());
        assertTrue(a.actionPatterns().contains("(read|write)"));
    }

    @Test
    void allowedResourcesForViewer() {
        assertEquals(List.of("document", "report"),
                service.allowedResources("carol", Set.of("viewer")).resources());
    }

    @Test
    void permissionsForRolesFlagsUnknownRole() {
        List<RolePermissions> result = service.permissionsForRoles(List.of("approver", "ghost"));
        RolePermissions approver = result.get(0);
        assertTrue(approver.known());
        assertTrue(approver.inheritedRoles().contains("viewer"));
        assertTrue(approver.permissions().stream()
                .anyMatch(p -> p.resource().equals("invoice") && p.action().equals("approve")));
        assertFalse(result.get(1).known());
    }

    @Test
    void policyListingContainsRoleLinks() {
        assertEquals(12, service.policies().policies().size());
        assertEquals(3, service.policies().roleLinks().size());
    }
}
