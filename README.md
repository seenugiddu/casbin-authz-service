# casbin-authz-service

A Spring Boot 3.5 micro-service that acts as a **policy decision point** (PDP) using
[jCasbin](https://github.com/casbin/jcasbin). Policies are written against **roles**;
the roles of the authenticated caller are taken from Spring Security and evaluated
against the Casbin RBAC model.

```
Client ──HTTP Basic──▶ Spring Security (authentication, ROLE_* authorities)
                              │
                              ▼
                     AuthorizationService  ──▶  jCasbin Enforcer (model.conf + policy.csv)
                              │
                              ▼
                     JSON decision / listings
```

## Run

```bash
mvn spring-boot:run
# or
mvn package && java -jar target/casbin-authz-service-0.1.0.jar
```

Sample users (password is `password` for all):

| user  | Spring roles          | Casbin subjects        |
|-------|-----------------------|------------------------|
| alice | ADMIN                 | admin (→ editor → viewer) |
| bob   | EDITOR                | editor (→ viewer)      |
| carol | VIEWER                | viewer                 |
| dave  | AUDITOR, CONTRACTOR   | auditor, contractor    |
| erin  | APPROVER              | approver (→ viewer)    |

`ROLE_ADMIN` is mapped to the Casbin subject `admin` (prefix stripped, lower-cased) by
`RoleExtractor`. Replace the in-memory `UserDetailsService` in `SecurityConfig` with your
real identity provider; nothing else needs to change as long as authorities are `ROLE_*`.

## Endpoints (all under `/api/authz`, all require authentication)

| # | Method & path | Purpose |
|---|---------------|---------|
| 1 | `POST /check` | Allow/deny for the caller + the policies that decided it |
| 2 | `GET /resources` | Resources the caller may access |
| 3 | `GET /actions?resource=document` | Actions the caller may perform on a resource |
| 4 | `GET /policies` | All `p` rules and `g` role links |
| 5 | `POST /roles/permissions` / `GET /roles/permissions?roles=a,b` | Resources + actions (with inheritance) for any list of roles |

### 1. Decision

```bash
curl -u dave:password -H 'Content-Type: application/json' \
  -d '{"resource":"report","action":"read"}' localhost:8080/api/authz/check
```

```json
{
  "principal": "dave",
  "roles": ["auditor", "contractor"],
  "resource": "report",
  "action": "read",
  "decision": "DENY",
  "reason": "Explicit deny policy matched and overrides 1 allow policy(ies)",
  "decidingPolicies": [
    { "role": "contractor", "resource": "report", "action": "read", "effect": "deny" }
  ],
  "roleEvaluations": [
    { "role": "auditor", "inheritedRoles": [], "decision": "ALLOW",
      "matchedPolicies": [ { "role": "auditor", "resource": "report", "action": "read", "effect": "allow" } ] },
    { "role": "contractor", "inheritedRoles": [], "decision": "DENY",
      "matchedPolicies": [ { "role": "contractor", "resource": "report", "action": "read", "effect": "deny" } ] }
  ]
}
```

Multi-role semantics are exactly the model's policy effect
`some(allow) && !some(deny)` applied across the union of the caller's roles.

### 2. Allowed resources

```bash
curl -u carol:password localhost:8080/api/authz/resources
```

```json
{ "principal": "carol", "roles": ["viewer"],
  "resources": ["document", "report"],
  "resourcePatterns": ["document", "report"] }
```

`resources` is computed by evaluating every entry of `authz.known-resources` ×
`authz.known-actions` through the enforcer, so wildcard policies such as `admin, *, .*`
resolve to concrete names. `resourcePatterns` is the raw pattern list from the policies.

### 3. Allowed actions

```bash
curl -u bob:password 'localhost:8080/api/authz/actions?resource=document'
```

```json
{ "principal": "bob", "roles": ["editor"], "resource": "document",
  "actions": ["read", "write"],
  "actionPatterns": ["(read|write)", "read"],
  "deniedActions": [] }
```

### 4. Policies

```bash
curl -u alice:password localhost:8080/api/authz/policies
```

Returns `{ "policies": [ {role, resource, action, effect}, ... ], "roleLinks": [ {role, inheritsFrom}, ... ] }`.

### 5. Permissions for a list of roles

```bash
curl -u alice:password -H 'Content-Type: application/json' \
  -d '{"roles":["approver","ghost"]}' localhost:8080/api/authz/roles/permissions
# or
curl -u alice:password 'localhost:8080/api/authz/roles/permissions?roles=approver,ghost'
```

```json
[
  { "role": "approver", "known": true, "inheritedRoles": ["viewer"],
    "permissions": [
      { "resource": "invoice",  "action": "approve", "effect": "allow", "grantedBy": "approver" },
      { "resource": "document", "action": "read",    "effect": "allow", "grantedBy": "viewer" },
      { "resource": "report",   "action": "read",    "effect": "allow", "grantedBy": "viewer" } ] },
  { "role": "ghost", "known": false, "inheritedRoles": [], "permissions": [] }
]
```

## Policy model

`src/main/resources/casbin/model.conf`

* request `(sub, obj, act)` – `sub` is a **role**
* policy `(sub, obj, act, eft)` – `eft` is `allow` or `deny`
* `g, child, parent` – role inheritance
* matcher: `g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)`
* effect: allowed if any `allow` matches and no `deny` matches

`src/main/resources/casbin/policy.csv` holds the sample rules. Point `authz.casbin.policy`
at `file:/etc/authz/policy.csv` to externalise it, or swap the `FileAdapter` in
`CasbinConfig` for a database adapter (`org.casbin:jdbc-adapter`) – the service code
only talks to the `Enforcer`.

`authz.known-resources` / `authz.known-actions` are the vocabulary used to expand
wildcard/regex patterns into concrete lists for endpoints 2 and 3.

## Notes

* Built against Spring Boot 3.5.16 (last 3.x line) and jCasbin 1.99.0. To move to Spring
  Boot 4.x, rename `spring-boot-starter-web` to `spring-boot-starter-webmvc`.
* `mvn test` runs `AuthorizationServiceTest`, which covers inheritance, wildcards,
  cross-role deny override and the listing endpoints.
