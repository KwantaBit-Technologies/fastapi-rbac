---
name: rbac-security-review
description: Security review checklist tailored to this FastAPI RBAC library. Use when reviewing changes to auth, permission/role decorators, token handling, LDAP/Keycloak integration, or password hashing — or when the user asks for a security review of authorization code.
---

# RBAC Security Review

This is a security library: its whole job is to correctly grant and deny access.
A subtle logic slip here becomes a privilege-escalation CVE in every downstream app.
Review with an adversary's mindset — assume the caller is hostile.

## Scope — files that carry authorization decisions

- `src/rbac/decorators/rbac.py` — `RBACDecorators.check_permissions`, `.check_roles`
- `src/rbac/dependencies/auth.py` — `require_permissions`, `require_roles`,
  `require_self_or_permission`, `public_route`, `RBACMiddleware`, `TokenPayload`, `UserContext`
- `src/rbac/services/permission_service.py`, `role_service.py`, `assignment_service.py`
- `src/rbac/integration/` — `ldap_provider.py`, `keycloak_provider.py`, `sync_service.py`
- `src/rbac/middleware/audit.py`

## Checklist

### Permission / role logic
- [ ] `require_all=True` vs `False` — confirm the AND/OR semantics match the intent. An OR where AND was meant grants access with a single low-privilege permission.
- [ ] Fail **closed**: any exception, missing user context, or unresolved permission must DENY, never fall through to allow.
- [ ] No permission check silently skipped when `permissions=[]` or `roles=[]` — an empty required set must not mean "allow everyone".
- [ ] Role/permission comparisons are exact (no substring/`in`-on-string matching that lets `admin` match `admin-readonly`).

### Tokens & identity
- [ ] JWT signature **and** expiry (`exp`), issuer, and audience are all verified — not just decoded. Reject `alg=none`.
- [ ] `TokenPayload`/`UserContext` fields come from verified claims, never from client-supplied headers/body.
- [ ] `require_self_or_permission` compares the authenticated subject to the target id using the token subject, not a request param that the caller controls.

### Multi-tenancy (IDOR)
- [ ] Every service query is scoped by tenant. A user in tenant A must not read/mutate tenant B's roles, permissions, or assignments.
- [ ] Object ids from the request are authorized against the caller's tenant before use.

### Secrets & crypto
- [ ] passlib/argon2 used for passwords — no plaintext, no fast hashes (md5/sha1), no home-rolled comparisons. Use constant-time verify.
- [ ] No secrets, tokens, or full DB URLs logged (check `audit.py` and `utils/logger.py`).
- [ ] LDAP binds sanitize the DN/filter (no LDAP injection); Keycloak tokens validated against the realm's keys.

### SQL & data access
- [ ] All asyncpg/SQLAlchemy queries are parameterized — no f-string/`%`-formatted SQL.

### Audit integrity
- [ ] Security-relevant events (grant, revoke, denied access, login) are audited, and audit failures don't swallow the underlying deny.

## Output
Report findings ranked by severity (privilege escalation / auth bypass first). For each: the file:line, the concrete exploit scenario (inputs → wrong grant), and the minimal fix. If nothing is found, say so plainly — don't invent issues.
