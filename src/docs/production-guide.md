# Production Guide

This guide shows how to use FastAPI RBAC Engine in a production FastAPI API server.
It covers package wiring, database setup, token handling, permission design,
route protection, audit logging, caching, Docker deployment, and operational checks.

## 1. Install the Package

Install the core package in your application environment:

```bash
pip install kb-fastapi-rbac
```

For Redis-backed caching, install the Redis extra:

```bash
pip install "kb-fastapi-rbac[redis]"
```

For identity providers:

```bash
pip install "kb-fastapi-rbac[ldap,keycloak]"
```

## 2. Configure Environment Variables

Keep secrets and infrastructure URLs outside your source code.

```env
DATABASE_URL=postgresql://rbac_user:strong-password@postgres:5432/app_db
REDIS_URL=redis://redis:6379/0
RBAC_SECRET_KEY=replace-with-a-long-random-secret
RBAC_JWT_ALGORITHM=HS256
```

Use a secret manager in production. Examples include AWS Secrets Manager,
GCP Secret Manager, Azure Key Vault, Doppler, Vault, or your orchestrator's
native secret store.

## 3. Initialize the Database Layer

Create the RBAC services during FastAPI startup and close the database connection
during shutdown.

```python
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from rbac import Database, PermissionService, RoleService, AssignmentService, AuditService
from rbac.dependencies.auth import RBACDependencies


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = Database(os.environ["DATABASE_URL"], min_size=5, max_size=20)
    await db.connect()

    permission_service = PermissionService(db)
    role_service = RoleService(db, permission_service)
    assignment_service = AssignmentService(db, role_service, permission_service)
    audit_service = AuditService(db, retention_days=180)

    await role_service.initialize_default_roles()

    app.state.db = db
    app.state.permission_service = permission_service
    app.state.role_service = role_service
    app.state.assignment_service = assignment_service
    app.state.audit_service = audit_service
    app.state.rbac = RBACDependencies(
        permission_service=permission_service,
        assignment_service=assignment_service,
        secret_key=os.environ["RBAC_SECRET_KEY"],
        algorithm=os.getenv("RBAC_JWT_ALGORITHM", "HS256"),
    )

    yield

    await db.disconnect()


app = FastAPI(lifespan=lifespan)
```

The package creates its RBAC tables through SQLAlchemy metadata when `connect()`
runs. In larger systems, you may prefer managing the same schema with Alembic
migrations so schema changes are reviewed and deployed explicitly.

## 4. Design Permissions

Permissions use this format:

```text
resource:action
resource:action:scope
```

Good production examples:

```text
invoice:read
invoice:create
invoice:update
invoice:approve
tenant:manage
user:read:self
```

Use `*:*` only for trusted platform administrators. For normal roles, prefer
small explicit permissions.

Create permissions during a seed step:

```python
from rbac import ResourceType, PermissionAction

await permission_service.create_permission(
    name="Read users",
    resource=ResourceType.USER,
    action=PermissionAction.READ,
    tenant_id=tenant_id,
)
```

If your app has resources beyond the built-in enum, extend the package enum or
centralize permission creation in your application so the permission vocabulary
stays consistent.

## 5. Create Roles and Assign Permissions

Roles collect permissions. Roles can inherit from parent roles.

```python
viewer = await role_service.create_role(
    name="Viewer",
    description="Read-only access",
    tenant_id=tenant_id,
)

manager = await role_service.create_role(
    name="Manager",
    description="Can manage users",
    parent_ids=[viewer.id],
    tenant_id=tenant_id,
)

read_users = await permission_service.get_permission_by_string("user:read", tenant_id)
update_users = await permission_service.get_permission_by_string("user:update", tenant_id)

await permission_service.grant_permission_to_role(viewer.id, read_users.id)
await permission_service.grant_permission_to_role(manager.id, update_users.id)
```

## 6. Assign Roles to Users

The package does not own your user table. It stores role assignments against
external user UUIDs from your application or identity provider.

```python
await assignment_service.assign_role_to_user(
    user_id=current_admin_id,
    role_id=manager.id,
    tenant_id=tenant_id,
    granted_by=platform_admin_id,
)
```

Temporary access:

```python
await assignment_service.assign_role_to_user(
    user_id=contractor_id,
    role_id=viewer.id,
    tenant_id=tenant_id,
    expires_in_days=30,
)
```

Resource-scoped access:

```python
await assignment_service.assign_role_to_user(
    user_id=doctor_id,
    role_id=patient_viewer_role.id,
    tenant_id=tenant_id,
    resource_scope={"patient_id": "patient-123"},
)
```

## 7. Authenticate Users

Your application remains responsible for login, password policy, SSO, MFA, and
JWT issuance. The RBAC dependency reads a JWT where `sub` is the user UUID and
`tenant_id` is optional.

Example token payload:

```json
{
  "sub": "2de0f3b0-2b0b-4e34-b561-7d86e2747cab",
  "tenant_id": "65f3b551-d56a-4db4-9f09-bf7644fbe431",
  "metadata": {
    "username": "sara",
    "email": "sara@example.com"
  }
}
```

Use short JWT lifetimes, rotate signing secrets carefully, and clear RBAC caches
when roles or permissions change.

## 8. Protect Routes

Use FastAPI dependencies for enforcement. The cleanest production pattern is to
build routers from a configured `RBACDependencies` instance:

```python
from fastapi import APIRouter, Depends
from rbac.dependencies.auth import RBACDependencies, UserContext


def build_user_router(rbac: RBACDependencies) -> APIRouter:
    router = APIRouter(prefix="/users", tags=["users"])

    require_user_read = rbac.require_permissions(["user:read"])
    require_user_update = rbac.require_permissions(["user:update"])

    @router.get("")
    async def list_users(
        current_user: UserContext = Depends(require_user_read),
    ):
        return []

    @router.patch("/{user_id}")
    async def update_user(
        user_id: str,
        current_user: UserContext = Depends(require_user_update),
    ):
        return {"user_id": user_id}

    return router
```

Then include the router after constructing the RBAC services:

```python
app.include_router(build_user_router(app.state.rbac))
```

For path-scoped checks:

```python
def build_patient_router(rbac: RBACDependencies) -> APIRouter:
    router = APIRouter(prefix="/patients", tags=["patients"])

    require_patient_read = rbac.require_permissions(
        ["patient:read"],
        resource_scope_param="patient_id",
    )

    @router.get("/{patient_id}")
    async def get_patient(
        patient_id: str,
        current_user: UserContext = Depends(require_patient_read),
    ):
        return {"patient_id": patient_id}

    return router
```

If you must build routes before startup, create a small dependency module that is
initialized by your application factory:

```python
from fastapi import Depends
from rbac.dependencies.auth import RBACDependencies

rbac: RBACDependencies | None = None


def configure_rbac(value: RBACDependencies) -> None:
    global rbac
    rbac = value


def require_patient_read():
    if rbac is None:
        raise RuntimeError("RBAC has not been configured")
    return rbac.require_permissions(
            ["patient:read"],
            resource_scope_param="patient_id",
    )
```

## 9. Add Middleware

Add audit middleware after your authentication/RBAC middleware has populated
`request.state.user`.

```python
from rbac.middleware.audit import AuditMiddleware

app.add_middleware(
    AuditMiddleware,
    audit_service=app.state.audit_service,
    exclude_paths=["/health", "/metrics", "/docs", "/openapi.json"],
)
```

If middleware needs startup-created services, register it inside the lifespan
setup or use a small custom middleware that reads from `request.app.state`.

## 10. Enable Redis Caching

Redis is optional, but recommended for high-volume permission checks.

```python
from rbac.cache import (
    RedisCache,
    RedisCachedPermissionService,
    RedisCachedRoleService,
    RedisCachedAssignmentService,
    CacheManager,
)

redis_cache = RedisCache(os.environ["REDIS_URL"], prefix="myapp:rbac:")
await redis_cache.initialize()

permission_service = RedisCachedPermissionService(permission_service, redis_cache)
role_service = RedisCachedRoleService(role_service, redis_cache)
assignment_service = RedisCachedAssignmentService(assignment_service, redis_cache)
cache_manager = CacheManager(redis_cache, permission_service, role_service, assignment_service)
```

Invalidate caches after admin changes:

```python
await cache_manager.invalidate_user(user_id, tenant_id)
await cache_manager.invalidate_role(role_id)
await cache_manager.invalidate_tenant(tenant_id)
```

## 11. Audit Important Events

Use the audit service for compliance-sensitive actions:

```python
from rbac.services.audit_service import AuditAction, AuditResourceType

await audit_service.log_action(
    user_id=current_user.id,
    tenant_id=current_user.tenant_id,
    action=AuditAction.PERMISSION_CHANGE,
    resource_type=AuditResourceType.PERMISSION,
    resource_id=permission_id,
    description="Granted invoice approval permission",
)
```

Operational recommendations:

- Keep audit retention aligned with compliance requirements.
- Export old logs to object storage before cleanup.
- Avoid logging secrets, tokens, or sensitive request bodies.
- Include request IDs so logs can be correlated with API traces.

## 12. Docker Deployment

The repository includes a `Dockerfile`, `docker-compose.yml`, and `.env`.

Run the example API:

```bash
docker compose up app
```

Run tests with Dockerized PostgreSQL and Redis:

```bash
docker compose run --rm test
```

The Compose file reads:

```env
POSTGRES_IMAGE=postgres:15-alpine
POSTGRES_DB=rbac
POSTGRES_TEST_DB=rbac_test
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_PORT=5432
REDIS_IMAGE=redis:7-alpine
REDIS_PORT=6379
APP_PORT=8000
SECRET_KEY=development-secret-key-change-in-production
```

For production, replace local passwords, do not expose Postgres publicly, and use
managed persistent volumes or a managed database service.

## 13. Production Server Checklist

- Use HTTPS at the ingress or load balancer.
- Use strong JWT secrets or asymmetric signing keys.
- Keep JWT lifetimes short and rotate signing keys.
- Enforce tenant isolation in every application query, not only RBAC checks.
- Seed permissions and roles idempotently during deploys.
- Run database migrations before app rollout.
- Enable Redis for permission-heavy APIs.
- Emit audit logs for role, permission, tenant, and assignment changes.
- Monitor permission check latency, denied access rate, database pool usage, and Redis hit rate.
- Back up the RBAC database tables.
- Keep admin endpoints behind additional controls such as MFA or trusted networks.

## 14. Common Production Pattern

Most production apps use this layout:

```text
app/
  main.py
  core/config.py
  auth/jwt.py
  rbac/bootstrap.py
  rbac/dependencies.py
  routers/admin.py
  routers/users.py
```

Put package initialization in `rbac/bootstrap.py`, dependency factories in
`rbac/dependencies.py`, and keep route modules focused on business logic.

## 15. Troubleshooting

If every permission check fails:

- Confirm `sub` in the JWT is a UUID.
- Confirm `tenant_id` in the token matches the assignment tenant.
- Confirm the role is active and the assignment is active.
- Confirm the assignment is not expired.
- Confirm the required permission string matches the stored permission.

If tests fail locally but pass in Docker:

- Check local PostgreSQL credentials.
- Check that `TEST_DATABASE_URL` points at a disposable test database.
- Check that Redis is running if Redis tests are enabled.

If Docker tests cannot start:

- Confirm `POSTGRES_IMAGE` in `.env` exists locally or can be pulled.
- Run `docker images postgres` to inspect cached PostgreSQL images.
- Run `docker compose config` to verify the final environment.
