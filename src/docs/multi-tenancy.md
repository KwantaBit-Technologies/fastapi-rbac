
### docs/multi-tenancy.md

```markdown
# Multi-tenancy Guide

This guide covers implementing multi-tenant support in your FastAPI RBAC application.

## Overview

Multi-tenancy allows a single RBAC instance to serve multiple independent organizations (tenants) with complete data isolation. Each tenant has:

- Isolated roles and permissions
- Separate user assignments
- Tenant-specific configuration
- Optional cross-tenant access for super admins

## Tenant Models

### Tenant Schema

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

Tenant Model
python
from pydantic import BaseModel
from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, Dict, Any

class Tenant(BaseModel):
    """Tenant model for multi-tenant support"""
    
    id: UUID = Field(default_factory=uuid4)
    name: str
    domain: Optional[str] = None
    is_active: bool = True
    settings: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        from_attributes = True
Tenant Management
Creating Tenants
python
from rbac.core.models import Tenant
from rbac.services.role_service import RoleService

async def create_tenant(
    name: str,
    domain: Optional[str] = None,
    settings: Optional[Dict] = None
) -> Tenant:
    """Create a new tenant with default roles"""
    
    # Insert tenant
    tenant_id = await db.fetch_one(
        """
        INSERT INTO tenants (name, domain, settings)
        VALUES ($1, $2, $3)
        RETURNING *
        """,
        name, domain, settings or {}
    )
    
    tenant = Tenant.model_validate(tenant_id)
    
    # Initialize default roles for this tenant
    await role_service.initialize_default_roles(tenant_id=tenant.id)
    
    return tenant

@app.post("/tenants", response_model=Tenant)
@require_roles(["super_admin"])
async def create_tenant_endpoint(
    name: str,
    domain: Optional[str] = None,
    settings: Optional[Dict] = None
):
    """Create a new tenant (super admin only)"""
    return await create_tenant(name, domain, settings)
Tenant Isolation
All RBAC operations are automatically tenant-isolated when a tenant_id is provided:

python
# Tenant-specific operations
roles = await role_service.list_roles(tenant_id=current_tenant.id)
permissions = await permission_service.list_permissions(tenant_id=current_tenant.id)
assignments = await assignment_service.get_user_assignments(
    user_id=user.id,
    tenant_id=current_tenant.id
)

# Global operations (system-wide)
system_roles = await role_service.list_roles(tenant_id=None)
system_permissions = await permission_service.list_permissions(tenant_id=None)
Tenant Resolution
Multiple Strategies for Tenant Identification
1. Subdomain-based
python
from fastapi import Request

async def get_tenant_from_subdomain(request: Request) -> Optional[Tenant]:
    """Extract tenant from subdomain"""
    host = request.headers.get("host", "")
    subdomain = host.split(".")[0] if "." in host else None
    
    if subdomain:
        result = await db.fetch_one(
            "SELECT * FROM tenants WHERE domain = $1 OR name = $1",
            subdomain
        )
        return Tenant.model_validate(result) if result else None
    
    return None

# Middleware to set tenant
@app.middleware("http")
async def tenant_middleware(request: Request, call_next):
    tenant = await get_tenant_from_subdomain(request)
    request.state.tenant = tenant
    response = await call_next(request)
    return response
2. Header-based
python
async def get_tenant_from_header(request: Request) -> Optional[Tenant]:
    """Extract tenant from X-Tenant-ID header"""
    tenant_id = request.headers.get("X-Tenant-ID")
    
    if tenant_id:
        result = await db.fetch_one(
            "SELECT * FROM tenants WHERE id = $1",
            UUID(tenant_id)
        )
        return Tenant.model_validate(result) if result else None
    
    return None
3. Path-based
python
@app.get("/api/{tenant_id}/users")
async def get_users(
    tenant_id: str,
    current_user = Depends(rbac.get_current_active_user)
):
    """Get users for specific tenant from path"""
    # Verify tenant exists and user has access
    tenant = await get_tenant(UUID(tenant_id))
    if not tenant:
        raise HTTPException(404, "Tenant not found")
    
    # Ensure user belongs to this tenant
    if current_user.tenant_id != UUID(tenant_id):
        raise HTTPException(403, "Access to this tenant denied")
    
    # Proceed with tenant-scoped operations
    users = await get_users_for_tenant(tenant_id)
    return users
4. JWT Claim-based
python
# Include tenant_id in JWT token
def create_access_token(data: dict, tenant_id: Optional[UUID] = None):
    to_encode = data.copy()
    if tenant_id:
        to_encode["tenant_id"] = str(tenant_id)
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Extract from token in RBAC dependencies
class RBACDependencies:
    async def get_current_user(self, token: str = Depends(oauth2_scheme)):
        payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        
        # Get user permissions for this tenant
        permissions = await self.permission_service.get_user_permissions(
            user_id=UUID(user_id),
            tenant_id=UUID(tenant_id) if tenant_id else None
        )
        
        return UserContext(
            id=UUID(user_id),
            tenant_id=UUID(tenant_id) if tenant_id else None,
            permissions=list(permissions)
        )
Tenant-Access Control
Tenant Isolation Middleware
python
from rbac.dependencies.auth import RBACMiddleware

# Add tenant-aware middleware
app.add_middleware(
    RBACMiddleware,
    rbac_dependencies=rbac,
    exclude_paths=["/health", "/public"]
)

# The middleware automatically:
# 1. Extracts tenant from request
# 2. Validates user belongs to tenant
# 3. Sets tenant context in request.state
Tenant Access Dependency
python
from rbac.dependencies.auth import require_tenant_access

# Require tenant access for a route
@app.get("/tenant/settings")
async def get_tenant_settings(
    current_user = Depends(rbac.require_tenant_access()(rbac.get_current_active_user))
):
    """Get current tenant settings"""
    return {"settings": await get_tenant_settings(current_user.tenant_id)}

# Allow cross-tenant access for support
@app.get("/admin/tenants/{tenant_id}/users")
async def get_tenant_users(
    tenant_id: str,
    current_user = Depends(
        rbac.require_tenant_access(allow_cross_tenant=True)(rbac.get_current_active_user)
    )
):
    """Get users for any tenant (support only)"""
    # Only super admins can access other tenants
    if not current_user.is_superuser and current_user.tenant_id != UUID(tenant_id):
        raise HTTPException(403, "Cannot access other tenants")
    
    return await get_users_for_tenant(tenant_id)
Tenant-Scoped Queries
All service methods accept tenant_id parameter for isolation:

python
class PermissionService:
    async def list_permissions(
        self,
        tenant_id: Optional[UUID] = None,  # None = system-wide
        resource: Optional[ResourceType] = None,
        limit: int = 100
    ) -> List[Permission]:
        """List permissions, optionally filtered by tenant"""
        query = "SELECT * FROM permissions WHERE 1=1"
        params = []
        
        if tenant_id:
            query += " AND (tenant_id = $1 OR tenant_id IS NULL)"
            params.append(tenant_id)
        else:
            query += " AND tenant_id IS NULL"
        
        # ... rest of query


Cross-Tenant Operations
Super Admin Access
python
# Super admin can operate across tenants
@app.get("/admin/stats")
@require_roles(["super_admin"])
async def get_global_stats(
    current_user = Depends(rbac.get_current_active_user)
):
    """Get statistics across all tenants"""
    
    # Get all tenants
    tenants = await db.fetch_all("SELECT * FROM tenants WHERE is_active = true")
    
    stats = []
    for tenant in tenants:
        # Get stats for each tenant
        tenant_stats = await assignment_service.get_assignment_stats(
            tenant_id=tenant['id']
        )
        stats.append({
            "tenant_name": tenant['name'],
            "tenant_id": str(tenant['id']),
            **tenant_stats
        })
    
    return {"tenants": stats}
Data Migration Between Tenants
python
@app.post("/admin/migrate/role")
@require_roles(["super_admin"])
async def migrate_role(
    source_tenant_id: str,
    target_tenant_id: str,
    role_id: str
):
    """Migrate a role from one tenant to another"""
    
    # Get role from source tenant
    role = await role_service.get_role(
        role_id=UUID(role_id),
        tenant_id=UUID(source_tenant_id)
    )
    
    if not role:
        raise HTTPException(404, "Role not found")
    
    # Create copy in target tenant
    new_role = await role_service.create_role(
        name=role.name,
        description=role.description,
        tenant_id=UUID(target_tenant_id)
    )
    
    # Copy permissions
    permissions = await role_service.get_role_permissions(role.id)
    for perm in permissions:
        await permission_service.grant_permission_to_role(
            role_id=new_role.id,
            permission_id=perm.id
        )
    
    return {
        "message": "Role migrated successfully",
        "source_role_id": role_id,
        "target_role_id": str(new_role.id)
    }
Tenant Configuration
Tenant Settings
python
class TenantSettings(BaseModel):
    """Tenant-specific settings"""
    max_users: int = 100
    max_roles: int = 50
    allowed_auth_providers: List[str] = ["local"]
    session_timeout_minutes: int = 60
    require_mfa: bool = False
    allowed_domains: List[str] = []

@app.get("/tenant/settings")
@require_permissions(["tenant:read"])
async def get_tenant_settings(
    current_user = Depends(rbac.get_current_active_user)
):
    """Get settings for current tenant"""
    tenant = await get_tenant(current_user.tenant_id)
    return TenantSettings(**tenant.settings)

@app.put("/tenant/settings")
@require_roles(["admin"])
async def update_tenant_settings(
    settings: TenantSettings,
    current_user = Depends(rbac.get_current_active_user)
):
    """Update tenant settings"""
    await db.execute(
        """
        UPDATE tenants 
        SET settings = $1, updated_at = $2
        WHERE id = $3
        """,
        settings.dict(),
        datetime.utcnow(),
        current_user.tenant_id
    )
    
    # Log the change
    await audit_service.log_action(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        action=AuditAction.UPDATE,
        resource_type=AuditResourceType.TENANT,
        resource_id=current_user.tenant_id,
        new_value=settings.dict()
    )
    
    return {"message": "Settings updated"}
Tenant-Aware Caching
Multi-tenant Redis Cache
python
class TenantAwareCache:
    """Cache wrapper that includes tenant in keys"""
    
    def __init__(self, redis_cache: RedisCache):
        self.cache = redis_cache
    
    def _key(self, tenant_id: Optional[UUID], key: str) -> str:
        """Generate tenant-aware cache key"""
        tenant_part = str(tenant_id) if tenant_id else "system"
        return f"{tenant_part}:{key}"
    
    async def get_user_permissions(
        self,
        user_id: UUID,
        tenant_id: Optional[UUID]
    ):
        cache_key = self._key(tenant_id, f"user_perms:{user_id}")
        return await self.cache.get(cache_key)
    
    async def set_user_permissions(
        self,
        user_id: UUID,
        tenant_id: Optional[UUID],
        permissions: Set[str]
    ):
        cache_key = self._key(tenant_id, f"user_perms:{user_id}")
        await self.cache.set(cache_key, list(permissions), ttl=3600)
Tenant-Specific Cache Invalidation
python
@app.post("/cache/invalidate/tenant/{tenant_id}")
@require_roles(["super_admin"])
async def invalidate_tenant_cache(
    tenant_id: str,
    current_user = Depends(rbac.get_current_active_user)
):
    """Invalidate all cache for a specific tenant"""
    
    # Delete all keys with this tenant prefix
    deleted = await cache_manager.invalidate_tenant(tenant_id)
    
    return {
        "message": f"Invalidated {deleted} cache entries for tenant {tenant_id}"
    }
Tenant Analytics
Tenant Usage Statistics
python
@app.get("/admin/analytics/tenants")
@require_roles(["super_admin"])
async def get_tenant_analytics():
    """Get usage statistics for all tenants"""
    
    tenants = await db.fetch_all("""
        SELECT 
            t.id,
            t.name,
            t.created_at,
            COUNT(DISTINCT u.id) as user_count,
            COUNT(DISTINCT r.id) as role_count,
            COUNT(DISTINCT p.id) as permission_count,
            COUNT(DISTINCT a.id) as assignment_count
        FROM tenants t
        LEFT JOIN users u ON u.tenant_id = t.id
        LEFT JOIN roles r ON r.tenant_id = t.id
        LEFT JOIN permissions p ON p.tenant_id = t.id
        LEFT JOIN user_roles a ON a.tenant_id = t.id
        GROUP BY t.id, t.name, t.created_at
    """)
    
    return {"tenants": [dict(t) for t in tenants]}
Tenant Audit Summary
python
@app.get("/tenant/audit/summary")
@require_roles(["admin"])
async def get_tenant_audit_summary(
    days: int = 30,
    current_user = Depends(rbac.get_current_active_user)
):
    """Get audit summary for current tenant"""
    
    summary = await audit_service.get_tenant_audit_summary(
        tenant_id=current_user.tenant_id,
        days=days
    )
    
    return summary
Best Practices
Always validate tenant access - Use tenant middleware or dependencies

Include tenant_id in all queries - Never forget tenant isolation

Use tenant-aware caching - Include tenant in cache keys

Log tenant context - Include tenant_id in audit logs

Handle tenant deletion - Cascade or block based on requirements

Monitor tenant usage - Track quotas and limits

Backup per tenant - Consider tenant-level backups

Test isolation - Verify tenants cannot access each other's data

Document tenant limits - Clear SLAs per tenant

Plan for scaling - Consider sharding by tenant

Complete Multi-tenant Example
python
from fastapi import FastAPI, Depends, Request
from contextlib import asynccontextmanager
from uuid import UUID
import uvicorn

from rbac.core.database import Database
from rbac.services import PermissionService, RoleService, AssignmentService
from rbac.dependencies.auth import RBACDependencies, require_permissions, require_roles
from rbac.core.models import Tenant

# Initialize
db = Database("postgresql://user:pass@localhost/rbac")
permission_service = PermissionService(db)
role_service = RoleService(db, permission_service)
assignment_service = AssignmentService(db, role_service, permission_service)

# Tenant resolver
async def get_tenant_from_request(request: Request) -> Optional[Tenant]:
    tenant_id = request.headers.get("X-Tenant-ID")
    if tenant_id:
        result = await db.fetch_one(
            "SELECT * FROM tenants WHERE id = $1 AND is_active = true",
            UUID(tenant_id)
        )
        return Tenant.model_validate(result) if result else None
    return None

# Tenant middleware
@app.middleware("http")
async def tenant_middleware(request: Request, call_next):
    tenant = await get_tenant_from_request(request)
    request.state.tenant = tenant
    response = await call_next(request)
    return response

# RBAC with tenant context
rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key="your-secret-key"
)

@app.get("/api/users")
@require_permissions(["user:read"])
async def list_users(
    request: Request,
    current_user = Depends(rbac.get_current_active_user)
):
    """List users for current tenant"""
    
    tenant = request.state.tenant
    if not tenant:
        raise HTTPException(400, "Tenant context required")
    
    # Ensure user belongs to this tenant
    if current_user.tenant_id != tenant.id:
        raise HTTPException(403, "Access denied")
    
    # Get tenant-scoped users
    users = await db.fetch_all(
        "SELECT * FROM users WHERE tenant_id = $1",
        tenant.id
    )
    
    return {"tenant": tenant.name, "users": users}

@app.post("/api/roles")
@require_roles(["admin"])
async def create_role(
    name: str,
    description: str = None,
    request: Request,
    current_user = Depends(rbac.get_current_active_user)
):
    """Create a role for current tenant"""
    
    tenant = request.state.tenant
    if not tenant:
        raise HTTPException(400, "Tenant context required")
    
    role = await role_service.create_role(
        name=name,
        description=description,
        tenant_id=tenant.id,
        created_by=current_user.id
    )
    
    return role

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
With multi-tenancy properly implemented, your RBAC system can securely serve multiple organizations from a single deployment!