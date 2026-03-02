# examples/redis_example.py
from fastapi import FastAPI, Depends
import uvicorn
from uuid import uuid4

from core.database import Database
from services.permission_service import PermissionService
from services.role_service import RoleService
from services.assignment_service import AssignmentService
from cache import (
    RedisCache,
    RedisCachedPermissionService,
    RedisCachedRoleService,
    RedisCachedAssignmentService,
    CacheManager,
)
from dependencies.auth import RBACDependencies, require_permissions

app = FastAPI(title="RBAC with Redis Caching")

# Initialize database
db = Database("postgresql://postgres:postgres@localhost/rbac")

# Initialize Redis cache
redis_cache = RedisCache(
    redis_url="redis://localhost:6379",
    prefix="rbac:",
    default_ttl=3600,
    max_connections=10,
)

# Initialize base services
base_permission_service = PermissionService(db)
base_role_service = RoleService(db, base_permission_service)
base_assignment_service = AssignmentService(
    db, base_role_service, base_permission_service
)

# Wrap with caching
permission_service = RedisCachedPermissionService(
    base_permission_service,
    redis_cache,
    user_permissions_ttl=3600,
    role_permissions_ttl=7200,
)

role_service = RedisCachedRoleService(
    base_role_service, redis_cache, role_ttl=7200, hierarchy_ttl=3600
)

assignment_service = RedisCachedAssignmentService(
    base_assignment_service, redis_cache, assignment_ttl=1800
)

# Create cache manager
cache_manager = CacheManager(
    redis_cache, permission_service, role_service, assignment_service
)

# Initialize RBAC dependencies
rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key="your-secret-key",
)


@app.on_event("startup")
async def startup():
    await db.connect()
    await redis_cache.initialize()
    await base_role_service.initialize_default_roles()

    # Warm up common caches
    await cache_manager.warm_role_cache("admin")
    await cache_manager.warm_role_cache("user")


@app.on_event("shutdown")
async def shutdown():
    await redis_cache.close()
    await db.disconnect()


@app.get("/users/{user_id}/permissions")
@require_permissions(["user:read"])
async def get_user_permissions(
    user_id: str, current_user=Depends(rbac.get_current_active_user)
):
    """Get user permissions (cached)"""
    permissions = await permission_service.get_user_permissions(
        user_id=user_id, tenant_id=current_user.tenant_id
    )

    # Check if from cache
    cache_key = f"user_perms:{user_id}:{current_user.tenant_id or 'global'}"
    from_cache = await redis_cache.exists(cache_key)

    return {
        "user_id": user_id,
        "permissions": list(permissions),
        "from_cache": from_cache,
        "permission_count": len(permissions),
    }


@app.post("/cache/invalidate/user/{user_id}")
async def invalidate_user_cache(
    user_id: str, current_user=Depends(rbac.require_permissions(["cache:invalidate"]))
):
    """Invalidate cache for a specific user"""
    await cache_manager.invalidate_user(
        user_id=user_id, tenant_id=current_user.tenant_id
    )
    return {"message": f"Cache invalidated for user {user_id}"}


@app.post("/cache/invalidate/role/{role_id}")
async def invalidate_role_cache(
    role_id: str, current_user=Depends(rbac.require_permissions(["cache:invalidate"]))
):
    """Invalidate cache for a specific role"""
    await cache_manager.invalidate_role(role_id)
    return {"message": f"Cache invalidated for role {role_id}"}


@app.post("/cache/invalidate/all")
async def invalidate_all_caches(
    current_user=Depends(rbac.require_permissions(["cache:invalidate"])),
):
    """Invalidate all caches"""
    await cache_manager.invalidate_all()
    return {"message": "All caches invalidated"}


@app.get("/cache/stats")
async def get_cache_stats(
    current_user=Depends(rbac.require_permissions(["cache:read"])),
):
    """Get cache statistics"""
    stats = await cache_manager.get_stats()
    return stats


@app.post("/cache/warm/user/{user_id}")
async def warm_user_cache(
    user_id: str, current_user=Depends(rbac.require_permissions(["cache:warm"]))
):
    """Pre-warm cache for a user"""
    await cache_manager.warm_user_cache(
        user_id=user_id, tenant_id=current_user.tenant_id
    )
    return {"message": f"Cache warmed for user {user_id}"}


@app.post("/cache/warm/role/{role_id}")
async def warm_role_cache(
    role_id: str, current_user=Depends(rbac.require_permissions(["cache:warm"]))
):
    """Pre-warm cache for a role"""
    await cache_manager.warm_role_cache(role_id)
    return {"message": f"Cache warmed for role {role_id}"}


@app.get("/performance/compare")
async def compare_performance(
    user_id: str, current_user=Depends(rbac.get_current_active_user)
):
    """Compare cached vs uncached performance"""
    import time

    # Uncached (clear cache first)
    await cache_manager.invalidate_user(user_id)

    start = time.time()
    uncached_perms = await base_permission_service.get_user_permissions(
        user_id=user_id, tenant_id=current_user.tenant_id
    )
    uncached_time = time.time() - start

    # Cached
    start = time.time()
    cached_perms = await permission_service.get_user_permissions(
        user_id=user_id, tenant_id=current_user.tenant_id
    )
    cached_time = time.time() - start

    return {
        "user_id": user_id,
        "uncached_time_ms": round(uncached_time * 1000, 2),
        "cached_time_ms": round(cached_time * 1000, 2),
        "speedup": f"{round(uncached_time / cached_time, 2)}x",
        "permission_count": len(cached_perms),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
