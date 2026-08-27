"""
FastAPI Enterprise RBAC Engine

A production-grade Role-Based Access Control (RBAC) system for FastAPI applications.
"""

__version__ = "0.1.0"
__author__ = "Munya Junior (khalid) at Kwantabit Technologies"
__license__ = "MIT"

from rbac.core import (
    Database,
    Permission,
    Role,
    UserRole,
    Tenant,
    AuditLog,
    ResourceType,
    PermissionAction,
    RBACError,
    PermissionDeniedError,
    RoleNotFoundError,
)
from rbac.services import (
    PermissionService,
    RoleService,
    AssignmentService,
    AuditService,
)
from rbac.cache import (
    RedisCache,
    RedisCachedPermissionService,
    RedisCachedRoleService,
    RedisCachedAssignmentService,
    CacheManager,
)
from rbac.dependencies import (
    RBACDependencies,
    UserContext,
    require_permissions,
    require_roles,
    public_route,
)
from rbac.integration import IdentitySyncService, ExternalUser


def __getattr__(name):
    if name in {"LDAPProvider", "LDAPConfig", "KeycloakProvider", "KeycloakConfig"}:
        from rbac import integration

        return getattr(integration, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Core
    "Database",
    "Permission",
    "Role",
    "UserRole",
    "Tenant",
    "AuditLog",
    "ResourceType",
    "PermissionAction",
    "RBACError",
    "PermissionDeniedError",
    "RoleNotFoundError",
    # Services
    "PermissionService",
    "RoleService",
    "AssignmentService",
    "AuditService",
    # Cache
    "RedisCache",
    "RedisCachedPermissionService",
    "RedisCachedRoleService",
    "RedisCachedAssignmentService",
    "CacheManager",
    # Dependencies
    "RBACDependencies",
    "UserContext",
    "require_permissions",
    "require_roles",
    "public_route",
    # Integration
    "LDAPProvider",
    "LDAPConfig",
    "KeycloakProvider",
    "KeycloakConfig",
    "IdentitySyncService",
    "ExternalUser",
]
