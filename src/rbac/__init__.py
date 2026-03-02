"""
FastAPI Enterprise RBAC Engine

A production-grade Role-Based Access Control (RBAC) system for FastAPI applications.
"""

__version__ = "0.1.0"
__author__ = "Munya Junior (khalid) at Kwantabit Technologies"
__license__ = "MIT"

from core import (
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
from services import (
    PermissionService,
    RoleService,
    AssignmentService,
    AuditService,
)
from cache import (
    RedisCache,
    RedisCachedPermissionService,
    RedisCachedRoleService,
    RedisCachedAssignmentService,
    CacheManager,
)
from dependencies import (
    RBACDependencies,
    UserContext,
    require_permissions,
    require_roles,
    public_route,
)
from integration import (
    LDAPProvider,
    LDAPConfig,
    KeycloakProvider,
    KeycloakConfig,
    IdentitySyncService,
    ExternalUser,
)

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
