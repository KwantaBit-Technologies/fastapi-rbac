# rbac/core/constants.py
from enum import Enum
from typing import Final


class PermissionAction(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    MANAGE = "manage"
    APPROVE = "approve"
    REJECT = "reject"


class ResourceType(str, Enum):
    ALL = "*"
    ROLE = "role"
    PERMISSION = "permission"
    USER = "user"
    TENANT = "tenant"


# Default roles that every system should have
DEFAULT_ROLES: Final[dict] = {
    "super_admin": {
        "name": "Super Admin",
        "description": "Full system access",
        "is_system_role": True,
        "permissions": ["*:*"],  # All permissions on all resources
    },
    "admin": {
        "name": "Admin",
        "description": "Administrative access within tenant",
        "is_system_role": False,
        "permissions": ["*:*"],  # Will be scoped to tenant
    },
    "user": {
        "name": "User",
        "description": "Basic user access",
        "is_system_role": False,
        "permissions": ["user:read:self", "user:update:self"],
    },
}
