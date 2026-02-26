# rbac/core/exceptions.py
from typing import Optional, Any


class RBACError(Exception):
    """Base exception for RBAC errors"""

    def __init__(self, message: str, details: Optional[dict] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class PermissionDeniedError(RBACError):
    """Raised when user doesn't have required permission"""

    def __init__(self, required_permission: str, user_id: Optional[Any] = None):
        details = {
            "required_permission": required_permission,
            "user_id": str(user_id) if user_id else None,
        }
        super().__init__(
            f"User lacks required permission: {required_permission}", details
        )


class RoleNotFoundError(RBACError):
    """Raised when role doesn't exist"""

    def __init__(self, role_id: Any):
        super().__init__(f"Role not found: {role_id}", {"role_id": str(role_id)})


class PermissionNotFoundError(RBACError):
    """Raised when permission doesn't exist"""

    def __init__(self, permission_id: Any):
        super().__init__(
            f"Permission not found: {permission_id}",
            {"permission_id": str(permission_id)},
        )


class TenantNotFoundError(RBACError):
    """Raised when tenant doesn't exist"""

    def __init__(self, tenant_id: Any):
        super().__init__(
            f"Tenant not found: {tenant_id}", {"tenant_id": str(tenant_id)}
        )


class CircularRoleHierarchyError(RBACError):
    """Raised when role hierarchy would create a cycle"""

    def __init__(self, role_id: Any, parent_id: Any):
        super().__init__(
            f"Circular role hierarchy detected: {role_id} -> {parent_id}",
            {"role_id": str(role_id), "parent_id": str(parent_id)},
        )
