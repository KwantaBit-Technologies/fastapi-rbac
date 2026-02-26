# rbac/services/permission_service.py
from typing import Optional, List, Dict, Any, Set
from uuid import UUID
from datetime import datetime, timezone

from core.models import Permission, Role, UserRole, Tenant
from core.database import Database
from core.exceptions import (
    PermissionNotFoundError,
    PermissionDeniedError,
    TenantNotFoundError,
)
from core.constants import PermissionAction, ResourceType
from utils.logger import setup_logger

logger = setup_logger("PERMISSION_SERVICE")


class PermissionService:
    """Core service for managing and checking permissions"""

    def __init__(self, db: Database):
        self.db = db
        self._permission_cache: Dict[str, Set[str]] = (
            {}
        )  # user_id -> set of permission strings

    async def create_permission(
        self,
        name: str,
        resource: ResourceType,
        action: PermissionAction,
        scope: Optional[str] = None,
        description: Optional[str] = None,
        tenant_id: Optional[UUID] = None,
        created_by: Optional[UUID] = None,
    ) -> Permission:
        """Create a new permission"""

        # Check if tenant exists if tenant_id provided
        if tenant_id:
            tenant = await self._get_tenant(tenant_id)
            if not tenant:
                raise TenantNotFoundError(tenant_id)

        # Check if permission already exists
        existing = await self.db.fetch_one(
            """
            SELECT * FROM permissions 
            WHERE resource = $1 AND action = $2 
            AND (scope = $3 OR (scope IS NULL AND $3 IS NULL))
            AND (tenant_id = $4 OR (tenant_id IS NULL AND $4 IS NULL))
            """,
            resource.value,
            action.value,
            scope,
            tenant_id,
        )

        if existing:
            logger.warning(
                f"Permission already exists: {resource.value}:{action.value}"
            )
            return Permission.model_validate(existing)

        # Create new permission
        permission_id = await self.db.fetch_one(
            """
            INSERT INTO permissions (
                name, resource, action, scope, description, 
                tenant_id, is_system, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            """,
            name,
            resource.value,
            action.value,
            scope,
            description,
            tenant_id,
            False,
            datetime.now(timezone.utc),
            datetime.now(timezone.utc),
        )

        permission = Permission.model_validate(permission_id)

        # Audit log
        await self._audit_log(
            user_id=created_by,
            tenant_id=tenant_id,
            action="CREATE",
            resource_type="permission",
            resource_id=permission.id,
            new_value=permission.model_dump(),
        )

        logger.info(f"Created permission: {permission.permission_string}")
        return permission

    async def get_permission(
        self, permission_id: UUID, tenant_id: Optional[UUID] = None
    ) -> Optional[Permission]:
        """Get permission by ID"""
        query = "SELECT * FROM permissions WHERE id = $1"
        params = [permission_id]

        if tenant_id:
            query += " AND (tenant_id = $2 OR tenant_id IS NULL)"
            params.append(tenant_id)

        result = await self.db.fetch_one(query, *params)
        return Permission.model_validate(result) if result else None

    async def get_permission_by_string(
        self, permission_string: str, tenant_id: Optional[UUID] = None
    ) -> Optional[Permission]:
        """Get permission by its string representation (resource:action:scope)"""
        parts = permission_string.split(":")
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else None
        scope = parts[2] if len(parts) > 2 else None

        query = """
            SELECT * FROM permissions 
            WHERE resource = $1 AND action = $2 
            AND (scope = $3 OR (scope IS NULL AND $3 IS NULL))
        """
        params = [resource, action, scope]

        if tenant_id:
            query += " AND (tenant_id = $4 OR tenant_id IS NULL)"
            params.append(tenant_id)

        result = await self.db.fetch_one(query, *params)
        return Permission.model_validate(result) if result else None

    async def update_permission(
        self,
        permission_id: UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        updated_by: Optional[UUID] = None,
    ) -> Permission:
        """Update permission details"""
        # Get existing permission
        existing = await self.get_permission(permission_id)
        if not existing:
            raise PermissionNotFoundError(permission_id)

        # Don't allow updating system permissions
        if existing.is_system:
            raise PermissionDeniedError(
                f"Cannot update system permission: {existing.permission_string}"
            )

        update_fields = []
        params = []
        param_index = 1

        if name is not None:
            update_fields.append(f"name = ${param_index}")
            params.append(name)
            param_index += 1

        if description is not None:
            update_fields.append(f"description = ${param_index}")
            params.append(description)
            param_index += 1

        if update_fields:
            update_fields.append(f"updated_at = ${param_index}")
            params.append(datetime.now(timezone.utc))
            param_index += 1

            params.append(permission_id)
            query = f"""
                UPDATE permissions 
                SET {', '.join(update_fields)}
                WHERE id = ${param_index}
                RETURNING *
            """

            result = await self.db.fetch_one(query, *params)
            updated = Permission.model_validate(result)

            # Audit log
            await self._audit_log(
                user_id=updated_by,
                tenant_id=existing.tenant_id,
                action="UPDATE",
                resource_type="permission",
                resource_id=permission_id,
                old_value=existing.model_dump(),
                new_value=updated.model_dump(),
            )

            logger.info(f"Updated permission: {updated.permission_string}")
            return updated

        return existing

    async def delete_permission(
        self, permission_id: UUID, deleted_by: Optional[UUID] = None
    ):
        """Delete a permission"""
        # Get existing permission
        existing = await self.get_permission(permission_id)
        if not existing:
            raise PermissionNotFoundError(permission_id)

        # Don't allow deleting system permissions
        if existing.is_system:
            raise PermissionDeniedError(
                f"Cannot delete system permission: {existing.permission_string}"
            )

        # Check if permission is assigned to any roles
        assigned_roles = await self.db.fetch_all(
            """
            SELECT r.id, r.name 
            FROM roles r
            JOIN role_permissions rp ON r.id = rp.role_id
            WHERE rp.permission_id = $1
            """,
            permission_id,
        )

        if assigned_roles:
            role_names = [r["name"] for r in assigned_roles]
            raise PermissionDeniedError(
                f"Cannot delete permission assigned to roles: {', '.join(role_names)}"
            )

        # Delete permission
        await self.db.execute("DELETE FROM permissions WHERE id = $1", permission_id)

        # Audit log
        await self._audit_log(
            user_id=deleted_by,
            tenant_id=existing.tenant_id,
            action="DELETE",
            resource_type="permission",
            resource_id=permission_id,
            old_value=existing.model_dump(),
        )

        logger.info(f"Deleted permission: {existing.permission_string}")

    async def list_permissions(
        self,
        tenant_id: Optional[UUID] = None,
        resource: Optional[ResourceType] = None,
        action: Optional[PermissionAction] = None,
        include_system: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Permission]:
        """List permissions with optional filters"""
        query = "SELECT * FROM permissions WHERE 1=1"
        params = []
        param_index = 1

        if tenant_id:
            query += f" AND (tenant_id = ${param_index} OR tenant_id IS NULL)"
            params.append(tenant_id)
            param_index += 1

        if resource:
            query += f" AND resource = ${param_index}"
            params.append(resource.value)
            param_index += 1

        if action:
            query += f" AND action = ${param_index}"
            params.append(action.value)
            param_index += 1

        if not include_system:
            query += " AND is_system = false"

        query += (
            f" ORDER BY resource, action LIMIT ${param_index} OFFSET ${param_index + 1}"
        )
        params.extend([limit, offset])

        results = await self.db.fetch_all(query, *params)
        return [Permission.model_validate(r) for r in results]

    async def check_user_permission(
        self,
        user_id: UUID,
        required_permission: str,
        tenant_id: Optional[UUID] = None,
        resource_scope: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if a user has a specific permission"""
        # Get all user permissions (with caching)
        user_permissions = await self.get_user_permissions(user_id, tenant_id)

        # Check for exact match
        if required_permission in user_permissions:
            return True

        # Check for wildcard permissions
        parts = required_permission.split(":")
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else None

        # Check resource wildcard (*:action)
        if action and f"*:{action}" in user_permissions:
            return True

        # Check action wildcard (resource:*)
        if f"{resource}:*" in user_permissions:
            return True

        # Check full wildcard (*:*)
        if "*:*" in user_permissions:
            return True

        # Check scoped permissions if scope provided
        if resource_scope and len(parts) > 2:
            scope_key = f"{resource}:{action}:{resource_scope.get('id')}"
            if scope_key in user_permissions:
                return True

        return False

    async def get_user_permissions(
        self, user_id: UUID, tenant_id: Optional[UUID] = None
    ) -> Set[str]:
        """Get all permissions for a user (including inherited)"""
        cache_key = f"{user_id}:{tenant_id}"

        # Check cache
        if cache_key in self._permission_cache:
            return self._permission_cache[cache_key]

        # Get all roles assigned to user
        user_roles = await self.db.fetch_all(
            """
            SELECT ur.role_id, ur.resource_scope, r.parent_ids
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 
            AND ur.is_active = true
            AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
            AND ($2::uuid IS NULL OR ur.tenant_id = $2)
            """,
            user_id,
            tenant_id,
        )

        if not user_roles:
            return set()

        # Get all role IDs including inherited
        all_role_ids = set()
        for ur in user_roles:
            all_role_ids.add(ur["role_id"])
            if ur["parent_ids"]:
                all_role_ids.update(await self._get_inherited_roles(ur["parent_ids"]))

        # Get all permissions for these roles
        permissions = await self.db.fetch_all(
            """
            SELECT DISTINCT p.resource, p.action, p.scope
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ANY($1::uuid[])
            """,
            list(all_role_ids),
        )

        # Convert to permission strings
        permission_strings = set()
        for p in permissions:
            if p["scope"]:
                permission_strings.add(f"{p['resource']}:{p['action']}:{p['scope']}")
            else:
                permission_strings.add(f"{p['resource']}:{p['action']}")

        # Add role-based scoped permissions
        for ur in user_roles:
            if ur["resource_scope"]:
                for resource_id in ur["resource_scope"].values():
                    permission_strings.add(f"*:*:{resource_id}")

        # Cache the result
        self._permission_cache[cache_key] = permission_strings

        return permission_strings

    async def _get_inherited_roles(
        self, parent_ids: List[UUID], visited: Optional[Set[UUID]] = None
    ) -> Set[UUID]:
        """Recursively get all inherited roles"""
        if visited is None:
            visited = set()

        inherited = set()
        for parent_id in parent_ids:
            if parent_id in visited:
                continue  # Prevent circular references

            visited.add(parent_id)
            inherited.add(parent_id)

            # Get parent's parents
            parent_role = await self.db.fetch_one(
                "SELECT parent_ids FROM roles WHERE id = $1", parent_id
            )

            if parent_role and parent_role["parent_ids"]:
                inherited.update(
                    await self._get_inherited_roles(parent_role["parent_ids"], visited)
                )

        return inherited

    async def grant_permission_to_role(
        self, role_id: UUID, permission_id: UUID, granted_by: Optional[UUID] = None
    ):
        """Grant a permission to a role"""
        # Check if permission already granted
        existing = await self.db.fetch_one(
            """
            SELECT 1 FROM role_permissions 
            WHERE role_id = $1 AND permission_id = $2
            """,
            role_id,
            permission_id,
        )

        if not existing:
            await self.db.execute(
                """
                INSERT INTO role_permissions (role_id, permission_id, granted_at)
                VALUES ($1, $2, $3)
                """,
                role_id,
                permission_id,
                datetime.now(timezone.utc),
            )

            # Clear cache for all users with this role
            await self._clear_role_cache(role_id)

            # Audit log
            await self._audit_log(
                user_id=granted_by,
                action="GRANT",
                resource_type="role_permission",
                new_value={
                    "role_id": str(role_id),
                    "permission_id": str(permission_id),
                },
            )

            logger.info(f"Granted permission {permission_id} to role {role_id}")

    async def revoke_permission_from_role(
        self, role_id: UUID, permission_id: UUID, revoked_by: Optional[UUID] = None
    ):
        """Revoke a permission from a role"""
        await self.db.execute(
            """
            DELETE FROM role_permissions 
            WHERE role_id = $1 AND permission_id = $2
            """,
            role_id,
            permission_id,
        )

        # Clear cache for all users with this role
        await self._clear_role_cache(role_id)

        # Audit log
        await self._audit_log(
            user_id=revoked_by,
            action="REVOKE",
            resource_type="role_permission",
            old_value={"role_id": str(role_id), "permission_id": str(permission_id)},
        )

        logger.info(f"Revoked permission {permission_id} from role {role_id}")

    async def _clear_role_cache(self, role_id: UUID):
        """Clear cache for all users with this role"""
        users = await self.db.fetch_all(
            "SELECT DISTINCT user_id FROM user_roles WHERE role_id = $1", role_id
        )

        for user in users:
            cache_keys = [
                key
                for key in self._permission_cache.keys()
                if key.startswith(str(user["user_id"]))
            ]
            for key in cache_keys:
                self._permission_cache.pop(key, None)

    async def _get_tenant(self, tenant_id: UUID) -> Optional[Tenant]:
        """Get tenant by ID"""
        result = await self.db.fetch_one(
            "SELECT * FROM tenants WHERE id = $1", tenant_id
        )
        return Tenant.model_validate(result) if result else None

    async def _audit_log(
        self,
        user_id: Optional[UUID],
        action: str,
        resource_type: str,
        resource_id: Optional[UUID] = None,
        tenant_id: Optional[UUID] = None,
        old_value: Optional[Dict] = None,
        new_value: Optional[Dict] = None,
    ):
        """Create audit log entry"""
        try:
            await self.db.execute(
                """
                INSERT INTO audit_logs (
                    user_id, tenant_id, action, resource_type, 
                    resource_id, old_value, new_value, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                user_id,
                tenant_id,
                action,
                resource_type,
                resource_id,
                old_value,
                new_value,
                datetime.now(timezone.utc),
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")

    async def clear_user_cache(self, user_id: UUID):
        """Clear permission cache for a specific user"""
        keys_to_clear = [
            key for key in self._permission_cache.keys() if key.startswith(str(user_id))
        ]
        for key in keys_to_clear:
            self._permission_cache.pop(key, None)
        logger.debug(f"Cleared permission cache for user {user_id}")

    async def validate_permission_string(self, permission_string: str) -> bool:
        """Validate if a permission string is properly formatted"""
        try:
            parts = permission_string.split(":")

            if len(parts) < 2 or len(parts) > 3:
                return False

            resource = parts[0]
            action = parts[1]

            # Validate resource
            if resource != "*" and resource not in [r.value for r in ResourceType]:
                return False

            # Validate action
            if action != "*" and action not in [a.value for a in PermissionAction]:
                return False

            # Scope is optional and can be any string
            return True

        except Exception:
            return False
