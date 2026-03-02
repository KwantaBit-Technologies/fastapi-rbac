# rbac/services/permission_service.py
from typing import Optional, List, Dict, Any, Set
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy import select, insert, update, delete, and_, or_, func, text
from sqlalchemy.sql import exists

from core.models import Permission, Role, UserRole, Tenant
from core.database import Database
from core.database import (
    tenants,
    permissions,
    roles,
    role_permissions,
    user_roles,
    audit_logs,
)
from core.exceptions import (
    PermissionNotFoundError,
    PermissionDeniedError,
    TenantNotFoundError,
    RoleNotFoundError,
)
from core.constants import PermissionAction, ResourceType
from utils.logger import setup_logger

logger = setup_logger("PERMISSION_SERVICE")


class PermissionService:
    """Core service for managing and checking permissions using SQLAlchemy Core"""

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
        conditions = [
            permissions.c.resource == resource.value,
            permissions.c.action == action.value,
        ]

        # Handle scope (can be None)
        if scope is not None:
            conditions.append(permissions.c.scope == scope)
        else:
            conditions.append(permissions.c.scope.is_(None))

        # Handle tenant_id (can be None)
        if tenant_id is not None:
            conditions.append(permissions.c.tenant_id == tenant_id)
        else:
            conditions.append(permissions.c.tenant_id.is_(None))

        query = select(permissions).where(and_(*conditions))

        existing = await self.db.fetch_one(query)
        if existing:
            logger.warning(
                f"Permission already exists: {resource.value}:{action.value}"
            )
            return Permission.model_validate(existing)

        # Create new permission
        now = datetime.now(timezone.utc)
        stmt = (
            insert(permissions)
            .values(
                name=name,
                resource=resource.value,
                action=action.value,
                scope=scope,
                description=description,
                tenant_id=tenant_id,
                is_system=False,
                created_at=now,
                updated_at=now,
            )
            .returning(*permissions.columns)
        )

        result = await self.db.fetch_one(stmt)
        if not result:
            raise RuntimeError("Failed to create permission")

        permission = Permission.model_validate(result)

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
        conditions = [permissions.c.id == permission_id]

        if tenant_id:
            conditions.append(
                or_(
                    permissions.c.tenant_id == tenant_id,
                    permissions.c.tenant_id.is_(None),
                )
            )

        query = select(permissions).where(and_(*conditions))
        result = await self.db.fetch_one(query)
        return Permission.model_validate(result) if result else None

    async def get_permission_by_string(
        self, permission_string: str, tenant_id: Optional[UUID] = None
    ) -> Optional[Permission]:
        """Get permission by its string representation (resource:action:scope)"""
        parts = permission_string.split(":")
        if len(parts) < 2:
            return None

        resource = parts[0]
        action = parts[1]
        scope = parts[2] if len(parts) > 2 else None

        conditions = [
            permissions.c.resource == resource,
            permissions.c.action == action,
        ]

        # Handle scope
        if scope is not None:
            conditions.append(permissions.c.scope == scope)
        else:
            conditions.append(permissions.c.scope.is_(None))

        # Handle tenant
        if tenant_id:
            conditions.append(
                or_(
                    permissions.c.tenant_id == tenant_id,
                    permissions.c.tenant_id.is_(None),
                )
            )

        query = select(permissions).where(and_(*conditions))
        result = await self.db.fetch_one(query)
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

        # Build update statement
        update_values = {}
        if name is not None:
            update_values["name"] = name
        if description is not None:
            update_values["description"] = description

        if update_values:
            update_values["updated_at"] = datetime.now(timezone.utc)

            stmt = (
                update(permissions)
                .where(permissions.c.id == permission_id)
                .values(**update_values)
                .returning(*permissions.columns)
            )

            result = await self.db.fetch_one(stmt)
            if not result:
                raise RuntimeError("Failed to update permission")

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
        assigned_query = (
            select(roles.c.id, roles.c.name)
            .select_from(
                roles.join(role_permissions, roles.c.id == role_permissions.c.role_id)
            )
            .where(role_permissions.c.permission_id == permission_id)
        )

        assigned_roles = await self.db.fetch_all(assigned_query)

        if assigned_roles:
            role_names = [r["name"] for r in assigned_roles]
            raise PermissionDeniedError(
                f"Cannot delete permission assigned to roles: {', '.join(role_names)}"
            )

        # Delete permission
        stmt = delete(permissions).where(permissions.c.id == permission_id)
        await self.db.execute(stmt)

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
        query = select(permissions)

        conditions = []
        if tenant_id:
            conditions.append(
                or_(
                    permissions.c.tenant_id == tenant_id,
                    permissions.c.tenant_id.is_(None),
                )
            )

        if resource:
            conditions.append(permissions.c.resource == resource.value)

        if action:
            conditions.append(permissions.c.action == action.value)

        if not include_system:
            conditions.append(permissions.c.is_system == False)

        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(permissions.c.resource, permissions.c.action)

        # Add pagination
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)

        results = await self.db.fetch_all(query)
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
        if len(parts) < 2:
            return False

        resource = parts[0]
        action = parts[1]

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

        # Get all roles assigned to user with CTE for role hierarchy
        role_hierarchy_cte = text(
            """
            WITH RECURSIVE role_tree AS (
                -- Base: roles directly assigned to user
                SELECT r.id, r.parent_ids, 1 as level
                FROM roles r
                JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = :user_id 
                AND ur.is_active = true
                AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
                AND (:tenant_id::uuid IS NULL OR ur.tenant_id = :tenant_id)
                
                UNION ALL
                
                -- Recursive: parent roles
                SELECT r.id, r.parent_ids, rt.level + 1
                FROM roles r
                JOIN role_tree rt ON r.id = ANY(rt.parent_ids)
                WHERE r.is_active = true
            )
            SELECT DISTINCT id FROM role_tree
        """
        )

        # Execute CTE to get all role IDs
        all_roles = await self.db.fetch_all(
            role_hierarchy_cte, {"user_id": user_id, "tenant_id": tenant_id}
        )

        if not all_roles:
            return set()

        role_ids = [r["id"] for r in all_roles]

        # Get all permissions for these roles
        perm_query = (
            select(permissions.c.resource, permissions.c.action, permissions.c.scope)
            .distinct()
            .select_from(
                permissions.join(
                    role_permissions,
                    permissions.c.id == role_permissions.c.permission_id,
                )
            )
            .where(role_permissions.c.role_id.in_(role_ids))
        )

        permissions_list = await self.db.fetch_all(perm_query)

        # Convert to permission strings
        permission_strings = set()
        for p in permissions_list:
            if p["scope"]:
                permission_strings.add(f"{p['resource']}:{p['action']}:{p['scope']}")
            else:
                permission_strings.add(f"{p['resource']}:{p['action']}")

        # Get resource-scoped permissions from user_roles
        scope_conditions = [
            user_roles.c.user_id == user_id,
            user_roles.c.is_active == True,
        ]
        if tenant_id:
            scope_conditions.append(user_roles.c.tenant_id == tenant_id)

        scope_query = select(user_roles.c.resource_scope).where(and_(*scope_conditions))

        scopes = await self.db.fetch_all(scope_query)
        for scope in scopes:
            if scope["resource_scope"]:
                for resource_id in scope["resource_scope"].values():
                    permission_strings.add(f"*:*:{resource_id}")

        # Cache the result
        self._permission_cache[cache_key] = permission_strings

        return permission_strings

    async def grant_permission_to_role(
        self, role_id: UUID, permission_id: UUID, granted_by: Optional[UUID] = None
    ):
        """Grant a permission to a role"""
        # Check if role exists
        role = await self.db.fetch_one(select(roles).where(roles.c.id == role_id))
        if not role:
            raise RoleNotFoundError(role_id)

        # Check if permission already granted
        exists_query = select(role_permissions).where(
            and_(
                role_permissions.c.role_id == role_id,
                role_permissions.c.permission_id == permission_id,
            )
        )

        existing = await self.db.fetch_one(exists_query)
        if not existing:
            stmt = insert(role_permissions).values(
                role_id=role_id,
                permission_id=permission_id,
                granted_at=datetime.now(timezone.utc),
            )
            await self.db.execute(stmt)

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
        stmt = delete(role_permissions).where(
            and_(
                role_permissions.c.role_id == role_id,
                role_permissions.c.permission_id == permission_id,
            )
        )
        await self.db.execute(stmt)

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
        users_query = (
            select(user_roles.c.user_id)
            .distinct()
            .where(user_roles.c.role_id == role_id)
        )
        users = await self.db.fetch_all(users_query)

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
        query = select(tenants).where(tenants.c.id == tenant_id)
        result = await self.db.fetch_one(query)
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
            stmt = insert(audit_logs).values(
                user_id=user_id,
                tenant_id=tenant_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                old_value=old_value,
                new_value=new_value,
                created_at=datetime.now(timezone.utc),
            )
            await self.db.execute(stmt)
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")

    async def clear_user_cache(self, user_id: UUID):
        """Clear permission cache for a specific user"""
        keys_to_clear = [
            key for key in self._permission_cache.keys() if key.startswith(str(user_id))
        ]
        for key in keys_to_clear:
            self._permission_cache.pop(key, None)
        logger.info(f"Cleared permission cache for user {user_id}")

    async def clear_user_cache_for_role(self, role_id: UUID):
        """Clear permission cache for all users with a specific role"""
        try:
            # Get all users with this role
            query = (
                select(user_roles.c.user_id)
                .distinct()
                .where(user_roles.c.role_id == role_id)
            )
            users = await self.db.fetch_all(query)

            # Clear cache for each user
            for user in users:
                await self.clear_user_cache(user["user_id"])

            logger.info(f"Cleared permission cache for all users with role {role_id}")
        except Exception as e:
            logger.error(f"Failed to clear cache for role {role_id}: {e}")

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
