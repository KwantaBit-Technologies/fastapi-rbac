# rbac/services/role_service.py
from typing import Optional, List, Dict, Any, Set, Tuple
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy import select, insert, update, delete, and_, or_, func, text, union
from sqlalchemy.sql import exists

from core.models import Role, Permission, UserRole
from core.database import (
    Database,
    roles,
    tenants,
    user_roles,
    role_permissions,
    permissions,
    audit_logs,
)
from core.exceptions import (
    RoleNotFoundError,
    CircularRoleHierarchyError,
    PermissionDeniedError,
    TenantNotFoundError,
)
from core.constants import DEFAULT_ROLES, ResourceType, PermissionAction
from utils.logger import setup_logger
from .permission_service import PermissionService

logger = setup_logger("ROLE_SERVICE")


class RoleService:
    """Service for managing roles and role hierarchies using SQLAlchemy Core"""

    def __init__(self, db: Database, permission_service: PermissionService):
        self.db = db
        self.permission_service = permission_service
        self._role_hierarchy_cache: Dict[UUID, Set[UUID]] = (
            {}
        )  # role_id -> set of child role IDs
        self._role_permissions_cache: Dict[str, Set[str]] = (
            {}
        )  # role_id:include_inherited -> set of permission strings

    async def initialize_default_roles(self, tenant_id: Optional[UUID] = None):
        """Initialize default system roles"""
        for role_key, role_config in DEFAULT_ROLES.items():
            # Check if role already exists
            stmt = select(roles.c.id).where(
                and_(
                    roles.c.name == role_config["name"], roles.c.tenant_id == tenant_id
                )
            )
            existing = await self.db.fetch_one(stmt)

            if not existing:
                # Create the role
                role = await self.create_role(
                    name=role_config["name"],
                    description=role_config["description"],
                    is_system_role=role_config["is_system_role"],
                    tenant_id=tenant_id,
                )

                # Grant default permissions
                for perm_string in role_config["permissions"]:
                    permission = await self.permission_service.get_permission_by_string(
                        perm_string, tenant_id
                    )
                    if not permission:
                        # Create the permission if it doesn't exist
                        parts = perm_string.split(":")
                        resource = parts[0]
                        action = parts[1] if len(parts) > 1 else "*"
                        scope = parts[2] if len(parts) > 2 else None

                        permission = await self.permission_service.create_permission(
                            name=f"{resource}:{action}",
                            resource=(
                                ResourceType(resource)
                                if resource != "*"
                                else ResourceType.ALL
                            ),
                            action=(
                                PermissionAction(action)
                                if action != "*"
                                else PermissionAction.MANAGE
                            ),
                            scope=scope,
                            tenant_id=tenant_id,
                            created_by=None,  # System creation
                        )

                    await self.permission_service.grant_permission_to_role(
                        role_id=role.id, permission_id=permission.id
                    )

                logger.info(f"Initialized default role: {role.name}")

    async def create_role(
        self,
        name: str,
        description: Optional[str] = None,
        parent_ids: Optional[List[UUID]] = None,
        is_system_role: bool = False,
        tenant_id: Optional[UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        created_by: Optional[UUID] = None,
    ) -> Role:
        """Create a new role with optional parent relationships"""

        # Check if tenant exists if tenant_id provided
        if tenant_id:
            tenant = await self._get_tenant(tenant_id)
            if not tenant:
                raise TenantNotFoundError(tenant_id)

        # Check for duplicate role name within tenant
        stmt = select(roles.c.id).where(
            and_(roles.c.name == name, roles.c.tenant_id == tenant_id)
        )
        existing = await self.db.fetch_one(stmt)

        if existing:
            raise PermissionDeniedError(
                f"Role with name '{name}' already exists in this tenant"
            )

        # Validate parent hierarchy
        if parent_ids:
            await self._validate_role_hierarchy(None, parent_ids, tenant_id)

        # Create the role
        now = datetime.now(timezone.utc)
        stmt = (
            insert(roles)
            .values(
                name=name,
                description=description,
                parent_ids=parent_ids or [],
                is_system_role=is_system_role,
                tenant_id=tenant_id,
                metadata=metadata or {},
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            .returning(*roles.columns)
        )

        result = await self.db.fetch_one(stmt)
        if not result:
            raise RuntimeError("Failed to create role")

        role = Role.model_validate(result)

        # Audit log
        await self._audit_log(
            user_id=created_by,
            tenant_id=tenant_id,
            action="CREATE",
            resource_type="role",
            resource_id=role.id,
            new_value=role.model_dump(),
        )

        # Clear hierarchy cache
        self._role_hierarchy_cache.clear()

        logger.info(f"Created role: {role.name} (ID: {role.id})")
        return role

    async def get_role(
        self, role_id: UUID, tenant_id: Optional[UUID] = None
    ) -> Optional[Role]:
        """Get role by ID"""
        conditions = [roles.c.id == role_id]

        if tenant_id:
            conditions.append(
                or_(roles.c.tenant_id == tenant_id, roles.c.tenant_id.is_(None))
            )

        stmt = select(roles).where(and_(*conditions))
        result = await self.db.fetch_one(stmt)
        return Role.model_validate(result) if result else None

    async def get_role_by_name(
        self, name: str, tenant_id: Optional[UUID] = None
    ) -> Optional[Role]:
        """Get role by name within tenant"""
        conditions = [roles.c.name == name]

        if tenant_id:
            conditions.append(roles.c.tenant_id == tenant_id)
        else:
            conditions.append(roles.c.tenant_id.is_(None))

        stmt = select(roles).where(and_(*conditions))
        result = await self.db.fetch_one(stmt)
        return Role.model_validate(result) if result else None

    async def update_role(
        self,
        role_id: UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parent_ids: Optional[List[UUID]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        is_active: Optional[bool] = None,
        updated_by: Optional[UUID] = None,
    ) -> Role:
        """Update role details"""
        # Get existing role
        existing = await self.get_role(role_id)
        if not existing:
            raise RoleNotFoundError(role_id)

        # Don't allow modifying system role names
        if existing.is_system_role and name and name != existing.name:
            raise PermissionDeniedError(f"Cannot rename system role: {existing.name}")

        # Check for duplicate name if changing name
        if name and name != existing.name:
            stmt = select(roles.c.id).where(
                and_(
                    roles.c.name == name,
                    roles.c.tenant_id == existing.tenant_id,
                    roles.c.id != role_id,
                )
            )
            duplicate = await self.db.fetch_one(stmt)
            if duplicate:
                raise PermissionDeniedError(f"Role with name '{name}' already exists")

        # Validate new parent hierarchy if changing parents
        if parent_ids is not None:
            await self._validate_role_hierarchy(role_id, parent_ids, existing.tenant_id)

        # Build update values
        update_values = {}
        if name is not None:
            update_values["name"] = name
        if description is not None:
            update_values["description"] = description
        if parent_ids is not None:
            update_values["parent_ids"] = parent_ids
        if metadata is not None:
            update_values["metadata"] = metadata
        if is_active is not None:
            update_values["is_active"] = is_active

        if update_values:
            update_values["updated_at"] = datetime.now(timezone.utc)

            stmt = (
                update(roles)
                .where(roles.c.id == role_id)
                .values(**update_values)
                .returning(*roles.columns)
            )

            result = await self.db.fetch_one(stmt)
            if not result:
                raise RuntimeError("Failed to update role")

            updated = Role.model_validate(result)

            # Clear caches
            self._role_hierarchy_cache.clear()
            self._role_permissions_cache.clear()
            await self.permission_service.clear_user_cache_for_role(role_id)

            # Audit log
            await self._audit_log(
                user_id=updated_by,
                tenant_id=existing.tenant_id,
                action="UPDATE",
                resource_type="role",
                resource_id=role_id,
                old_value=existing.model_dump(),
                new_value=updated.model_dump(),
            )

            logger.info(f"Updated role: {updated.name}")
            return updated

        return existing

    async def delete_role(
        self,
        role_id: UUID,
        transfer_to_role_id: Optional[UUID] = None,
        deleted_by: Optional[UUID] = None,
    ):
        """Delete a role, optionally transferring assignments to another role"""
        # Get existing role
        existing = await self.get_role(role_id)
        if not existing:
            raise RoleNotFoundError(role_id)

        # Don't allow deleting system roles
        if existing.is_system_role:
            raise PermissionDeniedError(f"Cannot delete system role: {existing.name}")

        # Check if role has any users assigned
        stmt = (
            select(func.count())
            .select_from(user_roles)
            .where(user_roles.c.role_id == role_id)
        )
        user_count = await self.db.fetch_val(stmt) or 0

        if user_count > 0 and not transfer_to_role_id:
            raise PermissionDeniedError(
                f"Cannot delete role with {user_count} assigned users. "
                "Provide transfer_to_role_id to reassign users."
            )

        # Transfer users if requested
        if transfer_to_role_id:
            transfer_role = await self.get_role(transfer_to_role_id, existing.tenant_id)
            if not transfer_role:
                raise RoleNotFoundError(transfer_to_role_id)

            stmt = (
                update(user_roles)
                .where(user_roles.c.role_id == role_id)
                .values(role_id=transfer_to_role_id)
            )
            await self.db.execute(stmt)

            logger.info(
                f"Transferred users from role {role_id} to {transfer_to_role_id}"
            )

        # Remove role from any parent relationships in other roles
        # This uses PostgreSQL's array_remove function via text()
        stmt = text(
            """
            UPDATE roles 
            SET parent_ids = array_remove(parent_ids, :role_id)
            WHERE :role_id = ANY(parent_ids)
        """
        )
        await self.db.execute(stmt, {"role_id": role_id})

        # Delete role permissions
        stmt = delete(role_permissions).where(role_permissions.c.role_id == role_id)
        await self.db.execute(stmt)

        # Delete user assignments
        stmt = delete(user_roles).where(user_roles.c.role_id == role_id)
        await self.db.execute(stmt)

        # Delete the role
        stmt = delete(roles).where(roles.c.id == role_id)
        await self.db.execute(stmt)

        # Clear caches
        self._role_hierarchy_cache.clear()
        self._role_permissions_cache.clear()
        await self.permission_service.clear_user_cache_for_role(role_id)

        # Audit log
        await self._audit_log(
            user_id=deleted_by,
            tenant_id=existing.tenant_id,
            action="DELETE",
            resource_type="role",
            resource_id=role_id,
            old_value=existing.model_dump(),
        )

        logger.info(f"Deleted role: {existing.name}")

    async def list_roles(
        self,
        tenant_id: Optional[UUID] = None,
        include_system: bool = True,
        include_inactive: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Role]:
        """List roles with optional filters"""
        conditions = []

        if tenant_id:
            conditions.append(
                or_(roles.c.tenant_id == tenant_id, roles.c.tenant_id.is_(None))
            )
        else:
            conditions.append(roles.c.tenant_id.is_(None))

        if not include_system:
            conditions.append(roles.c.is_system_role == False)

        if not include_inactive:
            conditions.append(roles.c.is_active == True)

        stmt = select(roles).where(and_(*conditions)).order_by(roles.c.name)

        if limit:
            stmt = stmt.limit(limit)
        if offset:
            stmt = stmt.offset(offset)

        results = await self.db.fetch_all(stmt)
        return [Role.model_validate(r) for r in results]

    async def get_role_hierarchy(self, role_id: UUID) -> Dict[str, List[Dict]]:
        """Get complete role hierarchy tree"""
        role = await self.get_role(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        # Get all descendants
        descendants = await self._get_descendant_roles(role_id)

        # Get all ancestors
        ancestors = await self._get_ancestor_roles(role_id)

        # Get all permissions (including inherited)
        permissions = await self.get_role_permissions(role_id, include_inherited=True)

        return {
            "role": role.model_dump(),
            "ancestors": [r.model_dump() for r in ancestors],
            "descendants": [r.model_dump() for r in descendants],
            "permissions": [p.model_dump() for p in permissions],
            "inherited_permissions_count": (
                len(permissions) - len(role.permissions) if role.permissions else 0
            ),
        }

    async def add_role_parent(
        self, role_id: UUID, parent_id: UUID, added_by: Optional[UUID] = None
    ):
        """Add a parent to a role (role will inherit from parent)"""
        # Get roles
        role = await self.get_role(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        parent = await self.get_role(parent_id, role.tenant_id)
        if not parent:
            raise RoleNotFoundError(parent_id)

        # Check for circular hierarchy
        if await self._would_create_cycle(role_id, parent_id):
            raise CircularRoleHierarchyError(role_id, parent_id)

        # Add parent if not already present
        if parent_id not in role.parent_ids:
            new_parent_ids = role.parent_ids + [parent_id]

            stmt = (
                update(roles)
                .where(roles.c.id == role_id)
                .values(
                    parent_ids=new_parent_ids, updated_at=datetime.now(timezone.utc)
                )
            )
            await self.db.execute(stmt)

            # Clear caches
            self._role_hierarchy_cache.clear()
            self._role_permissions_cache.clear()
            await self.permission_service.clear_user_cache_for_role(role_id)

            # Audit log
            await self._audit_log(
                user_id=added_by,
                tenant_id=role.tenant_id,
                action="ADD_PARENT",
                resource_type="role",
                resource_id=role_id,
                new_value={"parent_id": str(parent_id)},
            )

            logger.info(f"Added parent {parent_id} to role {role_id}")

    async def remove_role_parent(
        self, role_id: UUID, parent_id: UUID, removed_by: Optional[UUID] = None
    ):
        """Remove a parent from a role"""
        role = await self.get_role(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        if parent_id in role.parent_ids:
            new_parent_ids = [pid for pid in role.parent_ids if pid != parent_id]

            stmt = (
                update(roles)
                .where(roles.c.id == role_id)
                .values(
                    parent_ids=new_parent_ids, updated_at=datetime.now(timezone.utc)
                )
            )
            await self.db.execute(stmt)

            # Clear caches
            self._role_hierarchy_cache.clear()
            self._role_permissions_cache.clear()
            await self.permission_service.clear_user_cache_for_role(role_id)

            # Audit log
            await self._audit_log(
                user_id=removed_by,
                tenant_id=role.tenant_id,
                action="REMOVE_PARENT",
                resource_type="role",
                resource_id=role_id,
                old_value={"parent_id": str(parent_id)},
            )

            logger.info(f"Removed parent {parent_id} from role {role_id}")

    async def get_role_permissions(
        self, role_id: UUID, include_inherited: bool = True
    ) -> List[Permission]:
        """Get all permissions for a role"""
        # Check cache
        cache_key = f"{role_id}:{include_inherited}"
        if cache_key in self._role_permissions_cache:
            # Convert cached permission strings back to Permission objects
            perm_strings = self._role_permissions_cache[cache_key]
            permissions_list = []
            for perm_string in perm_strings:
                perm = await self.permission_service.get_permission_by_string(
                    perm_string
                )
                if perm:
                    permissions_list.append(perm)
            return permissions_list

        # Get direct permissions
        stmt = (
            select(permissions)
            .select_from(
                permissions.join(
                    role_permissions,
                    permissions.c.id == role_permissions.c.permission_id,
                )
            )
            .where(role_permissions.c.role_id == role_id)
        )

        direct_results = await self.db.fetch_all(stmt)
        permissions_list = [Permission.model_validate(p) for p in direct_results]
        perm_strings = {p.permission_string for p in permissions_list}

        # Include inherited permissions if requested
        if include_inherited:
            ancestors = await self._get_ancestor_roles(role_id)
            for ancestor in ancestors:
                ancestor_perms = await self.get_role_permissions(
                    ancestor.id, include_inherited=False
                )
                for perm in ancestor_perms:
                    if perm.permission_string not in perm_strings:
                        permissions_list.append(perm)
                        perm_strings.add(perm.permission_string)

        # Cache the permission strings
        self._role_permissions_cache[cache_key] = perm_strings

        return permissions_list

    async def get_roles_for_user(
        self,
        user_id: UUID,
        tenant_id: Optional[UUID] = None,
        include_inherited: bool = True,
    ) -> List[Tuple[Role, Optional[Dict]]]:
        """Get all roles assigned to a user"""
        conditions = [
            user_roles.c.user_id == user_id,
            user_roles.c.is_active == True,
            or_(
                user_roles.c.expires_at.is_(None),
                user_roles.c.expires_at > func.current_timestamp(),
            ),
        ]

        if tenant_id:
            conditions.append(user_roles.c.tenant_id == tenant_id)

        stmt = (
            select(roles, user_roles.c.resource_scope)
            .select_from(roles.join(user_roles, roles.c.id == user_roles.c.role_id))
            .where(and_(*conditions))
        )

        results = await self.db.fetch_all(stmt)

        roles_with_scope = []
        for row in results:
            # Extract role data (excluding resource_scope)
            role_data = {k: v for k, v in row.items() if k != "resource_scope"}
            role = Role.model_validate(role_data)
            roles_with_scope.append((role, row["resource_scope"]))

        # Include inherited roles if requested
        if include_inherited:
            inherited_roles = set()
            for role, _ in roles_with_scope:
                ancestors = await self._get_ancestor_roles(role.id)
                for ancestor in ancestors:
                    if not any(r[0].id == ancestor.id for r in roles_with_scope):
                        inherited_roles.add((ancestor, None))

            roles_with_scope.extend(list(inherited_roles))

        return roles_with_scope

    async def get_users_in_role(
        self,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        include_inherited: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get all users assigned to a role"""
        role_ids = [role_id]

        if include_inherited:
            descendants = await self._get_descendant_roles(role_id)
            role_ids.extend([r.id for r in descendants])

        conditions = [
            user_roles.c.role_id.in_(role_ids),
            user_roles.c.is_active == True,
            or_(
                user_roles.c.expires_at.is_(None),
                user_roles.c.expires_at > func.current_timestamp(),
            ),
        ]

        if tenant_id:
            conditions.append(user_roles.c.tenant_id == tenant_id)

        stmt = (
            select(
                user_roles.c.user_id,
                user_roles.c.resource_scope,
                user_roles.c.granted_at,
                user_roles.c.expires_at,
                roles.c.name.label("role_name"),
                roles.c.id.label("role_id"),
            )
            .select_from(user_roles.join(roles, user_roles.c.role_id == roles.c.id))
            .where(and_(*conditions))
            .distinct()
            .order_by(user_roles.c.granted_at.desc())
        )

        if limit:
            stmt = stmt.limit(limit)
        if offset:
            stmt = stmt.offset(offset)

        results = await self.db.fetch_all(stmt)
        return [dict(r) for r in results]

    async def _validate_role_hierarchy(
        self, role_id: Optional[UUID], parent_ids: List[UUID], tenant_id: Optional[UUID]
    ):
        """Validate that the role hierarchy doesn't create cycles"""
        if not parent_ids:
            return

        # Check if all parent roles exist
        for pid in parent_ids:
            parent = await self.get_role(pid, tenant_id)
            if not parent:
                raise RoleNotFoundError(pid)

        # Check for cycles
        if role_id:
            for pid in parent_ids:
                if await self._would_create_cycle(role_id, pid):
                    raise CircularRoleHierarchyError(role_id, pid)

    async def _would_create_cycle(self, role_id: UUID, parent_id: UUID) -> bool:
        """Check if adding parent_id to role_id would create a cycle"""
        if role_id == parent_id:
            return True

        # Get all descendants of parent
        descendants = await self._get_descendant_roles(parent_id)
        return role_id in [d.id for d in descendants]

    async def _get_descendant_roles(self, role_id: UUID) -> List[Role]:
        """Get all roles that inherit from this role"""
        # Check cache
        if role_id in self._role_hierarchy_cache:
            descendant_ids = self._role_hierarchy_cache[role_id]
            descendants = []
            for rid in descendant_ids:
                role = await self.get_role(rid)
                if role:
                    descendants.append(role)
            return descendants

        # Use recursive CTE to get all descendants
        descendant_cte = text(
            """
            WITH RECURSIVE role_descendants AS (
                -- Base: direct children
                SELECT id, parent_ids, 1 as level
                FROM roles
                WHERE :role_id = ANY(parent_ids)
                
                UNION ALL
                
                -- Recursive: grandchildren
                SELECT r.id, r.parent_ids, rd.level + 1
                FROM roles r
                JOIN role_descendants rd ON r.id = ANY(rd.parent_ids)
            )
            SELECT DISTINCT id FROM role_descendants
        """
        )

        results = await self.db.fetch_all(descendant_cte, {"role_id": role_id})

        descendant_ids = {r["id"] for r in results}
        descendants = []

        for rid in descendant_ids:
            role = await self.get_role(rid)
            if role:
                descendants.append(role)

        # Cache the result
        self._role_hierarchy_cache[role_id] = descendant_ids

        return descendants

    async def _get_ancestor_roles(self, role_id: UUID) -> List[Role]:
        """Get all roles that this role inherits from"""
        role = await self.get_role(role_id)
        if not role or not role.parent_ids:
            return []

        # Use recursive CTE to get all ancestors
        ancestor_cte = text(
            """
            WITH RECURSIVE role_ancestors AS (
                -- Base: direct parents
                SELECT id, parent_ids, 1 as level
                FROM roles
                WHERE id = ANY(:parent_ids::uuid[])
                
                UNION ALL
                
                -- Recursive: grandparents
                SELECT r.id, r.parent_ids, ra.level + 1
                FROM roles r
                JOIN role_ancestors ra ON r.id = ANY(ra.parent_ids)
            )
            SELECT DISTINCT id FROM role_ancestors
        """
        )

        results = await self.db.fetch_all(ancestor_cte, {"parent_ids": role.parent_ids})

        ancestors = []
        for row in results:
            ancestor = await self.get_role(row["id"])
            if ancestor:
                ancestors.append(ancestor)

        return ancestors

    async def _get_tenant(self, tenant_id: UUID) -> Optional[Any]:
        """Get tenant by ID"""
        stmt = select(tenants).where(tenants.c.id == tenant_id)
        result = await self.db.fetch_one(stmt)
        from core.models import Tenant

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

    async def bulk_assign_permissions(
        self,
        role_id: UUID,
        permission_ids: List[UUID],
        assigned_by: Optional[UUID] = None,
    ):
        """Bulk assign multiple permissions to a role"""
        role = await self.get_role(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        # Get existing permissions
        stmt = select(role_permissions.c.permission_id).where(
            role_permissions.c.role_id == role_id
        )
        existing = await self.db.fetch_all(stmt)
        existing_ids = {r["permission_id"] for r in existing}

        # Add new permissions
        new_permissions = []
        for perm_id in permission_ids:
            if perm_id not in existing_ids:
                await self.permission_service.grant_permission_to_role(
                    role_id=role_id, permission_id=perm_id, granted_by=assigned_by
                )
                new_permissions.append(str(perm_id))

        if new_permissions:
            logger.info(
                f"Bulk assigned {len(new_permissions)} permissions to role {role_id}"
            )

    async def get_role_stats(self, role_id: UUID) -> Dict[str, Any]:
        """Get statistics about a role"""
        role = await self.get_role(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        # Get user count
        user_count_stmt = (
            select(func.count())
            .select_from(user_roles)
            .where(
                and_(user_roles.c.role_id == role_id, user_roles.c.is_active == True)
            )
        )
        user_count = await self.db.fetch_val(user_count_stmt) or 0

        # Get permission count
        perm_count_stmt = (
            select(func.count())
            .select_from(role_permissions)
            .where(role_permissions.c.role_id == role_id)
        )
        perm_count = await self.db.fetch_val(perm_count_stmt) or 0

        # Get descendant count
        descendants = await self._get_descendant_roles(role_id)

        # Get ancestor count
        ancestors = await self._get_ancestor_roles(role_id)

        # Get inherited permission count
        all_permissions = await self.get_role_permissions(
            role_id, include_inherited=True
        )

        return {
            "role_id": str(role_id),
            "role_name": role.name,
            "is_system_role": role.is_system_role,
            "is_active": role.is_active,
            "direct_user_count": user_count,
            "direct_permission_count": perm_count,
            "inherited_permission_count": len(all_permissions) - perm_count,
            "descendant_count": len(descendants),
            "ancestor_count": len(ancestors),
            "hierarchy_depth": len(ancestors),
            "created_at": role.created_at.isoformat() if role.created_at else None,
            "updated_at": role.updated_at.isoformat() if role.updated_at else None,
        }
