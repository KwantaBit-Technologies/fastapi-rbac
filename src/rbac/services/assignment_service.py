# rbac/services/assignment_service.py
from typing import Optional, List, Dict, Any, Tuple, Callable, Awaitable
from uuid import UUID
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, insert, update, delete, and_, or_, func, desc
from enum import Enum

from rbac.core.models import UserRole, Role, Permission
from rbac.core.database import Database, user_roles, roles, tenants, audit_logs
from rbac.core.exceptions import (
    RoleNotFoundError,
    PermissionDeniedError,
    TenantNotFoundError,
)
from .role_service import RoleService
from .permission_service import PermissionService
from rbac.utils.logger import setup_logger

logger = setup_logger("Assignment_service")


class RoleExclusivity(str, Enum):
    """Defines exclusivity rules for role assignments"""

    NONE = "none"  # No restrictions
    GLOBAL = "global"  # User can only have one role globally
    PER_TENANT = "per_tenant"  # User can only have one role per tenant
    MUTUALLY_EXCLUSIVE = "mutually_exclusive"  # Certain roles cannot be combined
    HIERARCHICAL = "hierarchical"  # Roles must follow hierarchy rules


class AssignmentValidator:
    """Handles custom validation rules for role assignments"""

    def __init__(self, db: Database, role_service: RoleService):
        self.db = db
        self.role_service = role_service
        self._custom_validators: List[
            Callable[
                [UUID, UUID, Optional[UUID], Optional[Dict]],
                Awaitable[Tuple[bool, str]],
            ]
        ] = []

    async def validate_exclusivity(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        exclusivity_rule: RoleExclusivity = RoleExclusivity.NONE,
        exclusive_role_ids: Optional[List[UUID]] = None,
    ) -> Tuple[bool, str]:
        """
        Validate role exclusivity rules

        Args:
            user_id: The user to assign the role to
            role_id: The role being assigned
            tenant_id: Optional tenant context
            exclusivity_rule: The exclusivity rule to apply
            exclusive_role_ids: List of role IDs that cannot be combined with this role

        Returns:
            Tuple of (is_valid, message)
        """

        # Get user's current active roles
        from sqlalchemy import select

        stmt = select(user_roles.c.role_id).where(
            and_(
                user_roles.c.user_id == user_id,
                user_roles.c.is_active == True,
                or_(
                    user_roles.c.expires_at.is_(None),
                    user_roles.c.expires_at > func.current_timestamp(),
                ),
            )
        )

        if tenant_id:
            stmt = stmt.where(user_roles.c.tenant_id == tenant_id)

        current_roles = await self.db.fetch_all(stmt)
        current_role_ids = {r["role_id"] for r in current_roles}

        # If user has no roles, always valid
        if not current_role_ids:
            return True, "Valid"

        # Apply exclusivity rules
        if exclusivity_rule == RoleExclusivity.GLOBAL:
            # User can only have one role globally
            if current_role_ids:
                return False, "User already has a role assigned globally"

        elif exclusivity_rule == RoleExclusivity.PER_TENANT:
            # User can only have one role per tenant
            if current_role_ids:
                return False, f"User already has a role in this tenant"

        elif exclusivity_rule == RoleExclusivity.MUTUALLY_EXCLUSIVE:
            # Check if any current role is in the exclusive list
            if exclusive_role_ids:
                conflicting = current_role_ids.intersection(set(exclusive_role_ids))
                if conflicting:
                    # Get role names for better error message
                    conflicting_roles = []
                    for rid in conflicting:
                        role = await self.role_service.get_role(rid, tenant_id)
                        if role:
                            conflicting_roles.append(role.name)

                    return (
                        False,
                        f"Cannot combine with exclusive roles: {', '.join(conflicting_roles)}",
                    )

        return True, "Valid"

    async def validate_hierarchy(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
    ) -> Tuple[bool, str]:
        """
        Validate role hierarchy rules
        Ensures that if a user has a child role, they must have the parent role
        """

        # Get the role being assigned
        new_role = await self.role_service.get_role(role_id, tenant_id)
        if not new_role:
            return False, f"Role {role_id} not found"

        return True, "Valid"

    async def validate_max_assignments(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        max_roles_per_user: int = 10,
    ) -> Tuple[bool, str]:
        """Validate that user doesn't exceed maximum role assignments"""

        # Count user's current active roles
        stmt = (
            select(func.count())
            .select_from(user_roles)
            .where(
                and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.is_active == True,
                    or_(
                        user_roles.c.expires_at.is_(None),
                        user_roles.c.expires_at > func.current_timestamp(),
                    ),
                )
            )
        )

        if tenant_id:
            stmt = stmt.where(user_roles.c.tenant_id == tenant_id)

        current_count = await self.db.fetch_val(stmt) or 0

        if current_count >= max_roles_per_user:
            return (
                False,
                f"User already has maximum number of roles ({max_roles_per_user})",
            )

        return True, "Valid"

    async def validate_business_hours(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
    ) -> Tuple[bool, str]:
        """
        Example custom validator: Only allow certain role assignments during business hours
        This is just an example - you can implement any custom logic
        """
        current_hour = datetime.now(timezone.utc).hour

        # Example: Don't allow sensitive role assignments outside business hours (9 AM - 5 PM UTC)
        sensitive_roles = ["admin", "super_admin", "manager"]

        role = await self.role_service.get_role(role_id, tenant_id)
        if role and role.name in sensitive_roles:
            if current_hour < 9 or current_hour > 17:
                return (
                    False,
                    "Sensitive roles can only be assigned during business hours (9 AM - 5 PM UTC)",
                )

        return True, "Valid"

    def register_validator(
        self,
        validator: Callable[
            [UUID, UUID, Optional[UUID], Optional[Dict]], Awaitable[Tuple[bool, str]]
        ],
    ):
        """Register a custom validator function"""
        self._custom_validators.append(validator)

    async def run_custom_validators(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        context: Optional[Dict] = None,
    ) -> Tuple[bool, str]:
        """Run all registered custom validators"""
        for validator in self._custom_validators:
            is_valid, message = await validator(user_id, role_id, tenant_id, context)
            if not is_valid:
                return False, message
        return True, "All custom validations passed"


class AssignmentService:
    """Service for managing user-role assignments with advanced features"""

    def __init__(
        self,
        db: Database,
        role_service: RoleService,
        permission_service: PermissionService,
    ):
        self.db = db
        self.role_service = role_service
        self.permission_service = permission_service
        self.validator = AssignmentValidator(db, role_service)
        self._assignment_cache: Dict[str, List[UserRole]] = (
            {}
        )  # user_id -> list of assignments

        # Configure exclusivity rules per role (can be loaded from database or config)
        self._role_exclusivity_rules: Dict[
            UUID, Tuple[RoleExclusivity, Optional[List[UUID]]]
        ] = {}

        # Configure max roles per user (can be per tenant or global)
        self._max_roles_per_user: Dict[Optional[UUID], int] = {
            None: 10,  # Global default
        }

        # Configure required validations per role
        self._required_validations: Dict[UUID, List[str]] = {}

    async def load_exclusivity_config(self):
        """Load exclusivity rules from database or config"""
        # This could load from a configuration table
        # For now, we'll set some defaults based on role names
        all_roles = await self.role_service.list_roles(include_system=True)

        for role in all_roles:
            if role.is_system_role:
                # System roles might have special rules
                if "admin" in role.name.lower():
                    # Admin roles might be mutually exclusive with other admin roles
                    admin_roles = [r.id for r in all_roles if "admin" in r.name.lower()]
                    self._role_exclusivity_rules[role.id] = (
                        RoleExclusivity.MUTUALLY_EXCLUSIVE,
                        [r for r in admin_roles if r != role.id],
                    )
            else:
                # Regular roles have no exclusivity by default
                self._role_exclusivity_rules[role.id] = (RoleExclusivity.NONE, None)

    async def assign_role_to_user(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        resource_scope: Optional[Dict[str, Any]] = None,
        expires_in_days: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        granted_by: Optional[UUID] = None,
        prevent_duplicates: bool = True,
        skip_validation: bool = False,
        validation_context: Optional[Dict] = None,
    ) -> UserRole:
        """Assign a role to a user with optional scope and expiration"""

        # Validate role exists
        role = await self.role_service.get_role(role_id, tenant_id)
        if not role:
            raise RoleNotFoundError(role_id)

        # Check if role is active
        if not role.is_active:
            raise PermissionDeniedError(f"Cannot assign inactive role: {role.name}")

        # Validate tenant if provided
        if tenant_id:
            tenant = await self._get_tenant(tenant_id)
            if not tenant:
                raise TenantNotFoundError(tenant_id)

        # Run validations unless skipped
        if not skip_validation:
            await self._validate_assignment(
                user_id=user_id,
                role_id=role_id,
                role=role,
                tenant_id=tenant_id,
                resource_scope=resource_scope,
                context=validation_context,
            )

        # Check for existing active assignment
        if prevent_duplicates:
            conditions = [
                user_roles.c.user_id == user_id,
                user_roles.c.role_id == role_id,
                user_roles.c.is_active == True,
                or_(
                    user_roles.c.expires_at.is_(None),
                    user_roles.c.expires_at > func.current_timestamp(),
                ),
            ]

            # Handle tenant_id condition (can be None)
            if tenant_id is not None:
                conditions.append(user_roles.c.tenant_id == tenant_id)
            else:
                conditions.append(user_roles.c.tenant_id.is_(None))

            stmt = select(user_roles).where(and_(*conditions))
            existing = await self.db.fetch_one(stmt)

            if existing:
                logger.info(f"User {user_id} already has role {role_id}")
                return UserRole.model_validate(existing)

        # Calculate expiration if set
        if expires_at is None and expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        # Create assignment
        now = datetime.now(timezone.utc)
        stmt = (
            insert(user_roles)
            .values(
                user_id=user_id,
                role_id=role_id,
                tenant_id=tenant_id,
                resource_scope=resource_scope or {},
                granted_by=granted_by,
                granted_at=now,
                expires_at=expires_at,
                is_active=True,
            )
            .returning(*user_roles.columns)
        )

        result = await self.db.fetch_one(stmt)
        if not result:
            raise RuntimeError("Failed to create role assignment")

        assignment = UserRole.model_validate(result)

        # Clear user cache
        await self.permission_service.clear_user_cache(user_id)
        self._assignment_cache.pop(str(user_id), None)

        # Audit log
        await self._audit_log(
            user_id=granted_by,
            tenant_id=tenant_id,
            action="ASSIGN",
            resource_type="user_role",
            resource_id=assignment.id,
            new_value=assignment.model_dump(mode="json"),
        )

        logger.info(f"Assigned role {role_id} to user {user_id}")
        return assignment

    async def _validate_assignment(
        self,
        user_id: UUID,
        role_id: UUID,
        role: Role,
        tenant_id: Optional[UUID] = None,
        resource_scope: Optional[Dict] = None,
        context: Optional[Dict] = None,
    ):
        """
        Comprehensive validation for role assignments
        Runs all configured validation rules
        """

        # Get exclusivity rule for this role
        exclusivity_rule, exclusive_ids = self._role_exclusivity_rules.get(
            role_id, (RoleExclusivity.NONE, None)
        )

        # 1. Validate exclusivity rules
        is_valid, message = await self.validator.validate_exclusivity(
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
            exclusivity_rule=exclusivity_rule,
            exclusive_role_ids=exclusive_ids,
        )
        if not is_valid:
            raise PermissionDeniedError(f"Exclusivity validation failed: {message}")

        # 2. Validate hierarchy rules
        is_valid, message = await self.validator.validate_hierarchy(
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
        )
        if not is_valid:
            raise PermissionDeniedError(f"Hierarchy validation failed: {message}")

        # 3. Validate max assignments
        max_roles = self._max_roles_per_user.get(
            tenant_id, self._max_roles_per_user[None]
        )
        is_valid, message = await self.validator.validate_max_assignments(
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
            max_roles_per_user=max_roles,
        )
        if not is_valid:
            raise PermissionDeniedError(f"Max assignments validation failed: {message}")

        # 4. Run any custom validators
        is_valid, message = await self.validator.run_custom_validators(
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
            context=context or {},
        )
        if not is_valid:
            raise PermissionDeniedError(f"Custom validation failed: {message}")

        # 5. Role-specific validations
        required_checks = self._required_validations.get(role_id, [])
        for check in required_checks:
            if check == "business_hours":
                is_valid, message = await self.validator.validate_business_hours(
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id,
                )
                if not is_valid:
                    raise PermissionDeniedError(
                        f"Business hours validation failed: {message}"
                    )

            # Add more role-specific checks here as needed

        logger.debug(
            f"All validations passed for assigning role {role_id} to user {user_id}"
        )

    async def validate_bulk_assignments(
        self,
        user_ids: List[UUID],
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        resource_scope: Optional[Dict] = None,
    ) -> Tuple[List[UUID], List[Tuple[UUID, str]]]:
        """
        Validate assignments for multiple users before bulk operation
        Returns (valid_user_ids, list of (invalid_user_id, reason))
        """
        valid_users = []
        invalid_users = []

        role = await self.role_service.get_role(role_id, tenant_id)
        if not role:
            raise RoleNotFoundError(role_id)

        for user_id in user_ids:
            try:
                await self._validate_assignment(
                    user_id=user_id,
                    role_id=role_id,
                    role=role,
                    tenant_id=tenant_id,
                    resource_scope=resource_scope,
                )
                valid_users.append(user_id)
            except PermissionDeniedError as e:
                invalid_users.append((user_id, str(e)))
            except Exception as e:
                invalid_users.append((user_id, f"Unexpected error: {e}"))

        return valid_users, invalid_users

    async def configure_role_exclusivity(
        self,
        role_id: UUID,
        rule: RoleExclusivity,
        exclusive_with: Optional[List[UUID]] = None,
    ):
        """Configure exclusivity rules for a role"""
        self._role_exclusivity_rules[role_id] = (rule, exclusive_with)
        logger.info(f"Configured exclusivity rule for role {role_id}: {rule.value}")

    async def configure_max_roles(
        self,
        max_roles: int,
        tenant_id: Optional[UUID] = None,
    ):
        """Configure maximum roles per user (globally or per tenant)"""
        self._max_roles_per_user[tenant_id] = max_roles
        logger.info(f"Set max roles to {max_roles} for tenant {tenant_id or 'global'}")

    def register_custom_validator(
        self,
        validator: Callable[
            [UUID, UUID, Optional[UUID], Optional[Dict]], Awaitable[Tuple[bool, str]]
        ],
    ):
        """Register a custom validator function"""
        self.validator.register_validator(validator)
        logger.info("Registered custom validator")

    async def revoke_role_from_user(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        revoked_by: Optional[UUID] = None,
        hard_delete: bool = False,
    ):
        """Revoke a role from a user"""
        tenant_condition = (
            user_roles.c.tenant_id == tenant_id
            if tenant_id is not None
            else user_roles.c.tenant_id.is_(None)
        )

        if hard_delete:
            stmt = (
                delete(user_roles)
                .where(
                    and_(
                        user_roles.c.user_id == user_id,
                        user_roles.c.role_id == role_id,
                        tenant_condition,
                    )
                )
                .returning(*user_roles.columns)
            )
            deleted = await self.db.fetch_one(stmt)

            if deleted:
                old_value = dict(deleted)

                # Audit log
                await self._audit_log(
                    user_id=revoked_by,
                    tenant_id=tenant_id,
                    action="DELETE",
                    resource_type="user_role",
                    resource_id=deleted["id"],
                    old_value=old_value,
                )

                logger.info(
                    f"Permanently deleted role {role_id} assignment for user {user_id}"
                )
        else:
            stmt = (
                update(user_roles)
                .where(
                    and_(
                        user_roles.c.user_id == user_id,
                        user_roles.c.role_id == role_id,
                        tenant_condition,
                        user_roles.c.is_active == True,
                    )
                )
                .values(is_active=False, updated_at=datetime.now(timezone.utc))
                .returning(*user_roles.columns)
            )
            updated = await self.db.fetch_one(stmt)

            if updated:
                # Audit log
                await self._audit_log(
                    user_id=revoked_by,
                    tenant_id=tenant_id,
                    action="REVOKE",
                    resource_type="user_role",
                    resource_id=updated["id"],
                    old_value=dict(updated),
                )

                logger.info(f"Revoked role {role_id} from user {user_id}")

        # Clear caches
        await self.permission_service.clear_user_cache(user_id)
        self._assignment_cache.pop(str(user_id), None)

    async def get_user_assignments(
        self,
        user_id: UUID,
        tenant_id: Optional[UUID] = None,
        include_inactive: bool = False,
        include_expired: bool = False,
    ) -> List[UserRole]:
        """Get all role assignments for a user"""

        # Check cache
        cache_key = f"{user_id}:{tenant_id}:{include_inactive}:{include_expired}"
        if cache_key in self._assignment_cache:
            return self._assignment_cache[cache_key]

        conditions = [user_roles.c.user_id == user_id]

        if tenant_id:
            conditions.append(
                or_(user_roles.c.tenant_id == tenant_id, user_roles.c.tenant_id.is_(None))
            )

        if not include_inactive:
            conditions.append(user_roles.c.is_active == True)

        if not include_inactive and not include_expired:
            conditions.append(
                or_(
                    user_roles.c.expires_at.is_(None),
                    user_roles.c.expires_at > func.current_timestamp(),
                )
            )

        stmt = select(user_roles).where(and_(*conditions)).order_by(desc(user_roles.c.granted_at))

        results = await self.db.fetch_all(stmt)
        assignments = [UserRole.model_validate(r) for r in results]

        # Cache the result
        self._assignment_cache[cache_key] = assignments

        return assignments

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
            # Get all descendant roles
            descendants = await self.role_service._get_descendant_roles(role_id)
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

    async def get_role_assignments(
        self,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        include_inactive: bool = False,
        include_expired: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UserRole]:
        """Get all users assigned to a role"""

        conditions = [user_roles.c.role_id == role_id]

        if tenant_id:
            conditions.append(user_roles.c.tenant_id == tenant_id)

        if not include_inactive:
            conditions.append(user_roles.c.is_active == True)

        if not include_expired:
            conditions.append(
                or_(
                    user_roles.c.expires_at.is_(None),
                    user_roles.c.expires_at > func.current_timestamp(),
                )
            )

        stmt = select(user_roles).where(and_(*conditions)).order_by(desc(user_roles.c.granted_at))
        if limit:
            stmt = stmt.limit(limit)
        if offset:
            stmt = stmt.offset(offset)

        results = await self.db.fetch_all(stmt)
        return [UserRole.model_validate(r) for r in results]

    async def update_assignment_scope(
        self,
        assignment_id: UUID,
        resource_scope: Dict[str, Any],
        updated_by: Optional[UUID] = None,
    ) -> UserRole:
        """Update the resource scope of an assignment"""

        # Get existing assignment
        existing = await self.db.fetch_one(select(user_roles).where(user_roles.c.id == assignment_id))

        if not existing:
            raise ValueError(f"Assignment not found: {assignment_id}")

        old_value = dict(existing)

        # Update scope
        updated = await self.db.fetch_one(
            update(user_roles)
            .where(user_roles.c.id == assignment_id)
            .values(resource_scope=resource_scope, updated_at=datetime.now(timezone.utc))
            .returning(*user_roles.columns)
        )

        assignment = UserRole.model_validate(updated)

        # Clear user cache
        await self.permission_service.clear_user_cache(assignment.user_id)
        self._assignment_cache.pop(str(assignment.user_id), None)

        # Audit log
        await self._audit_log(
            user_id=updated_by,
            tenant_id=assignment.tenant_id,
            action="UPDATE_SCOPE",
            resource_type="user_role",
            resource_id=assignment_id,
            old_value={"resource_scope": old_value["resource_scope"]},
            new_value={"resource_scope": resource_scope},
        )

        logger.info(f"Updated scope for assignment {assignment_id}")
        return assignment

    async def extend_assignment(
        self,
        assignment_id: UUID,
        additional_days: int,
        extended_by: Optional[UUID] = None,
    ) -> UserRole:
        """Extend the expiration date of an assignment"""

        # Get existing assignment
        existing = await self.db.fetch_one(select(user_roles).where(user_roles.c.id == assignment_id))

        if not existing:
            raise ValueError(f"Assignment not found: {assignment_id}")

        old_expires_at = existing["expires_at"]

        # Calculate new expiration
        if existing["expires_at"]:
            new_expires_at = existing["expires_at"] + timedelta(days=additional_days)
        else:
            new_expires_at = datetime.now(timezone.utc) + timedelta(days=additional_days)

        # Update expiration
        updated = await self.db.fetch_one(
            update(user_roles)
            .where(user_roles.c.id == assignment_id)
            .values(expires_at=new_expires_at, updated_at=datetime.now(timezone.utc))
            .returning(*user_roles.columns)
        )

        assignment = UserRole.model_validate(updated)

        # Clear user cache
        await self.permission_service.clear_user_cache(assignment.user_id)

        # Audit log
        await self._audit_log(
            user_id=extended_by,
            tenant_id=assignment.tenant_id,
            action="EXTEND",
            resource_type="user_role",
            resource_id=assignment_id,
            old_value={
                "expires_at": old_expires_at.isoformat() if old_expires_at else None
            },
            new_value={"expires_at": new_expires_at.isoformat()},
        )

        logger.info(f"Extended assignment {assignment_id} by {additional_days} days")
        return assignment

    async def bulk_assign_roles(
        self,
        user_ids: List[UUID],
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        resource_scope: Optional[Dict[str, Any]] = None,
        expires_in_days: Optional[int] = None,
        granted_by: Optional[UUID] = None,
    ) -> Tuple[int, List[UUID]]:
        """Bulk assign a role to multiple users"""

        successful = []
        failed = []

        for user_id in user_ids:
            try:
                await self.assign_role_to_user(
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id,
                    resource_scope=resource_scope,
                    expires_in_days=expires_in_days,
                    granted_by=granted_by,
                )
                successful.append(user_id)
            except Exception as e:
                logger.error(f"Failed to assign role to user {user_id}: {e}")
                failed.append(user_id)

        logger.info(
            f"Bulk assigned role {role_id} to {len(successful)} users, {len(failed)} failed"
        )
        return len(successful), failed

    async def transfer_assignments(
        self,
        from_role_id: UUID,
        to_role_id: UUID,
        tenant_id: Optional[UUID] = None,
        transferred_by: Optional[UUID] = None,
    ) -> int:
        """Transfer all assignments from one role to another"""

        # Validate roles
        from_role = await self.role_service.get_role(from_role_id, tenant_id)
        if not from_role:
            raise RoleNotFoundError(from_role_id)

        to_role = await self.role_service.get_role(to_role_id, tenant_id)
        if not to_role:
            raise RoleNotFoundError(to_role_id)

        # Get all active assignments for from_role
        assignments = await self.get_role_assignments(
            from_role_id, tenant_id, include_inactive=False
        )

        # Transfer each assignment
        transferred_count = 0
        for assignment in assignments:
            try:
                tenant_condition = (
                    user_roles.c.tenant_id == tenant_id
                    if tenant_id is not None
                    else user_roles.c.tenant_id.is_(None)
                )
                existing = await self.db.fetch_one(
                    select(user_roles.c.id).where(
                        and_(
                            user_roles.c.user_id == assignment.user_id,
                            user_roles.c.role_id == to_role_id,
                            tenant_condition,
                            user_roles.c.is_active == True,
                        )
                    )
                )

                if not existing:
                    # Create new assignment with same properties
                    await self.assign_role_to_user(
                        user_id=assignment.user_id,
                        role_id=to_role_id,
                        tenant_id=tenant_id,
                        resource_scope=assignment.resource_scope,
                        expires_at=assignment.expires_at,
                        granted_by=transferred_by,
                    )

                # Revoke old assignment
                await self.revoke_role_from_user(
                    user_id=assignment.user_id,
                    role_id=from_role_id,
                    tenant_id=tenant_id,
                    revoked_by=transferred_by,
                )

                transferred_count += 1

            except Exception as e:
                logger.error(f"Failed to transfer assignment {assignment.id}: {e}")

        # Audit log
        await self._audit_log(
            user_id=transferred_by,
            tenant_id=tenant_id,
            action="TRANSFER",
            resource_type="bulk",
            new_value={
                "from_role": str(from_role_id),
                "to_role": str(to_role_id),
                "count": transferred_count,
            },
        )

        logger.info(
            f"Transferred {transferred_count} assignments from role {from_role_id} to {to_role_id}"
        )
        return transferred_count

    async def get_expiring_assignments(
        self,
        days_threshold: int = 7,
        tenant_id: Optional[UUID] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get assignments that will expire within the specified days"""

        expiry_threshold = datetime.now(timezone.utc) + timedelta(days=days_threshold)

        conditions = [
            user_roles.c.expires_at.isnot(None),
            user_roles.c.expires_at <= expiry_threshold,
            user_roles.c.expires_at > func.current_timestamp(),
            user_roles.c.is_active == True,
        ]
        if tenant_id:
            conditions.append(user_roles.c.tenant_id == tenant_id)

        stmt = (
            select(
                user_roles,
                roles.c.name.label("role_name"),
            )
            .select_from(user_roles.join(roles, user_roles.c.role_id == roles.c.id))
            .where(and_(*conditions))
            .order_by(user_roles.c.expires_at)
            .limit(limit)
        )
        results = await self.db.fetch_all(stmt)
        return [dict(r) for r in results]

    async def get_user_effective_roles(
        self,
        user_id: UUID,
        tenant_id: Optional[UUID] = None,
        resource_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get all roles a user has, including inherited and scoped roles"""

        # Get direct assignments
        assignments = await self.get_user_assignments(user_id, tenant_id)

        effective_roles = []
        seen_role_ids = set()

        for assignment in assignments:
            role = await self.role_service.get_role(assignment.role_id, tenant_id)
            if not role:
                continue

            # Check if role applies to this resource
            if resource_id and assignment.resource_scope:
                if resource_id not in assignment.resource_scope.values():
                    continue

            if role.id not in seen_role_ids:
                role_data = role.model_dump(mode="json")
                role_data["assignment_id"] = str(assignment.id)
                role_data["resource_scope"] = assignment.resource_scope
                role_data["expires_at"] = assignment.expires_at
                role_data["is_direct"] = True
                effective_roles.append(role_data)
                seen_role_ids.add(role.id)

            # Add inherited roles
            if role.parent_ids:
                for parent_id in role.parent_ids:
                    if parent_id not in seen_role_ids:
                        parent_role = await self.role_service.get_role(
                            parent_id, tenant_id
                        )
                        if parent_role:
                            parent_data = parent_role.model_dump(mode="json")
                            parent_data["inherited_from"] = str(role.id)
                            parent_data["is_direct"] = False
                            effective_roles.append(parent_data)
                            seen_role_ids.add(parent_id)

        return effective_roles

    async def validate_assignment(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: Optional[UUID] = None,
        resource_scope: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Validate if a user can be assigned a role"""

        # Check if role exists and is active
        role = await self.role_service.get_role(role_id, tenant_id)
        if not role or not role.is_active:
            return False

        try:
            await self._validate_assignment(user_id, role_id, role, tenant_id, resource_scope)
            return True
        except PermissionDeniedError:
            return False

    async def get_assignment_history(
        self,
        user_id: Optional[UUID] = None,
        role_id: Optional[UUID] = None,
        tenant_id: Optional[UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get audit history for assignments"""

        conditions = [audit_logs.c.resource_type == "user_role"]

        if user_id:
            conditions.append(audit_logs.c.user_id == user_id)

        if role_id:
            conditions.append(audit_logs.c.new_value["role_id"].astext == str(role_id))

        if tenant_id:
            conditions.append(audit_logs.c.tenant_id == tenant_id)

        stmt = (
            select(audit_logs)
            .where(and_(*conditions))
            .order_by(desc(audit_logs.c.created_at))
            .limit(limit)
            .offset(offset)
        )

        results = await self.db.fetch_all(stmt)
        return [dict(r) for r in results]

    async def cleanup_expired_assignments(self) -> int:
        """Clean up or mark expired assignments"""

        stmt = (
            update(user_roles)
            .where(
                and_(
                    user_roles.c.expires_at < func.current_timestamp(),
                    user_roles.c.is_active == True,
                )
            )
            .values(is_active=False, updated_at=datetime.now(timezone.utc))
        )
        affected_count = await self.db.execute(stmt)

        if affected_count > 0:
            logger.info(f"Cleaned up {affected_count} expired assignments")

        return affected_count

    async def get_assignment_stats(
        self, tenant_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Get statistics about assignments"""

        active_conditions = [
            user_roles.c.is_active == True,
            or_(
                user_roles.c.expires_at.is_(None),
                user_roles.c.expires_at > func.current_timestamp(),
            ),
        ]
        if tenant_id:
            active_conditions.append(user_roles.c.tenant_id == tenant_id)

        total_active_count = await self.db.fetch_val(
            select(func.count()).select_from(user_roles).where(and_(*active_conditions))
        )

        by_role = await self.db.fetch_all(
            select(roles.c.name.label("role_name"), func.count().label("count"))
            .select_from(user_roles.join(roles, user_roles.c.role_id == roles.c.id))
            .where(and_(*active_conditions))
            .group_by(roles.c.name)
            .order_by(desc("count"))
            .limit(10)
        )

        expiring_conditions = [
            user_roles.c.expires_at.isnot(None),
            user_roles.c.expires_at <= datetime.now(timezone.utc) + timedelta(days=7),
            user_roles.c.expires_at > func.current_timestamp(),
            user_roles.c.is_active == True,
        ]
        if tenant_id:
            expiring_conditions.append(user_roles.c.tenant_id == tenant_id)
        expiring_soon_count = await self.db.fetch_val(
            select(func.count()).select_from(user_roles).where(and_(*expiring_conditions))
        )

        top_users = await self.db.fetch_all(
            select(user_roles.c.user_id, func.count().label("role_count"))
            .where(and_(*active_conditions))
            .group_by(user_roles.c.user_id)
            .order_by(desc("role_count"))
            .limit(10)
        )

        return {
            "total_active_assignments": total_active_count or 0,
            "assignments_by_role": [dict(r) for r in by_role],
            "expiring_within_7_days": expiring_soon_count or 0,
            "users_with_most_roles": [dict(u) for u in top_users],
            "tenant_id": str(tenant_id) if tenant_id else "global",
        }

    async def _get_tenant(self, tenant_id: UUID) -> Optional[Any]:
        """Get tenant by ID"""
        result = await self.db.fetch_one(select(tenants).where(tenants.c.id == tenant_id))
        from ..core.models import Tenant

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
                insert(audit_logs).values(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    old_value=old_value,
                    new_value=new_value,
                    created_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")

    async def clear_user_cache(self, user_id: UUID):
        """Clear cache for a specific user"""
        keys_to_clear = [
            key for key in self._assignment_cache.keys() if key.startswith(str(user_id))
        ]
        for key in keys_to_clear:
            self._assignment_cache.pop(key, None)
        logger.debug(f"Cleared assignment cache for user {user_id}")
