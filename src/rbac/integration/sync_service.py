# rbac/integration/sync_service.py
from typing import Optional, List, Dict, Any, Callable
from uuid import UUID
from datetime import datetime, timedelta, timezone
import asyncio
from enum import Enum

from .base import IdentityProvider, ExternalUser, IdentityProviderHook
from services.role_service import RoleService
from services.assignment_service import AssignmentService
from core.exceptions import RoleNotFoundError
from utils.logger import setup_logger

logger = setup_logger("sync_integration")


class SyncStrategy(Enum):
    """Synchronization strategies"""

    FULL = "full"  # Full sync all users
    INCREMENTAL = "incremental"  # Only sync changed users
    MANUAL = "manual"  # Manual sync only


class SyncDirection(Enum):
    """Synchronization direction"""

    IMPORT = "import"  # Import from external to local
    EXPORT = "export"  # Export from local to external
    BIDIRECTIONAL = "bidirectional"  # Both directions


class SyncConflictResolution(Enum):
    """Conflict resolution strategies"""

    EXTERNAL_WINS = "external_wins"
    LOCAL_WINS = "local_wins"
    MANUAL = "manual"
    LATEST_WINS = "latest_wins"


class IdentitySyncService:
    """Service for synchronizing identities with external providers"""

    def __init__(
        self,
        provider: IdentityProvider,
        role_service: RoleService,
        assignment_service: AssignmentService,
        hook: Optional[IdentityProviderHook] = None,
        strategy: SyncStrategy = SyncStrategy.INCREMENTAL,
        direction: SyncDirection = SyncDirection.IMPORT,
        conflict_resolution: SyncConflictResolution = SyncConflictResolution.EXTERNAL_WINS,
        role_mapping: Optional[Dict[str, str]] = None,
        group_mapping: Optional[Dict[str, str]] = None,
        auto_sync_interval: Optional[int] = 3600,  # 1 hour
    ):
        self.provider = provider
        self.role_service = role_service
        self.assignment_service = assignment_service
        self.hook = hook or IdentityProviderHook(provider)
        self.strategy = strategy
        self.direction = direction
        self.conflict_resolution = conflict_resolution
        self.role_mapping = role_mapping or {}
        self.group_mapping = group_mapping or {}
        self.auto_sync_interval = auto_sync_interval
        self._sync_task: Optional[asyncio.Task] = None
        self._last_sync: Optional[datetime] = None
        self._sync_stats: Dict[str, Any] = {
            "total_syncs": 0,
            "users_created": 0,
            "users_updated": 0,
            "users_deactivated": 0,
            "roles_assigned": 0,
            "roles_revoked": 0,
            "errors": 0,
        }

    async def start_auto_sync(self):
        """Start automatic synchronization"""
        if self.auto_sync_interval and not self._sync_task:
            self._sync_task = asyncio.create_task(self._auto_sync_loop())
            logger.info(f"Auto-sync started with interval {self.auto_sync_interval}s")

    async def stop_auto_sync(self):
        """Stop automatic synchronization"""
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            self._sync_task = None
            logger.info("Auto-sync stopped")

    async def sync_now(self) -> Dict[str, Any]:
        """Perform immediate synchronization"""
        logger.info("Starting manual sync")

        sync_stats = {
            "start_time": datetime.now(timezone.utc),
            "users_created": 0,
            "users_updated": 0,
            "users_deactivated": 0,
            "roles_assigned": 0,
            "roles_revoked": 0,
            "errors": [],
        }

        try:
            # Determine sync strategy
            if self.strategy == SyncStrategy.FULL:
                users_created, users_updated = await self.provider.sync_users()
                sync_stats["users_created"] = users_created
                sync_stats["users_updated"] = users_updated
            elif self.strategy == SyncStrategy.INCREMENTAL:
                users_created, users_updated = await self.provider.sync_users(
                    self._last_sync
                )
                sync_stats["users_created"] = users_created
                sync_stats["users_updated"] = users_updated

            # Process users if we have them
            # This would depend on your user storage implementation

            self._last_sync = datetime.now(timezone.utc)
            self._sync_stats["total_syncs"] += 1
            self._sync_stats["users_created"] += sync_stats["users_created"]
            self._sync_stats["users_updated"] += sync_stats["users_updated"]

            sync_stats["end_time"] = datetime.now(timezone.utc)
            sync_stats["duration"] = (
                sync_stats["end_time"] - sync_stats["start_time"]
            ).total_seconds()

            logger.info(f"Sync completed: {sync_stats}")

        except Exception as e:
            logger.error(f"Sync failed: {e}")
            sync_stats["errors"].append(str(e))
            self._sync_stats["errors"] += 1

        return sync_stats

    async def sync_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Synchronize a single user"""
        logger.info(f"Syncing user: {user_id}")

        try:
            # Get user from external provider
            external_user = await self.provider.get_user(user_id)
            if not external_user:
                logger.warning(f"User {user_id} not found in external provider")
                return None

            # Check if user exists locally
            local_user = await self._get_local_user(external_user.username)

            if local_user:
                # Update existing user
                external_user = await self.hook.before_user_update(
                    external_user, local_user.id
                )
                await self._update_local_user(local_user.id, external_user)
                await self.hook.after_user_update(external_user, local_user.id)
                action = "updated"
            else:
                # Create new user
                external_user = await self.hook.before_user_create(external_user)
                local_user_id = await self._create_local_user(external_user)
                await self.hook.after_user_create(external_user, local_user_id)
                action = "created"

            # Sync role assignments
            roles_synced = await self._sync_user_roles(
                external_user, local_user.id if local_user else local_user_id
            )

            result = {
                "user_id": user_id,
                "action": action,
                "roles_synced": roles_synced,
                "username": external_user.username,
                "email": external_user.email,
            }

            logger.info(f"User sync completed: {result}")
            return result

        except Exception as e:
            logger.error(f"Error syncing user {user_id}: {e}")
            return None

    async def _sync_user_roles(
        self, external_user: ExternalUser, local_user_id: UUID
    ) -> int:
        """Synchronize roles for a user"""
        roles_synced = 0

        # Map external groups to internal roles
        internal_roles = set()
        for group in external_user.groups:
            if group in self.group_mapping:
                internal_roles.add(self.group_mapping[group])

        # Add mapped roles
        for external_role in external_user.roles:
            if external_role in self.role_mapping:
                internal_roles.add(self.role_mapping[external_role])

        # Get current user roles
        current_assignments = await self.assignment_service.get_user_assignments(
            user_id=local_user_id, tenant_id=external_user.tenant_id
        )
        current_roles = {a.role_id for a in current_assignments}

        # Get role IDs for internal role names
        role_ids = {}
        for role_name in internal_roles:
            role = await self.role_service.get_role_by_name(
                name=role_name, tenant_id=external_user.tenant_id
            )
            if role:
                role_ids[role_name] = role.id

        # Assign new roles
        for role_name, role_id in role_ids.items():
            if role_id not in current_roles:
                if await self.hook.before_role_assign(local_user_id, role_name):
                    await self.assignment_service.assign_role_to_user(
                        user_id=local_user_id,
                        role_id=role_id,
                        tenant_id=external_user.tenant_id,
                        granted_by=None,  # System assignment
                    )
                    await self.hook.after_role_assign(local_user_id, role_name)
                    roles_synced += 1
                    self._sync_stats["roles_assigned"] += 1

        # Revoke roles that are no longer present
        for assignment in current_assignments:
            role = await self.role_service.get_role(assignment.role_id)
            if role and role.name not in internal_roles:
                if await self.hook.before_role_revoke(local_user_id, role.name):
                    await self.assignment_service.revoke_role_from_user(
                        user_id=local_user_id,
                        role_id=assignment.role_id,
                        tenant_id=external_user.tenant_id,
                        revoked_by=None,
                    )
                    await self.hook.after_role_revoke(local_user_id, role.name)
                    roles_synced += 1
                    self._sync_stats["roles_revoked"] += 1

        return roles_synced

    async def _auto_sync_loop(self):
        """Automatic synchronization loop"""
        while True:
            try:
                await asyncio.sleep(self.auto_sync_interval)
                await self.sync_now()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auto-sync error: {e}")
                await asyncio.sleep(60)  # Wait a minute on error

    async def _get_local_user(self, username: str) -> Optional[Any]:
        """Get local user by username"""
        # TODO should be implemented based on user model
        # For now, return None as placeholder
        return None

    async def _create_local_user(self, external_user: ExternalUser) -> UUID:
        """Create local user from external user"""
        # TODO should be implemented based on user model
        # Return dummy UUID for now
        return UUID(int=0)

    async def _update_local_user(self, user_id: UUID, external_user: ExternalUser):
        """Update local user from external user"""
        # TODO should be implemented based on user model
        pass

    def get_stats(self) -> Dict[str, Any]:
        """Get synchronization statistics"""
        return {
            **self._sync_stats,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "strategy": self.strategy.value,
            "direction": self.direction.value,
            "auto_sync_enabled": self._sync_task is not None,
        }

    def set_role_mapping(self, external_role: str, internal_role: str):
        """Set mapping from external role to internal role"""
        self.role_mapping[external_role] = internal_role

    def set_group_mapping(self, external_group: str, internal_role: str):
        """Set mapping from external group to internal role"""
        self.group_mapping[external_group] = internal_role

    def remove_role_mapping(self, external_role: str):
        """Remove role mapping"""
        self.role_mapping.pop(external_role, None)

    def remove_group_mapping(self, external_group: str):
        """Remove group mapping"""
        self.group_mapping.pop(external_group, None)
