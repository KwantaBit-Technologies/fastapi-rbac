# rbac/integration/base.py
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel
from utils.logger import setup_logger

logger = setup_logger("integration_base")


class ExternalUser(BaseModel):
    """Standardized external user model"""

    external_id: str
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    full_name: Optional[str] = None
    groups: List[str] = []
    roles: List[str] = []
    attributes: Dict[str, Any] = {}
    is_active: bool = True
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = {}


class ExternalGroup(BaseModel):
    """Standardized external group model"""

    external_id: str
    name: str
    description: Optional[str] = None
    members: List[str] = []
    roles: List[str] = []
    parent_id: Optional[str] = None
    attributes: Dict[str, Any] = {}


class IdentityProvider(ABC):
    """Abstract base class for identity providers"""

    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[ExternalUser]:
        """Authenticate user with credentials"""
        pass

    @abstractmethod
    async def get_user(self, user_id: str) -> Optional[ExternalUser]:
        """Get user by ID"""
        pass

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[ExternalUser]:
        """Get user by username"""
        pass

    @abstractmethod
    async def get_user_groups(self, user_id: str) -> List[ExternalGroup]:
        """Get groups for a user"""
        pass

    @abstractmethod
    async def sync_users(self, last_sync: Optional[datetime] = None) -> Tuple[int, int]:
        """Sync users from external provider"""
        pass


class IdentityProviderHook:
    """Base hook class for identity provider integration"""

    def __init__(self, provider: IdentityProvider):
        self.provider = provider
        self._mapping_cache = {}
        self._sync_in_progress = False

    async def before_user_create(self, user: ExternalUser) -> ExternalUser:
        """Hook called before creating a user"""
        return user

    async def after_user_create(self, user: ExternalUser, local_user_id: UUID):
        """Hook called after creating a user"""
        pass

    async def before_user_update(
        self, user: ExternalUser, local_user_id: UUID
    ) -> ExternalUser:
        """Hook called before updating a user"""
        return user

    async def after_user_update(self, user: ExternalUser, local_user_id: UUID):
        """Hook called after updating a user"""
        pass

    async def before_role_assign(self, user_id: UUID, role_name: str) -> bool:
        """Hook called before assigning a role"""
        return True

    async def after_role_assign(self, user_id: UUID, role_name: str):
        """Hook called after assigning a role"""
        pass

    async def before_role_revoke(self, user_id: UUID, role_name: str) -> bool:
        """Hook called before revoking a role"""
        return True

    async def after_role_revoke(self, user_id: UUID, role_name: str):
        """Hook called after revoking a role"""
        pass
