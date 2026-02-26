# rbac/core/models.py
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum

from .constants import PermissionAction, ResourceType


class Tenant(BaseModel):
    """Tenant model for multi-tenant support"""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    name: str
    domain: Optional[str] = None
    is_active: bool = True
    settings: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=datetime.now(timezone.utc))


class Permission(BaseModel):
    """Permission model representing an action on a resource"""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    name: str
    resource: ResourceType
    action: PermissionAction
    scope: Optional[str] = None  # For resource-specific permissions (e.g., patient_id)
    description: Optional[str] = None
    is_system: bool = False
    tenant_id: Optional[UUID] = None  # Null for system-wide permissions
    created_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=datetime.now(timezone.utc))

    @property
    def permission_string(self) -> str:
        """Returns the permission in 'resource:action' format"""
        if self.scope:
            return f"{self.resource.value}:{self.action.value}:{self.scope}"
        return f"{self.resource.value}:{self.action.value}"


class Role(BaseModel):
    """Role model with hierarchy support"""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    parent_ids: List[UUID] = Field(default_factory=list)  # Role inheritance
    permissions: List[Permission] = Field(default_factory=list)
    is_system_role: bool = False
    is_active: bool = True
    tenant_id: Optional[UUID] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=datetime.now(timezone.utc))


class UserRole(BaseModel):
    """User-Role assignment with optional resource scope"""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    user_id: UUID  # External user ID from your auth system
    role_id: UUID
    tenant_id: Optional[UUID] = None
    resource_scope: Optional[Dict[str, Any]] = Field(
        default_factory=dict
    )  # e.g., {"patient_id": "123"}
    granted_by: Optional[UUID] = None  # User ID who granted this role
    granted_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    is_active: bool = True


class AuditLog(BaseModel):
    """Audit log for tracking RBAC changes"""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    user_id: Optional[UUID] = None
    tenant_id: Optional[UUID] = None
    action: str  # CREATE, UPDATE, DELETE, ASSIGN, REVOKE
    resource_type: str  # role, permission, assignment
    resource_id: Optional[UUID] = None
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now(timezone.utc))
