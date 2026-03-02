# API Reference

Complete API reference for the FastAPI RBAC Engine.

## Core Models

### Permission

```python
class Permission(BaseModel):
    """Permission model representing an action on a resource"""
    
    id: UUID
    name: str
    resource: ResourceType
    action: PermissionAction
    scope: Optional[str] = None
    description: Optional[str] = None
    is_system: bool = False
    tenant_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    
    @property
    def permission_string(self) -> str:
        """Returns the permission in 'resource:action' format"""
        if self.scope:
            return f"{self.resource.value}:{self.action.value}:{self.scope}"
        return f"{self.resource.value}:{self.action.value}"
```

### Role

```python
class Role(BaseModel):
    """Role model with hierarchy support"""
    
    id: UUID
    name: str
    description: Optional[str] = None
    parent_ids: List[UUID] = []
    permissions: List[Permission] = []
    is_system_role: bool = False
    is_active: bool = True
    tenant_id: Optional[UUID] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime
### UserRole

```python
class UserRole(BaseModel):
    """User-Role assignment with optional resource scope"""
    
    id: UUID
    user_id: UUID
    role_id: UUID
    tenant_id: Optional[UUID] = None
    resource_scope: Dict[str, Any] = {}
    granted_by: Optional[UUID] = None
    granted_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool = True
```

### Tenant

```python
class Tenant(BaseModel):
    """Tenant model for multi-tenant support"""
    
    id: UUID
    name: str
    domain: Optional[str] = None
    is_active: bool = True
    settings: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime
```

### AuditLog

```python
class AuditLog(BaseModel):
    """Audit log for tracking RBAC changes"""
    
    id: UUID
    user_id: Optional[UUID] = None
    tenant_id: Optional[UUID] = None
    action: str
    resource_type: str
    resource_id: Optional[UUID] = None
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
```

## Permission Service

### Methods

#### create_permission()

```python
async def create_permission(
    name: str,
    resource: ResourceType,
    action: PermissionAction,
    scope: Optional[str] = None,
    description: Optional[str] = None,
    tenant_id: Optional[UUID] = None,
    created_by: Optional[UUID] = None
) -> Permission:
    """
    Create a new permission.
    
    Args:
        name: Human-readable name for the permission
        resource: Resource type (user, role, patient, etc.)
        action: Action to perform (create, read, update, delete)
        scope: Optional resource scope identifier
        description: Optional description
        tenant_id: Optional tenant ID (None for global permissions)
        created_by: User ID creating the permission
    
    Returns:
        Created permission object
    
    Example:
        ```python
        permission = await permission_service.create_permission(
            name="Read Patient Records",
            resource=ResourceType.PATIENT,
            action=PermissionAction.READ,
            tenant_id=tenant.id
        )
"""

#### get_permission()

```python
async def get_permission(
    permission_id: UUID,
    tenant_id: Optional[UUID] = None
) -> Optional[Permission]:
    """
    Get permission by ID.
    
    Args:
        permission_id: UUID of the permission
        tenant_id: Optional tenant ID for isolation
    
    Returns:
        Permission object or None if not found
    """
#### get_permission_by_string()

```python
async def get_permission_by_string(
    permission_string: str,
    tenant_id: Optional[UUID] = None
) -> Optional[Permission]:
    """
    Get permission by its string representation (resource:action:scope).
    
    Args:
        permission_string: Permission string (e.g., "patient:read:123")
        tenant_id: Optional tenant ID for isolation
    
    Returns:
        Permission object or None if not found
    """
#### update_permission()

```python
async def update_permission(
    permission_id: UUID,
    name: Optional[str] = None,
    description: Optional[str] = None,
    updated_by: Optional[UUID] = None
) -> Permission:
    """
    Update permission details.
    
    Args:
        permission_id: UUID of the permission to update
        name: New name (optional)
        description: New description (optional)
        updated_by: User ID making the update
    
    Returns:
        Updated permission object
    
    Raises:
        PermissionNotFoundError: If permission doesn't exist
        PermissionDeniedError: If trying to update system permission
    """
#### delete_permission()

```python
async def delete_permission(
    permission_id: UUID,
    deleted_by: Optional[UUID] = None
):
    """
    Delete a permission.
    
    Args:
        permission_id: UUID of the permission to delete
        deleted_by: User ID deleting the permission
    
    Raises:
        PermissionNotFoundError: If permission doesn't exist
        PermissionDeniedError: If permission is assigned to roles
    """
#### list_permissions()

```python
async def list_permissions(
    tenant_id: Optional[UUID] = None,
    resource: Optional[ResourceType] = None,
    action: Optional[PermissionAction] = None,
    include_system: bool = True,
    limit: int = 100,
    offset: int = 0
) -> List[Permission]:
    """
    List permissions with optional filters.
    
    Args:
        tenant_id: Filter by tenant
        resource: Filter by resource type
        action: Filter by action
        include_system: Include system permissions
        limit: Maximum number of results
        offset: Pagination offset
    
    Returns:
        List of permissions
    """
#### check_user_permission()

```python
async def check_user_permission(
    user_id: UUID,
    required_permission: str,
    tenant_id: Optional[UUID] = None,
    resource_scope: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Check if a user has a specific permission.
    
    Args:
        user_id: User ID to check
        required_permission: Permission string to check
        tenant_id: Optional tenant context
        resource_scope: Optional resource scope for scoped permissions
    
    Returns:
        True if user has permission, False otherwise
    
    Example:
        ```python
        # Check if user can read patient 123
        has_access = await permission_service.check_user_permission(
            user_id=user.id,
            required_permission="patient:read",
            resource_scope={"id": "123"}
        )
"""


#### get_user_permissions()

```python
async def get_user_permissions(
    user_id: UUID,
    tenant_id: Optional[UUID] = None
) -> Set[str]:
    """
    Get all permissions for a user (including inherited).
    
    Args:
        user_id: User ID
        tenant_id: Optional tenant context
    
    Returns:
        Set of permission strings
    """
#### grant_permission_to_role()

```python
async def grant_permission_to_role(
    role_id: UUID,
    permission_id: UUID,
    granted_by: Optional[UUID] = None
):
    """
    Grant a permission to a role.
    
    Args:
        role_id: Role ID
        permission_id: Permission ID
        granted_by: User ID granting the permission
    """
#### revoke_permission_from_role()

```python
async def revoke_permission_from_role(
    role_id: UUID,
    permission_id: UUID,
    revoked_by: Optional[UUID] = None
):
    """
    Revoke a permission from a role.
    
    Args:
        role_id: Role ID
        permission_id: Permission ID
        revoked_by: User ID revoking the permission
    """
Role Service
Methods
#### create_role()

```python
async def create_role(
    name: str,
    description: Optional[str] = None,
    parent_ids: Optional[List[UUID]] = None,
    is_system_role: bool = False,
    tenant_id: Optional[UUID] = None,
    metadata: Optional[Dict[str, Any]] = None,
    created_by: Optional[UUID] = None
) -> Role:
    """
    Create a new role with optional parent relationships.
    
    Args:
        name: Role name
        description: Optional description
        parent_ids: List of parent role IDs for inheritance
        is_system_role: Whether this is a system role
        tenant_id: Optional tenant ID
        metadata: Additional metadata
        created_by: User ID creating the role
    
    Returns:
        Created role object
    
    Example:
        ```python
        # Create admin role that inherits from user role
        admin_role = await role_service.create_role(
            name="Admin",
            description="Administrator role",
            parent_ids=[user_role.id],
            tenant_id=tenant.id
        )
"""


#### get_role()

```python
async def get_role(
    role_id: UUID,
    tenant_id: Optional[UUID] = None
) -> Optional[Role]:
    """
    Get role by ID.
    
    Args:
        role_id: Role UUID
        tenant_id: Optional tenant context
    
    Returns:
        Role object or None
    """
#### get_role_by_name()

```python
async def get_role_by_name(
    name: str,
    tenant_id: Optional[UUID] = None
) -> Optional[Role]:
    """
    Get role by name within tenant.
    
    Args:
        name: Role name
        tenant_id: Optional tenant context
    
    Returns:
        Role object or None
    """
#### update_role()

```python
async def update_role(
    role_id: UUID,
    name: Optional[str] = None,
    description: Optional[str] = None,
    parent_ids: Optional[List[UUID]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    is_active: Optional[bool] = None,
    updated_by: Optional[UUID] = None
) -> Role:
    """
    Update role details.
    
    Args:
        role_id: Role ID to update
        name: New name (optional)
        description: New description (optional)
        parent_ids: New parent IDs (optional)
        metadata: New metadata (optional)
        is_active: Active status (optional)
        updated_by: User ID making the update
    
    Returns:
        Updated role object
    
    Raises:
        RoleNotFoundError: If role doesn't exist
        CircularRoleHierarchyError: If update would create cycle
    """
#### delete_role()

```python
async def delete_role(
    role_id: UUID,
    transfer_to_role_id: Optional[UUID] = None,
    deleted_by: Optional[UUID] = None
):
    """
    Delete a role, optionally transferring assignments to another role.
    
    Args:
        role_id: Role ID to delete
        transfer_to_role_id: Optional role to transfer users to
        deleted_by: User ID deleting the role
    
    Raises:
        RoleNotFoundError: If role doesn't exist
        PermissionDeniedError: If role has users and no transfer role
    """
#### list_roles()

```python
async def list_roles(
    tenant_id: Optional[UUID] = None,
    include_system: bool = True,
    include_inactive: bool = False,
    limit: int = 100,
    offset: int = 0
) -> List[Role]:
    """
    List roles with optional filters.
    
    Args:
        tenant_id: Filter by tenant
        include_system: Include system roles
        include_inactive: Include inactive roles
        limit: Maximum results
        offset: Pagination offset
    
    Returns:
        List of roles
    """
#### get_role_hierarchy()

```python
async def get_role_hierarchy(role_id: UUID) -> Dict[str, List[Dict]]:
    """
    Get complete role hierarchy tree.
    
    Args:
        role_id: Role ID
    
    Returns:
        Dictionary with role, ancestors, descendants, and permissions
    
    Example:
        ```python
        hierarchy = await role_service.get_role_hierarchy(role.id)
        # Returns:
        # {
        #     "role": {...},
        #     "ancestors": [...],
        #     "descendants": [...],
        #     "permissions": [...],
        #     "inherited_permissions_count": 5
        # }
"""


#### add_role_parent()

```python
async def add_role_parent(
    role_id: UUID,
    parent_id: UUID,
    added_by: Optional[UUID] = None
):
    """
    Add a parent to a role (role will inherit from parent).
    
    Args:
        role_id: Child role ID
        parent_id: Parent role ID
        added_by: User ID making the change
    
    Raises:
        CircularRoleHierarchyError: If adding would create cycle
    """
#### remove_role_parent()

```python
async def remove_role_parent(
    role_id: UUID,
    parent_id: UUID,
    removed_by: Optional[UUID] = None
):
    """
    Remove a parent from a role.
    
    Args:
        role_id: Child role ID
        parent_id: Parent role ID to remove
        removed_by: User ID making the change
    """
#### get_role_permissions()

```python
async def get_role_permissions(
    role_id: UUID,
    include_inherited: bool = True
) -> List[Permission]:
    """
    Get all permissions for a role.
    
    Args:
        role_id: Role ID
        include_inherited: Include inherited permissions from parents
    
    Returns:
        List of permissions
    """
Assignment Service
Methods
#### assign_role_to_user()

```python
async def assign_role_to_user(
    user_id: UUID,
    role_id: UUID,
    tenant_id: Optional[UUID] = None,
    resource_scope: Optional[Dict[str, Any]] = None,
    expires_in_days: Optional[int] = None,
    granted_by: Optional[UUID] = None,
    prevent_duplicates: bool = True
) -> UserRole:
    """
    Assign a role to a user with optional scope and expiration.
    
    Args:
        user_id: User ID
        role_id: Role ID to assign
        tenant_id: Optional tenant context
        resource_scope: Optional resource scope (e.g., {"patient_id": "123"})
        expires_in_days: Optional expiration in days
        granted_by: User ID making the assignment
        prevent_duplicates: Prevent duplicate active assignments
    
    Returns:
        Created assignment object
    
    Example:
        ```python
        # Assign doctor role to specific patient only
        assignment = await assignment_service.assign_role_to_user(
            user_id=doctor.id,
            role_id=doctor_role.id,
            resource_scope={"patient_id": "123"},
            expires_in_days=30
        )
"""


#### revoke_role_from_user()

```python
async def revoke_role_from_user(
    user_id: UUID,
    role_id: UUID,
    tenant_id: Optional[UUID] = None,
    revoked_by: Optional[UUID] = None,
    hard_delete: bool = False
):
    """
    Revoke a role from a user.
    
    Args:
        user_id: User ID
        role_id: Role ID to revoke
        tenant_id: Optional tenant context
        revoked_by: User ID revoking the role
        hard_delete: If True, permanently delete; if False, soft delete
    """
#### get_user_assignments()

```python
async def get_user_assignments(
    user_id: UUID,
    tenant_id: Optional[UUID] = None,
    include_inactive: bool = False,
    include_expired: bool = False
) -> List[UserRole]:
    """
    Get all role assignments for a user.
    
    Args:
        user_id: User ID
        tenant_id: Optional tenant context
        include_inactive: Include inactive assignments
        include_expired: Include expired assignments
    
    Returns:
        List of user role assignments
    """
#### get_role_assignments()

```python
async def get_role_assignments(
    role_id: UUID,
    tenant_id: Optional[UUID] = None,
    include_inactive: bool = False,
    include_expired: bool = False,
    limit: int = 100,
    offset: int = 0
) -> List[UserRole]:
    """
    Get all users assigned to a role.
    
    Args:
        role_id: Role ID
        tenant_id: Optional tenant context
        include_inactive: Include inactive assignments
        include_expired: Include expired assignments
        limit: Maximum results
        offset: Pagination offset
    
    Returns:
        List of user role assignments
    """
#### update_assignment_scope()

```python
async def update_assignment_scope(
    assignment_id: UUID,
    resource_scope: Dict[str, Any],
    updated_by: Optional[UUID] = None
) -> UserRole:
    """
    Update the resource scope of an assignment.
    
    Args:
        assignment_id: Assignment ID
        resource_scope: New resource scope
        updated_by: User ID making the update
    
    Returns:
        Updated assignment
    """
#### extend_assignment()

```python
async def extend_assignment(
    assignment_id: UUID,
    additional_days: int,
    extended_by: Optional[UUID] = None
) -> UserRole:
    """
    Extend the expiration date of an assignment.
    
    Args:
        assignment_id: Assignment ID
        additional_days: Days to add to expiration
        extended_by: User ID extending the assignment
    
    Returns:
        Updated assignment
    """
#### bulk_assign_roles()

```python
async def bulk_assign_roles(
    user_ids: List[UUID],
    role_id: UUID,
    tenant_id: Optional[UUID] = None,
    resource_scope: Optional[Dict[str, Any]] = None,
    expires_in_days: Optional[int] = None,
    granted_by: Optional[UUID] = None
) -> Tuple[int, List[UUID]]:
    """
    Bulk assign a role to multiple users.
    
    Args:
        user_ids: List of user IDs
        role_id: Role ID to assign
        tenant_id: Optional tenant context
        resource_scope: Optional resource scope
        expires_in_days: Optional expiration in days
        granted_by: User ID making the assignments
    
    Returns:
        Tuple of (successful_count, failed_user_ids)
    """
#### transfer_assignments()

```python
async def transfer_assignments(
    from_role_id: UUID,
    to_role_id: UUID,
    tenant_id: Optional[UUID] = None,
    transferred_by: Optional[UUID] = None
) -> int:
    """
    Transfer all assignments from one role to another.
    
    Args:
        from_role_id: Source role ID
        to_role_id: Destination role ID
        tenant_id: Optional tenant context
        transferred_by: User ID performing the transfer
    
    Returns:
        Number of assignments transferred
    """
#### get_expiring_assignments()

```python
async def get_expiring_assignments(
    days_threshold: int = 7,
    tenant_id: Optional[UUID] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get assignments that will expire within the specified days.
    
    Args:
        days_threshold: Number of days to check
        tenant_id: Optional tenant context
        limit: Maximum results
    
    Returns:
        List of expiring assignments with user and role details
    """
Audit Service
Methods
#### log()

```python
async def log(
    event: Union[AuditEvent, Dict[str, Any]]
) -> AuditLog:
    """
    Log an audit event.
    
    Args:
        event: AuditEvent object or dictionary
    
    Returns:
        Created audit log
    """
#### log_action()

```python
async def log_action(
    user_id: Optional[UUID],
    action: AuditAction,
    resource_type: AuditResourceType,
    resource_id: Optional[UUID] = None,
    tenant_id: Optional[UUID] = None,
    old_value: Optional[Dict] = None,
    new_value: Optional[Dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[Dict] = None,
    description: Optional[str] = None,
    status: str = "SUCCESS",
    error_message: Optional[str] = None
) -> AuditLog:
    """
    Simplified method to log an action.
    
    Example:
        ```python
        await audit_service.log_action(
            user_id=user.id,
            action=AuditAction.UPDATE,
            resource_type=AuditResourceType.ROLE,
            resource_id=role.id,
            old_value=old_data,
            new_value=new_data,
            description=f"Updated role {role.name}"
        )
"""


#### log_access()

```python
async def log_access(
    user_id: UUID,
    resource: str,
    resource_id: Optional[UUID] = None,
    tenant_id: Optional[UUID] = None,
    granted: bool = True,
    required_permission: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> AuditLog:
    """
    Log access attempts (both granted and denied).
    
    Example:
        ```python
        # Log denied access
        await audit_service.log_access(
            user_id=user.id,
            resource="/api/admin",
            granted=False,
            required_permission="admin:access",
            ip_address=request.client.host
        )
"""


#### query_logs()

```python
async def query_logs(
    user_id: Optional[UUID] = None,
    tenant_id: Optional[UUID] = None,
    action: Optional[AuditAction] = None,
    resource_type: Optional[AuditResourceType] = None,
    resource_id: Optional[UUID] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    severity: Optional[AuditSeverity] = None,
    status: Optional[str] = None,
    search_text: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "created_at",
    sort_desc: bool = True
) -> List[AuditLog]:
    """
    Query audit logs with filters.
    
    Example:
        ```python
        logs = await audit_service.query_logs(
            user_id=user.id,
            action=AuditAction.UPDATE,
            start_date=datetime.utcnow() - timedelta(days=7),
            limit=50
        )
"""


## Dependencies

### RBACDependencies

```python
class RBACDependencies:
    """Dependency injection class for RBAC"""
    
    def __init__(
        self,
        permission_service: PermissionService,
        assignment_service: AssignmentService,
        secret_key: str,
        algorithm: str = "HS256"
    ):
        """
        Initialize RBAC dependencies.
        
        Args:
            permission_service: Permission service instance
            assignment_service: Assignment service instance
            secret_key: JWT secret key
            algorithm: JWT algorithm (default: HS256)
        """
#### get_current_user()

```python
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[UserContext]:
    """
    Extract current user from JWT token.
    
    Returns:
        UserContext or None if not authenticated
    """
#### get_current_active_user()

```python
async def get_current_active_user(
    current_user: Optional[UserContext] = Depends(get_current_user)
) -> UserContext:
    """
    Get current active user or raise 401.
    
    Raises:
        HTTPException(401): If not authenticated
    """
#### require_permissions()

```python
def require_permissions(
    permissions: List[str],
    require_all: bool = True,
    resource_scope_param: Optional[str] = None
) -> Callable:
    """
    Dependency for requiring specific permissions.
    
    Args:
        permissions: List of required permissions
        require_all: If True, user must have all permissions
        resource_scope_param: Path parameter name containing resource ID
    
    Example:
        ```python
        @app.get("/patients/{patient_id}")
        async def get_patient(
            current_user = Depends(
                rbac.require_permissions(
                    ["patient:read"],
                    resource_scope_param="patient_id"
                )
            )
        ):
            ...
"""


#### require_roles()

```python
def require_roles(
    roles: List[str],
    require_all: bool = False
) -> Callable:
    """
    Dependency for requiring specific roles.
    
    Args:
        roles: List of required role names
        require_all: If True, user must have all roles
    
    Example:
        ```python
        @app.get("/admin")
        async def admin_only(
            current_user = Depends(rbac.require_roles(["admin"]))
        ):
            ...
"""


## Decorators

### `require_permissions`

```python
def require_permissions(
    permissions: List[str],
    require_all: bool = True,
    resource_scope_param: Optional[str] = None
):
    """
    Decorator to require permissions on a route.
    
    Example:
        ```python
        @router.get("/patients/{patient_id}")
        @require_permissions(["patient:read"], resource_scope_param="patient_id")
        async def get_patient(patient_id: str):
            return {"patient": patient_id}
"""


### `require_roles`

```python
def require_roles(roles: List[str], require_all: bool = False):
    """
    Decorator to require roles on a route.
    
    Example:
        ```python
        @router.get("/admin/dashboard")
        @require_roles(["admin", "super_admin"])
        async def admin_dashboard():
            return {"dashboard": "admin"}
"""


### `public_route`

```python
def public_route(func: Callable) -> Callable:
    """
    Mark a route as public (no authentication required).
    
    Example:
        ```python
        @router.get("/health")
        @public_route
        async def health_check():
            return {"status": "healthy"}
"""


## Exceptions

```python
class RBACError(Exception):
    """Base exception for RBAC errors"""

class PermissionDeniedError(RBACError):
    """Raised when user doesn't have required permission"""

class RoleNotFoundError(RBACError):
    """Raised when role doesn't exist"""

class PermissionNotFoundError(RBACError):
    """Raised when permission doesn't exist"""

class TenantNotFoundError(RBACError):
    """Raised when tenant doesn't exist"""

class CircularRoleHierarchyError(RBACError):
    """Raised when role hierarchy would create a cycle"""
Constants
ResourceType
python
class ResourceType(str, Enum):
    ALL = "*"
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    TENANT = "tenant"
    PATIENT = "patient"
    # Add your own resource types
PermissionAction
python
class PermissionAction(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    MANAGE = "manage"
    APPROVE = "approve"
    REJECT = "reject"
AuditAction
python
class AuditAction(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    ASSIGN = "ASSIGN"
    REVOKE = "REVOKE"
    GRANT = "GRANT"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    ACCESS = "ACCESS"
    DENIED = "DENIED"
```

### AuditSeverity

```python
class AuditSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
