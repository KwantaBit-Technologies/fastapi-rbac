# rbac/decorators/rbac.py
from typing import List, Optional, Callable, Any, Type, Union, Dict
from functools import wraps
from uuid import UUID
from fastapi import HTTPException, Request, status, Depends

from core.exceptions import PermissionDeniedError
from services.permission_service import PermissionService
from services.assignment_service import AssignmentService
from dependencies.auth import UserContext, RBACDependencies
from utils.logger import setup_logger

logger = setup_logger("RBAC DECORATORS")


class RBACDecorators:
    """Class-based decorators for RBAC"""

    def __init__(
        self,
        permission_service: PermissionService,
        assignment_service: AssignmentService,
    ):
        self.permission_service = permission_service
        self.assignment_service = assignment_service

    def check_permissions(
        self,
        permissions: List[str],
        require_all: bool = True,
        resource_id_param: Optional[str] = None,
        message: Optional[str] = None,
        status_code: int = status.HTTP_403_FORBIDDEN,
    ):
        """
        Method decorator for class-based views to check permissions

        Args:
            permissions: List of required permissions
            require_all: If True, user must have all permissions. If False, any one is sufficient
            resource_id_param: Name of parameter containing resource ID for scope checking
            message: Custom error message
            status_code: HTTP status code to return on failure
        """

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                # Get request from kwargs or args
                request = self._extract_request(*args, **kwargs)

                if not request:
                    logger.error("No request object found in method arguments")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request object not available",
                    )

                # Get user from request state
                user = self._extract_user(request)
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                # Superuser bypass
                if user.is_superuser:
                    return await func(self, *args, **kwargs)

                # Get resource scope if specified
                resource_scope = self._extract_resource_scope(resource_id_param, kwargs)

                # Check permissions
                if require_all:
                    missing = []
                    for permission in permissions:
                        has_perm = await self.permission_service.check_user_permission(
                            user_id=user.id,
                            required_permission=permission,
                            tenant_id=user.tenant_id,
                            resource_scope=resource_scope,
                        )
                        if not has_perm:
                            missing.append(permission)

                    if missing:
                        error_msg = (
                            message
                            or f"Missing required permissions: {', '.join(missing)}"
                        )
                        raise HTTPException(
                            status_code=status_code,
                            detail=error_msg,
                        )
                else:
                    has_any = False
                    for permission in permissions:
                        if await self.permission_service.check_user_permission(
                            user_id=user.id,
                            required_permission=permission,
                            tenant_id=user.tenant_id,
                            resource_scope=resource_scope,
                        ):
                            has_any = True
                            break

                    if not has_any:
                        error_msg = (
                            message
                            or f"None of the required permissions found: {permissions}"
                        )
                        raise HTTPException(
                            status_code=status_code,
                            detail=error_msg,
                        )

                return await func(self, *args, **kwargs)

            return wrapper

        return decorator

    def check_roles(
        self,
        roles: List[str],
        require_all: bool = False,
        message: Optional[str] = None,
        status_code: int = status.HTTP_403_FORBIDDEN,
    ):
        """
        Method decorator for class-based views to check roles

        Args:
            roles: List of required role names
            require_all: If True, user must have all roles. If False, any one is sufficient
            message: Custom error message
            status_code: HTTP status code to return on failure
        """

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                # Get request from kwargs or args
                request = self._extract_request(*args, **kwargs)

                if not request:
                    logger.error("No request object found in method arguments")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request object not available",
                    )

                # Get user from request state
                user = self._extract_user(request)
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                # Superuser bypass
                if user.is_superuser:
                    return await func(self, *args, **kwargs)

                user_roles = set(user.roles)
                required_roles = set(roles)

                if require_all:
                    if not required_roles.issubset(user_roles):
                        missing = required_roles - user_roles
                        error_msg = message or f"Missing required roles: {missing}"
                        raise HTTPException(
                            status_code=status_code,
                            detail=error_msg,
                        )
                else:
                    if not user_roles.intersection(required_roles):
                        error_msg = (
                            message or f"User must have one of these roles: {roles}"
                        )
                        raise HTTPException(
                            status_code=status_code,
                            detail=error_msg,
                        )

                return await func(self, *args, **kwargs)

            return wrapper

        return decorator

    def check_self_or_permission(
        self,
        user_id_param: str = "user_id",
        permission: str = "user:manage",
        message: str = "You can only access your own resources",
        status_code: int = status.HTTP_403_FORBIDDEN,
    ):
        """
        Method decorator to allow self-access or users with specific permission

        Args:
            user_id_param: Name of parameter containing the target user ID
            permission: Permission required to bypass self-check
            message: Custom error message
            status_code: HTTP status code to return on failure
        """

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                # Get request from kwargs or args
                request = self._extract_request(*args, **kwargs)

                if not request:
                    logger.error("No request object found in method arguments")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request object not available",
                    )

                # Get user from request state
                user = self._extract_user(request)
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                # Superuser bypass
                if user.is_superuser:
                    return await func(self, *args, **kwargs)

                # Get target user ID from kwargs
                target_user_id = kwargs.get(user_id_param)

                if target_user_id:
                    try:
                        # Convert to UUID if it's a string
                        if isinstance(target_user_id, str):
                            target_uuid = UUID(target_user_id)
                        else:
                            target_uuid = target_user_id

                        # Check if accessing own resource
                        if user.id == target_uuid:
                            return await func(self, *args, **kwargs)

                        # Check for required permission
                        has_permission = (
                            await self.permission_service.check_user_permission(
                                user_id=user.id,
                                required_permission=permission,
                                tenant_id=user.tenant_id,
                            )
                        )

                        if has_permission:
                            return await func(self, *args, **kwargs)

                    except ValueError:
                        # Invalid UUID format
                        pass

                raise HTTPException(
                    status_code=status_code,
                    detail=message,
                )

            return wrapper

        return decorator

    def require_tenant(
        self,
        allow_cross_tenant: bool = False,
        tenant_id_source: str = "auto",
        message: str = "Tenant access denied",
    ):
        """
        Method decorator to enforce tenant access

        Args:
            allow_cross_tenant: If True, allow superusers to access other tenants
            tenant_id_source: Where to get tenant ID from ('path', 'header', 'query', 'auto')
            message: Custom error message
        """

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                # Get request from kwargs or args
                request = self._extract_request(*args, **kwargs)

                if not request:
                    logger.error("No request object found in method arguments")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request object not available",
                    )

                # Get user from request state
                user = self._extract_user(request)
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                    )

                # Get tenant ID from request
                request_tenant_id = None

                if tenant_id_source in ["path", "auto"]:
                    request_tenant_id = request.path_params.get("tenant_id")

                if not request_tenant_id and tenant_id_source in ["header", "auto"]:
                    request_tenant_id = request.headers.get("X-Tenant-ID")

                if not request_tenant_id and tenant_id_source in ["query", "auto"]:
                    request_tenant_id = request.query_params.get("tenant_id")

                # If no tenant in request, use user's tenant
                if not request_tenant_id:
                    if user.tenant_id:
                        # Add tenant to request state for downstream use
                        request.state.current_tenant_id = user.tenant_id
                    return await func(self, *args, **kwargs)

                # Validate tenant ID format
                try:
                    request_tenant_uuid = UUID(request_tenant_id)
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid tenant ID format",
                    )

                # Superuser can access any tenant if allowed
                if user.is_superuser and allow_cross_tenant:
                    request.state.current_tenant_id = request_tenant_uuid
                    return await func(self, *args, **kwargs)

                # Check if user belongs to this tenant
                if user.tenant_id != request_tenant_uuid:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=message,
                    )

                # Add tenant to request state for downstream use
                request.state.current_tenant_id = request_tenant_uuid

                return await func(self, *args, **kwargs)

            return wrapper

        return decorator

    def _extract_request(self, *args, **kwargs) -> Optional[Request]:
        """Extract request object from method arguments"""
        # Check kwargs first
        if "request" in kwargs:
            return kwargs["request"]

        # Check args
        for arg in args:
            if isinstance(arg, Request):
                return arg

        # Check if first arg is self and has request attribute
        if args and hasattr(args[0], "request"):
            return args[0].request

        return None

    def _extract_user(self, request: Request) -> Optional[UserContext]:
        """Extract user from request state"""
        return getattr(request.state, "user", None)

    def _extract_resource_scope(
        self, resource_id_param: Optional[str], kwargs: Dict
    ) -> Optional[Dict]:
        """Extract resource scope from kwargs"""
        if resource_id_param and resource_id_param in kwargs:
            resource_id = kwargs[resource_id_param]
            if resource_id:
                return {"id": str(resource_id)}
        return None


# Permission checking utility
class PermissionChecker:
    """Utility class for programmatic permission checks"""

    def __init__(self, permission_service: PermissionService):
        self.permission_service = permission_service

    async def check(
        self,
        user_id: Union[str, UUID],
        permission: str,
        tenant_id: Optional[Union[str, UUID]] = None,
        resource_scope: Optional[dict] = None,
        raise_exception: bool = False,
        exception_message: Optional[str] = None,
    ) -> bool:
        """Check if user has permission"""
        # Convert string IDs to UUID
        user_uuid = self._to_uuid(user_id, "user_id")
        tenant_uuid = self._to_uuid(tenant_id) if tenant_id else None

        has_permission = await self.permission_service.check_user_permission(
            user_id=user_uuid,
            required_permission=permission,
            tenant_id=tenant_uuid,
            resource_scope=resource_scope,
        )

        if not has_permission and raise_exception:
            message = exception_message or f"Missing required permission: {permission}"
            raise PermissionDeniedError(message, user_id)

        return has_permission

    async def check_all(
        self,
        user_id: Union[str, UUID],
        permissions: List[str],
        tenant_id: Optional[Union[str, UUID]] = None,
        resource_scope: Optional[dict] = None,
        raise_exception: bool = False,
    ) -> bool:
        """Check if user has all permissions"""
        for permission in permissions:
            if not await self.check(
                user_id, permission, tenant_id, resource_scope, raise_exception=False
            ):
                if raise_exception:
                    raise PermissionDeniedError(
                        f"Missing required permission: {permission}", user_id
                    )
                return False
        return True

    async def check_any(
        self,
        user_id: Union[str, UUID],
        permissions: List[str],
        tenant_id: Optional[Union[str, UUID]] = None,
        resource_scope: Optional[dict] = None,
        raise_exception: bool = False,
    ) -> bool:
        """Check if user has any of the permissions"""
        for permission in permissions:
            if await self.check(
                user_id, permission, tenant_id, resource_scope, raise_exception=False
            ):
                return True

        if raise_exception:
            raise PermissionDeniedError(
                f"None of the required permissions found: {permissions}", user_id
            )
        return False

    async def filter_by_permission(
        self,
        items: List[Any],
        user_id: Union[str, UUID],
        permission: str,
        tenant_id: Optional[Union[str, UUID]] = None,
        scope_key: str = "id",
    ) -> List[Any]:
        """
        Filter a list of items to only those the user has permission for

        Args:
            items: List of items to filter
            user_id: User ID
            permission: Permission to check (should include scope placeholder)
            tenant_id: Optional tenant ID
            scope_key: Key in item dict to use as scope ID

        Returns:
            Filtered list of items
        """
        filtered_items = []

        for item in items:
            # Extract scope ID from item
            scope_id = None
            if isinstance(item, dict):
                scope_id = item.get(scope_key)
            elif hasattr(item, scope_key):
                scope_id = getattr(item, scope_key)

            resource_scope = {"id": str(scope_id)} if scope_id else None

            if await self.check(user_id, permission, tenant_id, resource_scope):
                filtered_items.append(item)

        return filtered_items

    def _to_uuid(self, value: Union[str, UUID], field_name: str = "value") -> UUID:
        """Convert string to UUID"""
        if isinstance(value, UUID):
            return value
        try:
            return UUID(str(value))
        except ValueError:
            raise ValueError(f"Invalid UUID format for {field_name}: {value}")

    def __call__(self, *args, **kwargs):
        """Make the class callable for dependency injection"""
        return self.check(*args, **kwargs)


# FastAPI route dependency
def get_current_user_from_request(request: Request) -> Optional[UserContext]:
    """Get current user from request state (set by middleware)"""
    return getattr(request.state, "user", None)


def require_user() -> UserContext:
    """Dependency to require authenticated user"""
    user = get_current_user_from_request
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user


# Helper function to create RBAC router
from fastapi import APIRouter, Depends


def create_rbac_router(
    prefix: str = "",
    tags: Optional[List[str]] = None,
    permissions: Optional[List[str]] = None,
    roles: Optional[List[str]] = None,
    dependencies: Optional[List[Callable]] = None,
    rbac_dependencies: Optional[RBACDependencies] = None,
) -> APIRouter:
    """
    Create a router with default RBAC dependencies

    Example:
        from dependencies.auth import rbac

        admin_router = create_rbac_router(
            prefix="/admin",
            tags=["admin"],
            permissions=["admin:access"],
            rbac_dependencies=rbac
        )

        @admin_router.get("/dashboard")
        async def admin_dashboard():
            return {"message": "Admin dashboard"}
    """
    router_dependencies = dependencies or []

    if permissions and rbac_dependencies:
        router_dependencies.append(
            Depends(rbac_dependencies.require_permissions(permissions))
        )

    if roles and rbac_dependencies:
        router_dependencies.append(Depends(rbac_dependencies.require_roles(roles)))

    return APIRouter(prefix=prefix, tags=tags or [], dependencies=router_dependencies)


# Combined decorator for common RBAC patterns
def rbac_required(
    permissions: Optional[List[str]] = None,
    roles: Optional[List[str]] = None,
    self_check: Optional[Dict[str, str]] = None,
    tenant_check: bool = False,
    message: Optional[str] = None,
):
    """
    Combined decorator for common RBAC patterns

    Example:
        @rbac_required(
            permissions=["patient:read"],
            self_check={"user_id_param": "patient_id", "permission": "patient:manage"},
            tenant_check=True
        )
        async def get_patient(patient_id: str):
            return {"patient": patient_id}
    """

    def decorator(func: Callable) -> Callable:
        # Store metadata for documentation
        func.__rbac_permissions__ = permissions or []
        func.__rbac_roles__ = roles or []
        func.__rbac_self_check__ = self_check
        func.__rbac_tenant_check__ = tenant_check
        func.__rbac_message__ = message

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # The actual checks are handled by dependencies
            # This decorator just adds metadata
            return await func(*args, **kwargs)

        return wrapper

    return decorator
