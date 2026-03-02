# rbac/dependencies/auth.py
from typing import Optional, List, Callable, Awaitable, Any, Dict, Union
from uuid import UUID
from fastapi import Depends, HTTPException, Security, Request, status
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
    OAuth2PasswordBearer,
)
from jose import JWTError, jwt
from pydantic import BaseModel, Field, ValidationError
from functools import wraps
import inspect
import time

from core.exceptions import PermissionDeniedError
from services.permission_service import PermissionService
from services.assignment_service import AssignmentService
from utils.logger import setup_logger

logger = setup_logger("AUTH")

# Security schemes
security = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


class TokenPayload(BaseModel):
    """JWT token payload model"""

    sub: str  # User ID
    exp: Optional[int] = None  # Expiration timestamp
    iat: Optional[int] = None  # Issued at timestamp
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scopes: List[str] = Field(default_factory=list)


class UserContext(BaseModel):
    """Current user context with permissions"""

    id: UUID
    tenant_id: Optional[UUID] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    role_ids: List[UUID] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    permission_strings: set = Field(default_factory=set)
    is_superuser: bool = False
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True

    def has_permission(
        self, permission: str, resource_scope: Optional[Dict] = None
    ) -> bool:
        """Check if user has a specific permission"""
        # Superuser has all permissions
        if self.is_superuser:
            return True

        # Check exact match
        if permission in self.permission_strings:
            return True

        # Check wildcards
        parts = permission.split(":")
        if len(parts) >= 2:
            resource, action = parts[0], parts[1]

            # Check resource wildcard (*:action)
            if f"*:{action}" in self.permission_strings:
                return True

            # Check action wildcard (resource:*)
            if f"{resource}:*" in self.permission_strings:
                return True

            # Check full wildcard (*:*)
            if "*:*" in self.permission_strings:
                return True

            # Check scoped permissions
            if resource_scope and len(parts) > 2:
                scope_key = f"{resource}:{action}:{resource_scope.get('id')}"
                if scope_key in self.permission_strings:
                    return True

        return False

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return role_name in self.roles

    def has_any_role(self, role_names: List[str]) -> bool:
        """Check if user has any of the specified roles"""
        return any(role in self.roles for role in role_names)

    def has_all_roles(self, role_names: List[str]) -> bool:
        """Check if user has all specified roles"""
        return all(role in self.roles for role in role_names)


class RBACDependencies:
    """Dependency injection class for RBAC"""

    def __init__(
        self,
        permission_service: PermissionService,
        assignment_service: AssignmentService,
        secret_key: str,
        algorithm: str = "HS256",
        token_expiry_seconds: int = 3600,
    ):
        self.permission_service = permission_service
        self.assignment_service = assignment_service
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry_seconds = token_expiry_seconds
        self._user_cache: Dict[str, tuple[UserContext, float]] = (
            {}
        )  # token -> (user, expiry)
        self.cache_ttl_seconds = 300  # Cache user contexts for 5 minutes

    async def get_current_user(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
        token: Optional[str] = Depends(oauth2_scheme),
    ) -> Optional[UserContext]:
        """Extract current user from JWT token"""

        # Get token from either security or oauth2 scheme
        token_str = None
        if credentials:
            token_str = credentials.credentials
        elif token:
            token_str = token

        if not token_str:
            return None

        # Check cache
        cached = self._user_cache.get(token_str)
        if cached:
            user, expiry = cached
            if time.time() < expiry:
                return user
            else:
                self._user_cache.pop(token_str, None)

        try:
            # Decode JWT token
            payload = jwt.decode(
                token_str, self.secret_key, algorithms=[self.algorithm]
            )

            # Validate payload
            token_data = TokenPayload(**payload)

            user_id = token_data.sub
            if not user_id:
                return None

            # Extract tenant from request or token
            tenant_id = token_data.tenant_id
            if not tenant_id and hasattr(request.state, "tenant_id"):
                tenant_id = request.state.tenant_id
            elif not tenant_id:
                # Try to get from headers
                tenant_id = request.headers.get("X-Tenant-ID")

            # Convert to UUID if present
            tenant_uuid = UUID(tenant_id) if tenant_id else None
            user_uuid = UUID(user_id)

            # Get user permissions
            permission_strings = await self.permission_service.get_user_permissions(
                user_id=user_uuid, tenant_id=tenant_uuid
            )

            # Get user roles
            roles = await self.assignment_service.get_user_effective_roles(
                user_id=user_uuid, tenant_id=tenant_uuid
            )

            # Build user context
            user_context = UserContext(
                id=user_uuid,
                tenant_id=tenant_uuid,
                username=token_data.metadata.get("username"),
                email=token_data.metadata.get("email"),
                roles=[r["name"] for r in roles],
                role_ids=[UUID(r["id"]) for r in roles if "id" in r],
                permissions=list(permission_strings),
                permission_strings=permission_strings,
                is_superuser="*:*" in permission_strings,
                metadata=token_data.metadata,
            )

            # Cache the result
            self._user_cache[token_str] = (
                user_context,
                time.time() + self.cache_ttl_seconds,
            )

            return user_context

        except JWTError as e:
            logger.warning(f"JWT decode error: {e}")
            return None
        except ValidationError as e:
            logger.warning(f"Token payload validation error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting current user: {e}")
            return None

    async def get_current_active_user(
        self, current_user: Optional[UserContext] = Depends(get_current_user)
    ) -> UserContext:
        """Get current active user or raise 401"""
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is inactive",
            )

        return current_user

    async def get_optional_user(
        self, current_user: Optional[UserContext] = Depends(get_current_user)
    ) -> Optional[UserContext]:
        """Get current user or None (no error if not authenticated)"""
        return current_user

    def require_permissions(
        self,
        permissions: List[str],
        require_all: bool = True,
        resource_scope_param: Optional[str] = None,
        message: Optional[str] = None,
    ) -> Callable:
        """
        Dependency for requiring specific permissions

        Args:
            permissions: List of required permissions
            require_all: If True, user must have all permissions. If False, any one is sufficient
            resource_scope_param: Name of path/query parameter containing resource ID for scope checking
            message: Custom error message
        """

        async def permission_dependency(
            request: Request,
            current_user: UserContext = Depends(self.get_current_active_user),
        ) -> UserContext:

            # Extract resource scope if specified
            resource_scope = None
            if resource_scope_param:
                # Try path params first, then query params
                resource_id = request.path_params.get(resource_scope_param)
                if not resource_id:
                    resource_id = request.query_params.get(resource_scope_param)

                if resource_id:
                    resource_scope = {"id": resource_id}

            # Check permissions
            if require_all:
                # User must have all permissions
                missing = []
                for permission in permissions:
                    has_perm = current_user.has_permission(permission, resource_scope)
                    if not has_perm:
                        missing.append(permission)

                if missing:
                    error_msg = (
                        message or f"Missing required permissions: {', '.join(missing)}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=error_msg,
                    )
            else:
                # User must have at least one permission
                for permission in permissions:
                    if current_user.has_permission(permission, resource_scope):
                        return current_user

                # No permissions matched
                error_msg = (
                    message or f"None of the required permissions found: {permissions}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=error_msg,
                )

            return current_user

        return permission_dependency

    def require_roles(
        self, roles: List[str], require_all: bool = False, message: Optional[str] = None
    ) -> Callable:
        """
        Dependency for requiring specific roles

        Args:
            roles: List of required role names
            require_all: If True, user must have all roles. If False, any one is sufficient
            message: Custom error message
        """

        async def role_dependency(
            current_user: UserContext = Depends(self.get_current_active_user),
        ) -> UserContext:

            if require_all:
                if not current_user.has_all_roles(roles):
                    missing = set(roles) - set(current_user.roles)
                    error_msg = message or f"Missing required roles: {missing}"
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=error_msg,
                    )
            else:
                if not current_user.has_any_role(roles):
                    error_msg = message or f"User must have one of these roles: {roles}"
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=error_msg,
                    )

            return current_user

        return role_dependency

    def require_tenant_access(
        self,
        allow_cross_tenant: bool = False,
        tenant_id_source: str = "path",  # 'path', 'header', 'query', or 'auto'
    ) -> Callable:
        """
        Dependency to ensure user has access to the current tenant

        Args:
            allow_cross_tenant: If True, allow users to access other tenants (for support/admin)
            tenant_id_source: Where to get tenant ID from: 'path', 'header', 'query', or 'auto'
        """

        async def tenant_dependency(
            request: Request,
            current_user: UserContext = Depends(self.get_current_active_user),
        ) -> UserContext:

            # Get tenant ID from request based on source
            request_tenant_id = None

            if tenant_id_source == "path" or tenant_id_source == "auto":
                request_tenant_id = request.path_params.get("tenant_id")

            if not request_tenant_id and (
                tenant_id_source == "header" or tenant_id_source == "auto"
            ):
                request_tenant_id = request.headers.get("X-Tenant-ID")

            if not request_tenant_id and (
                tenant_id_source == "query" or tenant_id_source == "auto"
            ):
                request_tenant_id = request.query_params.get("tenant_id")

            if not request_tenant_id and not current_user.tenant_id:
                # No tenant context required
                return current_user

            if request_tenant_id:
                try:
                    request_tenant_uuid = UUID(request_tenant_id)
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid tenant ID format",
                    )

                # Superuser can access any tenant if allowed
                if current_user.is_superuser and allow_cross_tenant:
                    # Update the user context with the current tenant
                    current_user.tenant_id = request_tenant_uuid
                    return current_user

                # Check if user belongs to this tenant
                if current_user.tenant_id != request_tenant_uuid:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access to this tenant is not allowed",
                    )

            return current_user

        return tenant_dependency

    def require_self_or_permission(
        self,
        user_id_param: str = "user_id",
        permission: str = "user:manage",
        message: str = "You can only access your own resources",
    ) -> Callable:
        """
        Allow access if user is accessing their own resource OR has specific permission

        Args:
            user_id_param: Name of path/query parameter containing the target user ID
            permission: Permission required to bypass self-check
            message: Custom error message
        """

        async def dependency(
            request: Request,
            current_user: UserContext = Depends(self.get_current_active_user),
        ) -> UserContext:

            # Superuser bypass
            if current_user.is_superuser:
                return current_user

            # Get target user ID from request
            target_user_id = request.path_params.get(
                user_id_param
            ) or request.query_params.get(user_id_param)

            if target_user_id:
                try:
                    target_uuid = UUID(str(target_user_id))

                    # Check if accessing own resource
                    if current_user.id == target_uuid:
                        return current_user

                    # Check for required permission
                    if current_user.has_permission(permission):
                        return current_user

                except ValueError:
                    pass

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message,
            )

        return dependency

    def clear_user_cache(self, user_id: Optional[UUID] = None):
        """Clear user cache for specific user or all users"""
        if user_id:
            # Clear cache entries for specific user
            keys_to_clear = []
            for token, (user, _) in self._user_cache.items():
                if user.id == user_id:
                    keys_to_clear.append(token)

            for key in keys_to_clear:
                self._user_cache.pop(key, None)

            logger.debug(f"Cleared cache for user {user_id}")
        else:
            # Clear all cache
            self._user_cache.clear()
            logger.debug("Cleared all user cache")


# Decorators for route protection
def require_permissions(
    permissions: List[str],
    require_all: bool = True,
    resource_scope_param: Optional[str] = None,
    message: Optional[str] = None,
):
    """
    Decorator to require permissions on a route

    Example:
        @router.get("/patients/{patient_id}")
        @require_permissions(["patient:read"], resource_scope_param="patient_id")
        async def get_patient(patient_id: str):
            return {"patient": patient_id}
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        # Add metadata to the function for documentation
        wrapper.__rbac_required_permissions__ = permissions
        wrapper.__rbac_require_all__ = require_all
        wrapper.__rbac_resource_scope__ = resource_scope_param
        wrapper.__rbac_message__ = message

        return wrapper

    return decorator


def require_roles(
    roles: List[str], require_all: bool = False, message: Optional[str] = None
):
    """
    Decorator to require roles on a route

    Example:
        @router.get("/admin/dashboard")
        @require_roles(["admin", "super_admin"])
        async def admin_dashboard():
            return {"dashboard": "admin"}
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        wrapper.__rbac_required_roles__ = roles
        wrapper.__rbac_roles_require_all__ = require_all
        wrapper.__rbac_roles_message__ = message

        return wrapper

    return decorator


def require_self_or_permission(
    user_id_param: str = "user_id",
    permission: str = "user:manage",
    message: str = "You can only access your own resources",
):
    """
    Decorator to allow self-access or users with specific permission

    Example:
        @router.get("/users/{user_id}")
        @require_self_or_permission()
        async def get_user(user_id: str):
            return {"user": user_id}
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        wrapper.__rbac_self_param__ = user_id_param
        wrapper.__rbac_self_permission__ = permission
        wrapper.__rbac_self_message__ = message

        return wrapper

    return decorator


def public_route(func: Callable) -> Callable:
    """
    Mark a route as public (no authentication required)

    Example:
        @router.get("/health")
        @public_route
        async def health_check():
            return {"status": "healthy"}
    """
    func.__rbac_public__ = True
    return func


# Middleware for adding user context to request
class RBACMiddleware:
    """Middleware to add user context to all requests"""

    def __init__(
        self,
        app,
        rbac_dependencies: RBACDependencies,
        exclude_paths: Optional[List[str]] = None,
        public_paths: Optional[List[str]] = None,
    ):
        self.app = app
        self.rbac = rbac_dependencies
        self.exclude_paths = exclude_paths or ["/docs", "/redoc", "/openapi.json"]
        self.public_paths = public_paths or ["/health", "/metrics"]

    async def __call__(self, request: Request, call_next):
        # Skip for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        # Check if path is public
        is_public = any(request.url.path.startswith(path) for path in self.public_paths)

        # Get current user
        try:
            current_user = await self.rbac.get_current_user(request)
            request.state.user = current_user
            request.state.is_public = is_public
        except Exception as e:
            logger.error(f"Error in RBAC middleware: {e}")
            request.state.user = None
            request.state.is_public = is_public

        # Process request
        response = await call_next(request)
        return response


# Helper function to create RBAC dependencies instance
def create_rbac_dependencies(
    permission_service: PermissionService,
    assignment_service: AssignmentService,
    secret_key: str,
    algorithm: str = "HS256",
) -> RBACDependencies:
    """Factory function to create RBAC dependencies"""
    return RBACDependencies(
        permission_service=permission_service,
        assignment_service=assignment_service,
        secret_key=secret_key,
        algorithm=algorithm,
    )
