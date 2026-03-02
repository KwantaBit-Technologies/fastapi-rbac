# rbac/middleware/audit.py
from fastapi import Request, Response, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable, Optional, Dict
from uuid import UUID, uuid4
import time

from services.audit_service import (
    AuditService,
    AuditAction,
    AuditResourceType,
    AuditSeverity,
)
from utils.logger import setup_logger

logger = setup_logger("audit_middleware")


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic request auditing"""

    def __init__(
        self,
        app,
        audit_service: AuditService,
        exclude_paths: Optional[list] = None,
        log_headers: bool = False,
        log_body: bool = False,
        log_response: bool = False,
    ):
        super().__init__(app)
        self.audit_service = audit_service
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/docs", "/redoc"]
        self.log_headers = log_headers
        self.log_body = log_body
        self.log_response = log_response

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid4())
        request.state.request_id = request_id

        # Skip excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        # Extract user info if available
        user_id = None
        tenant_id = None
        if hasattr(request.state, "user") and request.state.user:
            user_id = request.state.user.id
            tenant_id = request.state.user.tenant_id

        # Prepare metadata
        metadata = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
        }

        if self.log_headers:
            metadata["headers"] = dict(request.headers)

        # Log request start
        start_time = time.time()

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Log successful request
            if response.status_code < 400:
                await self.audit_service.log_action(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    action=AuditAction.ACCESS,
                    resource_type=AuditResourceType.API,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    metadata={
                        **metadata,
                        "status_code": response.status_code,
                        "duration_ms": round(duration * 1000, 2),
                    },
                    description=f"{request.method} {request.url.path}",
                )
            else:
                # Log error
                severity = (
                    AuditSeverity.ERROR
                    if response.status_code >= 500
                    else AuditSeverity.WARNING
                )
                await self.audit_service.log_action(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    action=AuditAction.ACCESS,
                    resource_type=AuditResourceType.API,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    metadata={
                        **metadata,
                        "status_code": response.status_code,
                        "duration_ms": round(duration * 1000, 2),
                    },
                    description=f"{request.method} {request.url.path} - {response.status_code}",
                    status="ERROR",
                    error_message=f"HTTP {response.status_code}",
                )

            return response

        except Exception as e:
            # Log exception
            duration = time.time() - start_time

            await self.audit_service.log_action(
                user_id=user_id,
                tenant_id=tenant_id,
                action=AuditAction.ACCESS,
                resource_type=AuditResourceType.API,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                metadata={**metadata, "duration_ms": round(duration * 1000, 2)},
                description=f"Exception in {request.method} {request.url.path}",
                status="ERROR",
                error_message=str(e),
            )

            raise


# Audit dependency for FastAPI
async def get_audit_service(request: Request) -> AuditService:
    """Get audit service from app state"""
    return request.app.state.audit_service


async def audit_logger(
    request: Request, audit_service: AuditService = Depends(get_audit_service)
) -> Callable:
    """Dependency for logging within route handlers"""

    async def log_action(
        action: AuditAction,
        resource_type: AuditResourceType,
        resource_id: Optional[UUID] = None,
        old_value: Optional[Dict] = None,
        new_value: Optional[Dict] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ):
        user_id = None
        tenant_id = None
        if hasattr(request.state, "user") and request.state.user:
            user_id = request.state.user.id
            tenant_id = request.state.user.tenant_id

        await audit_service.log_action(
            user_id=user_id,
            tenant_id=tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            old_value=old_value,
            new_value=new_value,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={
                "request_id": getattr(request.state, "request_id", None),
                "path": request.url.path,
                "method": request.method,
                **(metadata or {}),
            },
            description=description,
        )

    return log_action
