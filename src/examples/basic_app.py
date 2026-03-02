# examples/basic_app.py
from fastapi import FastAPI, Depends, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from uuid import uuid4, UUID
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import uvicorn
import os
from dotenv import load_dotenv

from rbac.core.database import Database
from rbac.services.permission_service import PermissionService
from rbac.services.role_service import RoleService
from rbac.services.assignment_service import AssignmentService, RoleExclusivity
from rbac.dependencies.auth import (
    RBACDependencies,
    RBACMiddleware,
    UserContext,
    require_permissions,
    require_roles,
    public_route,
    require_self_or_permission,
)
from rbac.decorators.rbac import (
    RBACDecorators,
    PermissionChecker,
    create_rbac_router,
    rbac_required,
    get_current_user_from_request,
)
from rbac.core.constants import ResourceType, PermissionAction
from rbac.core.exceptions import (
    PermissionDeniedError,
    RoleNotFoundError,
    TenantNotFoundError,
)
from rbac.core.models import Permission, Role, UserRole

load_dotenv()


# Initialize app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("Starting up...")
    await db.connect()

    # Initialize default roles and permissions
    await initialize_rbac()

    yield

    # Shutdown
    print("Shutting down...")
    await db.disconnect()


app = FastAPI(
    title="RBAC Example App",
    description="Example FastAPI application with Role-Based Access Control",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
db = Database(
    dsn=os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/rbac"),
    min_size=int(os.getenv("DB_POOL_MIN_SIZE", "10")),
    max_size=int(os.getenv("DB_POOL_MAX_SIZE", "20")),
)

permission_service = PermissionService(db)
role_service = RoleService(db, permission_service)
assignment_service = AssignmentService(db, role_service, permission_service)

# Initialize RBAC dependencies
rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key=os.getenv("JWT_SECRET_KEY", "your-secret-key-here"),
    algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
    token_expiry_seconds=int(os.getenv("JWT_EXPIRY_SECONDS", "3600")),
)

# Initialize RBAC decorators
rbac_decorators = RBACDecorators(permission_service, assignment_service)

# Initialize permission checker
permission_checker = PermissionChecker(permission_service)

# Add RBAC middleware
app.middleware("http")(
    RBACMiddleware(
        app,
        rbac,
        exclude_paths=["/docs", "/redoc", "/openapi.json", "/public", "/health"],
        public_paths=["/health", "/public/info", "/auth/login"],
    )
)

# Create specialized routers
admin_router = create_rbac_router(
    prefix="/admin",
    tags=["admin"],
    permissions=["admin:access"],
    rbac_dependencies=rbac,
)

patient_router = create_rbac_router(
    prefix="/patients",
    tags=["patients"],
    permissions=["patient:access"],
    rbac_dependencies=rbac,
)

# Include routers
app.include_router(admin_router)
app.include_router(patient_router)


# Initialize RBAC data
async def initialize_rbac():
    """Initialize default RBAC data"""

    # Create default tenant if needed
    try:
        from rbac.core.database import tenants
        from sqlalchemy import select

        # Check if default tenant exists
        stmt = select(tenants).where(tenants.c.name == "Default Tenant")
        tenant = await db.fetch_one(stmt)

        if not tenant:
            # Create default tenant
            from datetime import datetime, timezone
            from sqlalchemy import insert

            stmt = (
                insert(tenants)
                .values(
                    name="Default Tenant",
                    domain="localhost",
                    is_active=True,
                    settings={"theme": "light"},
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                .returning(*tenants.columns)
            )

            tenant = await db.fetch_one(stmt)
            print(f"Created default tenant: {tenant['id']}")

        # Initialize default roles
        await role_service.initialize_default_roles(tenant["id"] if tenant else None)

        # Configure role exclusivity rules
        admin_role = await role_service.get_role_by_name("Admin")
        super_admin_role = await role_service.get_role_by_name("Super Admin")

        if admin_role and super_admin_role:
            await assignment_service.configure_role_exclusivity(
                role_id=admin_role.id,
                rule=RoleExclusivity.MUTUALLY_EXCLUSIVE,
                exclusive_with=[super_admin_role.id],
            )

        # # Set max roles per user
        await assignment_service.configure_max_roles(max_roles=5)

        print("RBAC initialization complete")

    except Exception as e:
        print(f"Error initializing RBAC: {e}")


# Public routes
@app.get("/health", tags=["public"])
@public_route
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if db.engine else "disconnected",
    }


@app.get("/public/info", tags=["public"])
@public_route
async def public_info():
    """Public information endpoint"""
    return {
        "message": "This is public information",
        "version": "1.0.0",
        "features": ["RBAC", "Multi-tenancy", "JWT Auth"],
    }


# Authentication endpoints (simplified for example)
@app.post("/auth/login", tags=["auth"])
@public_route
async def login(username: str, password: str):
    """Simplified login endpoint - returns JWT token"""
    # In production, validate credentials against your user database
    # This is just an example

    # Mock user data
    user_id = uuid4()
    tenant_id = uuid4()

    # Create JWT token
    from jose import jwt
    import os

    token_data = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "metadata": {"username": username, "email": f"{username}@example.com"},
        "iat": datetime.now().timestamp(),
        "exp": (datetime.now() + timedelta(hours=1)).timestamp(),
    }

    token = jwt.encode(
        token_data,
        os.getenv("JWT_SECRET_KEY", "your-secret-key-here"),
        algorithm="HS256",
    )

    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


# Protected user routes
@app.get("/users/me", tags=["users"])
@require_permissions(["user:read:self"])
async def get_current_user_info(
    current_user: UserContext = Depends(rbac.get_current_active_user),
):
    """Get current user information"""
    return {
        "user_id": str(current_user.id),
        "tenant_id": str(current_user.tenant_id) if current_user.tenant_id else None,
        "username": current_user.username,
        "email": current_user.email,
        "roles": current_user.roles,
        "role_ids": [str(rid) for rid in current_user.role_ids],
        "permissions": current_user.permissions[:20],  # First 20 for brevity
        "permission_count": len(current_user.permissions),
        "is_superuser": current_user.is_superuser,
        "is_active": current_user.is_active,
        "metadata": current_user.metadata,
    }


@app.get("/users/{user_id}", tags=["users"])
@require_self_or_permission(
    user_id_param="user_id",
    permission="user:read",
    message="You can only view your own profile or have user:read permission",
)
async def get_user(
    user_id: UUID, current_user: UserContext = Depends(rbac.get_current_active_user)
):
    """Get user by ID (self or with permission)"""
    # In production, fetch user from database
    return {
        "user_id": str(user_id),
        "requested_by": str(current_user.id),
        "profile": {
            "username": f"user_{user_id}",
            "email": f"user_{user_id}@example.com",
        },
    }


# Patient routes
@patient_router.get("/")
async def list_patients(
    current_user: UserContext = Depends(rbac.get_current_active_user),
    limit: int = 10,
    offset: int = 0,
):
    """List all patients (requires patient:read permission)"""
    # This router already has patient:access permission, plus we check patient:read
    if not current_user.has_permission("patient:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required permission: patient:read",
        )

    # In production, fetch from database
    return {
        "patients": [
            {"id": str(uuid4()), "name": f"Patient {i}"}
            for i in range(offset, offset + limit)
        ],
        "total": 100,
        "limit": limit,
        "offset": offset,
        "user": str(current_user.id),
    }


@patient_router.get("/{patient_id}")
@require_permissions(["patient:read"], resource_scope_param="patient_id")
async def get_patient(
    patient_id: str,
    current_user: UserContext = Depends(rbac.get_current_active_user),
    include_details: bool = False,
):
    """Get specific patient (scoped permission check)"""
    # In production, fetch from database
    patient = {
        "id": patient_id,
        "name": f"Patient {patient_id}",
        "created_at": datetime.now().isoformat(),
    }

    if include_details and current_user.has_permission("patient:read:details"):
        patient["details"] = {
            "address": "123 Main St",
            "phone": "555-0123",
            "email": f"patient{patient_id}@example.com",
        }

    return {"patient": patient, "accessed_by": str(current_user.id)}


@patient_router.post("/")
@require_permissions(["patient:create"])
async def create_patient(
    patient_data: dict,
    current_user: UserContext = Depends(rbac.get_current_active_user),
):
    """Create a new patient"""
    # Validate input
    if not patient_data.get("name"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Patient name is required"
        )

    # In production, save to database
    patient_id = str(uuid4())

    # Audit log
    await assignment_service._audit_log(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        action="CREATE",
        resource_type="patient",
        resource_id=UUID(patient_id),
        new_value=patient_data,
    )

    return {
        "message": "Patient created",
        "patient_id": patient_id,
        "data": patient_data,
        "created_by": str(current_user.id),
    }


@patient_router.put("/{patient_id}")
@require_permissions(
    ["patient:update", "patient:write"],
    require_all=True,
    resource_scope_param="patient_id",
)
async def update_patient(
    patient_id: str,
    update_data: dict,
    current_user: UserContext = Depends(rbac.get_current_active_user),
):
    """Update patient (requires both permissions)"""
    # In production, fetch existing patient and update
    return {
        "message": f"Patient {patient_id} updated",
        "data": update_data,
        "updated_by": str(current_user.id),
    }


@patient_router.delete("/{patient_id}")
@require_permissions(["patient:delete"])
async def delete_patient(
    patient_id: str,
    current_user: UserContext = Depends(rbac.get_current_active_user),
    confirm: bool = False,
):
    """Delete a patient (requires confirmation)"""
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide confirm=true to delete",
        )

    # In production, soft delete or archive
    return {
        "message": f"Patient {patient_id} deleted",
        "deleted_by": str(current_user.id),
        "deleted_at": datetime.now().isoformat(),
    }


# Admin routes
@admin_router.get("/dashboard")
@require_roles(["admin", "super_admin"])
async def admin_dashboard(
    current_user: UserContext = Depends(rbac.get_current_active_user),
):
    """Admin dashboard - accessible by admin or super_admin"""
    # Get statistics
    stats = await assignment_service.get_assignment_stats(current_user.tenant_id)

    return {
        "dashboard": "Admin Dashboard",
        "user_role": current_user.roles,
        "stats": stats,
        "recent_activity": [
            {"action": "User login", "time": datetime.now().isoformat()}
        ],
    }


@admin_router.get("/users")
@require_permissions(["user:manage"])
async def manage_users(
    current_user: UserContext = Depends(rbac.get_current_active_user),
    role_id: Optional[UUID] = None,
    limit: int = 50,
    offset: int = 0,
):
    """Manage users (admin only)"""
    if role_id:
        # Get users in specific role
        users = await assignment_service.get_users_in_role(
            role_id=role_id,
            tenant_id=current_user.tenant_id,
            limit=limit,
            offset=offset,
        )
    else:
        # In production, get all users
        users = []

    return {"users": users, "total": len(users), "limit": limit, "offset": offset}


@admin_router.post("/roles/{role_id}/assign")
@require_permissions(["role:assign"])
async def assign_role_to_user(
    role_id: UUID,
    user_id: UUID,
    current_user: UserContext = Depends(rbac.get_current_active_user),
    expires_in_days: Optional[int] = None,
):
    """Assign role to user"""
    try:
        assignment = await assignment_service.assign_role_to_user(
            user_id=user_id,
            role_id=role_id,
            tenant_id=current_user.tenant_id,
            granted_by=current_user.id,
            expires_in_days=expires_in_days,
        )

        return {
            "message": "Role assigned successfully",
            "assignment": assignment.model_dump(),
        }

    except RoleNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionDeniedError as e:
        raise HTTPException(status_code=403, detail=str(e))


# Tenant-aware routes
@app.get("/tenant/settings", tags=["tenant"])
async def get_tenant_settings(
    current_user: UserContext = Depends(
        rbac.require_tenant_access()(rbac.get_current_active_user)
    ),
):
    """Get current tenant settings"""
    if not current_user.tenant_id:
        return {"message": "No tenant context"}

    # In production, fetch from database
    return {
        "tenant_id": str(current_user.tenant_id),
        "settings": {
            "theme": "light",
            "timezone": "UTC",
            "features": ["rbac", "audit"],
        },
    }


# Programmatic permission check example
@app.post("/api/v1/data/{resource_id}/process", tags=["dynamic"])
async def process_resource(resource_id: str, action: str, request: Request):
    """Example of programmatic permission check with dynamic permissions"""
    user = get_current_user_from_request(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    # Dynamic permission based on action
    required_permission = f"data:{action}"

    try:
        if await permission_checker.check(
            user_id=user.id,
            permission=required_permission,
            tenant_id=user.tenant_id,
            resource_scope={"id": resource_id},
            raise_exception=True,
            exception_message=f"Cannot {action} this resource",
        ):
            # Process the resource
            result = {
                "message": f"Processing {action} on {resource_id}",
                "status": "success",
                "processed_by": str(user.id),
                "timestamp": datetime.now().isoformat(),
            }

            # Audit log
            await assignment_service._audit_log(
                user_id=user.id,
                tenant_id=user.tenant_id,
                action=action.upper(),
                resource_type="data",
                resource_id=UUID(resource_id) if resource_id else None,
                new_value={"action": action},
            )

            return result

    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


# Batch operations with validation
@app.post("/api/v1/batch/assign", tags=["batch"])
@require_permissions(["role:batch_assign"])
async def batch_assign_roles(
    assignments: List[Dict[str, Any]],
    current_user: UserContext = Depends(rbac.get_current_active_user),
):
    """Batch assign roles with validation"""
    results = {"successful": [], "failed": []}

    for assignment in assignments:
        try:
            user_id = UUID(assignment["user_id"])
            role_id = UUID(assignment["role_id"])

            # Validate first
            valid_users, invalid = await assignment_service.validate_bulk_assignments(
                user_ids=[user_id], role_id=role_id, tenant_id=current_user.tenant_id
            )

            if valid_users:
                # Perform assignment
                result = await assignment_service.assign_role_to_user(
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=current_user.tenant_id,
                    granted_by=current_user.id,
                    expires_in_days=assignment.get("expires_in_days"),
                )
                results["successful"].append(
                    {
                        "user_id": str(user_id),
                        "role_id": str(role_id),
                        "assignment_id": str(result.id),
                    }
                )
            else:
                results["failed"].append(
                    {
                        "user_id": str(user_id),
                        "role_id": str(role_id),
                        "reason": invalid[0][1] if invalid else "Validation failed",
                    }
                )

        except Exception as e:
            results["failed"].append({"assignment": assignment, "reason": str(e)})

    return {"message": f"Batch assignment complete", "results": results}


# Example with class-based view
class ReportController:
    """Class-based view for reports"""

    def __init__(self, request: Request):
        self.request = request
        self.user = get_current_user_from_request(request)

    @rbac_decorators.check_permissions(
        permissions=["report:read"], resource_id_param="report_id"
    )
    async def get_report(self, report_id: str):
        """Get specific report"""
        return {
            "report_id": report_id,
            "data": f"Report data for {report_id}",
            "user": str(self.user.id) if self.user else None,
        }

    @rbac_decorators.check_permissions(
        permissions=["report:generate"], require_all=False
    )
    async def generate_report(self, report_type: str, parameters: dict):
        """Generate a new report"""
        return {
            "report_id": str(uuid4()),
            "type": report_type,
            "parameters": parameters,
            "generated_by": str(self.user.id) if self.user else None,
            "generated_at": datetime.now().isoformat(),
        }


# Wire up class-based view
@app.get("/reports/{report_id}", tags=["reports"])
async def get_report(report_id: str, request: Request):
    controller = ReportController(request)
    return await controller.get_report(report_id)


@app.post("/reports/generate", tags=["reports"])
async def generate_report(report_type: str, parameters: dict, request: Request):
    controller = ReportController(request)
    return await controller.generate_report(report_type, parameters)


# Error handlers
@app.exception_handler(PermissionDeniedError)
async def permission_denied_handler(request: Request, exc: PermissionDeniedError):
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"message": str(exc), "details": exc.details},
    )


@app.exception_handler(RoleNotFoundError)
async def role_not_found_handler(request: Request, exc: RoleNotFoundError):
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# Database status endpoint
@app.get("/debug/db-status", tags=["debug"])
@require_roles(["super_admin"])
async def db_status():
    """Get database connection pool status (super_admin only)"""
    status = await db.status()
    return status


if __name__ == "__main__":
    uvicorn.run(
        "examples.basic_app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("DEBUG", "False").lower() == "true",
    )
