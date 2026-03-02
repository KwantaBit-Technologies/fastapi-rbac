# examples/audit_example.py
from fastapi import FastAPI, Depends, Request
from uuid import uuid4
import uvicorn
from typing import Callable, Optional
from datetime import datetime

from core.database import Database
from services.audit_service import (
    AuditEvent,
    AuditService,
    AuditAction,
    AuditResourceType,
    AuditContext,
)
from middleware.audit import AuditMiddleware, audit_logger, get_audit_service

app = FastAPI()

# Initialize services
db = Database("postgresql://user:pass@localhost/rbac")
audit_service = AuditService(db, retention_days=90)

# Add audit middleware
app.add_middleware(
    AuditMiddleware,
    audit_service=audit_service,
    exclude_paths=["/health", "/metrics"],
    log_headers=True,
)

# Store in app state
app.state.audit_service = audit_service


@app.on_event("startup")
async def startup():
    await db.connect()


@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()
    await audit_service.flush_buffer()


# Routes with audit logging
@app.post("/api/roles")
async def create_role(role_data: dict, audit: Callable = Depends(audit_logger)):
    """Create a new role with audit logging"""

    # Your role creation logic here
    role_id = uuid4()

    # Log the action
    await audit(
        action=AuditAction.CREATE,
        resource_type=AuditResourceType.ROLE,
        resource_id=role_id,
        new_value=role_data,
        description=f"Created new role: {role_data.get('name')}",
    )

    return {"role_id": role_id, "message": "Role created"}


@app.patch("/api/roles/{role_id}")
async def update_role(
    role_id: str,
    updates: dict,
    old_data: dict,  # You'd get this from your service
    audit: Callable = Depends(audit_logger),
):
    """Update a role with change tracking"""

    # Log the changes
    await audit(
        action=AuditAction.UPDATE,
        resource_type=AuditResourceType.ROLE,
        resource_id=role_id,
        old_value=old_data,
        new_value=updates,
        description=f"Updated role {role_id}",
    )

    return {"message": "Role updated"}


@app.delete("/api/roles/{role_id}")
async def delete_role(
    role_id: str,
    role_data: dict,  # The role being deleted
    audit: Callable = Depends(audit_logger),
):
    """Delete a role"""

    await audit(
        action=AuditAction.DELETE,
        resource_type=AuditResourceType.ROLE,
        resource_id=role_id,
        old_value=role_data,
        description=f"Deleted role {role_id}",
    )

    return {"message": "Role deleted"}


# Using AuditContext for complex operations
@app.post("/api/bulk-assign")
async def bulk_assign_roles(
    assignments: list,
    request: Request,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Bulk assign roles with grouped audit logging"""

    user_id = request.state.user.id if hasattr(request.state, "user") else None

    async with AuditContext(
        audit_service=audit_service, user_id=user_id, metadata={"bulk_operation": True}
    ) as context:

        results = []
        for assignment in assignments:
            # Your assignment logic here
            result = {"user_id": assignment["user_id"], "success": True}
            results.append(result)

            # Log individual assignment
            await context.log(
                AuditEvent(
                    user_id=user_id,
                    action=AuditAction.ASSIGN,
                    resource_type=AuditResourceType.USER_ROLE,
                    resource_id=assignment.get("role_id"),
                    metadata={"assignment": assignment},
                )
            )

        return {"results": results, "count": len(results)}


# Query audit logs
@app.get("/api/audit/roles/{role_id}")
async def get_role_audit_history(
    role_id: str, audit_service: AuditService = Depends(get_audit_service)
):
    """Get audit history for a specific role"""

    logs = await audit_service.get_resource_history(
        resource_type=AuditResourceType.ROLE, resource_id=role_id, limit=50
    )

    return {"role_id": role_id, "audit_logs": [log.dict() for log in logs]}


@app.get("/api/audit/user/{user_id}")
async def get_user_audit_trail(
    user_id: str, audit_service: AuditService = Depends(get_audit_service)
):
    """Get complete audit trail for a user"""

    logs = await audit_service.get_user_trail(user_id=user_id, limit=100)

    return {"user_id": user_id, "audit_trail": [log.dict() for log in logs]}


@app.get("/api/audit/summary")
async def get_audit_summary(
    tenant_id: Optional[str] = None,
    days: int = 30,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Get audit summary"""

    if tenant_id:
        summary = await audit_service.get_tenant_audit_summary(
            tenant_id=tenant_id, days=days
        )
    else:
        summary = await audit_service.get_statistics(days=days)

    return summary


@app.post("/api/audit/export")
async def export_audit_logs(
    start_date: datetime,
    end_date: datetime,
    tenant_id: Optional[str] = None,
    format: str = "json",
    audit_service: AuditService = Depends(get_audit_service),
):
    """Export audit logs for compliance"""

    logs = await audit_service.export_logs(
        tenant_id=tenant_id, start_date=start_date, end_date=end_date, format=format
    )

    return {"logs": logs, "count": len(logs) if isinstance(logs, list) else "csv data"}


@app.post("/api/audit/cleanup")
async def cleanup_audit_logs(
    days: Optional[int] = None, audit_service: AuditService = Depends(get_audit_service)
):
    """Manually trigger cleanup of old audit logs"""

    deleted = await audit_service.cleanup_old_logs(days)

    return {"deleted_count": deleted, "message": f"Deleted {deleted} old audit logs"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
