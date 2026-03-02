# rbac/services/audit_service.py
from typing import Optional, List, Dict, Any, Union
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from fastapi import Request
from sqlalchemy import select, insert, delete, and_, or_, func, text, desc, asc
from enum import Enum
from pydantic import BaseModel, Field

from core.database import Database, audit_logs
from core.models import AuditLog
from utils.logger import setup_logger

logger = setup_logger("audit_service")


class AuditAction(str, Enum):
    """Standard audit actions"""

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
    EXPORT = "EXPORT"
    IMPORT = "IMPORT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    ROLE_CHANGE = "ROLE_CHANGE"
    USER_CHANGE = "USER_CHANGE"
    TENANT_CHANGE = "TENANT_CHANGE"


class AuditResourceType(str, Enum):
    """Standard resource types for auditing"""

    ROLE = "role"
    PERMISSION = "permission"
    USER_ROLE = "user_role"
    USER = "user"
    TENANT = "tenant"
    SETTINGS = "settings"
    API = "api"
    AUTH = "auth"
    SYSTEM = "system"
    SESSION = "session"


class AuditSeverity(str, Enum):
    """Severity levels for audit events"""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditEvent(BaseModel):
    """Structured audit event"""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    tenant_id: Optional[UUID] = None
    tenant_name: Optional[str] = None
    action: AuditAction
    resource_type: AuditResourceType
    resource_id: Optional[UUID] = None
    resource_name: Optional[str] = None
    severity: AuditSeverity = AuditSeverity.INFO
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    changes: Optional[List[Dict[str, Any]]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    status: str = "SUCCESS"
    error_message: Optional[str] = None

    class Config:
        use_enum_values = True
        arbitrary_types_allowed = True


class AuditService:
    """Comprehensive audit logging service with SQLAlchemy Core"""

    def __init__(self, db: Database, retention_days: int = 90, batch_size: int = 100):
        self.db = db
        self.retention_days = retention_days
        self.batch_size = batch_size
        self._audit_buffer: List[AuditEvent] = []

    async def log(self, event: Union[AuditEvent, Dict[str, Any]]) -> AuditLog:
        """Log an audit event"""

        # Convert dict to AuditEvent if needed
        if isinstance(event, dict):
            event = AuditEvent(**event)

        try:
            # Prepare metadata JSON
            metadata = {
                "username": event.username,
                "tenant_name": event.tenant_name,
                "resource_name": event.resource_name,
                "severity": (
                    event.severity.value if event.severity else AuditSeverity.INFO.value
                ),
                "changes": event.changes,
                "request_id": event.request_id,
                "session_id": event.session_id,
                "description": event.description,
                "status": event.status,
                "error_message": event.error_message,
                **event.metadata,
            }

            # Insert into database using SQLAlchemy Core
            stmt = (
                insert(audit_logs)
                .values(
                    user_id=event.user_id,
                    tenant_id=event.tenant_id,
                    action=event.action.value if event.action else None,
                    resource_type=(
                        event.resource_type.value if event.resource_type else None
                    ),
                    resource_id=event.resource_id,
                    old_value=event.old_value,
                    new_value=event.new_value,
                    ip_address=event.ip_address,
                    user_agent=event.user_agent,
                    metadata=metadata,
                    created_at=event.timestamp,
                )
                .returning(*audit_logs.columns)
            )

            result = await self.db.fetch_one(stmt)

            if not result:
                raise RuntimeError("Failed to create audit log")

            logger.debug(f"Audit log created: {result['id']}")
            return AuditLog.model_validate(result)

        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            # Buffer the event for retry
            self._audit_buffer.append(event)
            raise

    async def log_batch(self, events: List[AuditEvent]) -> List[AuditLog]:
        """Log multiple audit events in batch"""
        if not events:
            return []

        try:
            async with self.db.transaction() as conn:
                results = []
                for event in events:
                    # Prepare metadata JSON
                    metadata = {
                        "username": event.username,
                        "tenant_name": event.tenant_name,
                        "resource_name": event.resource_name,
                        "severity": (
                            event.severity.value
                            if event.severity
                            else AuditSeverity.INFO.value
                        ),
                        "changes": event.changes,
                        "request_id": event.request_id,
                        "session_id": event.session_id,
                        "description": event.description,
                        "status": event.status,
                        "error_message": event.error_message,
                        **event.metadata,
                    }

                    stmt = (
                        insert(audit_logs)
                        .values(
                            user_id=event.user_id,
                            tenant_id=event.tenant_id,
                            action=event.action.value if event.action else None,
                            resource_type=(
                                event.resource_type.value
                                if event.resource_type
                                else None
                            ),
                            resource_id=event.resource_id,
                            old_value=event.old_value,
                            new_value=event.new_value,
                            ip_address=event.ip_address,
                            user_agent=event.user_agent,
                            metadata=metadata,
                            created_at=event.timestamp,
                        )
                        .returning(*audit_logs.columns)
                    )

                    result = await conn.execute(stmt)
                    row = result.first()
                    if row:
                        results.append(AuditLog.model_validate(dict(row._mapping)))

                logger.info(f"Batch logged {len(results)} audit events")
                return results

        except Exception as e:
            logger.error(f"Failed to batch log audit events: {e}")
            # Add to buffer for retry
            self._audit_buffer.extend(events)
            raise

    async def log_action(
        self,
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
        error_message: Optional[str] = None,
    ) -> AuditLog:
        """Simplified method to log an action"""

        # Calculate changes if both old and new values exist
        changes = None
        if old_value and new_value:
            changes = self._calculate_changes(old_value, new_value)

        event = AuditEvent(
            user_id=user_id,
            tenant_id=tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            old_value=old_value,
            new_value=new_value,
            changes=changes,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            description=description,
            status=status,
            error_message=error_message,
        )

        return await self.log(event)

    async def log_access(
        self,
        user_id: UUID,
        resource: str,
        resource_id: Optional[UUID] = None,
        tenant_id: Optional[UUID] = None,
        granted: bool = True,
        required_permission: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> AuditLog:
        """Log access attempts (both granted and denied)"""

        action = AuditAction.ACCESS if granted else AuditAction.DENIED
        severity = AuditSeverity.INFO if granted else AuditSeverity.WARNING

        description = f"Access {'granted' if granted else 'denied'} to {resource}"
        if required_permission:
            description += f" (required: {required_permission})"

        event = AuditEvent(
            user_id=user_id,
            tenant_id=tenant_id,
            action=action,
            resource_type=AuditResourceType.API,
            resource_id=resource_id,
            severity=severity,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "resource": resource,
                "required_permission": required_permission,
                **(metadata or {}),
            },
            description=description,
            status="SUCCESS" if granted else "DENIED",
        )

        return await self.log(event)

    async def log_auth(
        self,
        user_id: Optional[UUID],
        action: str,  # login, logout, failed_login
        tenant_id: Optional[UUID] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> AuditLog:
        """Log authentication events"""

        action_map = {
            "login": AuditAction.LOGIN,
            "logout": AuditAction.LOGOUT,
            "failed_login": AuditAction.DENIED,
        }

        audit_action = action_map.get(action, AuditAction.ACCESS)
        severity = (
            AuditSeverity.INFO if action != "failed_login" else AuditSeverity.WARNING
        )
        status = "SUCCESS" if action != "failed_login" else "FAILED"

        event = AuditEvent(
            user_id=user_id,
            tenant_id=tenant_id,
            action=audit_action,
            resource_type=AuditResourceType.AUTH,
            severity=severity,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "username": username,
                "failure_reason": failure_reason,
                **(metadata or {}),
            },
            description=f"Authentication {action}",
            status=status,
            error_message=failure_reason,
        )

        return await self.log(event)

    async def log_change(
        self,
        user_id: UUID,
        resource_type: AuditResourceType,
        resource_id: UUID,
        old_value: Dict,
        new_value: Dict,
        tenant_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> AuditLog:
        """Log changes to resources with detailed diff"""

        changes = self._calculate_changes(old_value, new_value)

        event = AuditEvent(
            user_id=user_id,
            tenant_id=tenant_id,
            action=AuditAction.UPDATE,
            resource_type=resource_type,
            resource_id=resource_id,
            old_value=old_value,
            new_value=new_value,
            changes=changes,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            description=f"Updated {resource_type.value}: {resource_id}",
        )

        return await self.log(event)

    async def query_logs(
        self,
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
        sort_desc: bool = True,
    ) -> List[AuditLog]:
        """Query audit logs with filters using SQLAlchemy Core"""

        # Build conditions
        conditions = []

        if user_id:
            conditions.append(audit_logs.c.user_id == user_id)

        if tenant_id:
            conditions.append(audit_logs.c.tenant_id == tenant_id)

        if action:
            conditions.append(audit_logs.c.action == action.value)

        if resource_type:
            conditions.append(audit_logs.c.resource_type == resource_type.value)

        if resource_id:
            conditions.append(audit_logs.c.resource_id == resource_id)

        if start_date:
            conditions.append(audit_logs.c.created_at >= start_date)

        if end_date:
            conditions.append(audit_logs.c.created_at <= end_date)

        if severity:
            # Search in JSON metadata
            conditions.append(
                audit_logs.c.metadata["severity"].astext == severity.value
            )

        if status:
            conditions.append(audit_logs.c.metadata["status"].astext == status)

        if search_text:
            # Search in JSON metadata fields
            conditions.append(
                or_(
                    audit_logs.c.metadata["description"].astext.ilike(
                        f"%{search_text}%"
                    ),
                    audit_logs.c.metadata["resource_name"].astext.ilike(
                        f"%{search_text}%"
                    ),
                )
            )

        # Build query
        stmt = select(audit_logs)

        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Add sorting
        order_by = desc(sort_by) if sort_desc else asc(sort_by)
        stmt = stmt.order_by(order_by)

        # Add pagination
        stmt = stmt.limit(limit).offset(offset)

        results = await self.db.fetch_all(stmt)
        return [AuditLog.model_validate(r) for r in results]

    async def get_resource_history(
        self, resource_type: AuditResourceType, resource_id: UUID, limit: int = 50
    ) -> List[AuditLog]:
        """Get complete history of a resource"""

        stmt = (
            select(audit_logs)
            .where(
                and_(
                    audit_logs.c.resource_type == resource_type.value,
                    audit_logs.c.resource_id == resource_id,
                )
            )
            .order_by(desc(audit_logs.c.created_at))
            .limit(limit)
        )

        results = await self.db.fetch_all(stmt)
        return [AuditLog.model_validate(r) for r in results]

    async def get_user_trail(
        self,
        user_id: UUID,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get complete audit trail for a user"""

        conditions = [audit_logs.c.user_id == user_id]

        if start_date:
            conditions.append(audit_logs.c.created_at >= start_date)

        if end_date:
            conditions.append(audit_logs.c.created_at <= end_date)

        stmt = (
            select(audit_logs)
            .where(and_(*conditions))
            .order_by(desc(audit_logs.c.created_at))
            .limit(limit)
        )

        results = await self.db.fetch_all(stmt)
        return [AuditLog.model_validate(r) for r in results]

    async def get_tenant_audit_summary(
        self, tenant_id: UUID, days: int = 30
    ) -> Dict[str, Any]:
        """Get audit summary for a tenant"""

        start_date = datetime.now(timezone.utc) - timedelta(days=days)

        # Total events
        total_stmt = (
            select(func.count())
            .select_from(audit_logs)
            .where(
                and_(
                    audit_logs.c.tenant_id == tenant_id,
                    audit_logs.c.created_at >= start_date,
                )
            )
        )
        total = await self.db.fetch_val(total_stmt) or 0

        # Events by action
        by_action_stmt = (
            select(audit_logs.c.action, func.count().label("count"))
            .where(
                and_(
                    audit_logs.c.tenant_id == tenant_id,
                    audit_logs.c.created_at >= start_date,
                )
            )
            .group_by(audit_logs.c.action)
            .order_by(desc("count"))
        )

        by_action = await self.db.fetch_all(by_action_stmt)

        # Events by resource type
        by_resource_stmt = (
            select(audit_logs.c.resource_type, func.count().label("count"))
            .where(
                and_(
                    audit_logs.c.tenant_id == tenant_id,
                    audit_logs.c.created_at >= start_date,
                )
            )
            .group_by(audit_logs.c.resource_type)
            .order_by(desc("count"))
        )

        by_resource = await self.db.fetch_all(by_resource_stmt)

        # Events by severity
        by_severity_stmt = (
            select(
                audit_logs.c.metadata["severity"].astext.label("severity"),
                func.count().label("count"),
            )
            .where(
                and_(
                    audit_logs.c.tenant_id == tenant_id,
                    audit_logs.c.created_at >= start_date,
                )
            )
            .group_by(audit_logs.c.metadata["severity"].astext)
        )

        by_severity = await self.db.fetch_all(by_severity_stmt)

        # Access denied events
        denied_stmt = (
            select(func.count())
            .select_from(audit_logs)
            .where(
                and_(
                    audit_logs.c.tenant_id == tenant_id,
                    audit_logs.c.action == "DENIED",
                    audit_logs.c.created_at >= start_date,
                )
            )
        )
        denied = await self.db.fetch_val(denied_stmt) or 0

        # Most active users
        active_users_stmt = (
            select(audit_logs.c.user_id, func.count().label("event_count"))
            .where(
                and_(
                    audit_logs.c.tenant_id == tenant_id,
                    audit_logs.c.created_at >= start_date,
                    audit_logs.c.user_id.isnot(None),
                )
            )
            .group_by(audit_logs.c.user_id)
            .order_by(desc("event_count"))
            .limit(10)
        )

        active_users = await self.db.fetch_all(active_users_stmt)

        return {
            "tenant_id": str(tenant_id),
            "period_days": days,
            "total_events": total,
            "by_action": [dict(a) for a in by_action],
            "by_resource_type": [dict(r) for r in by_resource],
            "by_severity": [dict(s) for s in by_severity],
            "access_denied_count": denied,
            "most_active_users": [dict(u) for u in active_users],
        }

    async def cleanup_old_logs(self, days: Optional[int] = None) -> int:
        """Delete audit logs older than retention period"""

        retention = days or self.retention_days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention)

        stmt = (
            delete(audit_logs)
            .where(audit_logs.c.created_at < cutoff_date)
            .returning(audit_logs.c.id)
        )

        results = await self.db.fetch_all(stmt)
        affected = len(results)

        if affected > 0:
            logger.info(f"Cleaned up {affected} audit logs older than {retention} days")

        return affected

    async def export_logs(
        self,
        tenant_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json",
    ) -> Union[List[Dict], str]:
        """Export audit logs for compliance"""

        conditions = []

        if tenant_id:
            conditions.append(audit_logs.c.tenant_id == tenant_id)

        if start_date:
            conditions.append(audit_logs.c.created_at >= start_date)

        if end_date:
            conditions.append(audit_logs.c.created_at <= end_date)

        stmt = select(audit_logs).order_by(audit_logs.c.created_at)

        if conditions:
            stmt = stmt.where(and_(*conditions))

        results = await self.db.fetch_all(stmt)

        if format == "json":
            return [dict(r) for r in results]
        elif format == "csv":
            # Convert to CSV format
            import csv
            from io import StringIO

            output = StringIO()
            if results:
                writer = csv.DictWriter(output, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows([dict(r) for r in results])

            return output.getvalue()
        else:
            return [dict(r) for r in results]

    async def get_statistics(
        self, tenant_id: Optional[UUID] = None, days: int = 30
    ) -> Dict[str, Any]:
        """Get audit statistics"""

        start_date = datetime.now(timezone.utc) - timedelta(days=days)

        conditions = [audit_logs.c.created_at >= start_date]
        if tenant_id:
            conditions.append(audit_logs.c.tenant_id == tenant_id)

        # Daily event counts
        daily_stmt = (
            select(
                func.date(audit_logs.c.created_at).label("date"),
                func.count().label("count"),
            )
            .where(and_(*conditions))
            .group_by(func.date(audit_logs.c.created_at))
            .order_by("date")
        )

        daily = await self.db.fetch_all(daily_stmt)

        # Peak hours
        hourly_stmt = (
            select(
                func.extract("hour", audit_logs.c.created_at).label("hour"),
                func.count().label("count"),
            )
            .where(and_(*conditions))
            .group_by(func.extract("hour", audit_logs.c.created_at))
            .order_by("hour")
        )

        hourly = await self.db.fetch_all(hourly_stmt)

        # Most common actions
        top_actions_stmt = (
            select(audit_logs.c.action, func.count().label("count"))
            .where(and_(*conditions))
            .group_by(audit_logs.c.action)
            .order_by(desc("count"))
            .limit(10)
        )

        top_actions = await self.db.fetch_all(top_actions_stmt)

        # Total events
        total_stmt = (
            select(func.count()).select_from(audit_logs).where(and_(*conditions))
        )
        total = await self.db.fetch_val(total_stmt) or 0

        return {
            "period_days": days,
            "daily_counts": [
                {
                    "date": (
                        d["date"].isoformat()
                        if hasattr(d["date"], "isoformat")
                        else str(d["date"])
                    ),
                    "count": d["count"],
                }
                for d in daily
            ],
            "hourly_distribution": [
                {"hour": int(h["hour"]), "count": h["count"]} for h in hourly
            ],
            "top_actions": [dict(a) for a in top_actions],
            "total_events": total,
        }

    async def flush_buffer(self):
        """Flush buffered audit events"""
        if self._audit_buffer:
            events = self._audit_buffer.copy()
            self._audit_buffer.clear()

            try:
                await self.log_batch(events)
            except Exception as e:
                logger.error(f"Failed to flush audit buffer: {e}")
                # Re-add to buffer
                self._audit_buffer.extend(events)

    def _calculate_changes(
        self, old_value: Dict, new_value: Dict
    ) -> List[Dict[str, Any]]:
        """Calculate differences between old and new values"""
        changes = []
        all_keys = set(old_value.keys()) | set(new_value.keys())

        for key in all_keys:
            old = old_value.get(key)
            new = new_value.get(key)

            if old != new:
                change = {
                    "field": key,
                    "old_value": old,
                    "new_value": new,
                    "change_type": "modified",
                }

                if key not in old_value:
                    change["change_type"] = "added"
                elif key not in new_value:
                    change["change_type"] = "removed"

                # Handle nested dictionaries
                if isinstance(old, dict) and isinstance(new, dict):
                    nested_changes = self._calculate_changes(old, new)
                    if nested_changes:
                        change["nested_changes"] = nested_changes

                changes.append(change)

        return changes

    async def get_user_session_trail(
        self, session_id: str, limit: int = 100
    ) -> List[AuditLog]:
        """Get all events for a specific session"""

        stmt = (
            select(audit_logs)
            .where(audit_logs.c.metadata["session_id"].astext == session_id)
            .order_by(audit_logs.c.created_at)
            .limit(limit)
        )

        results = await self.db.fetch_all(stmt)
        return [AuditLog.model_validate(r) for r in results]

    async def get_anomaly_detection(
        self,
        tenant_id: Optional[UUID] = None,
        hours: int = 24,
        threshold: float = 2.0,  # Standard deviations
    ) -> List[Dict[str, Any]]:
        """Detect anomalous audit patterns"""

        start_date = datetime.now(timezone.utc) - timedelta(hours=hours)

        conditions = [audit_logs.c.created_at >= start_date]
        if tenant_id:
            conditions.append(audit_logs.c.tenant_id == tenant_id)

        # Get hourly event counts
        hourly_stmt = (
            select(
                func.date_trunc("hour", audit_logs.c.created_at).label("hour"),
                func.count().label("count"),
            )
            .where(and_(*conditions))
            .group_by(func.date_trunc("hour", audit_logs.c.created_at))
            .order_by("hour")
        )

        hourly = await self.db.fetch_all(hourly_stmt)

        if len(hourly) < 3:
            return []

        # Calculate statistics
        counts = [h["count"] for h in hourly]
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = variance**0.5

        # Detect anomalies
        anomalies = []
        for h in hourly:
            if abs(h["count"] - mean) > threshold * std_dev:
                anomalies.append(
                    {
                        "hour": h["hour"].isoformat(),
                        "count": h["count"],
                        "expected_range": [
                            mean - threshold * std_dev,
                            mean + threshold * std_dev,
                        ],
                        "deviation": (
                            (h["count"] - mean) / std_dev if std_dev > 0 else 0
                        ),
                    }
                )

        return anomalies


# Context manager for audit logging
class AuditContext:
    """Context manager for grouping related audit events"""

    def __init__(
        self,
        audit_service: AuditService,
        user_id: Optional[UUID] = None,
        tenant_id: Optional[UUID] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ):
        self.audit_service = audit_service
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.session_id = session_id or str(uuid4())
        self.metadata = metadata or {}
        self.events: List[AuditEvent] = []
        self.start_time = datetime.now(timezone.utc)

    async def __aenter__(self):
        # Log session start
        await self.audit_service.log_action(
            user_id=self.user_id,
            tenant_id=self.tenant_id,
            action=AuditAction.LOGIN,
            resource_type=AuditResourceType.SESSION,
            metadata={"session_id": self.session_id, **self.metadata},
            description=f"Session started",
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Log session end
        duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()

        await self.audit_service.log_action(
            user_id=self.user_id,
            tenant_id=self.tenant_id,
            action=AuditAction.LOGOUT,
            resource_type=AuditResourceType.SESSION,
            metadata={
                "session_id": self.session_id,
                "duration_seconds": duration,
                "event_count": len(self.events),
                "error": str(exc_val) if exc_val else None,
            },
            description=f"Session ended after {duration:.2f} seconds",
        )

        # Flush any pending events
        await self.audit_service.flush_buffer()

    async def log(self, event: AuditEvent):
        """Log an event within this context"""
        event.session_id = self.session_id
        event.metadata.update(self.metadata)
        self.events.append(event)
        await self.audit_service.log(event)


# Dependency for FastAPI
async def get_audit_service(db: Database, retention_days: int = 90) -> AuditService:
    """FastAPI dependency for AuditService"""
    return AuditService(db, retention_days=retention_days)


# Middleware for automatic request logging
class AuditMiddleware:
    """Middleware to automatically log API requests"""

    def __init__(
        self,
        app,
        audit_service: AuditService,
        exclude_paths: Optional[List[str]] = None,
    ):
        self.app = app
        self.audit_service = audit_service
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/docs", "/redoc"]

    async def __call__(self, request: Request, call_next):
        # Skip excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        # Get user from request state (set by auth middleware)
        user = getattr(request.state, "user", None)

        start_time = datetime.now(timezone.utc)

        try:
            # Process request
            response = await call_next(request)

            # Log successful request
            duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            await self.audit_service.log_access(
                user_id=user.id if user else None,
                resource=request.url.path,
                tenant_id=user.tenant_id if user else None,
                granted=response.status_code < 400,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "status_code": response.status_code,
                    "duration_ms": round(duration, 2),
                },
            )

            return response

        except Exception as e:
            # Log failed request
            duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            await self.audit_service.log_access(
                user_id=user.id if user else None,
                resource=request.url.path,
                tenant_id=user.tenant_id if user else None,
                granted=False,
                required_permission="N/A",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "error": str(e),
                    "duration_ms": round(duration, 2),
                },
            )
            raise
