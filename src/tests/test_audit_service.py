# tests/test_audit_service.py
import pytest
from uuid import uuid4
from datetime import datetime, timedelta

from services.audit_service import (
    AuditEvent,
    AuditAction,
    AuditResourceType,
    AuditSeverity,
)

pytestmark = pytest.mark.asyncio


class TestAuditService:

    async def test_log_event(self, audit_service, test_user_id, test_tenant):
        """Test logging a single audit event"""
        event = AuditEvent(
            user_id=test_user_id,
            tenant_id=test_tenant.id,
            action=AuditAction.CREATE,
            resource_type=AuditResourceType.ROLE,
            resource_id=uuid4(),
            description="Test audit event",
        )

        log = await audit_service.log(event)

        assert log.id is not None
        assert log.user_id == test_user_id
        assert log.tenant_id == test_tenant.id
        assert log.action == "CREATE"

    async def test_log_action(self, audit_service, test_user_id, test_tenant):
        """Test logging a simple action"""
        log = await audit_service.log_action(
            user_id=test_user_id,
            tenant_id=test_tenant.id,
            action=AuditAction.UPDATE,
            resource_type=AuditResourceType.PERMISSION,
            resource_id=uuid4(),
            description="Updated permission",
        )

        assert log is not None
        assert log.action == "UPDATE"

    async def test_log_access_granted(self, audit_service, test_user_id, test_tenant):
        """Test logging granted access"""
        log = await audit_service.log_access(
            user_id=test_user_id,
            resource="/api/users",
            resource_id=uuid4(),
            tenant_id=test_tenant.id,
            granted=True,
            required_permission="user:read",
        )

        assert log.action == "ACCESS"
        assert "granted" in log.metadata.get("description", "")

    async def test_log_access_denied(self, audit_service, test_user_id, test_tenant):
        """Test logging denied access"""
        log = await audit_service.log_access(
            user_id=test_user_id,
            resource="/api/admin",
            tenant_id=test_tenant.id,
            granted=False,
            required_permission="admin:access",
        )

        assert log.action == "DENIED"
        assert "denied" in log.metadata.get("description", "")

    async def test_log_auth(self, audit_service, test_user_id, test_tenant):
        """Test logging authentication events"""
        # Login
        login_log = await audit_service.log_auth(
            user_id=test_user_id,
            action="login",
            tenant_id=test_tenant.id,
            username="testuser",
        )
        assert login_log.action == "LOGIN"

        # Failed login
        failed_log = await audit_service.log_auth(
            user_id=None,
            action="failed_login",
            username="testuser",
            failure_reason="Invalid password",
        )
        assert failed_log.action == "DENIED"

        # Logout
        logout_log = await audit_service.log_auth(
            user_id=test_user_id, action="logout", tenant_id=test_tenant.id
        )
        assert logout_log.action == "LOGOUT"

    async def test_log_change(self, audit_service, test_user_id, test_tenant):
        """Test logging changes with diff"""
        old_value = {"name": "Old Name", "description": "Old Description"}
        new_value = {
            "name": "New Name",
            "description": "New Description",
            "extra": "field",
        }

        log = await audit_service.log_change(
            user_id=test_user_id,
            resource_type=AuditResourceType.ROLE,
            resource_id=uuid4(),
            old_value=old_value,
            new_value=new_value,
            tenant_id=test_tenant.id,
        )

        assert log.old_value == old_value
        assert log.new_value == new_value
        assert "changes" in log.metadata
        assert len(log.metadata["changes"]) >= 2  # Name and description changed

    async def test_batch_logging(self, audit_service, test_user_id, test_tenant):
        """Test logging multiple events in batch"""
        events = [
            AuditEvent(
                user_id=test_user_id,
                tenant_id=test_tenant.id,
                action=AuditAction.CREATE,
                resource_type=AuditResourceType.ROLE,
                description=f"Event {i}",
            )
            for i in range(5)
        ]

        logs = await audit_service.log_batch(events)

        assert len(logs) == 5
        for i, log in enumerate(logs):
            assert log.user_id == test_user_id

    async def test_query_logs(self, audit_service, test_user_id, test_tenant):
        """Test querying audit logs"""
        # Create multiple logs
        for i in range(10):
            await audit_service.log_action(
                user_id=test_user_id,
                tenant_id=test_tenant.id,
                action=AuditAction.CREATE if i % 2 == 0 else AuditAction.UPDATE,
                resource_type=AuditResourceType.ROLE,
                description=f"Test log {i}",
            )

        # Query all
        logs = await audit_service.query_logs(limit=20)
        assert len(logs) >= 10

        # Filter by action
        create_logs = await audit_service.query_logs(
            action=AuditAction.CREATE, limit=20
        )
        assert all(l.action == "CREATE" for l in create_logs)

        # Filter by user
        user_logs = await audit_service.query_logs(user_id=test_user_id, limit=20)
        assert all(l.user_id == test_user_id for l in user_logs)

        # Date range
        now = datetime.utcnow()
        recent_logs = await audit_service.query_logs(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
            limit=20,
        )
        assert len(recent_logs) >= 10

    async def test_get_resource_history(self, audit_service, test_user_id, test_tenant):
        """Test getting history for a specific resource"""
        resource_id = uuid4()

        # Create multiple logs for same resource
        for i in range(5):
            await audit_service.log_action(
                user_id=test_user_id,
                tenant_id=test_tenant.id,
                action=AuditAction.UPDATE,
                resource_type=AuditResourceType.ROLE,
                resource_id=resource_id,
                description=f"Update {i}",
            )

        # Get history
        history = await audit_service.get_resource_history(
            resource_type=AuditResourceType.ROLE, resource_id=resource_id, limit=10
        )

        assert len(history) == 5
        assert all(l.resource_id == resource_id for l in history)

    async def test_get_user_trail(self, audit_service, test_user_id, test_tenant):
        """Test getting audit trail for a user"""
        # Create logs for user
        for i in range(8):
            await audit_service.log_action(
                user_id=test_user_id,
                tenant_id=test_tenant.id,
                action=AuditAction.CREATE if i % 2 == 0 else AuditAction.UPDATE,
                resource_type=AuditResourceType.ROLE,
                description=f"User action {i}",
            )

        # Get user trail
        trail = await audit_service.get_user_trail(user_id=test_user_id, limit=10)

        assert len(trail) >= 8
        assert all(l.user_id == test_user_id for l in trail)

    async def test_get_tenant_audit_summary(
        self, audit_service, test_user_id, test_tenant
    ):
        """Test getting tenant audit summary"""
        # Create logs for tenant
        for i in range(20):
            await audit_service.log_action(
                user_id=test_user_id,
                tenant_id=test_tenant.id,
                action=AuditAction.CREATE if i < 10 else AuditAction.UPDATE,
                resource_type=AuditResourceType.ROLE,
                description=f"Tenant log {i}",
            )

        # Get summary
        summary = await audit_service.get_tenant_audit_summary(
            tenant_id=test_tenant.id, days=1
        )

        assert summary["total_events"] >= 20
        assert len(summary["by_action"]) >= 2
        assert len(summary["by_resource_type"]) >= 1

    async def test_get_statistics(self, audit_service, test_user_id, test_tenant):
        """Test getting audit statistics"""
        # Create logs over time
        base_time = datetime.utcnow() - timedelta(days=5)

        for day in range(5):
            for hour in range(24):
                if hour % 6 == 0:  # Create log every 6 hours
                    await audit_service.log_action(
                        user_id=test_user_id,
                        tenant_id=test_tenant.id,
                        action=AuditAction.ACCESS,
                        resource_type=AuditResourceType.API,
                        description=f"Log day {day} hour {hour}",
                    )

        # Get statistics
        stats = await audit_service.get_statistics(tenant_id=test_tenant.id, days=7)

        assert stats["total_events"] >= 20
        assert len(stats["daily_counts"]) >= 5
        assert len(stats["hourly_distribution"]) > 0

    async def test_export_logs(self, audit_service, test_user_id, test_tenant):
        """Test exporting audit logs"""
        # Create logs
        for i in range(5):
            await audit_service.log_action(
                user_id=test_user_id,
                tenant_id=test_tenant.id,
                action=AuditAction.CREATE,
                resource_type=AuditResourceType.ROLE,
                description=f"Export test {i}",
            )

        # Export as JSON
        json_export = await audit_service.export_logs(
            tenant_id=test_tenant.id, format="json"
        )

        assert len(json_export) == 5

        # Export as CSV
        csv_export = await audit_service.export_logs(
            tenant_id=test_tenant.id, format="csv"
        )

        assert isinstance(csv_export, str)
        assert "action,resource_type" in csv_export

    async def test_cleanup_old_logs(self, audit_service, test_user_id, test_tenant):
        """Test cleaning up old logs"""
        # Create old log
        old_time = datetime.utcnow() - timedelta(days=100)

        # Manually insert old log (bypassing service)
        async with audit_service.db.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs (user_id, tenant_id, action, resource_type, created_at)
                VALUES ($1, $2, $3, $4, $5)
                """,
                test_user_id,
                test_tenant.id,
                "TEST",
                "test",
                old_time,
            )

        # Create recent log
        await audit_service.log_action(
            user_id=test_user_id,
            tenant_id=test_tenant.id,
            action=AuditAction.TEST,
            resource_type=AuditResourceType.SYSTEM,
        )

        # Clean up old logs
        deleted = await audit_service.cleanup_old_logs(days=30)

        assert deleted >= 1

        # Check remaining logs
        remaining = await audit_service.query_logs(limit=10)
        assert all(
            l.created_at > datetime.utcnow() - timedelta(days=30) for l in remaining
        )

    async def test_calculate_changes(self, audit_service):
        """Test change calculation"""
        old = {"name": "John", "age": 30, "city": "New York"}

        new = {
            "name": "John",  # Unchanged
            "age": 31,  # Modified
            "country": "USA",  # Added
            # city removed
        }

        changes = audit_service._calculate_changes(old, new)

        assert len(changes) == 3

        modified = next(c for c in changes if c["field"] == "age")
        assert modified["change_type"] == "modified"
        assert modified["old_value"] == 30
        assert modified["new_value"] == 31

        added = next(c for c in changes if c["field"] == "country")
        assert added["change_type"] == "added"

        removed = next(c for c in changes if c["field"] == "city")
        assert removed["change_type"] == "removed"
