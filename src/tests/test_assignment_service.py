# tests/test_assignment_service.py
import pytest
from uuid import uuid4
from datetime import datetime, timedelta

pytestmark = pytest.mark.asyncio


class TestAssignmentService:

    async def test_assign_role_to_user(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test assigning role to user"""
        assignment = await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        assert assignment.id is not None
        assert assignment.user_id == test_user_id
        assert assignment.role_id == sample_roles["user"].id
        assert assignment.tenant_id == test_tenant.id
        assert assignment.is_active is True
        assert assignment.expires_at is None

    async def test_assign_role_with_expiration(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test assigning role with expiration"""
        assignment = await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            expires_in_days=30,
        )

        assert assignment.expires_at is not None
        assert assignment.expires_at > datetime.utcnow()
        assert assignment.expires_at < datetime.utcnow() + timedelta(days=31)

    async def test_prevent_duplicate_assignments(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test preventing duplicate role assignments"""
        # First assignment
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        # Second assignment with prevent_duplicates=True
        assignment2 = await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            prevent_duplicates=True,
        )

        # Should return existing assignment
        assert assignment2.id is not None

    async def test_revoke_role_from_user(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test revoking role from user"""
        # Assign role
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        # Soft revoke
        await assignment_service.revoke_role_from_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            hard_delete=False,
        )

        # Check assignments (should be inactive)
        assignments = await assignment_service.get_user_assignments(
            user_id=test_user_id, tenant_id=test_tenant.id, include_inactive=True
        )

        active_assignments = [a for a in assignments if a.is_active]
        assert len(active_assignments) == 0

    async def test_hard_delete_assignment(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test hard deleting assignment"""
        # Assign role
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        # Hard delete
        await assignment_service.revoke_role_from_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            hard_delete=True,
        )

        # Check assignments (should be completely gone)
        assignments = await assignment_service.get_user_assignments(
            user_id=test_user_id, tenant_id=test_tenant.id, include_inactive=True
        )

        assert len(assignments) == 0

    async def test_get_user_assignments(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test getting all assignments for a user"""
        # Assign multiple roles
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["manager"].id,
            tenant_id=test_tenant.id,
        )

        # Get assignments
        assignments = await assignment_service.get_user_assignments(
            user_id=test_user_id, tenant_id=test_tenant.id
        )

        assert len(assignments) == 2
        role_ids = {a.role_id for a in assignments}
        assert sample_roles["user"].id in role_ids
        assert sample_roles["manager"].id in role_ids

    async def test_get_role_assignments(
        self,
        assignment_service,
        test_user_id,
        test_admin_user_id,
        test_tenant,
        sample_roles,
    ):
        """Test getting all users assigned to a role"""
        # Assign same role to multiple users
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        await assignment_service.assign_role_to_user(
            user_id=test_admin_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        # Get role assignments
        assignments = await assignment_service.get_role_assignments(
            role_id=sample_roles["user"].id, tenant_id=test_tenant.id
        )

        assert len(assignments) == 2
        user_ids = {a.user_id for a in assignments}
        assert test_user_id in user_ids
        assert test_admin_user_id in user_ids

    async def test_update_assignment_scope(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test updating assignment resource scope"""
        # Assign role with scope
        assignment = await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            resource_scope={"patient_id": "123"},
        )

        # Update scope
        updated = await assignment_service.update_assignment_scope(
            assignment_id=assignment.id,
            resource_scope={"patient_id": "456", "department": "cardiology"},
        )

        assert updated.resource_scope == {
            "patient_id": "456",
            "department": "cardiology",
        }

    async def test_extend_assignment(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test extending assignment expiration"""
        # Assign role with expiration
        assignment = await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            expires_in_days=7,
        )

        original_expiry = assignment.expires_at

        # Extend by 30 days
        extended = await assignment_service.extend_assignment(
            assignment_id=assignment.id, additional_days=30
        )

        assert extended.expires_at > original_expiry
        assert (extended.expires_at - original_expiry).days == 30

    async def test_bulk_assign_roles(
        self, assignment_service, test_tenant, sample_roles
    ):
        """Test bulk assigning role to multiple users"""
        user_ids = [uuid4(), uuid4(), uuid4()]

        successful, failed = await assignment_service.bulk_assign_roles(
            user_ids=user_ids, role_id=sample_roles["user"].id, tenant_id=test_tenant.id
        )

        assert successful == 3
        assert len(failed) == 0

        # Check assignments
        for user_id in user_ids:
            assignments = await assignment_service.get_user_assignments(
                user_id=user_id, tenant_id=test_tenant.id
            )
            assert len(assignments) == 1

    async def test_transfer_assignments(
        self, assignment_service, role_service, test_user_id, test_tenant
    ):
        """Test transferring assignments from one role to another"""
        # Create roles
        old_role = await role_service.create_role(
            name="Old Role", tenant_id=test_tenant.id
        )

        new_role = await role_service.create_role(
            name="New Role", tenant_id=test_tenant.id
        )

        # Assign user to old role
        await assignment_service.assign_role_to_user(
            user_id=test_user_id, role_id=old_role.id, tenant_id=test_tenant.id
        )

        # Transfer assignments
        transferred = await assignment_service.transfer_assignments(
            from_role_id=old_role.id, to_role_id=new_role.id, tenant_id=test_tenant.id
        )

        assert transferred == 1

        # Check user now has new role, not old role
        assignments = await assignment_service.get_user_assignments(
            user_id=test_user_id, tenant_id=test_tenant.id
        )

        assert len(assignments) == 1
        assert assignments[0].role_id == new_role.id

    async def test_get_expiring_assignments(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test getting expiring assignments"""
        # Create assignment expiring in 5 days
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            expires_in_days=5,
        )

        # Create assignment expiring in 30 days
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["manager"].id,
            tenant_id=test_tenant.id,
            expires_in_days=30,
        )

        # Get expiring within 7 days
        expiring = await assignment_service.get_expiring_assignments(
            days_threshold=7, tenant_id=test_tenant.id
        )

        assert len(expiring) == 1
        assert expiring[0]["role_name"] == "User"

    async def test_get_user_effective_roles(
        self, assignment_service, role_service, test_user_id, test_tenant
    ):
        """Test getting effective roles including inheritance"""
        # Create role hierarchy
        admin = await role_service.create_role(name="Admin", tenant_id=test_tenant.id)

        manager = await role_service.create_role(
            name="Manager", parent_ids=[admin.id], tenant_id=test_tenant.id
        )

        # Assign manager role
        await assignment_service.assign_role_to_user(
            user_id=test_user_id, role_id=manager.id, tenant_id=test_tenant.id
        )

        # Get effective roles
        effective = await assignment_service.get_user_effective_roles(
            user_id=test_user_id, tenant_id=test_tenant.id
        )

        # Should include both manager and inherited admin
        assert len(effective) >= 2
        role_names = [r["name"] for r in effective]
        assert "Manager" in role_names
        assert "Admin" in role_names

    async def test_validate_assignment(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test assignment validation"""
        # Valid assignment
        is_valid = await assignment_service.validate_assignment(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        assert is_valid is True

        # Invalid role
        is_valid = await assignment_service.validate_assignment(
            user_id=test_user_id,
            role_id=uuid4(),  # Non-existent role
            tenant_id=test_tenant.id,
        )

        assert is_valid is False

    async def test_cleanup_expired_assignments(
        self, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test cleaning up expired assignments"""
        # Create expired assignment
        assignment = await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
            expires_in_days=-1,  # Already expired
        )

        # Run cleanup
        cleaned = await assignment_service.cleanup_expired_assignments()

        assert cleaned >= 1

        # Check assignment is now inactive
        assignments = await assignment_service.get_user_assignments(
            user_id=test_user_id, tenant_id=test_tenant.id, include_inactive=True
        )

        expired_assignment = next(
            (a for a in assignments if a.id == assignment.id), None
        )
        assert expired_assignment is not None
        assert expired_assignment.is_active is False

    async def test_get_assignment_stats(
        self,
        assignment_service,
        test_user_id,
        test_admin_user_id,
        test_tenant,
        sample_roles,
    ):
        """Test getting assignment statistics"""
        # Create some assignments
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        await assignment_service.assign_role_to_user(
            user_id=test_admin_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        await assignment_service.assign_role_to_user(
            user_id=test_admin_user_id,
            role_id=sample_roles["manager"].id,
            tenant_id=test_tenant.id,
        )

        # Get stats
        stats = await assignment_service.get_assignment_stats(tenant_id=test_tenant.id)

        assert stats["total_active_assignments"] == 3
        assert len(stats["assignments_by_role"]) > 0
        assert len(stats["users_with_most_roles"]) > 0
