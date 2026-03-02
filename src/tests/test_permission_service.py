# tests/test_permission_service.py
import pytest
from uuid import uuid4
from datetime import datetime

from core.exceptions import (
    PermissionNotFoundError,
    PermissionDeniedError,
    TenantNotFoundError,
)
from core.constants import ResourceType, PermissionAction

pytestmark = pytest.mark.asyncio


class TestPermissionService:

    async def test_create_permission(self, permission_service, test_tenant):
        """Test creating a new permission"""
        permission = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            scope=None,
            description="Test description",
            tenant_id=test_tenant.id,
        )

        assert permission.id is not None
        assert permission.name == "Test Permission"
        assert permission.resource == ResourceType.USER
        assert permission.action == PermissionAction.READ
        assert permission.permission_string == "user:read"
        assert permission.tenant_id == test_tenant.id

    async def test_create_duplicate_permission(self, permission_service, test_tenant):
        """Test creating duplicate permission returns existing one"""
        # Create first permission
        perm1 = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # Create duplicate
        perm2 = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        assert perm1.id == perm2.id

    async def test_create_permission_invalid_tenant(self, permission_service):
        """Test creating permission with invalid tenant"""
        with pytest.raises(TenantNotFoundError):
            await permission_service.create_permission(
                name="Test Permission",
                resource=ResourceType.USER,
                action=PermissionAction.READ,
                tenant_id=uuid4(),  # Non-existent tenant
            )

    async def test_get_permission(self, permission_service, test_tenant):
        """Test getting permission by ID"""
        # Create permission
        created = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # Get by ID
        fetched = await permission_service.get_permission(created.id, test_tenant.id)

        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.name == created.name

    async def test_get_permission_by_string(self, permission_service, test_tenant):
        """Test getting permission by string representation"""
        # Create permission
        await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # Get by string
        fetched = await permission_service.get_permission_by_string(
            "user:read", test_tenant.id
        )

        assert fetched is not None
        assert fetched.permission_string == "user:read"

    async def test_update_permission(self, permission_service, test_tenant):
        """Test updating permission"""
        # Create permission
        permission = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # Update
        updated = await permission_service.update_permission(
            permission_id=permission.id,
            name="Updated Name",
            description="Updated description",
        )

        assert updated.name == "Updated Name"
        assert updated.description == "Updated description"
        assert updated.updated_at > permission.created_at

    async def test_update_system_permission(self, permission_service):
        """Test updating system permission (should fail)"""
        # Create system permission
        permission = await permission_service.create_permission(
            name="System Permission",
            resource=ResourceType.ALL,
            action=PermissionAction.MANAGE,
            is_system=True,
        )

        with pytest.raises(PermissionDeniedError):
            await permission_service.update_permission(
                permission_id=permission.id, name="New Name"
            )

    async def test_delete_permission(self, permission_service, test_tenant):
        """Test deleting permission"""
        # Create permission
        permission = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # Delete
        await permission_service.delete_permission(permission.id)

        # Verify deleted
        fetched = await permission_service.get_permission(permission.id, test_tenant.id)
        assert fetched is None

    async def test_delete_permission_assigned_to_role(
        self, permission_service, role_service, test_tenant
    ):
        """Test deleting permission that's assigned to a role (should fail)"""
        # Create permission
        permission = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # Create role and assign permission
        role = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        await permission_service.grant_permission_to_role(
            role_id=role.id, permission_id=permission.id
        )

        # Try to delete
        with pytest.raises(PermissionDeniedError):
            await permission_service.delete_permission(permission.id)

    async def test_list_permissions(self, permission_service, test_tenant):
        """Test listing permissions with filters"""
        # Create multiple permissions
        await permission_service.create_permission(
            name="Read User",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        await permission_service.create_permission(
            name="Create User",
            resource=ResourceType.USER,
            action=PermissionAction.CREATE,
            tenant_id=test_tenant.id,
        )

        await permission_service.create_permission(
            name="Read Role",
            resource=ResourceType.ROLE,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        # List all
        all_perms = await permission_service.list_permissions(tenant_id=test_tenant.id)
        assert len(all_perms) >= 3

        # Filter by resource
        user_perms = await permission_service.list_permissions(
            tenant_id=test_tenant.id, resource=ResourceType.USER
        )
        assert len(user_perms) == 2
        assert all(p.resource == ResourceType.USER for p in user_perms)

        # Filter by action
        read_perms = await permission_service.list_permissions(
            tenant_id=test_tenant.id, action=PermissionAction.READ
        )
        assert len(read_perms) == 2
        assert all(p.action == PermissionAction.READ for p in read_perms)

    async def test_grant_and_revoke_permission(
        self, permission_service, role_service, test_tenant
    ):
        """Test granting and revoking permissions to/from role"""
        # Create permission and role
        permission = await permission_service.create_permission(
            name="Test Permission",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            tenant_id=test_tenant.id,
        )

        role = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        # Grant permission
        await permission_service.grant_permission_to_role(
            role_id=role.id, permission_id=permission.id
        )

        # Check role permissions
        role_perms = await role_service.get_role_permissions(role.id)
        assert len(role_perms) == 1
        assert role_perms[0].id == permission.id

        # Revoke permission
        await permission_service.revoke_permission_from_role(
            role_id=role.id, permission_id=permission.id
        )

        # Check again
        role_perms = await role_service.get_role_permissions(role.id)
        assert len(role_perms) == 0

    async def test_check_user_permission(
        self,
        permission_service,
        role_service,
        assignment_service,
        test_user_id,
        test_tenant,
        sample_permissions,
        sample_roles,
    ):
        """Test checking user permissions"""
        # Assign user role to test user
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        # Check permission
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="user:read",
            tenant_id=test_tenant.id,
        )

        assert has_perm is True

        # Check non-existent permission
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="user:delete",
            tenant_id=test_tenant.id,
        )

        assert has_perm is False

    async def test_wildcard_permissions(
        self,
        permission_service,
        role_service,
        assignment_service,
        test_user_id,
        test_tenant,
        sample_permissions,
    ):
        """Test wildcard permission matching"""
        # Create role with wildcard permission
        role = await role_service.create_role(
            name="Wildcard Role", tenant_id=test_tenant.id
        )

        await permission_service.grant_permission_to_role(
            role_id=role.id, permission_id=sample_permissions["*:*"].id
        )

        await assignment_service.assign_role_to_user(
            user_id=test_user_id, role_id=role.id, tenant_id=test_tenant.id
        )

        # Check any permission
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="anything:anything",
            tenant_id=test_tenant.id,
        )

        assert has_perm is True

    async def test_scoped_permissions(
        self,
        permission_service,
        role_service,
        assignment_service,
        test_user_id,
        test_tenant,
    ):
        """Test resource-scoped permissions"""
        # Create scoped permission
        permission = await permission_service.create_permission(
            name="Access Patient",
            resource=ResourceType.USER,
            action=PermissionAction.READ,
            scope="patient",
            tenant_id=test_tenant.id,
        )

        # Create role and assign permission
        role = await role_service.create_role(
            name="Doctor Role", tenant_id=test_tenant.id
        )

        await permission_service.grant_permission_to_role(
            role_id=role.id, permission_id=permission.id
        )

        # Assign role with scope
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=role.id,
            tenant_id=test_tenant.id,
            resource_scope={"patient_id": "123"},
        )

        # Check permission with correct scope
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="user:read",
            tenant_id=test_tenant.id,
            resource_scope={"id": "123"},
        )

        assert has_perm is True

        # Check with wrong scope
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="user:read",
            tenant_id=test_tenant.id,
            resource_scope={"id": "456"},
        )

        assert has_perm is False

    async def test_permission_cache_invalidation(
        self,
        permission_service,
        role_service,
        assignment_service,
        test_user_id,
        test_tenant,
        sample_permissions,
    ):
        """Test permission cache invalidation"""
        # Assign initial permissions
        await assignment_service.assign_role_to_user(
            user_id=test_user_id,
            role_id=sample_roles["user"].id,
            tenant_id=test_tenant.id,
        )

        # Check permission (caches)
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="user:read",
            tenant_id=test_tenant.id,
        )
        assert has_perm is True

        # Revoke permission
        await permission_service.revoke_permission_from_role(
            role_id=sample_roles["user"].id,
            permission_id=sample_permissions["user:read"].id,
        )

        # Check again (should be false, cache invalidated)
        has_perm = await permission_service.check_user_permission(
            user_id=test_user_id,
            required_permission="user:read",
            tenant_id=test_tenant.id,
        )
        assert has_perm is False

    async def test_validate_permission_string(self, permission_service):
        """Test permission string validation"""
        valid_strings = ["user:read", "user:read:123", "*:*", "user:*", "*:read"]

        invalid_strings = [
            "user",  # Missing action
            "user:read:extra:extra",  # Too many parts
            "invalid:action",  # Invalid resource
            "user:invalid",  # Invalid action
            "",  # Empty
        ]

        for string in valid_strings:
            assert await permission_service.validate_permission_string(string) is True

        for string in invalid_strings:
            assert await permission_service.validate_permission_string(string) is False
