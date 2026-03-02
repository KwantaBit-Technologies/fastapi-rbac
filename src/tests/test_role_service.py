# tests/test_role_service.py
import pytest
from uuid import uuid4

from core.exceptions import (
    RoleNotFoundError,
    CircularRoleHierarchyError,
    PermissionDeniedError,
)

pytestmark = pytest.mark.asyncio


class TestRoleService:

    async def test_create_role(self, role_service, test_tenant):
        """Test creating a new role"""
        role = await role_service.create_role(
            name="Test Role",
            description="Test Description",
            tenant_id=test_tenant.id,
            metadata={"key": "value"},
        )

        assert role.id is not None
        assert role.name == "Test Role"
        assert role.description == "Test Description"
        assert role.tenant_id == test_tenant.id
        assert role.metadata == {"key": "value"}
        assert role.is_active is True

    async def test_create_duplicate_role(self, role_service, test_tenant):
        """Test creating duplicate role name"""
        await role_service.create_role(name="Test Role", tenant_id=test_tenant.id)

        with pytest.raises(PermissionDeniedError):
            await role_service.create_role(name="Test Role", tenant_id=test_tenant.id)

    async def test_get_role(self, role_service, test_tenant):
        """Test getting role by ID"""
        created = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        fetched = await role_service.get_role(created.id, test_tenant.id)

        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.name == created.name

    async def test_get_role_by_name(self, role_service, test_tenant):
        """Test getting role by name"""
        created = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        fetched = await role_service.get_role_by_name("Test Role", test_tenant.id)

        assert fetched is not None
        assert fetched.id == created.id

    async def test_update_role(self, role_service, test_tenant):
        """Test updating role"""
        role = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        updated = await role_service.update_role(
            role_id=role.id,
            name="Updated Name",
            description="Updated Description",
            is_active=False,
        )

        assert updated.name == "Updated Name"
        assert updated.description == "Updated Description"
        assert updated.is_active is False

    async def test_delete_role(self, role_service, test_tenant):
        """Test deleting role"""
        role = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        await role_service.delete_role(role.id)

        fetched = await role_service.get_role(role.id, test_tenant.id)
        assert fetched is None

    async def test_delete_role_with_users(
        self, role_service, assignment_service, test_user_id, test_tenant
    ):
        """Test deleting role with assigned users"""
        # Create role
        role = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        # Assign user
        await assignment_service.assign_role_to_user(
            user_id=test_user_id, role_id=role.id, tenant_id=test_tenant.id
        )

        # Try to delete without transfer
        with pytest.raises(PermissionDeniedError):
            await role_service.delete_role(role.id)

        # Create transfer role
        transfer_role = await role_service.create_role(
            name="Transfer Role", tenant_id=test_tenant.id
        )

        # Delete with transfer
        await role_service.delete_role(role.id, transfer_to_role_id=transfer_role.id)

        # Check that user was transferred
        user_roles = await assignment_service.get_user_assignments(
            test_user_id, test_tenant.id
        )
        assert len(user_roles) == 1
        assert user_roles[0].role_id == transfer_role.id

    async def test_role_hierarchy(self, role_service, test_tenant):
        """Test role inheritance"""
        # Create base role
        base_role = await role_service.create_role(
            name="Base Role", tenant_id=test_tenant.id
        )

        # Create child role
        child_role = await role_service.create_role(
            name="Child Role", parent_ids=[base_role.id], tenant_id=test_tenant.id
        )

        # Create grandchild role
        grandchild_role = await role_service.create_role(
            name="Grandchild Role", parent_ids=[child_role.id], tenant_id=test_tenant.id
        )

        # Check hierarchy
        ancestors = await role_service._get_ancestor_roles(grandchild_role.id)
        assert len(ancestors) == 2
        assert ancestors[0].id == child_role.id
        assert ancestors[1].id == base_role.id

        descendants = await role_service._get_descendant_roles(base_role.id)
        assert len(descendants) == 2
        assert set(d.id for d in descendants) == {child_role.id, grandchild_role.id}

    async def test_circular_hierarchy(self, role_service, test_tenant):
        """Test preventing circular role hierarchy"""
        role1 = await role_service.create_role(name="Role 1", tenant_id=test_tenant.id)

        role2 = await role_service.create_role(
            name="Role 2", parent_ids=[role1.id], tenant_id=test_tenant.id
        )

        # Try to make role1 a child of role2 (creates cycle)
        with pytest.raises(CircularRoleHierarchyError):
            await role_service.update_role(role_id=role1.id, parent_ids=[role2.id])

    async def test_role_permission_inheritance(
        self, role_service, permission_service, test_tenant, sample_permissions
    ):
        """Test that roles inherit permissions from parents"""
        # Create base role with permissions
        base_role = await role_service.create_role(
            name="Base Role", tenant_id=test_tenant.id
        )

        await permission_service.grant_permission_to_role(
            role_id=base_role.id, permission_id=sample_permissions["user:read"].id
        )

        # Create child role
        child_role = await role_service.create_role(
            name="Child Role", parent_ids=[base_role.id], tenant_id=test_tenant.id
        )

        # Check inherited permissions
        child_perms = await role_service.get_role_permissions(
            child_role.id, include_inherited=True
        )
        assert len(child_perms) == 1
        assert child_perms[0].id == sample_permissions["user:read"].id

        # Check direct permissions only
        direct_perms = await role_service.get_role_permissions(
            child_role.id, include_inherited=False
        )
        assert len(direct_perms) == 0

    async def test_add_remove_parent(self, role_service, test_tenant):
        """Test adding and removing role parents"""
        # Create roles
        parent = await role_service.create_role(name="Parent", tenant_id=test_tenant.id)

        child = await role_service.create_role(name="Child", tenant_id=test_tenant.id)

        # Add parent
        await role_service.add_role_parent(child.id, parent.id)

        updated_child = await role_service.get_role(child.id)
        assert parent.id in updated_child.parent_ids

        # Remove parent
        await role_service.remove_role_parent(child.id, parent.id)

        updated_child = await role_service.get_role(child.id)
        assert parent.id not in updated_child.parent_ids

    async def test_get_role_hierarchy_tree(self, role_service, test_tenant):
        """Test getting complete role hierarchy"""
        # Create hierarchy
        admin = await role_service.create_role(name="Admin", tenant_id=test_tenant.id)

        manager = await role_service.create_role(
            name="Manager", parent_ids=[admin.id], tenant_id=test_tenant.id
        )

        user = await role_service.create_role(
            name="User", parent_ids=[manager.id], tenant_id=test_tenant.id
        )

        # Get hierarchy for user
        hierarchy = await role_service.get_role_hierarchy(user.id)

        assert hierarchy["role"]["name"] == "User"
        assert len(hierarchy["ancestors"]) == 2
        assert hierarchy["ancestors"][0]["name"] == "Manager"
        assert hierarchy["ancestors"][1]["name"] == "Admin"
        assert len(hierarchy["descendants"]) == 0

    async def test_get_roles_for_user(
        self, role_service, assignment_service, test_user_id, test_tenant, sample_roles
    ):
        """Test getting roles assigned to user"""
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

        # Get user roles
        roles_with_scope = await role_service.get_roles_for_user(
            user_id=test_user_id, tenant_id=test_tenant.id
        )

        assert len(roles_with_scope) >= 2

        # Check role names
        role_names = [r[0].name for r in roles_with_scope]
        assert "User" in role_names
        assert "Manager" in role_names

    async def test_get_users_in_role(
        self,
        role_service,
        assignment_service,
        test_user_id,
        test_admin_user_id,
        test_tenant,
        sample_roles,
    ):
        """Test getting users assigned to a role"""
        # Assign users to role
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

        # Get users in role
        users = await role_service.get_users_in_role(
            role_id=sample_roles["user"].id, tenant_id=test_tenant.id
        )

        assert len(users) == 2
        user_ids = {u["user_id"] for u in users}
        assert test_user_id in user_ids
        assert test_admin_user_id in user_ids

    async def test_bulk_assign_permissions(
        self, role_service, permission_service, test_tenant, sample_permissions
    ):
        """Test bulk assigning permissions to role"""
        # Create role
        role = await role_service.create_role(
            name="Test Role", tenant_id=test_tenant.id
        )

        # Bulk assign permissions
        perm_ids = [
            sample_permissions["user:read"].id,
            sample_permissions["user:create"].id,
            sample_permissions["role:read"].id,
        ]

        await role_service.bulk_assign_permissions(
            role_id=role.id, permission_ids=perm_ids
        )

        # Check assignments
        role_perms = await role_service.get_role_permissions(role.id)
        assert len(role_perms) == 3
        assert {p.id for p in role_perms} == set(perm_ids)

    async def test_get_role_stats(
        self,
        role_service,
        permission_service,
        assignment_service,
        test_user_id,
        test_tenant,
        sample_permissions,
    ):
        """Test getting role statistics"""
        # Create role with hierarchy
        parent = await role_service.create_role(name="Parent", tenant_id=test_tenant.id)

        role = await role_service.create_role(
            name="Test Role", parent_ids=[parent.id], tenant_id=test_tenant.id
        )

        # Add permissions
        await permission_service.grant_permission_to_role(
            role_id=role.id, permission_id=sample_permissions["user:read"].id
        )

        # Assign user
        await assignment_service.assign_role_to_user(
            user_id=test_user_id, role_id=role.id, tenant_id=test_tenant.id
        )

        # Get stats
        stats = await role_service.get_role_stats(role.id)

        assert stats["role_name"] == "Test Role"
        assert stats["direct_user_count"] == 1
        assert stats["direct_permission_count"] == 1
        assert stats["ancestor_count"] == 1
