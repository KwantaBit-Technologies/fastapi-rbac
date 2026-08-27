# tests/conftest.py
import asyncio
import os
from typing import AsyncGenerator
from urllib.parse import urlparse
from uuid import UUID, uuid4

import asyncpg
import pytest
from sqlalchemy import delete, insert

from rbac.core.constants import PermissionAction, ResourceType
from rbac.core.database import (
    Database,
    audit_logs,
    permissions,
    role_permissions,
    roles,
    tenants,
    user_roles,
)
from rbac.core.models import Tenant
from rbac.services.assignment_service import AssignmentService
from rbac.services.audit_service import AuditService
from rbac.services.permission_service import PermissionService
from rbac.services.role_service import RoleService

# Test database URL - use a separate test database.
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/rbac_test"),
)


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db() -> AsyncGenerator[Database, None]:
    """Create test database connection"""
    parsed = urlparse(TEST_DATABASE_URL)
    database_name = parsed.path.lstrip("/") or "rbac_test"

    # Create test database if it doesn't exist
    conn = await asyncpg.connect(
        user=parsed.username or os.getenv("POSTGRES_USER", "postgres"),
        password=parsed.password or os.getenv("POSTGRES_PASSWORD", "postgres"),
        host=parsed.hostname or os.getenv("POSTGRES_HOST", "localhost"),
        port=parsed.port or int(os.getenv("POSTGRES_PORT", "5432")),
        database="postgres",
    )

    try:
        await conn.execute(f'CREATE DATABASE "{database_name}"')
    except asyncpg.DuplicateDatabaseError:
        pass
    finally:
        await conn.close()

    # Connect to test database
    database = Database(TEST_DATABASE_URL, min_size=1, max_size=5)
    await database.connect()

    # Clear all tables before each test.
    async with database.transaction() as conn:
        for table in (audit_logs, user_roles, role_permissions, roles, permissions, tenants):
            await conn.execute(delete(table))

    yield database

    await database.disconnect()


@pytest.fixture
async def permission_service(db: Database) -> PermissionService:
    """Create permission service instance"""
    return PermissionService(db)


@pytest.fixture
async def role_service(db: Database, permission_service: PermissionService) -> RoleService:
    """Create role service instance"""
    return RoleService(db, permission_service)


@pytest.fixture
async def assignment_service(
    db: Database, role_service: RoleService, permission_service: PermissionService
) -> AssignmentService:
    """Create assignment service instance"""
    return AssignmentService(db, role_service, permission_service)


@pytest.fixture
async def audit_service(db: Database) -> AuditService:
    """Create audit service instance"""
    return AuditService(db, retention_days=7)


@pytest.fixture
async def test_tenant(db: Database) -> Tenant:
    """Create test tenant"""
    tenant = Tenant(id=uuid4(), name="Test Tenant", domain="test.example.com", is_active=True)
    await db.execute(
        insert(tenants).values(
            id=tenant.id,
            name=tenant.name,
            domain=tenant.domain,
            is_active=tenant.is_active,
            settings=tenant.settings,
            created_at=tenant.created_at,
            updated_at=tenant.updated_at,
        )
    )
    return tenant


@pytest.fixture
async def test_user_id() -> UUID:
    """Create test user ID"""
    return uuid4()


@pytest.fixture
async def test_admin_user_id() -> UUID:
    """Create test admin user ID"""
    return uuid4()


@pytest.fixture
async def sample_permissions(permission_service: PermissionService, test_tenant: Tenant) -> dict:
    """Create sample permissions for testing"""
    permissions = {}

    # Create resource permissions
    for resource in [ResourceType.USER, ResourceType.ROLE, ResourceType.PERMISSION]:
        for action in [
            PermissionAction.CREATE,
            PermissionAction.READ,
            PermissionAction.UPDATE,
            PermissionAction.DELETE,
        ]:
            perm = await permission_service.create_permission(
                name=f"{resource.value}:{action.value}",
                resource=resource,
                action=action,
                tenant_id=test_tenant.id,
                description=f"Can {action.value} {resource.value}",
            )
            permissions[f"{resource.value}:{action.value}"] = perm

    # Create wildcard permission
    wildcard = await permission_service.create_permission(
        name="*:*",
        resource=ResourceType.ALL,
        action=PermissionAction.MANAGE,
        tenant_id=None,  # System-wide
    )
    permissions["*:*"] = wildcard

    return permissions


@pytest.fixture
async def sample_roles(
    role_service: RoleService,
    permission_service: PermissionService,
    sample_permissions: dict,
    test_tenant: Tenant,
) -> dict:
    """Create sample roles for testing"""
    roles = {}

    # Create user role
    user_role = await role_service.create_role(
        name="User", description="Regular user", tenant_id=test_tenant.id
    )
    roles["user"] = user_role

    # Create manager role
    manager_role = await role_service.create_role(
        name="Manager",
        description="Manager role",
        parent_ids=[user_role.id],
        tenant_id=test_tenant.id,
    )
    roles["manager"] = manager_role

    # Create admin role
    admin_role = await role_service.create_role(
        name="Admin", description="Administrator", tenant_id=test_tenant.id
    )
    roles["admin"] = admin_role

    # Assign permissions
    await permission_service.grant_permission_to_role(
        role_id=user_role.id, permission_id=sample_permissions["user:read"].id
    )

    await permission_service.grant_permission_to_role(
        role_id=manager_role.id, permission_id=sample_permissions["user:update"].id
    )

    await permission_service.grant_permission_to_role(
        role_id=admin_role.id, permission_id=sample_permissions["*:*"].id
    )

    return roles
