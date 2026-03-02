# tests/conftest.py
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from uuid import uuid4, UUID
from datetime import datetime, timedelta
import asyncpg
from unittest.mock import Mock, AsyncMock

from core.database import Database
from core.models import Tenant, Role, Permission, UserRole
from core.constants import ResourceType, PermissionAction, DEFAULT_ROLES
from services.permission_service import PermissionService
from services.role_service import RoleService
from services.assignment_service import AssignmentService
from services.audit_service import AuditService

# Test database URL - use a separate test database
TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/rbac_test"


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db() -> AsyncGenerator[Database, None]:
    """Create test database connection"""
    # Create test database if it doesn't exist
    conn = await asyncpg.connect(
        user="postgres",
        password="postgres",
        host="localhost",
        port=5432,
        database="postgres",
    )

    try:
        await conn.execute("CREATE DATABASE rbac_test")
    except asyncpg.DuplicateDatabaseError:
        pass
    finally:
        await conn.close()

    # Connect to test database
    database = Database(TEST_DATABASE_URL, min_size=1, max_size=5)
    await database.connect()

    # Clear all tables before each test
    async with database.pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE audit_logs CASCADE")
        await conn.execute("TRUNCATE TABLE user_roles CASCADE")
        await conn.execute("TRUNCATE TABLE role_permissions CASCADE")
        await conn.execute("TRUNCATE TABLE roles CASCADE")
        await conn.execute("TRUNCATE TABLE permissions CASCADE")
        await conn.execute("TRUNCATE TABLE tenants CASCADE")

    yield database

    await database.disconnect()


@pytest.fixture
async def permission_service(db: Database) -> PermissionService:
    """Create permission service instance"""
    return PermissionService(db)


@pytest.fixture
async def role_service(
    db: Database, permission_service: PermissionService
) -> RoleService:
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
async def test_tenant() -> Tenant:
    """Create test tenant"""
    return Tenant(
        id=uuid4(), name="Test Tenant", domain="test.example.com", is_active=True
    )


@pytest.fixture
async def test_user_id() -> UUID:
    """Create test user ID"""
    return uuid4()


@pytest.fixture
async def test_admin_user_id() -> UUID:
    """Create test admin user ID"""
    return uuid4()


@pytest.fixture
async def sample_permissions(
    permission_service: PermissionService, test_tenant: Tenant
) -> dict:
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
    role_service: RoleService, sample_permissions: dict, test_tenant: Tenant
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
