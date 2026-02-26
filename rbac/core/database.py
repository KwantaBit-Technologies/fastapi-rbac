# rbac/core/database.py
from typing import Optional, AsyncGenerator, Dict, Any
from contextlib import asynccontextmanager
import asyncpg
from asyncpg import Pool, Connection
import json
from uuid import UUID
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("DATABASE: ")


class Database:
    """Database connection manager with connection pooling"""

    def __init__(self, dsn: str, min_size: int = 10, max_size: int = 20):
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self.pool: Optional[Pool] = None

    async def connect(self):
        """Initialize connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                self.dsn,
                min_size=self.min_size,
                max_size=self.max_size,
                command_timeout=60,
                max_inactive_connection_lifetime=300,
                init=self._init_connection,
            )
            logger.info("Database connection pool created successfully")
            await self._create_tables()
        except Exception as e:
            logger.error(f"Failed to create database connection pool: {e}")
            raise

    async def disconnect(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")

    async def _init_connection(self, conn: Connection):
        """Initialize connection with custom encoders/decoders"""
        await conn.set_type_codec(
            "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
        )
        await conn.set_type_codec(
            "uuid",
            encoder=lambda u: str(u) if isinstance(u, UUID) else u,
            decoder=lambda u: UUID(u) if isinstance(u, str) else u,
            schema="pg_catalog",
        )

    async def _create_tables(self):
        """Create necessary tables if they don't exist"""
        async with self.pool.acquire() as conn:
            # Tenants table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(255) NOT NULL,
                    domain VARCHAR(255),
                    is_active BOOLEAN DEFAULT true,
                    settings JSONB DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Permissions table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS permissions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(255) NOT NULL,
                    resource VARCHAR(50) NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    scope VARCHAR(255),
                    description TEXT,
                    is_system BOOLEAN DEFAULT false,
                    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(resource, action, scope, tenant_id)
                )
            """
            )

            # Roles table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS roles (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    parent_ids UUID[] DEFAULT '{}',
                    is_system_role BOOLEAN DEFAULT false,
                    is_active BOOLEAN DEFAULT true,
                    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                    metadata JSONB DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, tenant_id)
                )
            """
            )

            # Role-Permission junction table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS role_permissions (
                    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
                    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (role_id, permission_id)
                )
            """
            )

            # User-Role assignments
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL,
                    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
                    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                    resource_scope JSONB DEFAULT '{}',
                    granted_by UUID,
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT true,
                    UNIQUE(user_id, role_id, tenant_id)
                )
            """
            )

            # Audit logs
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID,
                    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
                    action VARCHAR(50) NOT NULL,
                    resource_type VARCHAR(50) NOT NULL,
                    resource_id UUID,
                    old_value JSONB,
                    new_value JSONB,
                    ip_address INET,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create indexes
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_roles_tenant ON user_roles(tenant_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_permissions_tenant ON permissions(tenant_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)"
            )

            logger.info("Database tables created/verified successfully")

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Connection, None]:
        """Context manager for database transactions"""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                yield conn

    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Fetch a single row"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None

    async def fetch_all(self, query: str, *args) -> list:
        """Fetch multiple rows"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(row) for row in rows]

    async def execute(self, query: str, *args) -> str:
        """Execute a query"""
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)
