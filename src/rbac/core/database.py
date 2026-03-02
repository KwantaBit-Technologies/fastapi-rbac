# rbac/core/database.py
from typing import Optional, AsyncGenerator, Dict, Any, List
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncEngine,
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy import (
    MetaData,
    Table,
    Column,
    String,
    Boolean,
    JSON,
    Text,
    TIMESTAMP,
    Index,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB, INET
import uuid
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("DATABASE: ")

# Define metadata and tables
metadata = MetaData()

# Tenants table
tenants = Table(
    "tenants",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
    Column("name", String(255), nullable=False),
    Column("domain", String(255)),
    Column("is_active", Boolean, default=True),
    Column("settings", JSONB, default={}),
    Column("created_at", TIMESTAMP(timezone=True), default=datetime.utcnow),
    Column(
        "updated_at",
        TIMESTAMP(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    ),
)

# Permissions table
permissions = Table(
    "permissions",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
    Column("name", String(255), nullable=False),
    Column("resource", String(50), nullable=False),
    Column("action", String(50), nullable=False),
    Column("scope", String(255)),
    Column("description", Text),
    Column("is_system", Boolean, default=False),
    Column(
        "tenant_id", PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    ),
    Column("created_at", TIMESTAMP(timezone=True), default=datetime.utcnow),
    Column(
        "updated_at",
        TIMESTAMP(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    ),
    UniqueConstraint(
        "resource",
        "action",
        "scope",
        "tenant_id",
        name="uq_permission_resource_action_scope_tenant",
    ),
)

# Roles table
roles = Table(
    "roles",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
    Column("name", String(255), nullable=False),
    Column("description", Text),
    Column("parent_ids", JSONB, default=list),  # Store as JSON array
    Column("is_system_role", Boolean, default=False),
    Column("is_active", Boolean, default=True),
    Column(
        "tenant_id", PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    ),
    Column("metadata", JSONB, default={}),
    Column("created_at", TIMESTAMP(timezone=True), default=datetime.utcnow),
    Column(
        "updated_at",
        TIMESTAMP(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    ),
    UniqueConstraint("name", "tenant_id", name="uq_role_name_tenant"),
)

# Role-Permissions junction table
role_permissions = Table(
    "role_permissions",
    metadata,
    Column(
        "role_id",
        PG_UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        PG_UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("granted_at", TIMESTAMP(timezone=True), default=datetime.utcnow),
)

# User-Roles table
user_roles = Table(
    "user_roles",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
    Column("user_id", PG_UUID(as_uuid=True), nullable=False),
    Column(
        "role_id", PG_UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE")
    ),
    Column(
        "tenant_id", PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    ),
    Column("resource_scope", JSONB, default={}),
    Column("granted_by", PG_UUID(as_uuid=True)),
    Column("granted_at", TIMESTAMP(timezone=True), default=datetime.utcnow),
    Column("expires_at", TIMESTAMP(timezone=True)),
    Column("is_active", Boolean, default=True),
    UniqueConstraint("user_id", "role_id", "tenant_id", name="uq_user_role_tenant"),
)

# Audit logs table
audit_logs = Table(
    "audit_logs",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
    Column("user_id", PG_UUID(as_uuid=True)),
    Column(
        "tenant_id",
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
    ),
    Column("action", String(50), nullable=False),
    Column("resource_type", String(50), nullable=False),
    Column("resource_id", PG_UUID(as_uuid=True)),
    Column("old_value", JSONB),
    Column("new_value", JSONB),
    Column("ip_address", String(45)),  # IPv6 can be up to 45 chars
    Column("user_agent", Text),
    Column("created_at", TIMESTAMP(timezone=True), default=datetime.utcnow),
)

# Indexes
Index("idx_user_roles_user_id", user_roles.c.user_id)
Index("idx_user_roles_tenant", user_roles.c.tenant_id)
Index("idx_roles_tenant", roles.c.tenant_id)
Index("idx_permissions_tenant", permissions.c.tenant_id)
Index("idx_audit_logs_created", audit_logs.c.created_at)
Index("idx_audit_logs_user", audit_logs.c.user_id)
Index("idx_audit_logs_resource", audit_logs.c.resource_type, audit_logs.c.resource_id)


class Database:
    """Database connection manager using SQLAlchemy Core with async support"""

    def __init__(self, dsn: str, min_size: int = 10, max_size: int = 20):
        # Store pool configuration
        self.min_size = min_size
        self.max_size = max_size
        self.dsn = dsn

        # Convert Postgres DSN to asyncpg format if needed
        if dsn.startswith("postgresql://"):
            self._async_dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
        else:
            self._async_dsn = dsn

        self.engine: Optional[AsyncEngine] = None
        self.async_session: Optional[async_sessionmaker[AsyncSession]] = None

    async def connect(self):
        """Initialize SQLAlchemy async engine and create tables"""
        try:
            # Calculate pool settings based on min/max size
            pool_size = self.min_size
            max_overflow = self.max_size - self.min_size

            self.engine = create_async_engine(
                self._async_dsn,
                pool_size=pool_size,
                max_overflow=max_overflow if max_overflow > 0 else 0,
                pool_pre_ping=True,
                pool_recycle=300,
                echo=False,  # Set to True for SQL logging
            )

            self.async_session = async_sessionmaker(
                self.engine, class_=AsyncSession, expire_on_commit=False
            )

            # Create tables if they don't exist
            async with self.engine.begin() as conn:
                await conn.run_sync(metadata.create_all)

            logger.info(
                f"Database connection pool created successfully with SQLAlchemy (min={self.min_size}, max={self.max_size})"
            )

        except Exception as e:
            logger.error(f"Failed to create database connection pool: {e}")
            raise

    async def disconnect(self):
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connection pool closed")

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncConnection, None]:
        """Context manager for database transactions"""
        if not self.engine:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self.engine.begin() as conn:
            yield conn

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Context manager for SQLAlchemy sessions (useful for ORM if needed later)"""
        if not self.async_session:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def fetch_one(self, query, *args) -> Optional[Dict[str, Any]]:
        """Fetch a single row using SQLAlchemy Core"""
        if not self.engine:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self.engine.connect() as conn:
            result = await conn.execute(query, *args)
            row = result.first()
            return dict(row._mapping) if row else None

    async def fetch_all(self, query, *args) -> List[Dict[str, Any]]:
        """Fetch multiple rows using SQLAlchemy Core"""
        if not self.engine:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self.engine.connect() as conn:
            result = await conn.execute(query, *args)
            return [dict(row._mapping) for row in result]

    async def execute(self, query, *args) -> None:
        """Execute a query using SQLAlchemy Core"""
        if not self.engine:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self.engine.begin() as conn:
            await conn.execute(query, *args)

    async def fetch_val(self, query, *args) -> Any:
        """Fetch a single value"""
        if not self.engine:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self.engine.connect() as conn:
            result = await conn.execute(query, *args)
            row = result.first()
            return row[0] if row else None

    async def status(self) -> Dict[str, Any]:
        """Get database connection pool status"""
        if not self.engine:
            return {"connected": False}

        pool = self.engine.pool
        return {
            "connected": True,
            "min_size": self.min_size,
            "max_size": self.max_size,
            "size": pool.size(),
            "overflow": pool.overflow(),
            "checked_in_connections": pool.checkedin(),
        }
