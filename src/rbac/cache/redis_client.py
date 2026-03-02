# rbac/cache/redis_client.py
from typing import Optional, Any, Dict, List, Union
import json
import pickle
from datetime import timedelta
import logging
from redis import asyncio as aioredis
from redis.asyncio import Redis, ConnectionPool
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from utils.logger import setup_logger

logger = setup_logger("redis_cache")


class RedisCache:
    """Redis cache client with connection pooling and error handling"""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        prefix: str = "rbac:",
        default_ttl: int = 3600,  # 1 hour
        max_connections: int = 10,
        socket_timeout: int = 5,
        socket_connect_timeout: int = 5,
        retry_on_timeout: bool = True,
        decode_responses: bool = False,  # Keep as bytes for pickle
    ):
        self.redis_url = redis_url
        self.prefix = prefix
        self.default_ttl = default_ttl
        self.max_connections = max_connections
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.retry_on_timeout = retry_on_timeout
        self.decode_responses = decode_responses

        self._redis: Optional[Redis] = None
        self._pool: Optional[ConnectionPool] = None

    async def initialize(self):
        """Initialize Redis connection pool"""
        try:
            # Configure retry strategy
            retry = Retry(ExponentialBackoff(cap=10, base=1), 3)

            # Create connection pool
            self._pool = aioredis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=self.max_connections,
                socket_timeout=self.socket_timeout,
                socket_connect_timeout=self.socket_connect_timeout,
                retry_on_timeout=self.retry_on_timeout,
                retry=retry,
                decode_responses=self.decode_responses,
            )

            # Create Redis client
            self._redis = await aioredis.Redis.from_pool(self._pool)

            # Test connection
            await self._redis.ping()
            logger.info(f"Redis cache initialized at {self.redis_url}")

        except Exception as e:
            logger.error(f"Failed to initialize Redis cache: {e}")
            # Fallback to no-op cache if Redis is unavailable
            self._redis = None

    async def close(self):
        """Close Redis connections"""
        if self._pool:
            await self._pool.disconnect()
            logger.info("Redis cache connection closed")

    def _key(self, key: str) -> str:
        """Add prefix to key"""
        return f"{self.prefix}{key}"

    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage"""
        try:
            return pickle.dumps(value)
        except Exception as e:
            logger.error(f"Serialization error: {e}")
            raise

    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage"""
        try:
            return pickle.loads(data) if data else None
        except Exception as e:
            logger.error(f"Deserialization error: {e}")
            return None

    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache"""
        if not self._redis:
            return default

        try:
            data = await self._redis.get(self._key(key))
            if data:
                return self._deserialize(data)
            return default
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis get error for key {key}: {e}")
            return default

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL"""
        if not self._redis:
            return False

        try:
            data = self._serialize(value)
            ttl = ttl or self.default_ttl
            await self._redis.setex(self._key(key), ttl, data)
            return True
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self._redis:
            return False

        try:
            result = await self._redis.delete(self._key(key))
            return result > 0
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis delete error for key {key}: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        if not self._redis:
            return 0

        try:
            keys = await self._redis.keys(self._key(pattern))
            if keys:
                return await self._redis.delete(*keys)
            return 0
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis delete pattern error for {pattern}: {e}")
            return 0

    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self._redis:
            return False

        try:
            return await self._redis.exists(self._key(key)) > 0
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis exists error for key {key}: {e}")
            return False

    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration on key"""
        if not self._redis:
            return False

        try:
            return await self._redis.expire(self._key(key), ttl)
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis expire error for key {key}: {e}")
            return False

    async def ttl(self, key: str) -> int:
        """Get TTL for key"""
        if not self._redis:
            return -2

        try:
            return await self._redis.ttl(self._key(key))
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis ttl error for key {key}: {e}")
            return -2

    async def incr(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter"""
        if not self._redis:
            return None

        try:
            return await self._redis.incrby(self._key(key), amount)
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis incr error for key {key}: {e}")
            return None

    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple keys at once"""
        if not self._redis or not keys:
            return {}

        try:
            prefixed_keys = [self._key(k) for k in keys]
            values = await self._redis.mget(prefixed_keys)

            result = {}
            for key, value in zip(keys, values):
                if value:
                    result[key] = self._deserialize(value)
            return result
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis mget error: {e}")
            return {}

    async def set_many(
        self, mapping: Dict[str, Any], ttl: Optional[int] = None
    ) -> bool:
        """Set multiple keys at once"""
        if not self._redis or not mapping:
            return False

        try:
            pipe = self._redis.pipeline()
            ttl = ttl or self.default_ttl

            for key, value in mapping.items():
                data = self._serialize(value)
                pipe.setex(self._key(key), ttl, data)

            await pipe.execute()
            return True
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis mset error: {e}")
            return False

    async def clear_prefix(self, prefix: str) -> int:
        """Clear all keys with given prefix"""
        return await self.delete_pattern(f"{prefix}*")

    async def clear_all(self) -> int:
        """Clear all cache keys"""
        return await self.delete_pattern("*")

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self._redis:
            return {"status": "disconnected"}

        try:
            info = await self._redis.info()
            return {
                "status": "connected",
                "used_memory": info.get("used_memory_human", "N/A"),
                "total_connections": info.get("total_connections_received", 0),
                "total_commands": info.get("total_commands_processed", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "hit_rate": self._calculate_hit_rate(info),
                "connected_clients": info.get("connected_clients", 0),
                "uptime_days": info.get("uptime_in_days", 0),
            }
        except Exception as e:
            logger.error(f"Failed to get Redis stats: {e}")
            return {"status": "error", "error": str(e)}

    def _calculate_hit_rate(self, info: Dict) -> float:
        """Calculate cache hit rate"""
        hits = info.get("keyspace_hits", 0)
        misses = info.get("keyspace_misses", 0)
        total = hits + misses
        return (hits / total * 100) if total > 0 else 0.0


class RedisCachedPermissionService:
    """Permission service with Redis caching"""

    def __init__(
        self,
        permission_service,
        redis_cache: RedisCache,
        user_permissions_ttl: int = 3600,  # 1 hour
        role_permissions_ttl: int = 7200,  # 2 hours
        cache_enabled: bool = True,
    ):
        self.permission_service = permission_service
        self.cache = redis_cache
        self.user_permissions_ttl = user_permissions_ttl
        self.role_permissions_ttl = role_permissions_ttl
        self.cache_enabled = cache_enabled

    async def get_user_permissions(
        self, user_id: str, tenant_id: Optional[str] = None
    ) -> set:
        """Get user permissions with Redis caching"""
        if not self.cache_enabled:
            return await self.permission_service.get_user_permissions(
                user_id, tenant_id
            )

        cache_key = f"user_perms:{user_id}:{tenant_id or 'global'}"

        # Try cache first
        cached = await self.cache.get(cache_key)
        if cached is not None:
            return set(cached)

        # Get from service
        permissions = await self.permission_service.get_user_permissions(
            user_id, tenant_id
        )

        # Cache the result
        await self.cache.set(
            cache_key,
            list(permissions),  # Convert set to list for serialization
            ttl=self.user_permissions_ttl,
        )

        return permissions

    async def check_user_permission(
        self,
        user_id: str,
        required_permission: str,
        tenant_id: Optional[str] = None,
        resource_scope: Optional[dict] = None,
    ) -> bool:
        """Check permission with caching"""
        # Get all user permissions (cached)
        permissions = await self.get_user_permissions(user_id, tenant_id)

        # Check for exact match
        if required_permission in permissions:
            return True

        # Check wildcards
        parts = required_permission.split(":")
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else None

        if action and f"*:{action}" in permissions:
            return True

        if f"{resource}:*" in permissions:
            return True

        if "*:*" in permissions:
            return True

        # Check scoped permissions
        if resource_scope and len(parts) > 2:
            scope_key = f"{resource}:{action}:{resource_scope.get('id')}"
            if scope_key in permissions:
                return True

        return False

    async def get_role_permissions(
        self, role_id: str, include_inherited: bool = True
    ) -> list:
        """Get role permissions with caching"""
        if not self.cache_enabled:
            return await self.permission_service.get_role_permissions(
                role_id, include_inherited
            )

        cache_key = f"role_perms:{role_id}:inherited={include_inherited}"

        # Try cache
        cached = await self.cache.get(cache_key)
        if cached is not None:
            return cached

        # Get from service
        permissions = await self.permission_service.get_role_permissions(
            role_id, include_inherited
        )

        # Cache the result
        await self.cache.set(cache_key, permissions, ttl=self.role_permissions_ttl)

        return permissions

    async def invalidate_user_cache(
        self, user_id: str, tenant_id: Optional[str] = None
    ):
        """Invalidate cache for a specific user"""
        if not self.cache_enabled:
            return

        pattern = f"user_perms:{user_id}:*"
        await self.cache.delete_pattern(pattern)
        logger.debug(f"Invalidated cache for user {user_id}")

    async def invalidate_role_cache(self, role_id: str):
        """Invalidate cache for a specific role"""
        if not self.cache_enabled:
            return

        pattern = f"role_perms:{role_id}:*"
        await self.cache.delete_pattern(pattern)
        logger.debug(f"Invalidated cache for role {role_id}")

    async def invalidate_all(self):
        """Invalidate all permission caches"""
        if not self.cache_enabled:
            return

        await self.cache.delete_pattern("user_perms:*")
        await self.cache.delete_pattern("role_perms:*")
        logger.info("Invalidated all permission caches")

    # Delegate other methods to underlying service
    async def create_permission(self, *args, **kwargs):
        result = await self.permission_service.create_permission(*args, **kwargs)
        await self.invalidate_all()  # Invalidate all caches on permission change
        return result

    async def update_permission(self, *args, **kwargs):
        result = await self.permission_service.update_permission(*args, **kwargs)
        await self.invalidate_all()
        return result

    async def delete_permission(self, *args, **kwargs):
        result = await self.permission_service.delete_permission(*args, **kwargs)
        await self.invalidate_all()
        return result

    async def grant_permission_to_role(self, role_id, permission_id, *args, **kwargs):
        result = await self.permission_service.grant_permission_to_role(
            role_id, permission_id, *args, **kwargs
        )
        await self.invalidate_role_cache(role_id)
        await self.cache.delete_pattern(
            f"user_perms:*"
        )  # All users with this role affected
        return result

    async def revoke_permission_from_role(
        self, role_id, permission_id, *args, **kwargs
    ):
        result = await self.permission_service.revoke_permission_from_role(
            role_id, permission_id, *args, **kwargs
        )
        await self.invalidate_role_cache(role_id)
        await self.cache.delete_pattern(f"user_perms:*")
        return result


class RedisCachedRoleService:
    """Role service with Redis caching"""

    def __init__(
        self,
        role_service,
        redis_cache: RedisCache,
        role_ttl: int = 7200,  # 2 hours
        hierarchy_ttl: int = 3600,  # 1 hour
        cache_enabled: bool = True,
    ):
        self.role_service = role_service
        self.cache = redis_cache
        self.role_ttl = role_ttl
        self.hierarchy_ttl = hierarchy_ttl
        self.cache_enabled = cache_enabled

    async def get_role(self, role_id: str, tenant_id: Optional[str] = None):
        """Get role with caching"""
        if not self.cache_enabled:
            return await self.role_service.get_role(role_id, tenant_id)

        cache_key = f"role:{role_id}:{tenant_id or 'global'}"

        cached = await self.cache.get(cache_key)
        if cached:
            return cached

        role = await self.role_service.get_role(role_id, tenant_id)
        if role:
            await self.cache.set(cache_key, role, ttl=self.role_ttl)

        return role

    async def get_role_by_name(self, name: str, tenant_id: Optional[str] = None):
        """Get role by name with caching"""
        if not self.cache_enabled:
            return await self.role_service.get_role_by_name(name, tenant_id)

        cache_key = f"role_name:{name}:{tenant_id or 'global'}"

        cached = await self.cache.get(cache_key)
        if cached:
            return cached

        role = await self.role_service.get_role_by_name(name, tenant_id)
        if role:
            await self.cache.set(cache_key, role, ttl=self.role_ttl)

        return role

    async def get_role_hierarchy(self, role_id: str):
        """Get role hierarchy with caching"""
        if not self.cache_enabled:
            return await self.role_service.get_role_hierarchy(role_id)

        cache_key = f"role_hierarchy:{role_id}"

        cached = await self.cache.get(cache_key)
        if cached:
            return cached

        hierarchy = await self.role_service.get_role_hierarchy(role_id)
        await self.cache.set(cache_key, hierarchy, ttl=self.hierarchy_ttl)

        return hierarchy

    async def invalidate_role(self, role_id: str):
        """Invalidate cache for a specific role"""
        if not self.cache_enabled:
            return

        await self.cache.delete_pattern(f"role:{role_id}:*")
        await self.cache.delete_pattern(f"role_name:*")  # Names might have changed
        await self.cache.delete_pattern(f"role_hierarchy:{role_id}")
        logger.debug(f"Invalidated cache for role {role_id}")

    async def create_role(self, *args, **kwargs):
        result = await self.role_service.create_role(*args, **kwargs)
        await self.invalidate_role(result.id)
        return result

    async def update_role(self, role_id, *args, **kwargs):
        result = await self.role_service.update_role(role_id, *args, **kwargs)
        await self.invalidate_role(role_id)
        return result

    async def delete_role(self, role_id, *args, **kwargs):
        result = await self.role_service.delete_role(role_id, *args, **kwargs)
        await self.invalidate_role(role_id)
        return result

    async def add_role_parent(self, role_id, parent_id, *args, **kwargs):
        result = await self.role_service.add_role_parent(
            role_id, parent_id, *args, **kwargs
        )
        await self.invalidate_role(role_id)
        await self.invalidate_role(parent_id)
        return result


class RedisCachedAssignmentService:
    """Assignment service with Redis caching"""

    def __init__(
        self,
        assignment_service,
        redis_cache: RedisCache,
        assignment_ttl: int = 1800,  # 30 minutes
        cache_enabled: bool = True,
    ):
        self.assignment_service = assignment_service
        self.cache = redis_cache
        self.assignment_ttl = assignment_ttl
        self.cache_enabled = cache_enabled

    async def get_user_assignments(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
        include_inactive: bool = False,
        include_expired: bool = False,
    ):
        """Get user assignments with caching"""
        if not self.cache_enabled or include_inactive or include_expired:
            return await self.assignment_service.get_user_assignments(
                user_id, tenant_id, include_inactive, include_expired
            )

        cache_key = f"user_assignments:{user_id}:{tenant_id or 'global'}"

        cached = await self.cache.get(cache_key)
        if cached is not None:
            return cached

        assignments = await self.assignment_service.get_user_assignments(
            user_id, tenant_id, include_inactive, include_expired
        )

        await self.cache.set(cache_key, assignments, ttl=self.assignment_ttl)

        return assignments

    async def get_role_assignments(
        self,
        role_id: str,
        tenant_id: Optional[str] = None,
        include_inactive: bool = False,
        include_expired: bool = False,
        limit: int = 100,
        offset: int = 0,
    ):
        """Get role assignments with caching (only first page)"""
        if not self.cache_enabled or include_inactive or include_expired or offset > 0:
            return await self.assignment_service.get_role_assignments(
                role_id, tenant_id, include_inactive, include_expired, limit, offset
            )

        cache_key = f"role_assignments:{role_id}:{tenant_id or 'global'}:limit={limit}"

        cached = await self.cache.get(cache_key)
        if cached is not None:
            return cached

        assignments = await self.assignment_service.get_role_assignments(
            role_id, tenant_id, include_inactive, include_expired, limit, offset
        )

        await self.cache.set(cache_key, assignments, ttl=self.assignment_ttl)

        return assignments

    async def invalidate_user_assignments(
        self, user_id: str, tenant_id: Optional[str] = None
    ):
        """Invalidate cache for a user's assignments"""
        if not self.cache_enabled:
            return

        pattern = f"user_assignments:{user_id}:*"
        await self.cache.delete_pattern(pattern)
        logger.debug(f"Invalidated assignments cache for user {user_id}")

    async def invalidate_role_assignments(self, role_id: str):
        """Invalidate cache for a role's assignments"""
        if not self.cache_enabled:
            return

        pattern = f"role_assignments:{role_id}:*"
        await self.cache.delete_pattern(pattern)
        logger.debug(f"Invalidated assignments cache for role {role_id}")

    async def assign_role_to_user(self, *args, **kwargs):
        result = await self.assignment_service.assign_role_to_user(*args, **kwargs)
        await self.invalidate_user_assignments(result.user_id)
        await self.invalidate_role_assignments(result.role_id)
        return result

    async def revoke_role_from_user(self, user_id, role_id, *args, **kwargs):
        result = await self.assignment_service.revoke_role_from_user(
            user_id, role_id, *args, **kwargs
        )
        await self.invalidate_user_assignments(user_id)
        await self.invalidate_role_assignments(role_id)
        return result

    async def update_assignment_scope(self, assignment_id, *args, **kwargs):
        assignment = await self.assignment_service.get_user_assignments(assignment_id)
        if assignment:
            await self.invalidate_user_assignments(assignment.user_id)
        return await self.assignment_service.update_assignment_scope(
            assignment_id, *args, **kwargs
        )

    async def extend_assignment(self, assignment_id, *args, **kwargs):
        assignment = await self.assignment_service.get_user_assignments(assignment_id)
        if assignment:
            await self.invalidate_user_assignments(assignment.user_id)
        return await self.assignment_service.extend_assignment(
            assignment_id, *args, **kwargs
        )


class CacheManager:
    """Central cache manager for coordinated cache operations"""

    def __init__(
        self,
        redis_cache: RedisCache,
        permission_service,
        role_service,
        assignment_service,
    ):
        self.cache = redis_cache
        self.permission_service = permission_service
        self.role_service = role_service
        self.assignment_service = assignment_service

    async def invalidate_user(self, user_id: str, tenant_id: Optional[str] = None):
        """Invalidate all caches for a specific user"""
        await self.permission_service.invalidate_user_cache(user_id, tenant_id)
        await self.assignment_service.invalidate_user_assignments(user_id, tenant_id)
        logger.info(f"Invalidated all caches for user {user_id}")

    async def invalidate_role(self, role_id: str):
        """Invalidate all caches for a specific role"""
        await self.permission_service.invalidate_role_cache(role_id)
        await self.role_service.invalidate_role(role_id)
        await self.assignment_service.invalidate_role_assignments(role_id)
        logger.info(f"Invalidated all caches for role {role_id}")

    async def invalidate_tenant(self, tenant_id: str):
        """Invalidate all caches for a tenant"""
        await self.cache.delete_pattern(f"*:{tenant_id}:*")
        logger.info(f"Invalidated all caches for tenant {tenant_id}")

    async def invalidate_all(self):
        """Invalidate all caches"""
        await self.cache.clear_all()
        logger.info("Invalidated all caches")

    async def warm_user_cache(self, user_id: str, tenant_id: Optional[str] = None):
        """Pre-warm cache for a user"""
        await self.permission_service.get_user_permissions(user_id, tenant_id)
        await self.assignment_service.get_user_assignments(user_id, tenant_id)
        logger.debug(f"Warmed cache for user {user_id}")

    async def warm_role_cache(self, role_id: str):
        """Pre-warm cache for a role"""
        await self.permission_service.get_role_permissions(role_id)
        await self.role_service.get_role_hierarchy(role_id)
        logger.debug(f"Warmed cache for role {role_id}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return await self.cache.get_stats()
