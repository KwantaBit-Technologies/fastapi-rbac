# tests/test_redis_cache.py
import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from rbac.cache.redis_client import (
    RedisCache,
    RedisCachedPermissionService,
    RedisCachedRoleService,
    RedisCachedAssignmentService,
    CacheManager,
)

pytestmark = pytest.mark.asyncio


class TestRedisCache:

    async def test_redis_cache_initialization(self):
        """Test Redis cache initialization"""
        cache = RedisCache(
            redis_url="redis://localhost:6379", prefix="test:", default_ttl=300
        )

        assert cache.prefix == "test:"
        assert cache.default_ttl == 300

        # Mock initialization since we don't have real Redis
        cache._redis = AsyncMock()
        await cache.initialize()

    async def test_key_prefixing(self):
        """Test key prefixing"""
        cache = RedisCache(prefix="test:")
        assert cache._key("user:123") == "test:user:123"

    async def test_serialization(self):
        """Test value serialization/deserialization"""
        cache = RedisCache()

        test_data = {"key": "value", "number": 123, "list": [1, 2, 3]}
        serialized = cache._serialize(test_data)
        deserialized = cache._deserialize(serialized)

        assert deserialized == test_data

    async def test_get_set_with_mock(self):
        """Test get and set operations with mock Redis"""
        cache = RedisCache()
        cache._redis = AsyncMock()

        # Mock get
        cache._redis.get.return_value = cache._serialize("test_value")
        value = await cache.get("test_key")
        assert value == "test_value"

        # Mock set
        cache._redis.setex.return_value = True
        result = await cache.set("test_key", "test_value", ttl=60)
        assert result is True

    async def test_delete_pattern_with_mock(self):
        """Test delete pattern with mock Redis"""
        cache = RedisCache()
        cache._redis = AsyncMock()

        # Mock keys and delete
        cache._redis.keys.return_value = ["key1", "key2"]
        cache._redis.delete.return_value = 2

        deleted = await cache.delete_pattern("test:*")
        assert deleted == 2


class TestRedisCachedPermissionService:

    async def test_get_user_permissions_cached(self, test_user_id):
        """Test getting user permissions with caching"""
        # Setup
        mock_base = AsyncMock()
        mock_cache = AsyncMock()

        service = RedisCachedPermissionService(
            mock_base, mock_cache, cache_enabled=True
        )

        # Mock cache miss then hit
        mock_cache.get.return_value = None
        mock_base.get_user_permissions.return_value = {"perm1", "perm2"}

        # First call - cache miss
        perms1 = await service.get_user_permissions(test_user_id)
        assert perms1 == {"perm1", "perm2"}
        mock_cache.set.assert_called_once()

        # Second call - cache hit
        mock_cache.get.return_value = ["perm1", "perm2"]
        perms2 = await service.get_user_permissions(test_user_id)
        assert perms2 == {"perm1", "perm2"}
        assert mock_base.get_user_permissions.call_count == 1  # Not called again

    async def test_invalidate_user_cache(self, test_user_id):
        """Test invalidating user cache"""
        mock_base = AsyncMock()
        mock_cache = AsyncMock()

        service = RedisCachedPermissionService(
            mock_base, mock_cache, cache_enabled=True
        )

        await service.invalidate_user_cache(test_user_id)
        mock_cache.delete_pattern.assert_called_once_with(
            f"user_perms:{test_user_id}:*"
        )


class TestRedisCachedRoleService:

    async def test_get_role_cached(self):
        """Test getting role with caching"""
        mock_base = AsyncMock()
        mock_cache = AsyncMock()

        service = RedisCachedRoleService(mock_base, mock_cache, cache_enabled=True)

        role_id = uuid4()
        mock_role = {"id": role_id, "name": "Test Role"}

        # Cache miss
        mock_cache.get.return_value = None
        mock_base.get_role.return_value = mock_role

        role = await service.get_role(role_id)
        assert role == mock_role
        mock_cache.set.assert_called_once()

        # Cache hit
        mock_cache.get.return_value = mock_role
        role = await service.get_role(role_id)
        assert role == mock_role


class TestCacheManager:

    async def test_invalidate_user(self, test_user_id):
        """Test invalidating all caches for a user"""
        mock_cache = AsyncMock()
        mock_permission = AsyncMock()
        mock_role = AsyncMock()
        mock_assignment = AsyncMock()

        manager = CacheManager(mock_cache, mock_permission, mock_role, mock_assignment)

        await manager.invalidate_user(test_user_id)

        mock_permission.invalidate_user_cache.assert_called_once_with(
            test_user_id, None
        )
        mock_assignment.invalidate_user_assignments.assert_called_once_with(
            test_user_id, None
        )

    async def test_warm_user_cache(self, test_user_id):
        """Test pre-warming cache for a user"""
        mock_cache = AsyncMock()
        mock_permission = AsyncMock()
        mock_role = AsyncMock()
        mock_assignment = AsyncMock()

        manager = CacheManager(mock_cache, mock_permission, mock_role, mock_assignment)

        await manager.warm_user_cache(test_user_id)

        mock_permission.get_user_permissions.assert_called_once_with(test_user_id, None)
        mock_assignment.get_user_assignments.assert_called_once_with(test_user_id, None)
