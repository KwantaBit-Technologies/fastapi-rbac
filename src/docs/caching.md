# Redis Caching Guide

This guide covers how to implement and optimize Redis caching for the FastAPI RBAC engine.

## Why Redis Caching?

RBAC systems frequently check permissions, which can become a database bottleneck at scale. Redis caching provides:

- **10-50x faster permission checks** (1-5ms vs 50-100ms)

- **Reduced database load** (up to 90% reduction)

- **Scalability** for high-concurrency applications

- **Automatic cache invalidation** when permissions change

## Installation

```bash

# Install with Redis support

pip install "fastapi-rbac[redis]"

# Or with uv

uv pip install "fastapi-rbac[redis]"

## Basic Setup

1. Initialize Redis Cache

```python

from rbac.cache import RedisCache

# Simple configuration

redis_cache = RedisCache(

    redis_url="redis://localhost:6379",

    prefix="rbac:",

    default_ttl=3600  # 1 hour default

)

# Advanced configuration

redis_cache = RedisCache(

    redis_url="redis://:password@localhost:6379/0",

    prefix="prod:rbac:",

    default_ttl=7200,

    max_connections=50,

    socket_timeout=2,

    socket_connect_timeout=2,

    retry_on_timeout=True

)

# Initialize connection pool

await redis_cache.initialize()

2. Wrap Services with Caching

```python

from rbac.cache import (

    RedisCachedPermissionService,

    RedisCachedRoleService,

    RedisCachedAssignmentService,

    CacheManager

)

# Base services (without cache)

base_permission_service = PermissionService(db)

base_role_service = RoleService(db, base_permission_service)

base_assignment_service = AssignmentService(db, base_role_service, base_permission_service)

# Wrap with caching

permission_service = RedisCachedPermissionService(

    base_permission_service=base_permission_service,

    redis_cache=redis_cache,

    user_permissions_ttl=3600,  # 1 hour

    role_permissions_ttl=7200,   # 2 hours

    cache_enabled=True

)

role_service = RedisCachedRoleService(

    role_service=base_role_service,

    redis_cache=redis_cache,

    role_ttl=7200,

    hierarchy_ttl=3600

)

assignment_service = RedisCachedAssignmentService(

    assignment_service=base_assignment_service,

    redis_cache=redis_cache,

    assignment_ttl=1800  # 30 minutes

)

# Create cache manager for coordinated operations

cache_manager = CacheManager(

    redis_cache=redis_cache,

    permission_service=permission_service,

    role_service=role_service,

    assignment_service=assignment_service

)

3. Integrate with FastAPI

```python

from fastapi import FastAPI, Depends

from contextlib import asynccontextmanager

@asynccontextmanager

async def lifespan(app: FastAPI):

    # Startup

    await db.connect()

    await redis_cache.initialize()

    await base_role_service.initialize_default_roles()

    # Warm up common caches

    await cache_manager.warm_role_cache("admin")

    await cache_manager.warm_role_cache("user")

    yield

    # Shutdown

    await redis_cache.close()

    await db.disconnect()

app = FastAPI(lifespan=lifespan)

# Use cached services in your app

rbac = RBACDependencies(

    permission_service=permission_service,  # Cached version

    assignment_service=assignment_service,  # Cached version

    secret_key="your-secret-key"

)

Cache Configuration Options

RedisCache Options

Parameter	Default	Description

redis_url	"redis://localhost:6379"	Redis connection URL

prefix	"rbac:"	Key prefix for isolation

default_ttl	3600	Default TTL in seconds

max_connections	10	Maximum connection pool size

socket_timeout	5	Socket timeout in seconds

socket_connect_timeout	5	Connection timeout in seconds

retry_on_timeout	True	Retry on timeout

decode_responses	False	Decode Redis responses

Service-Specific TTLs

Cache Type	Default TTL	Description

User Permissions	3600 (1 hour)	User's permission set

Role Permissions	7200 (2 hours)	Role's permission set

Role Details	7200 (2 hours)	Individual role data

Role Hierarchy	3600 (1 hour)	Role hierarchy tree

User Assignments	1800 (30 min)	User's role assignments

Role Assignments	1800 (30 min)	Users in a role

Cache Invalidation Strategies

Automatic Invalidation

The cache is automatically invalidated when:

```python

# Permission changes invalidate all related caches

await permission_service.update_permission(permission_id)

# Automatically invalidates:

# - All user permissions caches

# - All role permissions caches

# Role changes invalidate role and user caches

await role_service.update_role(role_id)

# Automatically invalidates:

# - Role cache

# - Role hierarchy cache

# - All user permissions caches for users with this role

# Assignment changes invalidate user caches

await assignment_service.assign_role_to_user(user_id, role_id)

# Automatically invalidates:

# - User assignments cache

# - Role assignments cache

# - User permissions cache

Manual Invalidation

```python

# Invalidate specific user

await cache_manager.invalidate_user(

    user_id=user.id,

    tenant_id=tenant.id

)

# Invalidate specific role

await cache_manager.invalidate_role(role_id)

# Invalidate entire tenant

await cache_manager.invalidate_tenant(tenant_id)

# Invalidate all caches (use with caution)

await cache_manager.invalidate_all()

# Pattern-based deletion

await redis_cache.delete_pattern("user_perms:123:*")

Cache Warming

Pre-load frequently accessed data to avoid cold starts:

```python

# Warm up during application startup

@app.on_event("startup")

async def startup():

    # Warm up common roles

    await cache_manager.warm_role_cache("admin")

    await cache_manager.warm_role_cache("user")

    await cache_manager.warm_role_cache("manager")

    # Warm up active users (custom logic)

    active_users = await get_active_users(limit=100)

    for user in active_users:

        await cache_manager.warm_user_cache(user.id)

# On-demand warming

@app.post("/cache/warm/user/{user_id}")

async def warm_user_cache(user_id: str):

    await cache_manager.warm_user_cache(user_id)

    return {"message": f"Cache warmed for user {user_id}"}

Monitoring and Statistics

Cache Statistics

```python

@app.get("/cache/stats")

async def get_cache_stats():

    """Get detailed cache statistics"""

    stats = await cache_manager.get_stats()

    return stats

# Example response:

{

    "status": "connected",

    "used_memory": "1.2M",

    "total_connections": 150,

    "total_commands": 5000,

    "keyspace_hits": 4500,

    "keyspace_misses": 500,

    "hit_rate": 90.0,

    "connected_clients": 5,

    "uptime_days": 2

}

Performance Comparison

```python

@app.get("/performance/compare")

async def compare_performance(user_id: str):

    """Compare cached vs uncached performance"""

    import time

    # Clear cache for this user

    await cache_manager.invalidate_user(user_id)

    # Uncached

    start = time.time()

    uncached_perms = await base_permission_service.get_user_permissions(user_id)

    uncached_time = time.time() - start

    # Cached

    start = time.time()

    cached_perms = await permission_service.get_user_permissions(user_id)

    cached_time = time.time() - start

    return {

        "user_id": user_id,

        "uncached_time_ms": round(uncached_time * 1000, 2),

        "cached_time_ms": round(cached_time * 1000, 2),

        "speedup": f"{round(uncached_time / cached_time, 2)}x",

        "permission_count": len(cached_perms)

    }

Advanced Patterns

Cache-Aside Pattern

```python

async def get_user_with_cache(user_id: str):

    # Try cache first

    cache_key = f"user:{user_id}"

    user = await redis_cache.get(cache_key)

    if user:

        return user

    # Cache miss - get from database

    user = await db.fetch_user(user_id)

    # Store in cache

    await redis_cache.set(cache_key, user, ttl=3600)

    return user

Write-Through Pattern

```python

async def update_user(user_id: str, data: dict):

    # Update database

    user = await db.update_user(user_id, data)

    # Update cache immediately

    cache_key = f"user:{user_id}"

    await redis_cache.set(cache_key, user, ttl=3600)

    # Invalidate related caches

    await cache_manager.invalidate_user(user_id)

    return user

Distributed Locking

```python

async def assign_role_with_lock(user_id: str, role_id: str):

    # Acquire distributed lock

    lock_key = f"lock:assign:{user_id}"

    acquired = await redis_cache.set(lock_key, "locked", ttl=10, nx=True)

    if not acquired:

        raise HTTPException(429, "Operation in progress")

    try:

        # Perform assignment

        result = await assignment_service.assign_role_to_user(user_id, role_id)

        return result

    finally:

        # Release lock

        await redis_cache.delete(lock_key)

Cache Stampede Prevention

```python

async def get_user_permissions_with_stampede_protection(user_id: str):

    cache_key = f"user_perms:{user_id}"

    # Check cache

    permissions = await redis_cache.get(cache_key)

    if permissions:

        return permissions

    # Use mutex to prevent stampede

    mutex_key = f"mutex:{cache_key}"

    if await redis_cache.set(mutex_key, "1", ttl=5, nx=True):

        # Only one process will compute

        permissions = await base_permission_service.get_user_permissions(user_id)

        await redis_cache.set(cache_key, permissions, ttl=3600)

        await redis_cache.delete(mutex_key)

        return permissions

    # Other processes wait and retry

    await asyncio.sleep(0.1)

    return await get_user_permissions_with_stampede_protection(user_id)

Production Considerations

High Availability Setup

```python

# Redis Sentinel for high availability

cache = RedisCache(

    redis_url="redis-sentinel://sentinel1:26379,sentinel2:26379/0",

    sentinel_kwargs={

        "master_name": "mymaster",

        "password": "sentinel_password"

    }

)

# Redis Cluster

cache = RedisCache(

    redis_url="redis://node1:6379,redis://node2:6379,redis://node3:6379/0",

    cluster=True

)

Connection Pool Tuning

```python

# Adjust pool size based on concurrency

cache = RedisCache(

    max_connections=100,  # For high concurrency

    socket_timeout=1,      # Fast failure

    retry_on_timeout=False  # Don't retry on timeout

)

Monitoring with Prometheus

```python

from prometheus_client import Counter, Histogram

cache_hits = Counter('rbac_cache_hits_total', 'Cache hits')

cache_misses = Counter('rbac_cache_misses_total', 'Cache misses')

cache_latency = Histogram('rbac_cache_latency_seconds', 'Cache latency')

async def monitored_get_user_permissions(user_id: str):

    with cache_latency.time():

        permissions = await permission_service.get_user_permissions(user_id)

    if permissions:

        cache_hits.inc()

    else:

        cache_misses.inc()

    return permissions

Backup and Persistence

```python

# Configure Redis persistence in redis.conf or command

cache = RedisCache(

    redis_url="redis://localhost:6379",

    # Redis will use its configured persistence

)

# Or set RDB/AOF options in connection

cache = RedisCache(

    redis_url="redis://localhost:6379/0?save=60,1000"  # Save every 60s if 1000 changes

)

Troubleshooting

Common Issues

Cache not working

```python

# Check Redis connection

await redis_cache.ping()

# Verify cache keys

keys = await redis_cache.keys("rbac:*")

print(f"Cache keys: {keys}")

High memory usage

```python

# Monitor memory

info = await redis_cache.info("memory")

print(f"Used memory: {info['used_memory_human']}")

# Set maxmemory policy

await redis_cache.config_set("maxmemory-policy", "allkeys-lru")

Cache inconsistency

```python

# Force invalidation

await cache_manager.invalidate_all()

# Check invalidation patterns

await redis_cache.delete_pattern("user_perms:*")

Debugging

```python

# Enable debug logging

import logging

logging.getLogger("rbac.cache").setLevel(logging.DEBUG)

# Inspect cache keys

@app.get("/debug/cache/keys")

async def list_cache_keys(pattern: str = "*"):

    keys = await redis_cache.keys(f"rbac:{pattern}")

    return {"keys": keys}

# Get cache value

@app.get("/debug/cache/get/{key}")

async def get_cache_key(key: str):

    value = await redis_cache.get(key)

    return {"key": key, "value": value, "exists": value is not None}

Best Practices

Set appropriate TTLs based on data volatility

Use cache warming for frequently accessed data

Monitor hit rates (aim for >90%)

Implement circuit breakers for Redis failures

Use different Redis databases for different environments

Regularly test cache invalidation logic

Consider cache size and eviction policies

Use connection pooling for high concurrency

Implement graceful degradation when Redis is down

Version your cache keys when data structures change

Performance Benchmarks

```python

# Run performance tests

pytest tests/test_performance.py -v --benchmark-only

# Example results:

# test_user_permissions_cached ................................ passed

# --------------------------------------------------------------------- benchmark: 2 tests --------------------------------------------------------------------

# Name (time in ms)                 Min                 Max                Mean            StdDev              Median                IQR            Outliers

# -------------------------------------------------------------------------------------------------------------------------------------------------------------

# test_user_permissions_cached    1.2345 (1.0)        2.3456 (1.0)        1.5678 (1.0)      0.1234 (1.0)        1.4567 (1.0)       0.2345 (1.0)         140;234

# test_user_permissions_uncached  45.6789 (37.0)      67.8901 (28.9)      52.3456 (33.4)     5.6789 (46.0)      50.1234 (34.4)      6.7890 (29.0)         12;8

# -------------------------------------------------------------------------------------------------------------------------------------------------------------

With Redis caching properly configured, your RBAC system will handle thousands of requests per second with minimal latency!
