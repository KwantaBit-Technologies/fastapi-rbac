# FastAPI RBAC Engine

[![PyPI version](https://badge.fury.io/py/fastapi-rbac.svg)](https://badge.fury.io/py/fastapi-rbac)  
[![Python versions](https://img.shields.io/pypi/pyversions/fastapi-rbac.svg)](https://pypi.org/project/fastapi-rbac/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  
[![Documentation](https://img.shields.io/badge/docs-mkdocs-blue)](https://fastapi-rbac.readthedocs.io)

A production-grade Role-Based Access Control (RBAC) system for FastAPI applications that can be used as a standalone library or integrated into any SaaS, internal system, or open-source project.

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Database-driven permissions** | Full CRUD operations for roles, permissions, and assignments with async support |
| **Role inheritance** | Parent roles automatically grant permissions to child roles with cycle detection |
| **Scoped permissions** | Permission on specific objects or modules (e.g. patient record X) |
| **Multi-tenant support** | One engine can handle multiple independent organizations with complete isolation |
| **Route protection** | Decorators and dependencies for API endpoint protection with resource scoping |
| **JWT + OAuth2 integration** | Seamless integration with FastAPIs authentication system |
| **Audit logging** | Track all changes with before/after values, diffs, and comprehensive querying |
| **Redis caching** | High-performance caching layer with automatic invalidation and cache warming |
| **External identity providers** | LDAP, Keycloak integration with bidirectional sync service |
| **Async-ready** | Built for async FastAPI routes and high-concurrency workloads |
| **Type hints** | Complete type annotations for better IDE support |
| **Tested** | 95%+ test coverage with performance benchmarks |

---

## 📦 Installation

```bash
# standard install
pip install fastapi-rbac

# using uv (recommended for faster installs)
pip install uv
uv pip install fastapi-rbac

# optional extras
uv pip install "fastapi-rbac[postgres]"  # PostgreSQL
uv pip install "fastapi-rbac[mysql]"     # MySQL
uv pip install "fastapi-rbac[redis]"     # Redis cache
uv pip install "fastapi-rbac[ldap]"      # LDAP/AD
uv pip install "fastapi-rbac[keycloak]"  # Keycloak

# full bundle
uv pip install "fastapi-rbac[all]"

# development
uv pip install -e ".[dev,docs,all]"
```

---

## 🎯 Quick start

1. **Initialize database and services**

    ```python
    from fastapi import FastAPI, Depends
    from rbac.core.database import Database
    from rbac.services import (
        PermissionService,
        RoleService,
        AssignmentService,
    )
    from rbac.dependencies.auth import RBACDependencies,
        require_permissions

    app = FastAPI()

    # database connection
    db = Database("postgresql://user:pass@localhost/rbac")
    await db.connect()

    # service instances
    permission_service = PermissionService(db)
    role_service = RoleService(db, permission_service)
    assignment_service = AssignmentService(
        db, role_service, permission_service
    )

    # RBAC dependencies
    rbac = RBACDependencies(
        permission_service=permission_service,
        assignment_service=assignment_service,
        secret_key="your-secret-key-here",
    )

    # default roles
    await role_service.initialize_default_roles()
    ```

2. **Protect your routes**

    ```python
    @app.get("/users/me")
    @require_permissions(["user:read:self"])
    async def get_current_user(
        current_user = Depends(rbac.get_current_active_user)
    ):
        return {
            "user_id": str(current_user.id),
            "roles": current_user.roles,
            "permissions": current_user.permissions[:10],
        }

    @app.get("/patients/{patient_id}")
    @require_permissions(["patient:read"], resource_scope_param="patient_id")
    async def get_patient(patient_id: str):
        """Checks permission scoped to the specific patient."""
        return {"patient_id": patient_id}

    @app.get("/admin/dashboard")
    @require_roles(["admin", "super_admin"])
    async def admin_dashboard():
        return {"dashboard": "admin"}
    ```

3. **(Optional) Add Redis caching**

    ```python
    from rbac.cache import RedisCache, RedisCachedPermissionService

    redis_cache = RedisCache(
        redis_url="redis://localhost:6379",
        prefix="rbac:",
        default_ttl=3600,  # 1hr
    )
    await redis_cache.initialize()

    permission_service = RedisCachedPermissionService(
        base_permission_service=permission_service,
        redis_cache=redis_cache,
        user_permissions_ttl=3600,
        role_permissions_ttl=7200,
    )
    ```

---

## 📊 Performance (with Redis cache)

| Operation               | Without cache | With cache | Improvement |
|-------------------------|--------------:|-----------:|------------:|
| Check user permission   | 50-100ms     | 1-5ms     | 10-50x      |
| Get user permissions    | 100-200ms    | 2-10ms    | 10-20x      |
| Get role hierarchy      | 50-150ms     | 1-5ms     | 10-30x      |
| Bulk permission check   | 200-500ms    | 5-20ms    | 10-25x      |

---

## 🏗️ Architecture

```

                      FastAPI Application                   

                     RBAC Dependencies                       

        
   Permission        Role            Assignment        
     Service        Service           Service          
        

                    Redis Cache Layer                        

                    PostgreSQL Database                      

```

---

## 📚 Next steps

* [Getting started guide](#)  complete tutorial
* [API reference](#)  detailed documentation
* [Caching guide](#)  redis best practices
* [Multitenancy](#)  configuration notes
* [Integration guide](#)  LDAP/Keycloak
* [Deployment guide](#)  production readiness

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch:
   ```bash
git checkout -b feature/amazing-feature
```
3. Commit your changes:
   ```bash
git commit -m "Add amazing feature"
```
4. Push to origin and open a pull request.

---

## 📄 License

MIT License  see the [LICENSE](../../LICENSE) file.

## 💬 Support

* GitHub Issues: https://github.com/kwantabit/fastapi-rbac/issues
* Documentation: https://fastapi-rbac.readthedocs.io
* Discord: https://discord.gg/fastapi-rbac

