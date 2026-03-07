![GitHub Repo stars](https://img.shields.io/github/stars/kwantabit-Technologies/fastapi-rbac)
![GitHub issues](https://img.shields.io/github/issues/kwantabit-Technologies/fastapi-rbac)
![License](https://img.shields.io/github/license/kwantabit-Technologies/fastapi-rbac)

# FastAPI RBAC Engine

**Production-grade Role-Based Access Control (RBAC) for FastAPI**

FastAPI RBAC Engine is a modular, async-first authorization system designed for **modern FastAPI applications**. It provides scalable permission management, role hierarchies, scoped access control, and multi-tenant support for SaaS and enterprise systems.

Built with ❤️ by Khalid at **Kwantabit Technologies**.

---

# Why FastAPI RBAC Engine?

Most FastAPI RBAC examples online are:

* Too simplistic
* Hardcoded
* Not scalable
* Not production-ready

FastAPI RBAC Engine provides a **complete authorization infrastructure** designed for real applications.

It is built for:

* SaaS platforms
* Enterprise APIs
* Healthcare systems
* Fintech dashboards
* Internal tools
* Open-source projects

---

# Features

| Feature              | Description                                              |
| -------------------- | -------------------------------------------------------- |
| Database-Driven      | Full CRUD for roles, permissions, and assignments        |
| Role Inheritance     | Hierarchical roles with automatic permission inheritance |
| Scoped Permissions   | Object-level access control                              |
| Multi-Tenant         | Support for multiple organizations                       |
| Async-First          | Built for FastAPI async workloads                        |
| Redis Caching        | High-performance permission checks                       |
| Audit Logging        | Full audit trail for compliance                          |
| Route Protection     | Elegant decorators for endpoints                         |
| Identity Integration | LDAP and Keycloak support                                |
| Extensible           | Plug in custom identity providers                        |

---

# Installation

Until the package is published to PyPI, install directly from GitHub.

## Install from GitHub

```bash
pip install git+https://github.com/kwantabit-Technologies/fastapi-rbac.git
```

## Install for Development

```bash
git clone https://github.com/kwantabit-Technologies/fastapi-rbac.git

cd fastapi-rbac

pip install -e .
```

## Install with uv (Recommended for Contributors)

```bash
pip install uv

git clone https://github.com/kwantabit-Technologies/fastapi-rbac.git
cd fastapi-rbac

uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

uv pip install -e ".[dev,all]"
```

## Future PyPI Installation

Once the package is released on PyPI, installation will be as simple as:

```bash
pip install fastapi-rbac
```

## Optional Features

```bash
# PostgreSQL support
pip install "fastapi-rbac[postgres]"

# Redis caching
pip install "fastapi-rbac[redis]"

# Identity providers
pip install "fastapi-rbac[ldap,keycloak]"

# Install everything
pip install "fastapi-rbac[all]"
```

---

# Quick Start

### Minimal Example

```python
from fastapi import FastAPI, Depends
from rbac.dependencies.auth import RBACDependencies, require_permissions

app = FastAPI()

rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key="your-secret-key"
)

@app.get("/protected")
@require_permissions(["resource:read"])
async def protected_route(
    current_user = Depends(rbac.get_current_active_user)
):
    return {"message": f"Hello {current_user.id}"}
```

---

# Full Setup Example

```python
from fastapi import FastAPI, Depends
from rbac import (
    Database,
    PermissionService,
    RoleService,
    AssignmentService,
    RBACDependencies,
    require_permissions
)

app = FastAPI()

# Initialize database
db = Database("postgresql://user:pass@localhost/rbac")
await db.connect()

permission_service = PermissionService(db)
role_service = RoleService(db, permission_service)
assignment_service = AssignmentService(db, role_service, permission_service)

rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key="your-secret-key"
)

await role_service.initialize_default_roles()

@app.get("/patients/{patient_id}")
@require_permissions(["patient:read"], resource_scope_param="patient_id")
async def get_patient(patient_id: str):
    return {"patient_id": patient_id}
```

---

# Architecture Overview

```
Your FastAPI Application
        │
        ▼
RBAC Decorators & Dependencies
        │
        ▼
Permission Service
Role Service
Assignment Service
        │
        ▼
Redis Cache (optional)
        │
        ▼
Database (PostgreSQL / MySQL)
        │
        ▼
Identity Providers
(LDAP / Keycloak / Others)
```

---

# Core Concepts

## Permissions

Permissions follow the format:

```
resource:action:scope
```

Examples:

```
patient:read
patient:update:123
user:delete
*:*   (superuser)
```

Example:

```python
permission = await permission_service.create_permission(
    name="Read Patients",
    resource=ResourceType.PATIENT,
    action=PermissionAction.READ,
    tenant_id=tenant.id
)
```

---

## Roles

Roles group permissions and can inherit from other roles.

Example hierarchy:

```
User
 └── Admin
      └── SuperAdmin
```

Example:

```python
user_role = await role_service.create_role(
    name="User",
    tenant_id=tenant.id
)

admin_role = await role_service.create_role(
    name="Admin",
    parent_ids=[user_role.id],
    tenant_id=tenant.id
)
```

---

## Assignments

Roles are assigned to users.

Assignments can include:

* expiration
* resource scope
* tenant isolation

Example:

```python
await assignment_service.assign_role_to_user(
    user_id=user.id,
    role_id=admin_role.id,
    tenant_id=tenant.id,
    expires_in_days=30
)
```

---

# Performance

With Redis caching enabled:

| Operation            | Without Cache | With Cache |
| -------------------- | ------------- | ---------- |
| Permission Check     | ~50-100ms     | ~1-5ms     |
| Get User Permissions | ~100-200ms    | ~2-10ms    |
| Get Role Hierarchy   | ~50-150ms     | ~1-5ms     |

---

# Testing

Run the test suite:

```bash
pytest tests/ -v --cov=rbac
```

Run benchmarks:

```bash
pytest tests/test_performance.py --benchmark-only
```

---

# Best Practices

* Follow **least privilege principle**
* Use **role hierarchy** to reduce duplication
* Enable **Redis caching** for performance
* Use **audit logging** for security compliance
* Set **expiration for temporary access**
* Use **scoped permissions** for sensitive resources

---

# Use Cases

FastAPI RBAC Engine works well for:

* SaaS platforms
* Healthcare systems
* Fintech dashboards
* Internal enterprise tools
* Developer platforms
* Open-source frameworks

---

# Roadmap

Upcoming features:

* Admin UI for RBAC management
* CLI management tool
* Webhooks for permission events
* Prometheus metrics
* Rate limiting module
* Additional identity providers (Okta, Auth0, Azure AD)

---

# Contributing

Contributions are welcome.

Ways to contribute:

* Fix bugs
* Improve documentation
* Add integrations
* Improve performance
* Expand test coverage

See:

`CONTRIBUTING.md`

---

# Documentation

Full documentation:

[https://fastapi-rbac.readthedocs.io](https://fastapi-rbac.readthedocs.io)

Includes:

* Getting Started
* API Reference
* Multi-tenancy Guide
* Integration Guide
* Deployment Guide

---

# Support

GitHub Issues  
[https://github.com/kwantabit-Technologies/fastapi-rbac/issues](https://github.com/kwantabit-Technologies/fastapi-rbac/issues)

Discussions  
[https://github.com/kwantabit-Technologies/fastapi-rbac/discussions](https://github.com/kwantabit-Technologies/fastapi-rbac/discussions)

---

# License

MIT License

See `LICENSE` file for details.

---

# Community

Twitter  
@kwantabit

GitHub  
[https://github.com/kwantabit-Technologies](https://github.com/kwantabit-Technologies)

Website  
[https://kwantabit.com](https://kwantabit.com)

---

<div align="center">

Built with ❤️ by khalid at **Kwantabit Technologies**

</div>