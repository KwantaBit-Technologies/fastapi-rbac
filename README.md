# FastAPI Enterprise RBAC Engine

A production-grade Role-Based Access Control (RBAC) system for FastAPI applications that can be used as a standalone library or integrated into any SaaS, internal system, or open-source project.

## Features

- **Database-driven roles and permissions** - Full CRUD operations for roles, permissions, and assignments
- **Role inheritance** - Parent roles automatically grant permissions to child roles
- **Scoped permissions** - Permission on specific objects or modules (e.g., patient record X)
- **Multi-tenant support** - One engine can handle multiple independent organizations
- **Route protection** - Decorators and dependencies for API endpoint protection
- **JWT + OAuth2 integration** - Seamless integration with FastAPI's auth system
- **Audit logging** - Track all changes in roles, permissions, and assignments
- **Async-ready** - Works with async FastAPI routes for high-performance apps
- **Integration hooks** - Support for external identity providers (LDAP, Keycloak)

## Installation

```bash
pip install fastapi-rbac
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🗃️ **Database-driven** | Full CRUD for roles, permissions, and assignments with async support |
| 🔄 **Role inheritance** | Create hierarchical roles with automatic permission inheritance |
| 🎯 **Scoped permissions** | Object-level permissions (e.g., access to specific patient records) |
| 🏢 **Multi-tenant** | Built-in support for multiple organizations with data isolation |
| 🛡️ **Route protection** | Elegant decorators and dependencies for FastAPI endpoints |
| 🔐 **JWT + OAuth2** | Seamless integration with FastAPI's authentication system |
| 📝 **Audit logging** | Comprehensive audit trail with before/after value tracking |
| 🚀 **Redis caching** | High-performance caching with automatic invalidation |
| 🔌 **Identity providers** | LDAP and Keycloak integration out-of-the-box |
| ⚡ **Async-first** | Built for high-concurrency workloads |


## 🚀 Quick Start

### Installation

```bash
# Basic installation
pip install fastapi-rbac

# With PostgreSQL support
pip install "fastapi-rbac[postgres]"

# With Redis caching
pip install "fastapi-rbac[redis]"

# With identity providers
pip install "fastapi-rbac[ldap,keycloak]"

# Install everything
pip install "fastapi-rbac[all]"
```

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

### Complete Setup

```python
from fastapi import FastAPI, Depends
from rbac import (
    Database, PermissionService, RoleService, 
    AssignmentService, RBACDependencies, require_permissions
)

app = FastAPI()

# Initialize database
db = Database("postgresql://user:pass@localhost/rbac")
await db.connect()

# Create services
permission_service = PermissionService(db)
role_service = RoleService(db, permission_service)
assignment_service = AssignmentService(db, role_service, permission_service)

# Setup RBAC
rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key="your-secret-key"
)

# Initialize default roles (Super Admin, Admin, User)
await role_service.initialize_default_roles()

@app.get("/users/me")
@require_permissions(["user:read:self"])
async def get_current_user(
    current_user = Depends(rbac.get_current_active_user)
):
    return {"user_id": str(current_user.id)}

@app.get("/patients/{patient_id}")
@require_permissions(["patient:read"], resource_scope_param="patient_id")
async def get_patient(patient_id: str):
    return {"patient_id": patient_id}
```

## 📊 Performance

With Redis caching enabled:

| Operation | Without Cache | With Cache | Improvement |
|-----------|---------------|-----------|-------------|
| Permission check | 50-100ms | 1-5ms | 10-50x |
| Get user permissions | 100-200ms | 2-10ms | 10-20x |
| Get role hierarchy | 50-150ms | 1-5ms | 10-30x |

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────┐
│                    Your FastAPI App                  │
├─────────────────────────────────────────────────────┤
│                    RBAC Decorators                    │
├─────────────────────────────────────────────────────┤
│   Permission   │     Role      │    Assignment       │
│    Service     │    Service    │     Service         │
├─────────────────────────────────────────────────────┤
│         Redis Cache (Optional)                       │
├─────────────────────────────────────────────────────┤
│         Database (PostgreSQL/MySQL)                  │
├─────────────────────────────────────────────────────┤
│    LDAP        │   Keycloak    │   Other IdPs        │
└─────────────────────────────────────────────────────┘
```

## Core Concepts

### Permissions

Permissions follow the format `resource:action:scope`:

- `resource:read` - Read access to all resources of type
- `resource:write:123` - Write access to specific resource ID 123
- `*:*` - Superuser access (all resources, all actions)

```python
# Create a permission
permission = await permission_service.create_permission(
    name="Read Patients",
    resource=ResourceType.PATIENT,
    action=PermissionAction.READ,
    tenant_id=tenant.id
)
```

### Roles

Roles can inherit from other roles, creating a hierarchy:

```python
# Create base role
user_role = await role_service.create_role(
    name="User",
    tenant_id=tenant.id
)

# Create admin role that inherits from user
admin_role = await role_service.create_role(
    name="Admin",
    parent_ids=[user_role.id],
    tenant_id=tenant.id
)
```

### Assignments

Assign roles to users with optional scopes and expiration:

```python
# Assign role with expiration
assignment = await assignment_service.assign_role_to_user(
    user_id=user.id,
    role_id=admin_role.id,
    tenant_id=tenant.id,
    expires_in_days=30,
    resource_scope={"department": "cardiology"}
)
```

## API Reference

### Permission Service

| Method | Description |
|--------|-------------|
| create_permission() | Create a new permission |
| get_permission() | Get permission by ID |
| get_permission_by_string() | Get permission by string representation |
| update_permission() | Update permission details |
| delete_permission() | Delete a permission |
| list_permissions() | List permissions with filters |
| check_user_permission() | Check if user has specific permission |
| get_user_permissions() | Get all permissions for a user |
| grant_permission_to_role() | Grant permission to a role |
| revoke_permission_from_role() | Revoke permission from a role |

### Role Service

| Method | Description |
|--------|-------------|
| create_role() | Create a new role |
| get_role() | Get role by ID |
| get_role_by_name() | Get role by name |
| update_role() | Update role details |
| delete_role() | Delete a role |
| list_roles() | List roles with filters |
| get_role_hierarchy() | Get complete role hierarchy |
| add_role_parent() | Add parent to role |
| remove_role_parent() | Remove parent from role |
| get_role_permissions() | Get all permissions for a role |
| get_roles_for_user() | Get all roles for a user |
| get_users_in_role() | Get all users in a role |

### Assignment Service

| Method | Description |
|--------|-------------|
| assign_role_to_user() | Assign role to user |
| revoke_role_from_user() | Revoke role from user |
| get_user_assignments() | Get all assignments for a user |
| get_role_assignments() | Get all assignments for a role |
| update_assignment_scope() | Update assignment scope |
| extend_assignment() | Extend assignment expiration |
| bulk_assign_roles() | Bulk assign roles to users |
| transfer_assignments() | Transfer assignments between roles |
| get_expiring_assignments() | Get expiring assignments |
| get_user_effective_roles() | Get effective roles with inheritance |

### Audit Service

| Method | Description |
|--------|-------------|
| log() | Log an audit event |
| log_action() | Log a simple action |
| log_access() | Log access attempts |
| log_auth() | Log authentication events |
| log_change() | Log changes with diff |
| query_logs() | Query audit logs |
| get_resource_history() | Get history for a resource |
| get_user_trail() | Get audit trail for a user |
| export_logs() | Export logs for compliance |

## Advanced Usage

### Multi-Tenancy

```python
# Create tenant
tenant = Tenant(name="Acme Corp", domain="acme.com")
await db.execute("INSERT INTO tenants ...")

# All operations are tenant-aware
permissions = await permission_service.list_permissions(tenant_id=tenant.id)
```

### Role Hierarchy

```python
# Create hierarchy
ceo = await role_service.create_role(name="CEO", tenant_id=tenant.id)
vp = await role_service.create_role(name="VP", parent_ids=[ceo.id], tenant_id=tenant.id)
manager = await role_service.create_role(name="Manager", parent_ids=[vp.id], tenant_id=tenant.id)

# Manager inherits all permissions from VP and CEO
manager_perms = await role_service.get_role_permissions(manager.id, include_inherited=True)
```

### Scoped Permissions

```python
# Assign role with scope
await assignment_service.assign_role_to_user(
    user_id=doctor.id,
    role_id=doctor_role.id,
    tenant_id=tenant.id,
    resource_scope={"patient_id": "123"}
)

# Check scoped access
has_access = await permission_service.check_user_permission(
    user_id=doctor.id,
    required_permission="patient:read",
    resource_scope={"id": "123"}  # This will match
)
```

### Audit Trail

```python
# Query audit logs
logs = await audit_service.query_logs(
    user_id=user.id,
    action=AuditAction.UPDATE,
    start_date=datetime.utcnow() - timedelta(days=7),
    limit=100
)

# Get resource history
history = await audit_service.get_resource_history(
    resource_type=AuditResourceType.ROLE,
    resource_id=role.id
)
```

### External Identity Provider Integration

```python
from rbac.integration import LDAPProvider, LDAPConfig, IdentitySyncService

# Configure LDAP
ldap_config = LDAPConfig(
    server_uri="ldap://localhost:389",
    base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="password"
)

# Create provider
ldap_provider = LDAPProvider(ldap_config)

# Create sync service
sync_service = IdentitySyncService(
    provider=ldap_provider,
    role_service=role_service,
    assignment_service=assignment_service,
    role_mapping={
        "admin": "Administrator",
        "user": "Regular User"
    }
)

# Sync users
await sync_service.sync_now()
```

## Testing

Run the test suite:

```bash
pytest tests/ -v --cov=rbac

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=rbac --cov-report=html

# Run specific test file
pytest tests/test_permission_service.py -v

# Run specific test
pytest tests/test_permission_service.py::TestPermissionService::test_create_permission -v

# Run performance tests
pytest tests/test_performance.py -v --benchmark-only
```

## Configuration

### Database

```python
db = Database(
    dsn="postgresql://user:pass@localhost/rbac",
    min_size=10,  # Min connection pool size
    max_size=20   # Max connection pool size
)
```

### JWT

```python
rbac = RBACDependencies(
    secret_key="your-secret-key",
    algorithm="HS256"  # or "RS256" for asymmetric keys
)
```

### Audit

```python
audit_service = AuditService(
    db=db,
    retention_days=90,  # Keep logs for 90 days
    batch_size=100      # Batch size for bulk operations
)
```

## Best Practices

- Use the principle of least privilege - Grant only necessary permissions
- Leverage role hierarchy - Reduce duplication through inheritance
- Implement audit logging - Track all security-relevant changes
- Use scoped permissions - Limit access to specific resources
- Set expiration for temporary access - Auto-revoke temporary roles
- Cache permissions - Use the built-in caching for performance
- Regular cleanup - Run cleanup_expired_assignments() periodically

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 💬 Support

- [GitHub Issues](https://github.com/KwantaBit-Technologies/fastapi-rbac/issues)
- [Documentation](https://fastapi-rbac.readthedocs.io)
- [Discord](https://discord.gg/fastapi-rbac)

## 📚 Documentation

Full documentation is available at [fastapi-rbac.readthedocs.io](https://fastapi-rbac.readthedocs.io)

- [Getting Started Guide](https://fastapi-rbac.readthedocs.io/en/latest/getting-started/)
- [API Reference](https://fastapi-rbac.readthedocs.io/en/latest/api/)
- [Caching Guide](https://fastapi-rbac.readthedocs.io/en/latest/caching/)
- [Multi-tenancy](https://fastapi-rbac.readthedocs.io/en/latest/multi-tenancy/)
- [Integration Guide](https://fastapi-rbac.readthedocs.io/en/latest/integration/)
- [Deployment Guide](https://fastapi-rbac.readthedocs.io/en/latest/deployment/)

## 🎯 Use Cases

- **SaaS Applications** - Multi-tenant access control
- **Healthcare Systems** - HIPAA-compliant patient data access
- **Financial Services** - Fine-grained permission management
- **Internal Tools** - Employee role management
- **Open Source Projects** - Reusable authorization layer

🧪 Testing
bash
# Clone the repository
git clone https://github.com/KwantaBit-Technologies/fastapi-rbac.git
cd fastapi-rbac

# Install with uv (recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv
source .venv/bin/activate
uv pip install -e ".[dev,all]"

# Run tests
pytest tests/ -v --cov=rbac

# Run performance benchmarks
pytest tests/test_performance.py -v --benchmark-only
🤝 Contributing
We welcome contributions! Please see our Contributing Guide.

🐛 Report a bug

💡 Request a feature

🔧 Submit a PR

📈 Roadmap
Core RBAC functionality

Role inheritance

Multi-tenancy

Audit logging

Redis caching

LDAP/Keycloak integration

Admin UI (Q2 2026)

Rate limiting (Q2 2026)

Webhooks (Q3 2026)

GraphQL support (Q3 2026)

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

⭐ Star History
https://api.star-history.com/svg?repos=KwantaBit-Technologies/fastapi-rbac&type=Date

💬 Community
📢 Discord Server

🐦 Twitter

📧 Email

<div align="center"> <sub>Built with ❤️ by Khalid at <a href="https://kwantabit.com">Kwantabit Technologies</a></sub> </div> ```