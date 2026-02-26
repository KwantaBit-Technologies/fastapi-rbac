<div align="center">
  <h1>⚡ FastAPI RBAC Engine</h1>
  <p>
    <strong>Production-grade Role-Based Access Control for FastAPI</strong>
  </p>
  <p>
    <a href="https://pypi.org/project/fastapi-rbac/">
      <img src="https://img.shields.io/pypi/v/fastapi-rbac.svg?style=flat-square&color=indigo" alt="PyPI version">
    </a>
    <a href="https://pypi.org/project/fastapi-rbac/">
      <img src="https://img.shields.io/pypi/pyversions/fastapi-rbac.svg?style=flat-square&color=indigo" alt="Python versions">
    </a>
    <a href="https://github.com/kwantabit/fastapi-rbac/actions">
      <img src="https://img.shields.io/github/actions/workflow/status/kwantabit/fastapi-rbac/test.yml?branch=main&style=flat-square&color=indigo" alt="Tests">
    </a>
    <a href="https://codecov.io/gh/kwantabit/fastapi-rbac">
      <img src="https://img.shields.io/codecov/c/github/kwantabit/fastapi-rbac?style=flat-square&color=indigo" alt="Coverage">
    </a>
    <a href="https://fastapi-rbac.readthedocs.io">
      <img src="https://img.shields.io/readthedocs/fastapi-rbac?style=flat-square&color=indigo" alt="Documentation">
    </a>
    <a href="https://github.com/kwantabit/fastapi-rbac/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/kwantabit/fastapi-rbac?style=flat-square&color=indigo" alt="License">
    </a>
  </p>
</div>

---

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

Minimal Example
python
from fastapi import FastAPI, Depends
from rbac import RBACDependencies, require_permissions

app = FastAPI()

# Initialize RBAC
rbac = RBACDependencies(secret_key="your-secret-key")

@app.get("/protected")
@require_permissions(["resource:read"])
async def protected_route(
    current_user = Depends(rbac.get_current_active_user)
):
    return {"message": f"Hello {current_user.id}"}
Complete Setup
python
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
📊 Performance
With Redis caching enabled:

Operation	Without Cache	With Cache	Improvement
Permission check	50-100ms	1-5ms	10-50x
Get user permissions	100-200ms	2-10ms	10-20x
Get role hierarchy	50-150ms	1-5ms	10-30x
🏗️ Architecture
text
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
📚 Documentation
Full documentation is available at fastapi-rbac.readthedocs.io

Getting Started Guide

API Reference

Caching Guide

Multi-tenancy

Integration Guide

Deployment Guide

🎯 Use Cases
SaaS Applications - Multi-tenant access control

Healthcare Systems - HIPAA-compliant patient data access

Financial Services - Fine-grained permission management

Internal Tools - Employee role management

Open Source Projects - Reusable authorization layer

🧪 Testing
bash
# Clone the repository
git clone https://github.com/kwantabit/fastapi-rbac.git
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
https://api.star-history.com/svg?repos=kwantabit/fastapi-rbac&type=Date

💬 Community
📢 Discord Server

🐦 Twitter

📧 Email

<div align="center"> <sub>Built with ❤️ by <a href="https://kwantabit.com">Kwantabit Technologies</a></sub> </div> ```