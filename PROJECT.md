fastapi-rbac/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── .python-version
├── uv.lock
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── mkdocs.yml
├── .github/
│   └── workflows/
│       ├── test.yml
│       ├── publish.yml
│       └── docs.yml
├── src/
│   └── rbac/
│       ├── __init__.py
│       ├── py.typed
│       ├── core/
│       │   ├── __init__.py
│       │   ├── constants.py
│       │   ├── database.py
│       │   ├── exceptions.py
│       │   └── models.py
│       ├── services/
│       │   ├── __init__.py
│       │   ├── permission_service.py
│       │   ├── role_service.py
│       │   ├── assignment_service.py
│       │   └── audit_service.py
│       ├── cache/
│       │   ├── __init__.py
│       │   └── redis_client.py
│       ├── dependencies/
│       │   ├── __init__.py
│       │   └── auth.py
│       ├── decorators/
│       │   ├── __init__.py
│       │   └── rbac.py
│       ├── middleware/
│       │   ├── __init__.py
│       │   └── audit.py
│       ├── integration/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── ldap_provider.py
│       │   ├── keycloak_provider.py
│       │   └── sync_service.py
│       └── utils/
│           ├── __init__.py
│           └── helpers.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_permission_service.py
│   ├── test_role_service.py
│   ├── test_assignment_service.py
│   ├── test_audit_service.py
│   ├── test_integration.py
│   ├── test_redis_cache.py
│   └── test_performance.py
├── examples/
│   ├── __init__.py
│   ├── basic_app.py
│   ├── redis_example.py
│   └── integration_example.py
└── docs/
    ├── index.md
    ├── getting-started.md
    ├── api-reference.md
    ├── caching.md
    ├── multi-tenancy.md
    ├── integration.md
    └── deployment.md