## Project Structure


fastapi-rbac/
├── rbac/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── database.py
│   │   ├── exceptions.py
│   │   └── constants.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── permission_service.py
│   │   ├── role_service.py
│   │   ├── assignment_service.py
│   │   └── audit_service.py
│   ├── dependencies/
│   │   ├── __init__.py
│   │   └── auth.py
│   ├── decorators/
│   │   ├── __init__.py
│   │   └── rbac.py
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── audit.py
│   └── utils/
│       ├── __init__.py
│       └── helpers.py
├── examples/
│   └── basic_app.py
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   └── test_services.py
├── setup.py
├── requirements.txt
└── README.md