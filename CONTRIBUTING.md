# Contributing to FastAPI RBAC Engine

First off, thank you for considering contributing to FastAPI RBAC Engine! It's people like you that make it such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples (code snippets, error messages)
- Describe the behavior you observed vs what you expected
- Include your Python version, FastAPI version, and database type

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a step-by-step description of the suggested enhancement
- Provide specific examples to demonstrate the steps
- Describe the current behavior and what you'd like to see instead
- Explain why this enhancement would be useful

### Pull Requests

1. Fork the repository and create your branch from `main`
2. Install development dependencies: `uv pip install -e ".[dev,all]"`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Run linters: `make lint`
6. Format code: `make format`
7. Update documentation if needed
8. Commit with a clear message
9. Push to your fork and submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/kwantabit/fastapi-rbac.git
cd fastapi-rbac

# Install uv (recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -e ".[dev,all]"

# Setup pre-commit hooks
pre-commit install

# Start services
docker-compose up -d

# Run tests
pytest tests/ -v --cov=rbac

Project Structure
text
fastapi-rbac/
├── src/
│   └── rbac/           # Main package code
├── tests/              # Test files
├── examples/           # Example applications
├── docs/               # Documentation
└── pyproject.toml      # Project configuration
Style Guides
Python Style
Follow PEP 8

Use type hints for all functions

Write docstrings in Google format

Maximum line length: 100 characters

Git Commit Messages
Use the present tense ("Add feature" not "Added feature")

Use the imperative mood ("Move cursor to..." not "Moves cursor to...")

Limit the first line to 72 characters or less

Reference issues and pull requests liberally after the first line

Documentation Style
Use Google-style docstrings

Include examples in docstrings where appropriate

Update the documentation in docs/ for significant changes

Testing Guidelines
Write tests for all new features

Maintain or improve code coverage

Use pytest fixtures for common setup

Mock external services (LDAP, Keycloak) in tests

python
# Example test
async def test_create_permission(permission_service, test_tenant):
    permission = await permission_service.create_permission(
        name="Test Permission",
        resource=ResourceType.USER,
        action=PermissionAction.READ
    )
    assert permission.id is not None
Release Process
Update version in src/rbac/__init__.py

Update CHANGELOG.md

Create a GitHub release with release notes

GitHub Actions will automatically publish to PyPI

Questions?
Feel free to reach out:

📢 Discord

📧 Email

🐦 Twitter

Thank you for contributing! 🎉