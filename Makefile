.PHONY: help install dev install-dev test coverage lint format clean build publish docs serve-docs docker-build docker-up docker-down

help:
	@echo "Available commands:"
	@echo "  install       Install production dependencies"
	@echo "  dev           Install development dependencies"
	@echo "  test          Run tests"
	@echo "  coverage      Run tests with coverage report"
	@echo "  lint          Run linters"
	@echo "  format        Format code"
	@echo "  clean         Clean build artifacts"
	@echo "  build         Build package"
	@echo "  publish       Publish to PyPI"
	@echo "  docs          Build documentation"
	@echo "  serve-docs    Serve documentation locally"
	@echo "  docker-build  Build Docker image"
	@echo "  docker-up     Start Docker services"
	@echo "  docker-down   Stop Docker services"

install:
	uv pip install .

dev: install
	uv pip install -e ".[dev,docs,all]"

test:
	pytest tests/ -v

coverage:
	pytest tests/ --cov=rbac --cov-report=term --cov-report=html

lint:
	ruff check src/ tests/
	black --check src/ tests/
	isort --check src/ tests/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/
	ruff check src/ tests/ --fix

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf site/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	uv build

publish: build
	twine upload dist/*

docs:
	mkdocs build

serve-docs:
	mkdocs serve

docker-build:
	docker build -t fastapi-rbac .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

benchmark:
	pytest tests/test_performance.py -v --benchmark-only

pre-commit: format lint test

release: test build publish
	@echo "Release complete!"