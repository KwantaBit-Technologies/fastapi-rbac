FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

# Build the distributable wheel.
FROM base AS builder

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN uv build

# Runtime image for the example app.
FROM base AS runtime
COPY --from=builder /app/dist/*.whl .
RUN pip install --no-cache-dir *.whl
COPY src/examples/ ./examples/

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket; socket.socket().connect(('localhost', 8000))" || exit 1

# Run the example app
CMD ["uvicorn", "examples.basic_app:app", "--host", "0.0.0.0", "--port", "8000"]

# Test image with source tree and dev dependencies.
FROM base AS test

COPY pyproject.toml README.md uv.lock ./
RUN pip install --no-cache-dir \
    asyncpg \
    fastapi \
    httpx \
    ldap3 \
    passlib[argon2] \
    pydantic \
    PyJWT \
    pytest \
    pytest-asyncio \
    pytest-benchmark \
    pytest-cov \
    python-dotenv \
    python-jose[cryptography] \
    redis \
    sqlalchemy \
    uvicorn

COPY src/ ./src/

RUN pip install --no-cache-dir --no-deps -e .

CMD ["python", "-m", "pytest", "src/tests", "-v", "--cov=rbac"]
