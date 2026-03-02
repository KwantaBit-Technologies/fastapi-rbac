# Multi-stage build for smaller final image
FROM python:3.11-slim AS builder

# Install uv
RUN pip install uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build wheel
RUN uv build

# Final stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy wheel from builder
COPY --from=builder /app/dist/*.whl .

# Install the package
RUN pip install *.whl

# Copy examples
COPY examples/ ./examples/

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket; socket.socket().connect(('localhost', 8000))" || exit 1

# Run the example app
CMD ["uvicorn", "examples.basic_app:app", "--host", "0.0.0.0", "--port", "8000"]