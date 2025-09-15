# Multi-stage build for production quantum cryptography
FROM python:3.11-slim-bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gcc \
    g++ \
    libssl-dev \
    git \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs from source
WORKDIR /opt
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/liboqs-install \
          -DBUILD_SHARED_LIBS=ON \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_USE_OPENSSL=ON .. && \
    ninja && \
    ninja install

# Build liboqs-python
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    pip install --no-cache-dir cython setuptools wheel && \
    python setup.py build_ext --inplace \
           --liboqs-install-dir=/opt/liboqs-install && \
    pip install .

# Final stage
FROM python:3.11-slim-bookworm

# Copy liboqs from builder
COPY --from=builder /opt/liboqs-install /opt/liboqs-install
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Set library path
ENV LD_LIBRARY_PATH=/opt/liboqs-install/lib:$LD_LIBRARY_PATH

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py service_quantum.py ./

# Create non-root user
RUN useradd -m -u 1000 qmsuser && chown -R qmsuser:qmsuser /app
USER qmsuser

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/health')" || exit 1

# Run with production server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-class", "uvicorn.workers.UvicornWorker", "--timeout", "120", "app:app"]