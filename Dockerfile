FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    gcc \
    g++ \
    libssl-dev \
    ninja-build \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build and install liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    cd ../.. && \
    rm -rf liboqs

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir cython numpy && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    python setup.py install && \
    cd .. && \
    rm -rf liboqs-python && \
    pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py service_quantum.py ./

# Create database directory
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]