# QSM Backend - Docker Configuration for Both Services

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    lsof \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make scripts executable
RUN chmod +x start_services.sh stop_services.sh diagnose.sh

# Create logs and data directories
RUN mkdir -p logs data

# Set environment variables for Docker deployment
ENV AZURE_ENV=production
ENV DATABASE_URL=sqlite:////app/data/qms_quantum.db
ENV QUANTUM_API_URL=http://localhost:8001
ENV ALLOWED_ORIGINS=*
ENV JWT_SECRET=docker-default-secret-change-in-production
ENV PORT=8000

# Expose both ports
EXPOSE 8000 8001

# Health check that validates both services
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health | grep -q '"status":"healthy"' || exit 1

# For production, we might want to use gunicorn for the main app
# But for development/testing, the startup script is more reliable

# Start both services using the startup script
CMD ["./start_services.sh"]

# Alternative CMD for production with gunicorn (comment out the above line and uncomment below)
# CMD ["sh", "-c", "python3 -m uvicorn service:app --host 0.0.0.0 --port 8001 & gunicorn --bind 0.0.0.0:8000 --workers 2 --worker-class uvicorn.workers.UvicornWorker --timeout 600 app:app"]