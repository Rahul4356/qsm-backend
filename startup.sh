#!/bin/bash

# Quantum Messaging System - Production Startup Script
# For Azure App Service deployment

echo "Starting Quantum Messaging System..."
echo "Environment: ${AZURE_ENV:-production}"
echo "Python version: $(python --version)"

# Set environment variables
export PYTHONUNBUFFERED=1
export AZURE_ENV=${AZURE_ENV:-production}
export LOG_LEVEL=${LOG_LEVEL:-INFO}
export DB_PATH=${DB_PATH:-/tmp/qms.db}

# Create necessary directories
mkdir -p /tmp/logs
mkdir -p /tmp/uploads

# Database initialization
echo "Initializing database..."
python -c "
import sqlite3
from app import init_database
init_database()
print('Database initialized successfully')
"

# Check if running on Azure
if [ ! -z "$WEBSITE_INSTANCE_ID" ]; then
    echo "Running on Azure App Service"
    echo "Instance ID: $WEBSITE_INSTANCE_ID"
    
    # Use Azure's port
    PORT=${WEBSITE_PORT:-8000}
    
    # Start with gunicorn for production
    echo "Starting Gunicorn with Uvicorn workers..."
    exec gunicorn \
        --bind 0.0.0.0:$PORT \
        --workers 2 \
        --worker-class uvicorn.workers.UvicornWorker \
        --timeout 600 \
        --keep-alive 5 \
        --max-requests 1000 \
        --max-requests-jitter 50 \
        --access-logfile - \
        --error-logfile - \
        --log-level ${LOG_LEVEL,,} \
        app:app
else
    echo "Running in development mode"
    PORT=${PORT:-8000}
    
    # Use uvicorn directly for development
    echo "Starting Uvicorn..."
    exec uvicorn app:app \
        --host 0.0.0.0 \
        --port $PORT \
        --reload \
        --log-level ${LOG_LEVEL,,}
fi