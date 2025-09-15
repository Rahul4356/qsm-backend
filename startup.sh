#!/bin/bash

echo "Starting QMS Backend Setup..."
echo "Python version: $(python --version)"
echo "Working directory: $(pwd)"

# Install dependencies first
echo "Installing Python dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "Dependencies installed successfully"

# Set environment variables
export PYTHONUNBUFFERED=1
export AZURE_ENV=${AZURE_ENV:-production}
export LOG_LEVEL=${LOG_LEVEL:-INFO}
export DB_PATH=${DB_PATH:-/tmp/qms.db}

# Create necessary directories
mkdir -p /tmp/logs
mkdir -p /tmp/uploads

echo "Starting application with gunicorn..."

# Check if running on Azure (simpler detection)
if [ ! -z "$WEBSITE_INSTANCE_ID" ]; then
    echo "Running on Azure App Service"
    # Use Azure's port or default to 8000
    PORT=${WEBSITE_PORT:-8000}
    
    # Start with gunicorn for production
    exec gunicorn \
        --bind=0.0.0.0:$PORT \
        --timeout 600 \
        --workers 1 \
        --worker-class uvicorn.workers.UvicornWorker \
        app:app
else
    echo "Running in development mode"
    PORT=${PORT:-8000}
    
    # Use gunicorn for consistency
    exec gunicorn \
        --bind=0.0.0.0:$PORT \
        --timeout 600 \
        --workers 1 \
        --worker-class uvicorn.workers.UvicornWorker \
        --reload \
        app:app
fi