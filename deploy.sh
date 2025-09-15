#!/bin/bash

# Simple Azure deployment script
echo "Azure Deployment: Installing dependencies and starting QMS"

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Start the application
gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers 1 --worker-class uvicorn.workers.UvicornWorker app:app