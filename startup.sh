#!/bin/bash
echo "Starting Quantum Crypto Service..."
echo "Python version: $(python --version)"
echo "Current directory: $(pwd)"
echo "Files in directory: $(ls -la)"
echo "PORT environment variable: ${PORT:-not_set}"

# Try to start the service
python -m uvicorn service:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info