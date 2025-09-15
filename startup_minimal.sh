#!/bin/bash
echo "Starting Quantum Crypto Service - Minimal Version for debugging..."
echo "Python version: $(python --version)"
echo "Current directory: $(pwd)"
echo "Files in directory: $(ls -la)"
echo "PORT environment variable: ${PORT:-not_set}"

# Try the minimal version first
python -m uvicorn service_minimal:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info