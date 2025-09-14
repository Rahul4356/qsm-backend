#!/bin/bash
echo "Starting Quantum Crypto Service..."
python -m uvicorn service:app --host 0.0.0.0 --port ${PORT:-8000}