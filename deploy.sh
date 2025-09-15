#!/bin/bash
# This runs during Azure deployment

# Install from pre-built wheel
pip install liboqs-python-*.whl

# Install other requirements
pip install -r requirements.txt

# Start the app
gunicorn --bind=0.0.0.0:8000 --workers=1 --worker-class uvicorn.workers.UvicornWorker app:app