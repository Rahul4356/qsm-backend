"""
Minimal Quantum Crypto Service for Azure Deployment Testing
"""

import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Simple configuration
AZURE_ENV = os.environ.get("AZURE_ENV", "production")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Configure simple logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Quantum Crypto Service - Minimal",
    description="Minimal version for Azure deployment testing",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/")
def root():
    return {
        "message": "Quantum Crypto Service - Minimal Version",
        "status": "operational",
        "environment": AZURE_ENV
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Quantum Crypto Service",
        "environment": AZURE_ENV
    }

@app.get("/api/quantum/info")
def get_quantum_service_info():
    return {
        "status": "operational",
        "mode": "QUANTUM-RESISTANT SIMULATION",
        "environment": AZURE_ENV,
        "algorithms": {
            "kem": "ML-KEM-768",
            "sig": "Falcon-512",
            "wrapper": "ECDSA-P256"
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting Quantum Crypto Service on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")