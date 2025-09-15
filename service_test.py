"""
Simple Test Service for Azure Deployment Verification
"""
from fastapi import FastAPI
import os

app = FastAPI(title="Quantum Service - Test", version="1.0.0")

@app.get("/")
def root():
    return {
        "status": "running", 
        "message": "Quantum Crypto Service Test Deployment",
        "port": os.environ.get("PORT", "8000"),
        "environment": os.environ.get("AZURE_ENV", "development")
    }

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "quantum-crypto-test"}

@app.get("/api/test")
def test():
    return {
        "message": "Azure deployment successful!",
        "features": ["FastAPI", "Uvicorn", "Gunicorn"],
        "ready_for": "Full quantum service deployment"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)