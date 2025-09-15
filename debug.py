"""
Simple debug app to test Azure deployment
"""
import os
from fastapi import FastAPI

app = FastAPI(title="Debug App", version="1.0.0")

@app.get("/")
def root():
    return {"message": "Hello from Azure!", "status": "working"}

@app.get("/debug")
def debug():
    return {
        "python_version": os.sys.version,
        "environment_vars": dict(os.environ),
        "working_directory": os.getcwd(),
        "port": os.environ.get("PORT", "not set")
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)