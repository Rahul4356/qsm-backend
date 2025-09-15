from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import sys

print("Starting QMS Backend...", file=sys.stderr)

app = FastAPI(title="QMS Backend", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for testing
users_db = {}

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

@app.get("/")
def root():
    return {"message": "QMS Backend API", "status": "running"}

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "QMS Backend"}

@app.get("/api/config")
def config():
    return {
        "backend_url": os.environ.get("WEBSITE_HOSTNAME", "localhost"),
        "api_version": "1.0.0"
    }

@app.post("/api/auth/register")
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    users_db[user.username] = {
        "email": user.email,
        "password": user.password  # In production, hash this!
    }
    
    return {
        "message": "User registered successfully",
        "user": {"username": user.username, "email": user.email}
    }

@app.post("/api/auth/login")
def login(creds: UserLogin):
    if creds.username not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if users_db[creds.username]["password"] != creds.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {
        "access_token": "dummy-token-for-testing",
        "token_type": "bearer",
        "user": {"username": creds.username}
    }

# Compatibility endpoints for frontend
@app.post("/api/register")
def register_compat(user: UserRegister):
    return register(user)

@app.post("/api/login")
def login_compat(creds: UserLogin):
    return login(creds)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
