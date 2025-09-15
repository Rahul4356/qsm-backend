from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt
import jwt
from datetime import datetime, timedelta
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "test-secret-key"
users_db = {}

class UserRegister(BaseModel):
    username: str
    email: str
    password: str  # No validation

class UserLogin(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm="HS256")

@app.get("/")
def root():
    return {"message": "QMS Backend"}

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/register")
@app.post("/api/auth/register")
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username exists")
    
    users_db[user.username] = {
        "email": user.email,
        "password": hash_password(user.password)
    }
    
    token = create_token(user.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": user.username, "email": user.email}
    }

@app.post("/api/login")
@app.post("/api/auth/login")
def login(creds: UserLogin):
    if creds.username not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(creds.password, users_db[creds.username]["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(creds.username)
    return {
        "access_token": token,
        "token_type": "bearer"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)