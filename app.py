"""
QMS Backend - TinyDB Version
Simplified version with TinyDB for Python 3.13 compatibility
"""

import sys
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import uuid
import jwt
import bcrypt
import json
import base64
import httpx
import hashlib
import logging
import traceback

# FastAPI imports
from fastapi import FastAPI, HTTPException, Depends, status, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# TinyDB for Python 3.13 compatibility
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

# Cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

print("All imports successful!", file=sys.stderr)

# ========== CONFIGURATION ==========

# Azure Environment Configuration
IS_PRODUCTION = os.environ.get("WEBSITE_SITE_NAME") is not None

# Use Azure-friendly database path
if IS_PRODUCTION:
    # In Azure, use local storage directory
    DB_PATH = os.environ.get("DB_PATH", "/home/site/wwwroot/qms_database.json")
else:
    # Local development
    DB_PATH = os.environ.get("DB_PATH", "/tmp/qms_database.json")

# Security configuration
SECRET_KEY = os.environ.get("JWT_SECRET", "quantum-secure-default-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("TOKEN_EXPIRE_MINUTES", "1440"))
BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

# ========== DATABASE SETUP ==========

# Initialize TinyDB with error handling
try:
    # Ensure directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = TinyDB(DB_PATH, storage=CachingMiddleware(JSONStorage))
    
    # Define tables
    users_table = db.table('users')
    connection_requests_table = db.table('connection_requests')
    secure_sessions_table = db.table('secure_sessions')
    messages_table = db.table('messages')
    audit_logs_table = db.table('audit_logs')
    
    # Query objects
    UserQuery = Query()
    ConnectionRequestQuery = Query()
    SecureSessionQuery = Query()
    MessageQuery = Query()
    AuditLogQuery = Query()
    
    print(f"TinyDB database initialized successfully at: {DB_PATH}", file=sys.stderr)
    
except Exception as e:
    print(f"Database initialization error: {e}", file=sys.stderr)
    # Fallback to in-memory storage for Azure troubleshooting
    print("Falling back to in-memory database", file=sys.stderr)
    from tinydb.storages import MemoryStorage
    db = TinyDB(storage=MemoryStorage)
    
    users_table = db.table('users')
    connection_requests_table = db.table('connection_requests')
    secure_sessions_table = db.table('secure_sessions')
    messages_table = db.table('messages')
    audit_logs_table = db.table('audit_logs')
    
    UserQuery = Query()
    ConnectionRequestQuery = Query()
    SecureSessionQuery = Query()
    MessageQuery = Query()
    AuditLogQuery = Query()

# ========== DATABASE FUNCTIONS ==========

def get_current_timestamp():
    return datetime.utcnow().isoformat()

def get_user_by_username(username: str):
    result = users_table.search(UserQuery.username == username)
    return result[0] if result else None

def get_user_by_email(email: str):
    result = users_table.search(UserQuery.email == email)
    return result[0] if result else None

def create_user(username: str, email: str, hashed_password: str):
    user_doc = {
        'id': str(uuid.uuid4()),
        'username': username,
        'email': email,
        'hashed_password': hashed_password,
        'created_at': get_current_timestamp(),
        'is_active': True,
        'last_seen': get_current_timestamp(),
        'public_keys': None,
        'key_generation_timestamp': None
    }
    users_table.insert(user_doc)
    return user_doc

def update_user_last_seen(user_id: str):
    users_table.update({'last_seen': get_current_timestamp()}, UserQuery.id == user_id)

# ========== PYDANTIC MODELS ==========

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=100)
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    created_at: str
    is_active: bool
    last_seen: str

# ========== HELPER FUNCTIONS ==========

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    
    token = authorization.split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

def get_current_user(username: str = Depends(verify_token)):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.get('is_active', True):
        raise HTTPException(status_code=403, detail="User account is inactive")
    
    update_user_last_seen(user['id'])
    return user

# ========== FASTAPI APP ==========

app = FastAPI(
    title="QMS Platform API",
    description="Quantum Messaging System with Post-Quantum Cryptography",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if not IS_PRODUCTION else [
        "https://qms-frontend.azurewebsites.net",
        "https://*.azurewebsites.net"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== API ENDPOINTS ==========

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "QMS Platform API",
        "version": "2.0.0",
        "environment": "production" if IS_PRODUCTION else "development",
        "database": "TinyDB",
        "timestamp": get_current_timestamp()
    }

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister, request: Request):
    # Check if username exists
    if get_user_by_username(user.username.lower()):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Check if email exists
    if get_user_by_email(user.email.lower()):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password and create user
    hashed_password = hash_password(user.password)
    
    try:
        db_user = create_user(
            username=user.username.lower(),
            email=user.email.lower(),
            hashed_password=hashed_password
        )
        
        return {
            "message": "User registered successfully",
            "user": {
                "id": db_user['id'],
                "username": db_user['username'],
                "email": db_user['email'],
                "created_at": db_user['created_at']
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/auth/login")
async def login(credentials: UserLogin, request: Request = None):
    user = get_user_by_username(credentials.username.lower())
    
    if not user or not verify_password(credentials.password, user['hashed_password']):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not user.get('is_active', True):
        raise HTTPException(status_code=403, detail="Account is inactive")
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    
    # Update last seen
    update_user_last_seen(user['id'])
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user['id'],
            "username": user['username'],
            "email": user['email']
        }
    }

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user['id'],
        "username": current_user['username'],
        "email": current_user['email'],
        "created_at": current_user['created_at'],
        "last_seen": current_user['last_seen'],
        "is_active": current_user['is_active']
    }

@app.get("/api/users/count")
async def get_user_count():
    """Get total number of registered users"""
    try:
        count = len(users_table.all())
        return {"total_users": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/api/database/info")
async def get_database_info():
    """Get database information and statistics"""
    try:
        users_count = len(users_table.all())
        requests_count = len(connection_requests_table.all())
        sessions_count = len(secure_sessions_table.all())
        messages_count = len(messages_table.all())
        logs_count = len(audit_logs_table.all())
        
        return {
            "database_type": "TinyDB",
            "database_path": DB_PATH,
            "tables": {
                "users": users_count,
                "connection_requests": requests_count,
                "secure_sessions": sessions_count,
                "messages": messages_count,
                "audit_logs": logs_count
            },
            "total_records": users_count + requests_count + sessions_count + messages_count + logs_count,
            "timestamp": get_current_timestamp()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# ========== FRONTEND COMPATIBILITY ENDPOINTS ==========

@app.get("/api/config")
async def get_frontend_config():
    """Configuration endpoint for frontend"""
    return {
        "backend_url": f"https://{os.environ.get('WEBSITE_HOSTNAME', 'localhost:8000')}",
        "api_version": "2.0.0",
        "features": {
            "authentication": True,
            "quantum_crypto": True,
            "user_management": True
        },
        "environment": "production" if IS_PRODUCTION else "development"
    }

@app.post("/api/login")
async def login_compatibility(credentials: UserLogin, request: Request = None):
    """Compatibility endpoint for frontend - redirects to /api/auth/login"""
    return await login(credentials, request)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "QMS Backend API - TinyDB Version",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/api/health",
            "auth": "/api/auth/*",
            "config": "/api/config",
            "docs": "/docs"
        }
    }

# ========== MAIN ==========

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

print("QMS TinyDB App initialized successfully!", file=sys.stderr)