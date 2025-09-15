from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import jwt
import bcrypt
import os
import json
from datetime import datetime, timedelta, timezone
from tinydb import TinyDB, Query
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Quantum Messaging System", version="1.0.0")

# Security
security = HTTPBearer()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
logger.info(f"Environment check - WEBSITE_SITE_NAME: {os.environ.get('WEBSITE_SITE_NAME')}")
logger.info(f"Environment check - PORT: {os.environ.get('PORT')}")

if os.environ.get("WEBSITE_SITE_NAME"):  # Azure environment
    db_path = "/tmp/qms_db.json"
    logger.info(f"Azure environment detected, using database path: {db_path}")
    try:
        db = TinyDB(db_path)
        logger.info(f"TinyDB initialized successfully at {db_path}")
    except Exception as e:
        logger.error(f"Failed to initialize TinyDB: {e}")
        # Fallback to in-memory database
        db = TinyDB(storage=None)
        logger.info("Using in-memory TinyDB as fallback")
else:
    # Local development
    logger.info("Local development environment detected")
    db = TinyDB('qms_db.json')

users_table = db.table('users')
messages_table = db.table('messages')

# JWT configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    content: str
    recipient_username: Optional[str] = None

class User(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime
    is_active: bool = True

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = verify_jwt_token(credentials.credentials)
    User = Query()
    user = users_table.search(User.username == payload.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user[0]

# Routes
@app.get("/")
async def root():
    return {"message": "Quantum Messaging System API", "status": "running"}

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "connected" if db else "disconnected"
    }

@app.get("/api/config")
async def get_config():
    return {
        "cors_enabled": True,
        "auth_required": True,
        "database_type": "TinyDB",
        "environment": "Azure" if os.environ.get("WEBSITE_SITE_NAME") else "Development"
    }

@app.post("/api/register")
async def register_user(user_data: UserCreate):
    try:
        User = Query()
        
        # Check if user already exists
        existing_user = users_table.search((User.username == user_data.username) | (User.email == user_data.email))
        if existing_user:
            raise HTTPException(status_code=400, detail="Username or email already exists")
        
        # Create new user
        hashed_password = hash_password(user_data.password)
        new_user = {
            "username": user_data.username,
            "email": user_data.email,
            "password": hashed_password,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True
        }
        
        user_id = users_table.insert(new_user)
        
        # Create JWT token
        token = create_jwt_token({"sub": user_data.username})
        
        return {
            "message": "User created successfully",
            "user": {
                "id": user_id,
                "username": user_data.username,
                "email": user_data.email
            },
            "access_token": token,
            "token_type": "bearer"
        }
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/login")
async def login_user(login_data: UserLogin):
    try:
        User = Query()
        user = users_table.search(User.username == login_data.username)
        
        if not user or not verify_password(login_data.password, user[0]["password"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        user_data = user[0]
        token = create_jwt_token({"sub": user_data["username"]})
        
        return {
            "message": "Login successful",
            "user": {
                "username": user_data["username"],
                "email": user_data["email"]
            },
            "access_token": token,
            "token_type": "bearer"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/users/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "created_at": current_user["created_at"],
        "is_active": current_user["is_active"]
    }

@app.post("/api/messages")
async def send_message(message_data: Message, current_user: dict = Depends(get_current_user)):
    try:
        new_message = {
            "content": message_data.content,
            "sender_username": current_user["username"],
            "recipient_username": message_data.recipient_username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_quantum": False  # Basic implementation
        }
        
        message_id = messages_table.insert(new_message)
        
        return {
            "message": "Message sent successfully",
            "message_id": message_id,
            "timestamp": new_message["timestamp"]
        }
    except Exception as e:
        logger.error(f"Send message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@app.get("/api/messages")
async def get_messages(current_user: dict = Depends(get_current_user)):
    try:
        Message = Query()
        user_messages = messages_table.search(
            (Message.sender_username == current_user["username"]) | 
            (Message.recipient_username == current_user["username"])
        )
        
        return {
            "messages": user_messages,
            "total_count": len(user_messages)
        }
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve messages")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting server on port {port}")
    logger.info(f"App title: {app.title}")
    uvicorn.run(app, host="0.0.0.0", port=port)