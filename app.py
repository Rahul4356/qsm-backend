"""
Complete Backend Service with Authentication, Database, and Session Management
Compatible with Python 3.13 and Azure deployment
"""

import os
import sys
import hashlib
import secrets
import json
import sqlite3
import base64
import logging
from datetime import datetime, timedelta
import uuid
from typing import Dict, Optional, List, Any

from fastapi import FastAPI, HTTPException, status, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, validator
import bcrypt
import jwt

# Configuration
AZURE_ENV = os.environ.get("AZURE_ENV", "development")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
DB_PATH = os.environ.get("DB_PATH", "/tmp/backend.db" if AZURE_ENV == "production" else "backend.db")

# Logging setup
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Backend Service API",
    description="Full-featured backend with authentication, sessions, and database",
    version="1.0.0",
    docs_url="/docs" if AZURE_ENV != "production" else None,
    redoc_url="/redoc" if AZURE_ENV != "production" else None
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Security
security = HTTPBearer()

# Database Class
class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            # Users table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    is_verified BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            ''')
            
            # Sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # User profiles table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id TEXT PRIMARY KEY,
                    bio TEXT,
                    avatar_url TEXT,
                    phone TEXT,
                    address TEXT,
                    metadata TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Activity logs table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    action TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            conn.commit()
    
    def create_user(self, username: str, email: str, password_hash: str, full_name: str = None) -> str:
        """Create a new user"""
        user_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO users (id, username, email, password_hash, full_name, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, email, password_hash, full_name, datetime.utcnow(), datetime.utcnow()))
            
            # Create empty profile
            conn.execute('''
                INSERT INTO user_profiles (user_id, metadata)
                VALUES (?, ?)
            ''', (user_id, json.dumps({})))
            
            conn.commit()
        return user_id
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM users WHERE email = ?
            ''', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM users WHERE id = ?
            ''', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_user(self, user_id: str, **kwargs):
        """Update user information"""
        allowed_fields = ['email', 'full_name', 'is_active', 'is_verified']
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return
        
        updates['updated_at'] = datetime.utcnow()
        
        set_clause = ', '.join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [user_id]
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f'''
                UPDATE users SET {set_clause} WHERE id = ?
            ''', values)
            conn.commit()
    
    def get_user_profile(self, user_id: str) -> Optional[Dict]:
        """Get user profile"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT u.*, p.bio, p.avatar_url, p.phone, p.address, p.metadata
                FROM users u
                LEFT JOIN user_profiles p ON u.id = p.user_id
                WHERE u.id = ?
            ''', (user_id,))
            row = cursor.fetchone()
            if row:
                profile = dict(row)
                profile['metadata'] = json.loads(profile['metadata']) if profile['metadata'] else {}
                del profile['password_hash']  # Don't send password hash
                return profile
            return None
    
    def update_user_profile(self, user_id: str, **kwargs):
        """Update user profile"""
        allowed_fields = ['bio', 'avatar_url', 'phone', 'address']
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if 'metadata' in kwargs:
            updates['metadata'] = json.dumps(kwargs['metadata'])
        
        if not updates:
            return
        
        set_clause = ', '.join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [user_id]
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f'''
                UPDATE user_profiles SET {set_clause} WHERE user_id = ?
            ''', values)
            conn.commit()
    
    def create_session(self, user_id: str, token: str, expires_at: datetime) -> str:
        """Create a session"""
        session_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO sessions (id, user_id, token, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, user_id, token, expires_at, datetime.utcnow()))
            conn.commit()
        return session_id
    
    def get_session_by_token(self, token: str) -> Optional[Dict]:
        """Get session by token"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM sessions WHERE token = ? AND expires_at > ?
            ''', (token, datetime.utcnow()))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def delete_session(self, token: str):
        """Delete a session"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
            conn.commit()
    
    def log_activity(self, user_id: str, action: str, details: str = None, ip_address: str = None, user_agent: str = None):
        """Log user activity"""
        log_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO activity_logs (id, user_id, action, details, ip_address, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (log_id, user_id, action, details, ip_address, user_agent, datetime.utcnow()))
            conn.commit()
    
    def get_user_activities(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get user activity logs"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM activity_logs 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (user_id, limit))
            return [dict(row) for row in cursor.fetchall()]

# Initialize database
db = Database(DB_PATH)

# Pydantic models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    
    @validator('username')
    def username_valid(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric with underscores or hyphens only')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None

class ProfileUpdate(BaseModel):
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict

# Helper functions
def hash_password(password: str) -> str:
    """Hash a password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_jwt_token(user_id: str) -> tuple[str, datetime]:
    """Create a JWT token"""
    expires_at = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        'user_id': user_id,
        'exp': expires_at,
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, expires_at

def verify_jwt_token(token: str) -> Optional[str]:
    """Verify a JWT token and return user_id"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    token = credentials.credentials
    user_id = verify_jwt_token(token)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user['is_active']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user

# API Endpoints
@app.get("/")
def root():
    return {
        "message": "Backend Service API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Backend API",
        "environment": AZURE_ENV,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    """Register a new user"""
    try:
        # Check if username exists
        if db.get_user_by_username(user.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Check if email exists
        if db.get_user_by_email(user.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create user
        password_hash = hash_password(user.password)
        user_id = db.create_user(
            username=user.username,
            email=user.email,
            password_hash=password_hash,
            full_name=user.full_name
        )
        
        # Log activity
        db.log_activity(user_id, "USER_REGISTERED", f"User {user.username} registered")
        
        # Create token
        token, expires_at = create_jwt_token(user_id)
        db.create_session(user_id, token, expires_at)
        
        logger.info(f"User registered: {user.username}")
        
        return TokenResponse(
            access_token=token,
            expires_in=JWT_EXPIRATION_HOURS * 3600,
            user={
                "id": user_id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@app.post("/api/auth/login")
def login(credentials: UserLogin):
    """Login user"""
    try:
        # Get user
        user = db.get_user_by_username(credentials.username)
        if not user:
            # Try email as username
            user = db.get_user_by_email(credentials.username)
        
        if not user or not verify_password(credentials.password, user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if not user['is_active']:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled"
            )
        
        # Create token
        token, expires_at = create_jwt_token(user['id'])
        db.create_session(user['id'], token, expires_at)
        
        # Log activity
        db.log_activity(user['id'], "USER_LOGIN", f"User logged in")
        
        logger.info(f"User logged in: {user['username']}")
        
        return TokenResponse(
            access_token=token,
            expires_in=JWT_EXPIRATION_HOURS * 3600,
            user={
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "full_name": user['full_name']
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@app.post("/api/auth/logout")
def logout(current_user: Dict = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout user"""
    try:
        token = credentials.credentials
        db.delete_session(token)
        db.log_activity(current_user['id'], "USER_LOGOUT", "User logged out")
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@app.get("/api/user/profile")
def get_profile(current_user: Dict = Depends(get_current_user)):
    """Get user profile"""
    profile = db.get_user_profile(current_user['id'])
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found"
        )
    return profile

@app.put("/api/user/profile")
def update_profile(profile: ProfileUpdate, current_user: Dict = Depends(get_current_user)):
    """Update user profile"""
    try:
        db.update_user_profile(
            current_user['id'],
            **profile.dict(exclude_unset=True)
        )
        
        db.log_activity(current_user['id'], "PROFILE_UPDATED", "User updated profile")
        
        return {"message": "Profile updated successfully"}
        
    except Exception as e:
        logger.error(f"Profile update failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Profile update failed"
        )

@app.put("/api/user/update")
def update_user(user_update: UserUpdate, current_user: Dict = Depends(get_current_user)):
    """Update user information"""
    try:
        # Check if email is already taken
        if user_update.email and user_update.email != current_user['email']:
            if db.get_user_by_email(user_update.email):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
        
        db.update_user(
            current_user['id'],
            **user_update.dict(exclude_unset=True)
        )
        
        db.log_activity(current_user['id'], "USER_UPDATED", "User information updated")
        
        return {"message": "User information updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User update failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User update failed"
        )

@app.post("/api/user/change-password")
def change_password(password_change: ChangePassword, current_user: Dict = Depends(get_current_user)):
    """Change user password"""
    try:
        # Verify current password
        if not verify_password(password_change.current_password, current_user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )
        
        # Update password
        new_password_hash = hash_password(password_change.new_password)
        
        with sqlite3.connect(db.db_path) as conn:
            conn.execute('''
                UPDATE users SET password_hash = ?, updated_at = ?
                WHERE id = ?
            ''', (new_password_hash, datetime.utcnow(), current_user['id']))
            conn.commit()
        
        db.log_activity(current_user['id'], "PASSWORD_CHANGED", "User changed password")
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

@app.get("/api/user/activities")
def get_activities(limit: int = 50, current_user: Dict = Depends(get_current_user)):
    """Get user activity logs"""
    activities = db.get_user_activities(current_user['id'], limit)
    return {"activities": activities}

@app.get("/api/admin/users")
def get_all_users(current_user: Dict = Depends(get_current_user)):
    """Get all users (admin only)"""
    # Add admin check here
    with sqlite3.connect(db.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('SELECT id, username, email, full_name, is_active, created_at FROM users')
        users = [dict(row) for row in cursor.fetchall()]
    return {"users": users}

# Backwards compatibility endpoints
@app.post("/api/register")
def register_compat(user: UserRegister):
    """Register endpoint for compatibility"""
    return register(user)

@app.post("/api/login")
def login_compat(credentials: UserLogin):
    """Login endpoint for compatibility"""
    return login(credentials)

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting Backend Service on port {port}")
    logger.info(f"Environment: {AZURE_ENV}")
    logger.info(f"Database path: {DB_PATH}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=LOG_LEVEL.lower()
    )