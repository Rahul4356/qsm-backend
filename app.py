"""
Full-Featured Production Backend with Complete Authentication System
Azure-ready with SQLite database, JWT auth, sessions, activity logging, and more
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
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import FastAPI, HTTPException, status, Depends, Header, Request, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
import bcrypt
import jwt
import pyotp
import qrcode
from io import BytesIO
import aiofiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configuration
AZURE_ENV = os.environ.get("AZURE_ENV", "production")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
REFRESH_TOKEN_EXPIRATION_DAYS = 30
DB_PATH = os.environ.get("DB_PATH", "/tmp/backend.db" if AZURE_ENV == "production" else "backend.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/uploads" if AZURE_ENV == "production" else "uploads")
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB

# Email configuration
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@qms-backend.com")

# Logging setup
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create upload directory
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# FastAPI app
app = FastAPI(
    title="QMS Backend API",
    description="Full-featured production backend with authentication, sessions, and database",
    version="2.0.0",
    docs_url="/docs" if AZURE_ENV != "production" else None,
    redoc_url="/redoc" if AZURE_ENV != "production" else None
)

# Rate limiting error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count", "X-Page", "X-Per-Page"]
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
            # Users table with all fields
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    phone TEXT,
                    role TEXT DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    is_verified BOOLEAN DEFAULT 0,
                    email_verified BOOLEAN DEFAULT 0,
                    two_factor_enabled BOOLEAN DEFAULT 0,
                    two_factor_secret TEXT,
                    avatar_url TEXT,
                    bio TEXT,
                    last_login TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    password_reset_token TEXT,
                    password_reset_expires TIMESTAMP,
                    email_verification_token TEXT,
                    email_verification_expires TIMESTAMP,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            ''')
            
            # Sessions table with device tracking
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    refresh_token TEXT UNIQUE,
                    device_info TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    last_activity TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            # Activity logs with detailed tracking
            conn.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT,
                    error_message TEXT,
                    created_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            # User preferences
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_preferences (
                    user_id TEXT PRIMARY KEY,
                    theme TEXT DEFAULT 'light',
                    language TEXT DEFAULT 'en',
                    notifications_enabled BOOLEAN DEFAULT 1,
                    email_notifications BOOLEAN DEFAULT 1,
                    sms_notifications BOOLEAN DEFAULT 0,
                    metadata TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            # API keys for external access
            conn.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT,
                    permissions TEXT,
                    last_used TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            # File uploads tracking
            conn.execute('''
                CREATE TABLE IF NOT EXISTS uploads (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    original_filename TEXT,
                    file_size INTEGER,
                    mime_type TEXT,
                    file_path TEXT,
                    is_public BOOLEAN DEFAULT 0,
                    download_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            conn.commit()
    
    def create_user(self, username: str, email: str, password_hash: str, **kwargs) -> str:
        """Create a new user with all fields"""
        user_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO users (
                    id, username, email, password_hash, full_name, phone, role,
                    email_verification_token, email_verification_expires,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, username, email, password_hash,
                kwargs.get('full_name'), kwargs.get('phone'), kwargs.get('role', 'user'),
                kwargs.get('verification_token'), kwargs.get('verification_expires'),
                datetime.utcnow(), datetime.utcnow()
            ))
            
            # Create user preferences
            conn.execute('''
                INSERT INTO user_preferences (user_id, metadata)
                VALUES (?, ?)
            ''', (user_id, json.dumps({})))
            
            conn.commit()
        return user_id
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_user(self, user_id: str, **kwargs):
        """Update user with any fields"""
        if not kwargs:
            return
        
        kwargs['updated_at'] = datetime.utcnow()
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [user_id]
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
            conn.commit()
    
    def create_session(self, user_id: str, token: str, refresh_token: str, 
                      expires_at: datetime, **kwargs) -> str:
        """Create session with device tracking"""
        session_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO sessions (
                    id, user_id, token, refresh_token, device_info, 
                    ip_address, user_agent, last_activity, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id, user_id, token, refresh_token,
                kwargs.get('device_info'), kwargs.get('ip_address'),
                kwargs.get('user_agent'), datetime.utcnow(),
                expires_at, datetime.utcnow()
            ))
            conn.commit()
        return session_id
    
    def get_session_by_token(self, token: str) -> Optional[Dict]:
        """Get valid session by token"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM sessions 
                WHERE token = ? AND expires_at > ?
            ''', (token, datetime.utcnow()))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_session_activity(self, token: str):
        """Update session last activity"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE sessions SET last_activity = ?
                WHERE token = ?
            ''', (datetime.utcnow(), token))
            conn.commit()
    
    def delete_session(self, token: str):
        """Delete session"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
            conn.commit()
    
    def delete_user_sessions(self, user_id: str):
        """Delete all user sessions"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            conn.commit()
    
    def log_activity(self, user_id: Optional[str], action: str, **kwargs):
        """Log activity with details"""
        log_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO activity_logs (
                    id, user_id, action, details, ip_address, 
                    user_agent, status, error_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id, user_id, action, kwargs.get('details'),
                kwargs.get('ip_address'), kwargs.get('user_agent'),
                kwargs.get('status', 'success'), kwargs.get('error_message'),
                datetime.utcnow()
            ))
            conn.commit()
    
    def get_user_activities(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get paginated user activities"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM activity_logs 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
            ''', (user_id, limit, offset))
            return [dict(row) for row in cursor.fetchall()]
    
    def increment_failed_login(self, username: str):
        """Increment failed login attempts"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1,
                    locked_until = CASE 
                        WHEN failed_login_attempts >= 4 
                        THEN datetime('now', '+30 minutes')
                        ELSE locked_until
                    END
                WHERE username = ? OR email = ?
            ''', (username, username))
            conn.commit()
    
    def reset_failed_login(self, user_id: str):
        """Reset failed login attempts"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE users 
                SET failed_login_attempts = 0, locked_until = NULL
                WHERE id = ?
            ''', (user_id,))
            conn.commit()
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                DELETE FROM sessions WHERE expires_at < ?
            ''', (datetime.utcnow(),))
            conn.commit()
    
    def get_users_paginated(self, page: int = 1, per_page: int = 20, 
                           search: Optional[str] = None) -> tuple[List[Dict], int]:
        """Get paginated users with search"""
        offset = (page - 1) * per_page
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            if search:
                cursor = conn.execute('''
                    SELECT COUNT(*) as total FROM users 
                    WHERE username LIKE ? OR email LIKE ? OR full_name LIKE ?
                ''', (f'%{search}%', f'%{search}%', f'%{search}%'))
                total = cursor.fetchone()['total']
                
                cursor = conn.execute('''
                    SELECT id, username, email, full_name, role, is_active, 
                           email_verified, created_at 
                    FROM users 
                    WHERE username LIKE ? OR email LIKE ? OR full_name LIKE ?
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                ''', (f'%{search}%', f'%{search}%', f'%{search}%', per_page, offset))
            else:
                cursor = conn.execute('SELECT COUNT(*) as total FROM users')
                total = cursor.fetchone()['total']
                
                cursor = conn.execute('''
                    SELECT id, username, email, full_name, role, is_active, 
                           email_verified, created_at 
                    FROM users 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                ''', (per_page, offset))
            
            users = [dict(row) for row in cursor.fetchall()]
            return users, total

# Initialize database
db = Database(DB_PATH)

# Email service
class EmailService:
    @staticmethod
    def send_email(to_email: str, subject: str, body: str, is_html: bool = False):
        """Send email"""
        if not SMTP_USER or not SMTP_PASSWORD:
            logger.warning("Email not configured, skipping email send")
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = FROM_EMAIL
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html' if is_html else 'plain'))
            
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email sent to {to_email}")
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
    
    @staticmethod
    def send_verification_email(email: str, token: str):
        """Send verification email"""
        verification_url = f"https://qms-backend.azurewebsites.net/api/auth/verify-email?token={token}"
        body = f"""
        <h2>Verify Your Email</h2>
        <p>Click the link below to verify your email address:</p>
        <a href="{verification_url}">{verification_url}</a>
        <p>This link will expire in 24 hours.</p>
        """
        EmailService.send_email(email, "Verify Your Email", body, is_html=True)
    
    @staticmethod
    def send_password_reset_email(email: str, token: str):
        """Send password reset email"""
        reset_url = f"https://qms-backend.azurewebsites.net/api/auth/reset-password?token={token}"
        body = f"""
        <h2>Reset Your Password</h2>
        <p>Click the link below to reset your password:</p>
        <a href="{reset_url}">{reset_url}</a>
        <p>This link will expire in 1 hour.</p>
        """
        EmailService.send_email(email, "Reset Your Password", body, is_html=True)

# Pydantic models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    phone: Optional[str] = None
    
    @validator('username')
    def username_valid(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must be alphanumeric with underscores or hyphens only')
        return v
    
    @validator('password')
    def password_strong(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserLogin(BaseModel):
    username: str
    password: str
    remember_me: Optional[bool] = False

class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = Field(None, max_length=500)

class Enable2FA(BaseModel):
    password: str

class Verify2FA(BaseModel):
    token: str

class PaginationParams(BaseModel):
    page: int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)
    search: Optional[str] = None

# Helper functions
def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_jwt_token(user_id: str, token_type: str = "access") -> tuple[str, datetime]:
    """Create JWT token"""
    if token_type == "refresh":
        expires_delta = timedelta(days=REFRESH_TOKEN_EXPIRATION_DAYS)
    else:
        expires_delta = timedelta(hours=JWT_EXPIRATION_HOURS)
    
    expires_at = datetime.utcnow() + expires_delta
    payload = {
        'user_id': user_id,
        'type': token_type,
        'exp': expires_at,
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, expires_at

def verify_jwt_token(token: str, token_type: str = "access") -> Optional[str]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get('type') != token_type:
            return None
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_verification_token() -> str:
    """Generate email verification token"""
    return secrets.token_urlsafe(32)

def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0]
    return request.client.host if request.client else "unknown"

# Authentication dependency
async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict:
    """Get current authenticated user"""
    token = credentials.credentials
    user_id = verify_jwt_token(token)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    # Check session
    session = db.get_session_by_token(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found"
        )
    
    # Update session activity
    db.update_session_activity(token)
    
    # Get user
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user['is_active']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    
    # Check if account is locked
    if user['locked_until']:
        locked_until = datetime.fromisoformat(user['locked_until'])
        if locked_until > datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked until {locked_until}"
            )
    
    return user

# Role-based access control
def require_role(required_role: str):
    """Require specific role"""
    async def role_checker(current_user: Dict = Depends(get_current_user)):
        if current_user.get('role') != required_role and current_user.get('role') != 'admin':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_role} role"
            )
        return current_user
    return role_checker

# API Endpoints
@app.get("/")
def root():
    return {
        "message": "QMS Backend API",
        "version": "2.0.0",
        "status": "operational",
        "environment": AZURE_ENV
    }

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "QMS Backend",
        "environment": AZURE_ENV,
        "database": "connected",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def register(
    request: Request,
    user: UserRegister,
    background_tasks: BackgroundTasks
):
    """Register new user with email verification"""
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
        
        # Generate verification token
        verification_token = generate_verification_token()
        verification_expires = datetime.utcnow() + timedelta(hours=24)
        
        # Create user
        password_hash = hash_password(user.password)
        user_id = db.create_user(
            username=user.username,
            email=user.email,
            password_hash=password_hash,
            full_name=user.full_name,
            phone=user.phone,
            verification_token=verification_token,
            verification_expires=verification_expires
        )
        
        # Send verification email
        background_tasks.add_task(
            EmailService.send_verification_email,
            user.email,
            verification_token
        )
        
        # Create tokens
        access_token, access_expires = create_jwt_token(user_id, "access")
        refresh_token, refresh_expires = create_jwt_token(user_id, "refresh")
        
        # Create session
        db.create_session(
            user_id=user_id,
            token=access_token,
            refresh_token=refresh_token,
            expires_at=access_expires,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent")
        )
        
        # Log activity
        db.log_activity(
            user_id=user_id,
            action="USER_REGISTERED",
            details=f"User {user.username} registered",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent")
        )
        
        logger.info(f"User registered: {user.username}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
            "user": {
                "id": user_id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "email_verified": False
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@app.post("/api/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, credentials: UserLogin):
    """Login with 2FA support"""
    try:
        # Get user
        user = db.get_user_by_username(credentials.username)
        if not user:
            user = db.get_user_by_email(credentials.username)
        
        if not user:
            db.increment_failed_login(credentials.username)
            db.log_activity(
                user_id=None,
                action="LOGIN_FAILED",
                details=f"Invalid username: {credentials.username}",
                ip_address=get_client_ip(request),
                status="failed"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check if account is locked
        if user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if locked_until > datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account locked until {locked_until}"
                )
        
        # Verify password
        if not verify_password(credentials.password, user['password_hash']):
            db.increment_failed_login(credentials.username)
            db.log_activity(
                user_id=user['id'],
                action="LOGIN_FAILED",
                details="Invalid password",
                ip_address=get_client_ip(request),
                status="failed"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if not user['is_active']:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled"
            )
        
        # Reset failed login attempts
        db.reset_failed_login(user['id'])
        
        # Check 2FA
        if user['two_factor_enabled']:
            # Return temporary token for 2FA verification
            temp_token = jwt.encode(
                {'user_id': user['id'], 'type': '2fa_pending', 'exp': datetime.utcnow() + timedelta(minutes=5)},
                SECRET_KEY,
                algorithm=JWT_ALGORITHM
            )
            return {
                "requires_2fa": True,
                "temp_token": temp_token
            }
        
        # Create tokens
        access_token, access_expires = create_jwt_token(user['id'], "access")
        refresh_token, refresh_expires = create_jwt_token(user['id'], "refresh")
        
        # Create session
        db.create_session(
            user_id=user['id'],
            token=access_token,
            refresh_token=refresh_token,
            expires_at=access_expires,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent")
        )
        
        # Update last login
        db.update_user(user['id'], last_login=datetime.utcnow())
        
        # Log activity
        db.log_activity(
            user_id=user['id'],
            action="USER_LOGIN",
            details="User logged in",
            ip_address=get_client_ip(request)
        )
        
        logger.info(f"User logged in: {user['username']}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "full_name": user['full_name'],
                "role": user['role'],
                "email_verified": bool(user['email_verified'])
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@app.post("/api/auth/logout")
async def logout(
    request: Request,
    current_user: Dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Logout and invalidate session"""
    try:
        token = credentials.credentials
        db.delete_session(token)
        
        db.log_activity(
            user_id=current_user['id'],
            action="USER_LOGOUT",
            details="User logged out",
            ip_address=get_client_ip(request)
        )
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@app.post("/api/auth/refresh")
async def refresh_token(refresh_token: str):
    """Refresh access token"""
    user_id = verify_jwt_token(refresh_token, "refresh")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user = db.get_user_by_id(user_id)
    if not user or not user['is_active']:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new access token
    access_token, access_expires = create_jwt_token(user_id, "access")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600
    }

@app.post("/api/auth/enable-2fa")
async def enable_2fa(
    password_confirm: Enable2FA,
    current_user: Dict = Depends(get_current_user)
):
    """Enable 2FA for user"""
    # Verify password
    if not verify_password(password_confirm.password, current_user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
    
    # Generate secret
    secret = pyotp.random_base32()
    
    # Update user
    db.update_user(
        current_user['id'],
        two_factor_secret=secret,
        two_factor_enabled=True
    )
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user['email'],
        issuer_name='QMS Backend'
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format='PNG')
    qr_code = base64.b64encode(buf.getvalue()).decode()
    
    return {
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_code}",
        "message": "2FA enabled successfully"
    }

@app.post("/api/auth/verify-2fa")
async def verify_2fa(request: Request, verification: Verify2FA, temp_token: str):
    """Verify 2FA token"""
    # Verify temp token
    try:
        payload = jwt.decode(temp_token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get('type') != '2fa_pending':
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = payload.get('user_id')
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Verify TOTP
    totp = pyotp.TOTP(user['two_factor_secret'])
    if not totp.verify(verification.token, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid 2FA token")
    
    # Create session
    access_token, access_expires = create_jwt_token(user_id, "access")
    refresh_token, refresh_expires = create_jwt_token(user_id, "refresh")
    
    db.create_session(
        user_id=user_id,
        token=access_token,
        refresh_token=refresh_token,
        expires_at=access_expires,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent")
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600
    }

@app.get("/api/user/profile")
async def get_profile(current_user: Dict = Depends(get_current_user)):
    """Get user profile"""
    # Remove sensitive fields
    profile = {k: v for k, v in current_user.items() 
               if k not in ['password_hash', 'two_factor_secret', 
                           'password_reset_token', 'email_verification_token']}
    return profile

@app.put("/api/user/profile")
async def update_profile(
    update: UserUpdate,
    current_user: Dict = Depends(get_current_user)
):
    """Update user profile"""
    try:
        # Check if email is being changed
        if update.email and update.email != current_user['email']:
            if db.get_user_by_email(update.email):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
        
        # Update user
        update_data = update.dict(exclude_unset=True)
        if update_data:
            db.update_user(current_user['id'], **update_data)
        
        db.log_activity(
            user_id=current_user['id'],
            action="PROFILE_UPDATED",
            details="User updated profile"
        )
        
        return {"message": "Profile updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile update failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Profile update failed"
        )

@app.post("/api/user/change-password")
async def change_password(
    password_change: ChangePassword,
    current_user: Dict = Depends(get_current_user)
):
    """Change password"""
    try:
        # Verify current password
        if not verify_password(password_change.current_password, current_user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )
        
        # Update password
        new_password_hash = hash_password(password_change.new_password)
        db.update_user(
            current_user['id'],
            password_hash=new_password_hash
        )
        
        # Invalidate all sessions
        db.delete_user_sessions(current_user['id'])
        
        db.log_activity(
            user_id=current_user['id'],
            action="PASSWORD_CHANGED",
            details="User changed password"
        )
        
        return {"message": "Password changed successfully. Please login again."}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

@app.post("/api/auth/forgot-password")
@limiter.limit("3/hour")
async def forgot_password(
    request: Request,
    forgot: ForgotPassword,
    background_tasks: BackgroundTasks
):
    """Request password reset"""
    user = db.get_user_by_email(forgot.email)
    
    # Don't reveal if email exists
    if user:
        reset_token = generate_verification_token()
        reset_expires = datetime.utcnow() + timedelta(hours=1)
        
        db.update_user(
            user['id'],
            password_reset_token=reset_token,
            password_reset_expires=reset_expires
        )
        
        background_tasks.add_task(
            EmailService.send_password_reset_email,
            forgot.email,
            reset_token
        )
        
        db.log_activity(
            user_id=user['id'],
            action="PASSWORD_RESET_REQUESTED",
            details="Password reset requested",
            ip_address=get_client_ip(request)
        )
    
    return {"message": "If the email exists, a reset link has been sent"}

@app.post("/api/auth/reset-password")
async def reset_password(reset: ResetPassword):
    """Reset password with token"""
    with sqlite3.connect(db.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM users 
            WHERE password_reset_token = ? 
            AND password_reset_expires > ?
        ''', (reset.token, datetime.utcnow()))
        user = cursor.fetchone()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    # Update password
    new_password_hash = hash_password(reset.new_password)
    db.update_user(
        user['id'],
        password_hash=new_password_hash,
        password_reset_token=None,
        password_reset_expires=None
    )
    
    # Invalidate all sessions
    db.delete_user_sessions(user['id'])
    
    db.log_activity(
        user_id=user['id'],
        action="PASSWORD_RESET",
        details="Password reset completed"
    )
    
    return {"message": "Password reset successfully"}

@app.get("/api/user/activities")
async def get_activities(
    page: int = 1,
    per_page: int = 50,
    current_user: Dict = Depends(get_current_user)
):
    """Get user activity logs"""
    offset = (page - 1) * per_page
    activities = db.get_user_activities(current_user['id'], per_page, offset)
    return {
        "activities": activities,
        "page": page,
        "per_page": per_page
    }

@app.get("/api/user/sessions")
async def get_sessions(current_user: Dict = Depends(get_current_user)):
    """Get active sessions"""
    with sqlite3.connect(db.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT id, device_info, ip_address, user_agent, 
                   last_activity, created_at
            FROM sessions 
            WHERE user_id = ? AND expires_at > ?
            ORDER BY last_activity DESC
        ''', (current_user['id'], datetime.utcnow()))
        sessions = [dict(row) for row in cursor.fetchall()]
    
    return {"sessions": sessions}

@app.delete("/api/user/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Revoke a specific session"""
    with sqlite3.connect(db.db_path) as conn:
        conn.execute('''
            DELETE FROM sessions 
            WHERE id = ? AND user_id = ?
        ''', (session_id, current_user['id']))
        conn.commit()
    
    return {"message": "Session revoked"}

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: Dict = Depends(get_current_user)
):
    """Upload file"""
    # Check file size
    if file.size > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Max size is {MAX_UPLOAD_SIZE} bytes"
        )
    
    # Generate unique filename
    file_id = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1]
    saved_filename = f"{file_id}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, saved_filename)
    
    # Save file
    async with aiofiles.open(file_path, 'wb') as f:
        content = await file.read()
        await f.write(content)
    
    # Save to database
    with sqlite3.connect(db.db_path) as conn:
        conn.execute('''
            INSERT INTO uploads (
                id, user_id, filename, original_filename, 
                file_size, mime_type, file_path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_id, current_user['id'], saved_filename,
            file.filename, file.size, file.content_type,
            file_path, datetime.utcnow()
        ))
        conn.commit()
    
    return {
        "file_id": file_id,
        "filename": file.filename,
        "size": file.size,
        "url": f"/api/files/{file_id}"
    }

# Admin endpoints
@app.get("/api/admin/users")
async def get_users(
    pagination: PaginationParams = Depends(),
    admin: Dict = Depends(require_role("admin"))
):
    """Get all users (admin only)"""
    users, total = db.get_users_paginated(
        page=pagination.page,
        per_page=pagination.per_page,
        search=pagination.search
    )
    
    return {
        "users": users,
        "total": total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total_pages": (total + pagination.per_page - 1) // pagination.per_page
    }

@app.put("/api/admin/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    is_active: bool,
    admin: Dict = Depends(require_role("admin"))
):
    """Enable/disable user account (admin only)"""
    db.update_user(user_id, is_active=is_active)
    
    action = "USER_ENABLED" if is_active else "USER_DISABLED"
    db.log_activity(
        user_id=admin['id'],
        action=action,
        details=f"Admin {admin['username']} {action.lower()} user {user_id}"
    )
    
    return {"message": f"User {'enabled' if is_active else 'disabled'}"}

@app.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: Dict = Depends(require_role("admin"))
):
    """Delete user (admin only)"""
    with sqlite3.connect(db.db_path) as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    
    db.log_activity(
        user_id=admin['id'],
        action="USER_DELETED",
        details=f"Admin {admin['username']} deleted user {user_id}"
    )
    
    return {"message": "User deleted"}

# Backwards compatibility
@app.post("/api/register")
async def register_compat(request: Request, user: UserRegister, background_tasks: BackgroundTasks):
    return await register(request, user, background_tasks)

@app.post("/api/login")
async def login_compat(request: Request, credentials: UserLogin):
    return await login(request, credentials)

# Cleanup task
@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info("Starting QMS Backend")
    # Clean expired sessions
    db.cleanup_expired_sessions()

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting QMS Backend on port {port}")
    logger.info(f"Environment: {AZURE_ENV}")
    logger.info(f"Database path: {DB_PATH}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=LOG_LEVEL.lower()
    )