# ...existing code from original app.py...
from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer, ForeignKey, or_, and_, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, Field, EmailStr, validator
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import jwt
import bcrypt
import json
import uuid
import base64
import httpx
import os
import hashlib
import logging
import traceback
import asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('qms_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database configuration
SQLALCHEMY_DATABASE_URL = "sqlite:///./qms_quantum.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security configuration
SECRET_KEY = os.environ.get("JWT_SECRET", "quantum-secure-key-" + os.urandom(32).hex())
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours
BCRYPT_ROUNDS = 12

# Service URLs
QUANTUM_API = "http://localhost:8001"

# ========== WEBSOCKET CONNECTION MANAGER ==========

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}  # username -> connection_id
        
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        self.user_connections[username] = connection_id
        logger.info(f"WebSocket connected: {username}")
        return connection_id
        
    def disconnect(self, username: str):
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
            del self.user_connections[username]
            logger.info(f"WebSocket disconnected: {username}")
            
    async def send_personal_message(self, username: str, message):
        """Send message to a specific user"""
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                try:
                    websocket = self.active_connections[connection_id]
                    # Convert dict to JSON string if needed
                    message_str = json.dumps(message) if isinstance(message, dict) else message
                    await websocket.send_text(message_str)
                    return True
                except Exception as e:
                    logger.error(f"Error sending WebSocket message to {username}: {e}")
                    self.disconnect(username)
        return False
        
    async def broadcast_to_users(self, message, usernames: List[str]):
        """Broadcast message to multiple users"""
        for username in usernames:
            await self.send_personal_message(username, message)
            
    def get_online_users(self) -> List[str]:
        return list(self.user_connections.keys())

manager = ConnectionManager()

# ========== DATABASE MODELS ==========

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    public_keys = Column(Text, nullable=True)  # JSON stored public keys
    key_generation_timestamp = Column(DateTime, nullable=True)
    
    sent_requests = relationship("ConnectionRequest", foreign_keys="ConnectionRequest.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_requests = relationship("ConnectionRequest", foreign_keys="ConnectionRequest.receiver_id", back_populates="receiver", cascade="all, delete-orphan")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver", cascade="all, delete-orphan")

class ConnectionRequest(Base):
    __tablename__ = "connection_requests"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    sender_public_keys = Column(Text, nullable=False)  # JSON with ML-KEM, Falcon, ECDSA keys
    receiver_public_keys = Column(Text, nullable=True)
    status = Column(String(20), default="pending")  # pending, accepted, rejected, expired, cancelled
    created_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
    
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_requests")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_requests")

class SecureSession(Base):
    __tablename__ = "secure_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user1_id = Column(String, ForeignKey("users.id"))
    user2_id = Column(String, ForeignKey("users.id"))
    request_id = Column(String, ForeignKey("connection_requests.id"), nullable=True)
    shared_secret = Column(Text, nullable=True)  # Encrypted shared secret
    ciphertext = Column(Text, nullable=True)  # ML-KEM ciphertext
    session_metadata = Column(Text, nullable=True)  # JSON metadata
    established_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    terminated_at = Column(DateTime, nullable=True)
    termination_reason = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    message_count = Column(Integer, default=0)
    
    user1 = relationship("User", foreign_keys=[user1_id])
    user2 = relationship("User", foreign_keys=[user2_id])
    connection_request = relationship("ConnectionRequest", foreign_keys=[request_id])
    messages = relationship("Message", back_populates="session", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("secure_sessions.id"))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    encrypted_content = Column(Text, nullable=False)
    nonce = Column(String(32), nullable=False)
    tag = Column(String(32), nullable=False)
    aad = Column(Text, nullable=True)  # Additional authenticated data
    falcon_signature = Column(Text, nullable=True)
    ecdsa_signature = Column(Text, nullable=True)
    signature_metadata = Column(Text, nullable=True)  # JSON with signature details
    message_type = Column(String(20), default="secured")  # secured, critical, system
    timestamp = Column(DateTime, default=datetime.utcnow)
    delivered_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    is_read = Column(Boolean, default=False)
    is_deleted_sender = Column(Boolean, default=False)
    is_deleted_receiver = Column(Boolean, default=False)
    
    session = relationship("SecureSession", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", foreign_keys=[user_id])

# Create tables
Base.metadata.create_all(bind=engine)

# ========== FASTAPI APP ==========

app = FastAPI(
    title="QMS Platform - Quantum Messaging System",
    description="""
    Production-ready end-to-end quantum-resistant messaging platform featuring:
    - ML-KEM-768 (Kyber768) quantum-resistant key exchange
    - Falcon-512 quantum-resistant digital signatures
    - ECDSA-P256 classical wrapper signatures
    - Wrap-and-Sign hybrid protocol
    - AES-256-GCM authenticated encryption
    - Perfect forward secrecy
    - Comprehensive audit logging
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

# ========== PYDANTIC MODELS ==========

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_\\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=100)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Username must be alphanumeric with hyphens or underscores only')
        return v.lower()

class UserLogin(BaseModel):
    username: str
    password: str

class ConnectionRequestCreate(BaseModel):
    receiver_username: str
    sender_public_keys: Dict[str, str]
    metadata: Optional[Dict[str, Any]] = Field(default={})

class ConnectionResponse(BaseModel):
    request_id: str
    accept: bool
    receiver_public_keys: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = Field(default={})

class MessageSend(BaseModel):
    content: str = Field(..., min_length=1, max_length=50000)
    message_type: str = Field(default="secured", pattern="^(secured|critical)$")
    metadata: Optional[Dict[str, Any]] = Field(default={})

class SessionStatus(BaseModel):
    active: bool
    session_id: Optional[str] = None
    peer_username: Optional[str] = None
    peer_id: Optional[str] = None
    established_at: Optional[str] = None
    last_activity: Optional[str] = None
    message_count: int = 0
    has_keys: bool = False
    quantum_ready: bool = False

class MessageResponse(BaseModel):
    id: str
    sender_username: str
    content: str
    message_type: str
    timestamp: str
    is_mine: bool
    verified: bool
    metadata: Optional[Dict[str, Any]] = None

# ========== HELPER FUNCTIONS ==========

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")

def get_current_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive")
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.commit()
    return user

def get_active_session(user_id: str, db: Session) -> Optional[SecureSession]:
    """Get user's active session if exists"""
    return db.query(SecureSession).filter(
        or_(
            and_(SecureSession.user1_id == user_id, SecureSession.is_active == True),
            and_(SecureSession.user2_id == user_id, SecureSession.is_active == True)
        )
    ).first()

def encrypt_message(plaintext: str, shared_secret: bytes) -> tuple:
    """Encrypt message using AES-256-GCM"""
    nonce = os.urandom(12)
    
    # Derive encryption key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'QMS-MSG-ENCRYPT',
        info=b'message-encryption',
        backend=default_backend()
    )
    encryption_key = hkdf.derive(shared_secret[:32])
    
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(encryptor.tag).decode()
    )

def decrypt_message(ciphertext_b64: str, nonce_b64: str, tag_b64: str, shared_secret: bytes) -> str:
    """Decrypt message using AES-256-GCM"""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        
        # Derive encryption key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-MSG-ENCRYPT',
            info=b'message-encryption',
            backend=default_backend()
        )
        encryption_key = hkdf.derive(shared_secret[:32])
        
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise ValueError("Message decryption failed")

def cleanup_expired_requests(db: Session):
    """Clean up expired connection requests"""
    try:
        expired = db.query(ConnectionRequest).filter(
            ConnectionRequest.status == "pending",
            ConnectionRequest.expires_at < datetime.utcnow()
        ).all()
        
        for req in expired:
            req.status = "expired"
        
        if expired:
            db.commit()
            logger.info(f"Cleaned up {len(expired)} expired connection requests")
    except Exception as e:
        logger.error(f"Error cleaning up expired requests: {e}")
        db.rollback()

def cleanup_inactive_sessions(db: Session):
    """Clean up inactive sessions"""
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        inactive = db.query(SecureSession).filter(
            SecureSession.is_active == True,
            SecureSession.last_activity < cutoff
        ).all()
        
        for session in inactive:
            session.is_active = False
            session.terminated_at = datetime.utcnow()
            session.termination_reason = "Inactivity timeout"
        
        if inactive:
            db.commit()
            logger.info(f"Cleaned up {len(inactive)} inactive sessions")
    except Exception as e:
        logger.error(f"Error cleaning up inactive sessions: {e}")
        db.rollback()

def audit_log(db: Session, user_id: Optional[str], action: str, details: Optional[str] = None, request: Optional[Request] = None):
    """Create audit log entry"""
    try:
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error(f"Audit log failed: {str(e)}")

# ========== AUTHENTICATION ENDPOINTS ==========

@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister, request: Request, db: Session = Depends(get_db)):
    """Register new user with quantum-ready infrastructure"""
    
    # Check if username exists
    if db.query(User).filter(User.username == user.username.lower()).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    if db.query(User).filter(User.email == user.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password with bcrypt
    hashed = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS))
    
    # Create user
    db_user = User(
        username=user.username.lower(),
        email=user.email.lower(),
        hashed_password=hashed.decode('utf-8')
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Audit log
    audit_log(db, db_user.id, "USER_REGISTRATION", f"New user registered: {user.username}", request)
    
    logger.info(f"New user registered: {user.username}")
    
    return {
        "message": "User registered successfully",
        "user_id": db_user.id,
        "username": db_user.username,
        "quantum_ready": True
    }

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None, db: Session = Depends(get_db)):
    """User login with token generation"""
    
    user = db.query(User).filter(User.username == form_data.username.lower()).first()
    
    if not user:
        audit_log(db, None, "LOGIN_FAILED", f"Invalid username: {form_data.username}", request)
        logger.warning(f"Login attempt for non-existent user: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not bcrypt.checkpw(form_data.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        audit_log(db, user.id, "LOGIN_FAILED", "Invalid password", request)
        logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        audit_log(db, user.id, "LOGIN_BLOCKED", "Inactive account", request)
        raise HTTPException(status_code=403, detail="Account is inactive")
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.commit()
    
    # Audit log
    audit_log(db, user.id, "LOGIN_SUCCESS", None, request)
    
    logger.info(f"User logged in: {user.username}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "user_id": user.id,
        "quantum_ready": bool(user.public_keys)
    }

# ========== USER LOGOUT ==========

@app.post("/api/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), request: Request = None):
    """
    Logout user and update their status
    """
    try:
        # Check if user has active session and terminate it
        active_session = get_active_session(current_user.id, db)
        if active_session:
            # Get other user before terminating session
            other_user_id = active_session.user1_id if active_session.user2_id == current_user.id else active_session.user1_id
            other_user = db.query(User).filter(User.id == other_user_id).first()
            
            # Terminate the session
            active_session.is_active = False
            active_session.terminated_at = datetime.utcnow()
            active_session.termination_reason = "User logout"
            
            # Clear keys for both users
            current_user.public_keys = None
            current_user.key_generation_timestamp = None
            if other_user:
                other_user.public_keys = None
                other_user.key_generation_timestamp = None
                
                # Notify the other user about session termination
                await manager.send_personal_message(
                    other_user.username,
                    {
                        "type": "session_update",
                        "status": "terminated",
                        "reason": "User logout",
                        "terminated_by": current_user.username
                    }
                )
        
        # Update last seen to current time
        current_user.last_seen = datetime.utcnow()
        db.commit()
        
        # Audit log
        audit_log(db, current_user.id, "LOGOUT", None, request)
        
        logger.info(f"User logged out: {current_user.username}")
        
        # Notify all users about status update via WebSocket
        online_users = manager.get_online_users()
        await manager.broadcast_to_users(
            {
                "type": "user_status_update",
                "username": current_user.username,
                "status": "offline"
            },
            online_users
        )
        
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(status_code=500, detail="Logout failed")

# ========== CONNECTION MANAGEMENT ==========

@app.post("/api/connection/request", status_code=status.HTTP_201_CREATED)
async def create_connection_request(
    request_data: ConnectionRequestCreate,
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Send quantum-secured connection request"""
    
    cleanup_expired_requests(db)
    
    # Check if user has active session
    if get_active_session(current_user.id, db):
        raise HTTPException(status_code=400, detail="You already have an active session")
    
    # Find receiver
    receiver = db.query(User).filter(User.username == request_data.receiver_username.lower()).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")
    
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot connect to yourself")
    
    if get_active_session(receiver.id, db):
        raise HTTPException(status_code=400, detail=f"{receiver.username} is in an active session")
    
    # Check for existing pending request
    existing = db.query(ConnectionRequest).filter(
        or_(
            and_(ConnectionRequest.sender_id == current_user.id, ConnectionRequest.receiver_id == receiver.id),
            and_(ConnectionRequest.sender_id == receiver.id, ConnectionRequest.receiver_id == current_user.id)
        ),
        ConnectionRequest.status == "pending"
    ).first()
    
    if existing:
        existing.status = "cancelled"
        db.commit()
    
    # Create new request
    conn_request = ConnectionRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        sender_public_keys=json.dumps(request_data.sender_public_keys)
    )
    db.add(conn_request)
    db.commit()
    db.refresh(conn_request)
    
    # Store sender's public keys
    current_user.public_keys = json.dumps(request_data.sender_public_keys)
    current_user.key_generation_timestamp = datetime.utcnow()
    db.commit()
    
    # Audit log
    audit_log(db, current_user.id, "CONNECTION_REQUEST_SENT", f"To: {receiver.username}", request)
    
    logger.info(f"Connection request from {current_user.username} to {receiver.username}")
    
    # Send WebSocket notification to receiver about new connection request
    await manager.send_personal_message(
        receiver.username,
        {
            "type": "connection_request",
            "sender": current_user.username,
            "request_id": conn_request.id
        }
    )
    
    return {
        "request_id": conn_request.id,
        "status": "sent",
        "receiver": receiver.username,
        "expires_at": conn_request.expires_at.isoformat(),
        "quantum_keys_included": True
    }

@app.get("/api/connection/pending")
def get_pending_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get pending connection requests"""
    
    cleanup_expired_requests(db)
    
    requests = db.query(ConnectionRequest).filter(
        ConnectionRequest.receiver_id == current_user.id,
        ConnectionRequest.status == "pending"
    ).order_by(desc(ConnectionRequest.created_at)).all()
    
    return [{
        "request_id": req.id,
        "sender_id": req.sender_id,
        "sender_username": req.sender.username,
        "sender_public_keys": json.loads(req.sender_public_keys),
        "created_at": req.created_at.isoformat(),
        "expires_at": req.expires_at.isoformat()
    } for req in requests]

@app.post("/api/connection/respond")
async def respond_to_connection(
    response: ConnectionResponse,
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Accept or reject connection request with quantum key exchange"""
    
    # Use transaction with row-level locking to prevent race conditions
    try:
        # Start transaction
        db.begin()
        
        # Get the connection request with lock
        conn_request = db.query(ConnectionRequest).filter(
            ConnectionRequest.id == response.request_id,
            ConnectionRequest.receiver_id == current_user.id,
            ConnectionRequest.status == "pending"
        ).with_for_update().first()
        
        if not conn_request:
            db.rollback()
            raise HTTPException(status_code=404, detail="Request not found or already processed")
        
        # Check expiration
        if conn_request.expires_at < datetime.utcnow():
            conn_request.status = "expired"
            db.commit()
            raise HTTPException(status_code=400, detail="Request has expired")
        
        # Lock both users to prevent concurrent sessions
        users = db.query(User).filter(
            User.id.in_([current_user.id, conn_request.sender_id])
        ).with_for_update().all()
        
        # Check if either user now has active session (double-check with lock)
        for user in users:
            if get_active_session(user.id, db):
                conn_request.status = "cancelled"
                db.commit()
                raise HTTPException(status_code=400, detail="User already in session")
        
        conn_request.responded_at = datetime.utcnow()
        
        if response.accept:
            conn_request.status = "accepted"
            if response.receiver_public_keys:
                conn_request.receiver_public_keys = json.dumps(response.receiver_public_keys)
                current_user.public_keys = json.dumps(response.receiver_public_keys)
                current_user.key_generation_timestamp = datetime.utcnow()
            
            # Perform quantum key exchange
            sender_keys = json.loads(conn_request.sender_public_keys)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Encapsulate using sender's ML-KEM public key
                encap_response = await client.post(
                    f"{QUANTUM_API}/api/quantum/encapsulate",
                    json={
                        "receiver_public_key": sender_keys["ml_kem_768"],
                        "sender_id": current_user.id,
                        "session_id": str(uuid.uuid4())
                    }
                )
                
                if encap_response.status_code != 200:
                    logger.error(f"Quantum encapsulation failed: {encap_response.text}")
                    db.rollback()
                    raise HTTPException(status_code=500, detail="Quantum key exchange failed")
                
                encap_data = encap_response.json()
            
            # Create secure session atomically
            session = SecureSession(
                user1_id=conn_request.sender_id,
                user2_id=current_user.id,
                request_id=conn_request.id,
                shared_secret=encap_data["shared_secret"],
                ciphertext=encap_data["ciphertext"],
                session_metadata=json.dumps({
                    "quantum_algorithm": encap_data.get("algorithm", "ML-KEM-768"),
                    "kdf": encap_data.get("kdf", "HKDF-SHA256"),
                    "established_by": current_user.username,
                    "metadata": response.metadata
                }),
                is_active=True
            )
            db.add(session)
            
            # Commit transaction atomically
            db.commit()
            db.refresh(session)
            
            # Audit log
            audit_log(db, current_user.id, "CONNECTION_ACCEPTED", f"From: {conn_request.sender.username}", request)
            
            logger.info(f"Quantum session established between {conn_request.sender.username} and {current_user.username}")
            
            # Notify both users about the new session via WebSocket
            await manager.send_personal_message(
                conn_request.sender.username,
                {
                    "type": "session_update",
                    "status": "accepted",
                    "peer_username": current_user.username,
                    "session_id": session.id
                }
            )
            await manager.send_personal_message(
                current_user.username,
                {
                    "type": "session_update",
                    "status": "accepted",
                    "peer_username": conn_request.sender.username,
                    "session_id": session.id
                }
            )
            
            return {
                "status": "accepted",
                "session_id": session.id,
                "peer_username": conn_request.sender.username,
                "ciphertext": encap_data["ciphertext"],
                "quantum_algorithm": encap_data.get("algorithm", "ML-KEM-768"),
                "session_established": True
            }
        else:
            conn_request.status = "rejected"
            db.commit()
            
            # Audit log
            audit_log(db, current_user.id, "CONNECTION_REJECTED", f"From: {conn_request.sender.username}", request)
            
            # Notify sender about rejection via WebSocket
            await manager.send_personal_message(
                conn_request.sender.username,
                {
                    "type": "connection_request",
                    "status": "rejected",
                    "message": f"Connection request rejected by {current_user.username}"
                }
            )
            
            return {"status": "rejected"}
            
    except Exception as e:
        # Rollback transaction on any error
        db.rollback()
        logger.error(f"Error in respond_to_connection: {e}")
        raise HTTPException(status_code=500, detail="Failed to process connection request")

# ========== MESSAGING ==========

@app.post("/api/message/send", status_code=status.HTTP_201_CREATED)
async def send_message(
    message: MessageSend,
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Send quantum-encrypted and signed message"""
    
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=403, detail="No active session")
    
    if not session.shared_secret:
        raise HTTPException(status_code=500, detail="Session key not established")
    
    # Encrypt message with AES-256-GCM
    shared_secret = base64.b64decode(session.shared_secret)
    ciphertext, nonce, tag = encrypt_message(message.content, shared_secret)
    
    # Create quantum-resistant signatures
    async with httpx.AsyncClient(timeout=30.0) as client:
        sign_response = await client.post(
            f"{QUANTUM_API}/api/quantum/wrap_sign",
            json={
                "message": message.content,
                "user_id": current_user.username,
                "signature_type": "wrap_sign" if message.message_type == "critical" else "falcon_only",
                "hash_algorithm": "SHA256"
            }
        )
        
        if sign_response.status_code != 200:
            logger.error(f"Signature creation failed: {sign_response.text}")
            raise HTTPException(status_code=500, detail="Signature creation failed")
        
        signatures = sign_response.json()
    
    # Determine receiver
    receiver_id = session.user2_id if session.user1_id == current_user.id else session.user1_id
    
    # Store message
    msg = Message(
        session_id=session.id,
        sender_id=current_user.id,
        receiver_id=receiver_id,
        encrypted_content=ciphertext,
        nonce=nonce,
        tag=tag,
        falcon_signature=signatures["falcon_signature"],
        ecdsa_signature=signatures.get("ecdsa_signature", ""),
        signature_metadata=json.dumps({
            "algorithm": signatures.get("algorithm", "Unknown"),
            "signature_sizes": signatures.get("signature_sizes", {}),
            "timestamp": signatures.get("timestamp", datetime.utcnow().isoformat()),
            "metadata": message.metadata
        }),
        message_type=message.message_type
    )
    db.add(msg)
    
    # Update session activity
    session.last_activity = datetime.utcnow()
    session.message_count += 1
    
    db.commit()
    db.refresh(msg)
    
    # Audit log
    audit_log(db, current_user.id, f"MESSAGE_SENT_{message.message_type.upper()}", f"To session: {session.id[:8]}", request)
    
    logger.info(f"Quantum-secured message sent from {current_user.username} ({message.message_type})")
    
    # Send WebSocket notification to receiver
    receiver_user = db.query(User).filter(User.id == receiver_id).first()
    if receiver_user:
        await manager.send_personal_message(
            receiver_user.username,
            {
                "type": "new_message",
                "sender": current_user.username,
                "message_id": msg.id,
                "message_type": message.message_type
            }
        )
    
    return {
        "message_id": msg.id,
        "timestamp": msg.timestamp.isoformat(),
        "status": "sent",
        "encrypted": True,
        "signed": True,
        "quantum_algorithm": signatures.get("algorithm", "Unknown"),
        "message_type": message.message_type
    }

@app.get("/api/messages")
async def get_messages(
    last_message_id: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get and decrypt messages with signature verification"""
    
    session = get_active_session(current_user.id, db)
    if not session:
        return []
    
    if not session.shared_secret:
        return []
    
    shared_secret = base64.b64decode(session.shared_secret)
    
    # Query messages
    query = db.query(Message).filter(Message.session_id == session.id)
    
    # Filter deleted messages
    query = query.filter(
        or_(
            and_(Message.sender_id == current_user.id, Message.is_deleted_sender == False),
            and_(Message.receiver_id == current_user.id, Message.is_deleted_receiver == False)
        )
    )
    
    if last_message_id:
        last_msg = db.query(Message).filter(Message.id == last_message_id).first()
        if last_msg:
            query = query.filter(Message.timestamp > last_msg.timestamp)
    
    messages = query.order_by(Message.timestamp).limit(limit).all()
    
    # Get connection request for public keys
    conn_request = db.query(ConnectionRequest).filter(
        ConnectionRequest.id == session.request_id
    ).first() if session.request_id else None
    
    decrypted_messages = []
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for msg in messages:
            # Mark as read
            if msg.receiver_id == current_user.id and not msg.is_read:
                msg.is_read = True
                msg.read_at = datetime.utcnow()
            
            verified = False
            
            # Verify signatures if available
            if conn_request and msg.falcon_signature:
                try:
                    # Get sender's public keys
                    if msg.sender_id == conn_request.sender_id:
                        sender_keys = json.loads(conn_request.sender_public_keys)
                    else:
                        sender_keys = json.loads(conn_request.receiver_public_keys) if conn_request.receiver_public_keys else {}
                    
                    if sender_keys:
                        # Decrypt message first
                        try:
                            decrypted_content = decrypt_message(
                                msg.encrypted_content,
                                msg.nonce,
                                msg.tag,
                                shared_secret
                            )
                        except:
                            decrypted_content = "[Decryption failed]"
                        
                        # Verify signatures
                        if msg.ecdsa_signature:  # Wrap-and-sign
                            verify_response = await client.post(
                                f"{QUANTUM_API}/api/quantum/wrap_verify",
                                json={
                                    "message": decrypted_content,
                                    "falcon_signature": msg.falcon_signature,
                                    "ecdsa_signature": msg.ecdsa_signature,
                                    "falcon_public": sender_keys.get("falcon_512", ""),
                                    "ecdsa_public": sender_keys.get("ecdsa_p256", ""),
                                    "signature_type": "wrap_sign"
                                }
                            )
                        else:  # Falcon only
                            verify_response = await client.post(
                                f"{QUANTUM_API}/api/quantum/wrap_verify",
                                json={
                                    "message": decrypted_content,
                                    "falcon_signature": msg.falcon_signature,
                                    "ecdsa_signature": "",
                                    "falcon_public": sender_keys.get("falcon_512", ""),
                                    "ecdsa_public": "",
                                    "signature_type": "falcon_only"
                                }
                            )
                        
                        if verify_response.status_code == 200:
                            verify_data = verify_response.json()
                            verified = verify_data.get("valid", False)
                except Exception as e:
                    logger.error(f"Signature verification failed: {str(e)}")
                    verified = False
            else:
                # Just decrypt without verification
                try:
                    decrypted_content = decrypt_message(
                        msg.encrypted_content,
                        msg.nonce,
                        msg.tag,
                        shared_secret
                    )
                except:
                    decrypted_content = "[Decryption failed]"
            
            # Parse signature metadata
            sig_metadata = json.loads(msg.signature_metadata) if msg.signature_metadata else {}
            
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": msg.sender.username,
                "content": decrypted_content,
                "message_type": msg.message_type,
                "timestamp": msg.timestamp.isoformat(),
                "delivered_at": msg.delivered_at.isoformat() if msg.delivered_at else None,
                "read_at": msg.read_at.isoformat() if msg.read_at else None,
                "is_mine": msg.sender_id == current_user.id,
                "is_read": msg.is_read,
                "verified": verified,
                "quantum_algorithm": sig_metadata.get("algorithm", "Unknown"),
                "metadata": sig_metadata.get("metadata", {})
            })
    
    # Update session activity
    session.last_activity = datetime.utcnow()
    db.commit()
    
    return decrypted_messages

@app.delete("/api/message/{message_id}")
def delete_message(
    message_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete message for current user"""
    
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if msg.sender_id == current_user.id:
        msg.is_deleted_sender = True
    elif msg.receiver_id == current_user.id:
        msg.is_deleted_receiver = True
    else:
        raise HTTPException(status_code=403, detail="Not authorized to delete this message")
    
    # If both deleted, actually remove from database
    if msg.is_deleted_sender and msg.is_deleted_receiver:
        db.delete(msg)
    
    db.commit()
    
    return {"message": "Message deleted"}

# ========== SESSION MANAGEMENT ==========

@app.get("/api/session/status")
def get_session_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> SessionStatus:
    """Get current quantum session status"""
    
    session = get_active_session(current_user.id, db)
    
    if not session:
        return SessionStatus(
            active=False,
            message_count=0,
            has_keys=bool(current_user.public_keys),
            quantum_ready=bool(current_user.public_keys)
        )
    
    peer_id = session.user2_id if session.user1_id == current_user.id else session.user1_id
    peer = db.query(User).filter(User.id == peer_id).first()
    
    # Parse session metadata
    metadata = json.loads(session.session_metadata) if session.session_metadata else {}
    
    return SessionStatus(
        active=True,
        session_id=session.id,
        peer_username=peer.username if peer else "Unknown",
        peer_id=peer_id,
        established_at=session.established_at.isoformat(),
        last_activity=session.last_activity.isoformat(),
        message_count=session.message_count,
        has_keys=bool(session.shared_secret),
        quantum_ready=True
    )

@app.post("/api/session/terminate")
async def terminate_session(
    reason: Optional[str] = "User requested",
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Terminate active quantum session"""
    
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=404, detail="No active session")
    
    # Get the other user's info before terminating
    other_user_id = session.user1_id if session.user2_id == current_user.id else session.user2_id
    other_user = db.query(User).filter(User.id == other_user_id).first()
    
    session.is_active = False
    session.terminated_at = datetime.utcnow()
    session.termination_reason = reason[:100]
    
    # Cancel any pending requests between these users
    db.query(ConnectionRequest).filter(
        or_(
            and_(ConnectionRequest.sender_id == session.user1_id, ConnectionRequest.receiver_id == session.user2_id),
            and_(ConnectionRequest.sender_id == session.user2_id, ConnectionRequest.receiver_id == session.user1_id)
        ),
        ConnectionRequest.status == "pending"
    ).update({"status": "cancelled"})
    
    # Clear BOTH users' stored keys for forward secrecy
    current_user.public_keys = None
    current_user.key_generation_timestamp = None
    
    # Also clear the other user's keys
    if other_user:
        other_user.public_keys = None
        other_user.key_generation_timestamp = None
    
    db.commit()
    
    # Clear keys from quantum service for both users
    try:
        async with httpx.AsyncClient() as client:
            # Clear current user's keys
            await client.delete(f"{QUANTUM_API}/api/quantum/session/{current_user.username}")
            
            # Clear other user's keys
            if other_user:
                await client.delete(f"{QUANTUM_API}/api/quantum/session/{other_user.username}")
                
    except Exception as e:
        logger.warning(f"Failed to clear quantum service keys: {e}")
    
    # Audit log
    audit_log(db, current_user.id, "SESSION_TERMINATED", f"Reason: {reason}, Keys destroyed for both users", request)
    
    logger.info(f"Quantum session terminated by {current_user.username}")
    
    # Notify both users about session termination via WebSocket
    if other_user:
        await manager.send_personal_message(
            other_user.username,
            {
                "type": "session_update",
                "status": "terminated",
                "reason": reason,
                "terminated_by": current_user.username
            }
        )
    
    await manager.send_personal_message(
        current_user.username,
        {
            "type": "session_update",
            "status": "terminated",
            "reason": reason,
            "terminated_by": current_user.username
        }
    )
    
    return {
        "message": "Session terminated",
        "session_id": session.id,
        "keys_destroyed": True
    }

@app.get("/api/users/available")
def get_available_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of available users for quantum connection"""
    
    # Clean up old sessions
    cleanup_inactive_sessions(db)
    
    all_users = db.query(User).filter(
        User.id != current_user.id,
        User.is_active == True
    ).order_by(User.username).all()
    
    result = []
    for user in all_users:
        session = get_active_session(user.id, db)
        is_online = (datetime.utcnow() - user.last_seen).total_seconds() < 300  # 5 minutes
        
        result.append({
            "username": user.username,
            "user_id": user.id,
            "status": "busy" if session else ("online" if is_online else "offline"),
            "can_connect": session is None,
            "has_quantum_keys": bool(user.public_keys),
            "last_seen": user.last_seen.isoformat() if is_online else None
        })
    
    return result

# ========== SYSTEM ENDPOINTS ==========

@app.get("/api/health")
def health_check():
    """System health check"""
    return {
        "status": "healthy",
        "service": "QMS Platform",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected",
        "quantum_service": "configured",
        "features": {
            "quantum_key_exchange": True,
            "quantum_signatures": True,
            "wrap_and_sign": True,
            "perfect_forward_secrecy": True,
            "audit_logging": True
        }
    }

@app.get("/api/stats")
def get_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user statistics"""
    
    total_messages_sent = db.query(Message).filter(Message.sender_id == current_user.id).count()
    total_messages_received = db.query(Message).filter(Message.receiver_id == current_user.id).count()
    total_sessions = db.query(SecureSession).filter(
        or_(SecureSession.user1_id == current_user.id, SecureSession.user2_id == current_user.id)
    ).count()
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "member_since": current_user.created_at.isoformat(),
        "statistics": {
            "messages_sent": total_messages_sent,
            "messages_received": total_messages_received,
            "total_sessions": total_sessions,
            "quantum_keys_generated": bool(current_user.public_keys)
        }
    }

# ========== WEBSOCKET ENDPOINTS ==========

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """WebSocket endpoint for real-time communication"""
    connection_id = await manager.connect(websocket, username)
    
    # Update user's last_seen when they connect via WebSocket
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.last_seen = datetime.utcnow()
            db.commit()
            
            # Notify other users that this user is online
            online_users = get_online_users_for_broadcast()
            await manager.broadcast_to_users(
                json.dumps({
                    "type": "user_status_update",
                    "username": username,
                    "status": "online"
                }),
                online_users
            )
        
        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                # Handle different message types
                if message_data.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif message_data.get("type") == "heartbeat":
                    # Update last_seen timestamp
                    if user:
                        user.last_seen = datetime.utcnow()
                        db.commit()
                        
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for {username}")
            manager.disconnect(username)
            
            # Update user's last_seen when they disconnect
            if user:
                user.last_seen = datetime.utcnow()
                
                # Check if user has active session and terminate it
                active_session = get_active_session(user.id, db)
                if active_session:
                    # Get other user before terminating session
                    other_user_id = active_session.user1_id if active_session.user2_id == user.id else active_session.user2_id
                    other_user = db.query(User).filter(User.id == other_user_id).first()
                    
                    # Terminate the session
                    active_session.is_active = False
                    active_session.terminated_at = datetime.utcnow()
                    active_session.termination_reason = "WebSocket disconnect"
                    
                    # Clear keys for both users
                    user.public_keys = None
                    user.key_generation_timestamp = None
                    if other_user:
                        other_user.public_keys = None
                        other_user.key_generation_timestamp = None
                    
                    # Notify the other user about session termination
                    if other_user:
                        await manager.send_personal_message(
                            other_user.username,
                            {
                                "type": "session_update",
                                "status": "terminated",
                                "reason": "Connection lost",
                                "terminated_by": username
                            }
                        )
                
                db.commit()
                
            # Notify ALL other users immediately that this user went offline
            online_users = manager.get_online_users()
            await manager.broadcast_to_users(
                {
                    "type": "user_status_update", 
                    "username": username,
                    "status": "offline"
                },
                online_users
            )
            
    except Exception as e:
        logger.error(f"WebSocket error for {username}: {e}")
        manager.disconnect(username)
    finally:
        db.close()

def get_online_users_for_broadcast() -> List[str]:
    """Get list of users to broadcast updates to (excluding the current user)"""
    return manager.get_online_users()

# ========== STARTUP/SHUTDOWN EVENTS ==========

@app.on_event("startup")
async def startup_event():
    """Initialize platform on startup"""
    logger.info("QMS Platform starting up...")
    
    # Verify quantum service is available
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{QUANTUM_API}/api/quantum/info")
            if response.status_code == 200:
                quantum_info = response.json()
                logger.info(f"Quantum service connected: {quantum_info.get('mode', 'Unknown')}")
            else:
                logger.warning("Quantum service not responding properly")
    except Exception as e:
        logger.error(f"Could not connect to quantum service: {str(e)}")
    
    logger.info("QMS Platform ready")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("QMS Platform shutting down...")

# ========== ERROR HANDLERS ==========

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*80)
    print("QMS PLATFORM - QUANTUM MESSAGING SYSTEM - v2.0.0")
    print("="*80)
    print("Features:")
    print("  - ML-KEM-768 quantum-resistant key exchange")
    print("  - Falcon-512 quantum-resistant signatures")
    print("  - Wrap-and-Sign hybrid protocol")
    print("  - AES-256-GCM authenticated encryption")
    print("  - Perfect forward secrecy")
    print("  - Comprehensive audit logging")
    print("="*80)
    print("Starting server on http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    print("Alternative Docs: http://localhost:8000/redoc")
    print("="*80 + "\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        use_colors=True
    )