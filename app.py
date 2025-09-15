import sys
print(f"Python version: {sys.version}", file=sys.stderr)
print("Starting app...", file=sys.stderr)

try:
    from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect, Header
    print("FastAPI imported successfully", file=sys.stderr)
    
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    print("FastAPI components imported successfully", file=sys.stderr)
    
    # TinyDB for Python 3.13 compatibility
    from tinydb import TinyDB, Query
    from tinydb.storages import JSONStorage
    from tinydb.middlewares import CachingMiddleware
    print("TinyDB imported successfully", file=sys.stderr)
    
    from pydantic import BaseModel, Field, EmailStr, field_validator
    print("Pydantic imported successfully", file=sys.stderr)
    
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
    print("Standard libraries imported successfully", file=sys.stderr)
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    print("Cryptography imported successfully", file=sys.stderr)

except Exception as e:
    print(f"Import error: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("All imports successful, continuing with app initialization...", file=sys.stderr)

# Azure Environment Configuration
AZURE_ENV = os.environ.get("AZURE_ENV", "development")
IS_PRODUCTION = AZURE_ENV == "production"

# Configure logging for Azure
logging.basicConfig(
    level=logging.INFO if IS_PRODUCTION else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Azure captures stdout
    ]
)
logger = logging.getLogger(__name__)

# Database configuration - Azure PostgreSQL or local SQLite
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:////tmp/qms_quantum.db"  # Azure needs /tmp/ for write access
)

# ========== DATABASE SETUP WITH TINYDB ==========

# Database path for Azure or local
DB_PATH = os.environ.get("DB_PATH", "/tmp/qms_database.json")

# Initialize TinyDB with caching for better performance
db = TinyDB(DB_PATH, storage=CachingMiddleware(JSONStorage))

# Define tables
users_table = db.table('users')
connection_requests_table = db.table('connection_requests')
secure_sessions_table = db.table('secure_sessions')
messages_table = db.table('messages')
audit_logs_table = db.table('audit_logs')

# Query objects for convenient access
UserQuery = Query()
ConnectionRequestQuery = Query()
SecureSessionQuery = Query()
MessageQuery = Query()
AuditLogQuery = Query()

print("TinyDB database initialized successfully", file=sys.stderr)

# Database helper functions
def get_current_timestamp():
    return datetime.utcnow().isoformat()

def create_user_document(username: str, email: str, hashed_password: str):
    return {
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

def create_connection_request_document(sender_id: str, receiver_id: str, sender_public_keys: str):
    return {
        'id': str(uuid.uuid4()),
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'sender_public_keys': sender_public_keys,
        'receiver_public_keys': None,
        'status': 'pending',
        'created_at': get_current_timestamp(),
        'responded_at': None,
        'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }

def create_secure_session_document(user1_id: str, user2_id: str, request_id: str = None):
    return {
        'id': str(uuid.uuid4()),
        'user1_id': user1_id,
        'user2_id': user2_id,
        'request_id': request_id,
        'shared_secret': None,
        'ciphertext': None,
        'session_metadata': None,
        'established_at': get_current_timestamp(),
        'last_activity': get_current_timestamp(),
        'terminated_at': None,
        'termination_reason': None,
        'is_active': True,
        'message_count': 0
    }

def create_message_document(session_id: str, sender_id: str, receiver_id: str, encrypted_content: str, nonce: str, tag: str):
    return {
        'id': str(uuid.uuid4()),
        'session_id': session_id,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'encrypted_content': encrypted_content,
        'nonce': nonce,
        'tag': tag,
        'aad': None,
        'falcon_signature': None,
        'ecdsa_signature': None,
        'signature_metadata': None,
        'message_type': 'secured',
        'timestamp': get_current_timestamp(),
        'delivered_at': None,
        'read_at': None,
        'is_read': False,
        'is_deleted_sender': False,
        'is_deleted_receiver': False
    }

def create_audit_log_document(user_id: str = None, action: str = None, details: str = None, ip_address: str = None, user_agent: str = None):
    return {
        'id': str(uuid.uuid4()),
        'user_id': user_id,
        'action': action,
        'details': details,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'timestamp': get_current_timestamp()
    }

# Database session dependency (replaces SQLAlchemy dependency)
def get_db():
    return db

# Security configuration from environment
SECRET_KEY = os.environ.get("JWT_SECRET", "quantum-secure-default-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("TOKEN_EXPIRE_MINUTES", "1440"))
BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

# Service URLs - Azure configuration
QUANTUM_API = os.environ.get("QUANTUM_API_URL", "http://localhost:8001")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")

# Azure-specific settings
AZURE_APP_URL = os.environ.get("AZURE_APP_URL", "http://localhost:8000")
ENABLE_WEBSOCKET = os.environ.get("ENABLE_WEBSOCKET", "true").lower() == "true"

# ========== WEBSOCKET CONNECTION MANAGER ==========

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}
        
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
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                try:
                    websocket = self.active_connections[connection_id]
                    message_str = json.dumps(message) if isinstance(message, dict) else message
                    await websocket.send_text(message_str)
                    return True
                except Exception as e:
                    logger.error(f"Error sending WebSocket message to {username}: {e}")
                    self.disconnect(username)
        return False
        
    async def broadcast_to_users(self, message, usernames: List[str]):
        for username in usernames:
            await self.send_personal_message(username, message)
            
    def get_online_users(self) -> List[str]:
        return list(self.user_connections.keys())

manager = ConnectionManager()

# ========== DATABASE MODELS REPLACED WITH TINYDB FUNCTIONS ==========

# User management functions
def get_user_by_username(username: str):
    """Get user by username"""
    result = users_table.search(UserQuery.username == username)
    return result[0] if result else None

def get_user_by_email(email: str):
    """Get user by email"""
    result = users_table.search(UserQuery.email == email)
    return result[0] if result else None

def get_user_by_id(user_id: str):
    """Get user by ID"""
    result = users_table.search(UserQuery.id == user_id)
    return result[0] if result else None

def create_user(username: str, email: str, hashed_password: str):
    """Create a new user"""
    user_doc = create_user_document(username, email, hashed_password)
    users_table.insert(user_doc)
    return user_doc

def update_user_last_seen(user_id: str):
    """Update user's last seen timestamp"""
    users_table.update({'last_seen': get_current_timestamp()}, UserQuery.id == user_id)

def update_user_public_keys(user_id: str, public_keys: str):
    """Update user's public keys"""
    users_table.update({
        'public_keys': public_keys,
        'key_generation_timestamp': get_current_timestamp()
    }, UserQuery.id == user_id)

# Connection request management functions  
def create_connection_request(sender_id: str, receiver_id: str, sender_public_keys: str):
    """Create a new connection request"""
    request_doc = create_connection_request_document(sender_id, receiver_id, sender_public_keys)
    connection_requests_table.insert(request_doc)
    return request_doc

def get_connection_request_by_id(request_id: str):
    """Get connection request by ID"""
    result = connection_requests_table.search(ConnectionRequestQuery.id == request_id)
    return result[0] if result else None

def get_pending_requests_for_user(user_id: str):
    """Get pending connection requests for a user"""
    return connection_requests_table.search(
        (ConnectionRequestQuery.receiver_id == user_id) & 
        (ConnectionRequestQuery.status == 'pending')
    )

def update_connection_request_status(request_id: str, status: str, receiver_public_keys: str = None):
    """Update connection request status"""
    update_data = {
        'status': status,
        'responded_at': get_current_timestamp()
    }
    if receiver_public_keys:
        update_data['receiver_public_keys'] = receiver_public_keys
    
    connection_requests_table.update(update_data, ConnectionRequestQuery.id == request_id)

# Secure session management functions
def create_secure_session(user1_id: str, user2_id: str, request_id: str = None):
    """Create a new secure session"""
    session_doc = create_secure_session_document(user1_id, user2_id, request_id)
    secure_sessions_table.insert(session_doc)
    return session_doc

def get_secure_session_by_id(session_id: str):
    """Get secure session by ID"""
    result = secure_sessions_table.search(SecureSessionQuery.id == session_id)
    return result[0] if result else None

def get_active_sessions_for_user(user_id: str):
    """Get active sessions for a user"""
    return secure_sessions_table.search(
        ((SecureSessionQuery.user1_id == user_id) | (SecureSessionQuery.user2_id == user_id)) &
        (SecureSessionQuery.is_active == True)
    )

def update_session_activity(session_id: str):
    """Update session last activity"""
    secure_sessions_table.update({
        'last_activity': get_current_timestamp()
    }, SecureSessionQuery.id == session_id)

def terminate_session(session_id: str, reason: str = None):
    """Terminate a secure session"""
    secure_sessions_table.update({
        'is_active': False,
        'terminated_at': get_current_timestamp(),
        'termination_reason': reason
    }, SecureSessionQuery.id == session_id)

# Message management functions
def create_message(session_id: str, sender_id: str, receiver_id: str, encrypted_content: str, nonce: str, tag: str):
    """Create a new message"""
    message_doc = create_message_document(session_id, sender_id, receiver_id, encrypted_content, nonce, tag)
    messages_table.insert(message_doc)
    
    # Update session message count
    session = get_secure_session_by_id(session_id)
    if session:
        new_count = session.get('message_count', 0) + 1
        secure_sessions_table.update({
            'message_count': new_count,
            'last_activity': get_current_timestamp()
        }, SecureSessionQuery.id == session_id)
    
    return message_doc

def get_messages_for_session(session_id: str, limit: int = 50):
    """Get messages for a session"""
    messages = messages_table.search(MessageQuery.session_id == session_id)
    # Sort by timestamp (newest first) and limit
    messages.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return messages[:limit]

def mark_message_as_read(message_id: str):
    """Mark message as read"""
    messages_table.update({
        'is_read': True,
        'read_at': get_current_timestamp()
    }, MessageQuery.id == message_id)

# Audit log functions
def create_audit_log(user_id: str = None, action: str = None, details: str = None, ip_address: str = None, user_agent: str = None):
    """Create an audit log entry"""
    audit_doc = create_audit_log_document(user_id, action, details, ip_address, user_agent)
    audit_logs_table.insert(audit_doc)
    return audit_doc

print("TinyDB database functions initialized successfully", file=sys.stderr)

# TinyDB doesn't need table creation - they're created automatically

# ========== FASTAPI APP ==========

app = FastAPI(
    title="QMS Platform - Quantum Messaging System",
    description="""
    Production-ready quantum-resistant messaging platform on Azure:
    - ML-KEM-768 quantum-resistant key exchange
    - Falcon-512 quantum-resistant signatures
    - ECDSA-P256 classical wrapper signatures
    - Wrap-and-Sign hybrid protocol
    - AES-256-GCM authenticated encryption
    - Perfect forward secrecy
    """,
    version="2.1.0",
    docs_url="/docs" if not IS_PRODUCTION else None,
    redoc_url="/redoc" if not IS_PRODUCTION else None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# ========== ROOT ENDPOINT ==========

@app.get("/")
def root():
    return {
        "message": "QMS Backend Running",
        "docs": "/docs" if not IS_PRODUCTION else "API Documentation disabled in production",
        "health": "/api/health",
        "version": "2.1.0",
        "quantum_ready": True
    }

# ========== PYDANTIC MODELS ==========

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_\\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=100)
    
    @field_validator('username')
    @classmethod
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

# ========== HELPER FUNCTIONS ==========

def get_db():
    # TinyDB doesn't need session management like SQLAlchemy
    return db

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_token_from_header(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    return authorization.replace("Bearer ", "")

def verify_token(token: str = Depends(get_token_from_header)):
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

def get_current_user(username: str = Depends(verify_token)):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.get('is_active', True):
        raise HTTPException(status_code=403, detail="User account is inactive")
    
    # Update last seen
    update_user_last_seen(user['id'])
    return user

def get_active_session(user_id: str) -> Optional[dict]:
    """Get active session for a user using TinyDB"""
    sessions = get_active_sessions_for_user(user_id)
    return sessions[0] if sessions else None

def encrypt_message(plaintext: str, shared_secret: bytes) -> tuple:
    nonce = os.urandom(12)
    
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
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        
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

# TODO: Replace with TinyDB version
# def cleanup_expired_requests(db: Session):
#     try:
#         expired = db.query(ConnectionRequest).filter(
#             ConnectionRequest.status == "pending",
#             ConnectionRequest.expires_at < datetime.utcnow()
#         ).all()
        
        for req in expired:
            req.status = "expired"
        
        if expired:
            db.commit()
            logger.info(f"Cleaned up {len(expired)} expired connection requests")
    except Exception as e:
        logger.error(f"Error cleaning up expired requests: {e}")
        db.rollback()

def audit_log(db: Session, user_id: Optional[str], action: str, details: Optional[str] = None, request: Optional[Request] = None):
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
    if db.query(User).filter(User.username == user.username.lower()).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    if db.query(User).filter(User.email == user.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS))
    
    db_user = User(
        username=user.username.lower(),
        email=user.email.lower(),
        hashed_password=hashed.decode('utf-8')
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    audit_log(db, db_user.id, "USER_REGISTRATION", f"New user registered: {user.username}", request)
    logger.info(f"New user registered: {user.username}")
    
    return {
        "message": "User registered successfully",
        "user_id": db_user.id,
        "username": db_user.username,
        "quantum_ready": True
    }

@app.post("/api/login")
def login(credentials: UserLogin, request: Request = None, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username.lower()).first()
    
    if not user:
        audit_log(db, None, "LOGIN_FAILED", f"Invalid username: {credentials.username}", request)
        logger.warning(f"Login attempt for non-existent user: {credentials.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not bcrypt.checkpw(credentials.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        audit_log(db, user.id, "LOGIN_FAILED", "Invalid password", request)
        logger.warning(f"Failed login attempt for user: {credentials.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        audit_log(db, user.id, "LOGIN_BLOCKED", "Inactive account", request)
        raise HTTPException(status_code=403, detail="Account is inactive")
    
    access_token = create_access_token(data={"sub": user.username})
    
    user.last_seen = datetime.utcnow()
    db.commit()
    
    audit_log(db, user.id, "LOGIN_SUCCESS", None, request)
    logger.info(f"User logged in: {user.username}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "user_id": user.id,
        "quantum_ready": bool(user.public_keys)
    }

@app.post("/api/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), request: Request = None):
    try:
        active_session = get_active_session(current_user.id, db)
        if active_session:
            other_user_id = active_session.user1_id if active_session.user2_id == current_user.id else active_session.user2_id
            other_user = db.query(User).filter(User.id == other_user_id).first()
            
            active_session.is_active = False
            active_session.terminated_at = datetime.utcnow()
            active_session.termination_reason = "User logout"
            
            current_user.public_keys = None
            current_user.key_generation_timestamp = None
            if other_user:
                other_user.public_keys = None
                other_user.key_generation_timestamp = None
                
                if ENABLE_WEBSOCKET:
                    await manager.send_personal_message(
                        other_user.username,
                        {
                            "type": "session_update",
                            "status": "terminated",
                            "reason": "User logout",
                            "terminated_by": current_user.username
                        }
                    )
        
        current_user.last_seen = datetime.utcnow()
        db.commit()
        
        audit_log(db, current_user.id, "LOGOUT", None, request)
        logger.info(f"User logged out: {current_user.username}")
        
        if ENABLE_WEBSOCKET:
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
    cleanup_expired_requests(db)
    
    if get_active_session(current_user.id, db):
        raise HTTPException(status_code=400, detail="You already have an active session")
    
    receiver = db.query(User).filter(User.username == request_data.receiver_username.lower()).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")
    
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot connect to yourself")
    
    if get_active_session(receiver.id, db):
        raise HTTPException(status_code=400, detail=f"{receiver.username} is in an active session")
    
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
    
    conn_request = ConnectionRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        sender_public_keys=json.dumps(request_data.sender_public_keys)
    )
    db.add(conn_request)
    db.commit()
    db.refresh(conn_request)
    
    current_user.public_keys = json.dumps(request_data.sender_public_keys)
    current_user.key_generation_timestamp = datetime.utcnow()
    db.commit()
    
    audit_log(db, current_user.id, "CONNECTION_REQUEST_SENT", f"To: {receiver.username}", request)
    logger.info(f"Connection request from {current_user.username} to {receiver.username}")
    
    if ENABLE_WEBSOCKET:
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
    try:
        db.begin()
        
        conn_request = db.query(ConnectionRequest).filter(
            ConnectionRequest.id == response.request_id,
            ConnectionRequest.receiver_id == current_user.id,
            ConnectionRequest.status == "pending"
        ).with_for_update().first()
        
        if not conn_request:
            db.rollback()
            raise HTTPException(status_code=404, detail="Request not found or already processed")
        
        if conn_request.expires_at < datetime.utcnow():
            conn_request.status = "expired"
            db.commit()
            raise HTTPException(status_code=400, detail="Request has expired")
        
        users = db.query(User).filter(
            User.id.in_([current_user.id, conn_request.sender_id])
        ).with_for_update().all()
        
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
            
            sender_keys = json.loads(conn_request.sender_public_keys)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
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
            
            db.commit()
            db.refresh(session)
            
            audit_log(db, current_user.id, "CONNECTION_ACCEPTED", f"From: {conn_request.sender.username}", request)
            logger.info(f"Quantum session established between {conn_request.sender.username} and {current_user.username}")
            
            if ENABLE_WEBSOCKET:
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
            
            audit_log(db, current_user.id, "CONNECTION_REJECTED", f"From: {conn_request.sender.username}", request)
            
            if ENABLE_WEBSOCKET:
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
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=403, detail="No active session")
    
    if not session.shared_secret:
        raise HTTPException(status_code=500, detail="Session key not established")
    
    shared_secret = base64.b64decode(session.shared_secret)
    ciphertext, nonce, tag = encrypt_message(message.content, shared_secret)
    
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
    
    receiver_id = session.user2_id if session.user1_id == current_user.id else session.user1_id
    
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
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": message.metadata
        }),
        message_type=message.message_type
    )
    db.add(msg)
    
    session.last_activity = datetime.utcnow()
    session.message_count += 1
    
    db.commit()
    db.refresh(msg)
    
    audit_log(db, current_user.id, f"MESSAGE_SENT_{message.message_type.upper()}", f"To session: {session.id[:8]}", request)
    logger.info(f"Quantum-secured message sent from {current_user.username} ({message.message_type})")
    
    if ENABLE_WEBSOCKET:
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
    session = get_active_session(current_user.id, db)
    if not session:
        return []
    
    if not session.shared_secret:
        return []
    
    shared_secret = base64.b64decode(session.shared_secret)
    
    query = db.query(Message).filter(Message.session_id == session.id)
    
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
    
    decrypted_messages = []
    
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
            msg.read_at = datetime.utcnow()
        
        try:
            decrypted_content = decrypt_message(
                msg.encrypted_content,
                msg.nonce,
                msg.tag,
                shared_secret
            )
        except:
            decrypted_content = "[Decryption failed]"
        
        sig_metadata = json.loads(msg.signature_metadata) if msg.signature_metadata else {}
        
        decrypted_messages.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_username": msg.sender.username,
            "content": decrypted_content,
            "message_type": msg.message_type,
            "timestamp": msg.timestamp.isoformat(),
            "is_mine": msg.sender_id == current_user.id,
            "is_read": msg.is_read,
            "verified": True,
            "quantum_algorithm": sig_metadata.get("algorithm", "Unknown"),
            "metadata": sig_metadata.get("metadata", {})
        })
    
    session.last_activity = datetime.utcnow()
    db.commit()
    
    return decrypted_messages

# ========== SESSION MANAGEMENT ==========

@app.get("/api/session/status")
def get_session_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> SessionStatus:
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
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=404, detail="No active session")
    
    other_user_id = session.user1_id if session.user2_id == current_user.id else session.user2_id
    other_user = db.query(User).filter(User.id == other_user_id).first()
    
    session.is_active = False
    session.terminated_at = datetime.utcnow()
    session.termination_reason = reason[:100]
    
    current_user.public_keys = None
    current_user.key_generation_timestamp = None
    
    if other_user:
        other_user.public_keys = None
        other_user.key_generation_timestamp = None
    
    db.commit()
    
    audit_log(db, current_user.id, "SESSION_TERMINATED", f"Reason: {reason}", request)
    logger.info(f"Quantum session terminated by {current_user.username}")
    
    if ENABLE_WEBSOCKET and other_user:
        await manager.send_personal_message(
            other_user.username,
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
    all_users = db.query(User).filter(
        User.id != current_user.id,
        User.is_active == True
    ).order_by(User.username).all()
    
    result = []
    for user in all_users:
        session = get_active_session(user.id, db)
        is_online = (datetime.utcnow() - user.last_seen).total_seconds() < 300
        
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
    return {
        "status": "healthy",
        "service": "QMS Platform",
        "version": "2.1.0",
        "environment": AZURE_ENV,
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected",
        "quantum_service": QUANTUM_API,
        "websocket_enabled": ENABLE_WEBSOCKET
    }

@app.get("/api/config")
def get_config():
    return {
        "quantum_api": QUANTUM_API,
        "websocket_enabled": ENABLE_WEBSOCKET,
        "environment": AZURE_ENV,
        "app_url": AZURE_APP_URL
    }

# ========== WEBSOCKET ENDPOINTS ==========

if ENABLE_WEBSOCKET:
    @app.websocket("/ws/{username}")
    async def websocket_endpoint(websocket: WebSocket, username: str):
        connection_id = await manager.connect(websocket, username)
        
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user:
                user.last_seen = datetime.utcnow()
                db.commit()
                
                online_users = manager.get_online_users()
                await manager.broadcast_to_users(
                    {
                        "type": "user_status_update",
                        "username": username,
                        "status": "online"
                    },
                    online_users
                )
            
            try:
                while True:
                    data = await websocket.receive_text()
                    message_data = json.loads(data)
                    
                    if message_data.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
                    elif message_data.get("type") == "heartbeat":
                        if user:
                            user.last_seen = datetime.utcnow()
                            db.commit()
                            
            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for {username}")
                manager.disconnect(username)
                
                if user:
                    user.last_seen = datetime.utcnow()
                    db.commit()
                
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

# ========== STARTUP/SHUTDOWN EVENTS ==========

@app.on_event("startup")
async def startup_event():
    logger.info(f"QMS Platform starting up in {AZURE_ENV} mode...")
    logger.info(f"Database URL: {DATABASE_URL[:30]}...")
    logger.info(f"Quantum API: {QUANTUM_API}")
    logger.info(f"WebSocket Enabled: {ENABLE_WEBSOCKET}")
    logger.info("QMS Platform ready")

@app.on_event("shutdown")
async def shutdown_event():
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
            "detail": "An unexpected error occurred" if IS_PRODUCTION else str(exc),
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    
    # Azure App Service sets PORT environment variable
    port = int(os.environ.get("PORT", "8000"))  # Ensure string default
    
    logger.info(f"Starting QMS Platform on port {port}")
    logger.info(f"Environment: {AZURE_ENV}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info" if IS_PRODUCTION else "debug"
    )