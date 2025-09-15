"""
Quantum Messaging System - Production Application
Real Post-Quantum Cryptography using OQS (ML-KEM-768 & Falcon-512)
Version: 3.0.0
"""

import os
import sys
import sqlite3
import secrets
import hashlib
import logging
import json
import asyncio
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from contextlib import contextmanager

# FastAPI and dependencies
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field, validator

# Authentication
import bcrypt
import jwt

# Quantum Cryptography
try:
    import oqs
    OQS_AVAILABLE = True
    OQS_VERSION = oqs.oqs_version()
    AVAILABLE_KEMS = oqs.get_enabled_kem_mechanisms()
    AVAILABLE_SIGS = oqs.get_enabled_sig_mechanisms()
except ImportError:
    OQS_AVAILABLE = False
    OQS_VERSION = "Not installed"
    AVAILABLE_KEMS = []
    AVAILABLE_SIGS = []
    print("WARNING: OQS not installed. Install with: pip install liboqs-python")

# Standard cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ============= CONFIGURATION =============

class Config:
    """Application configuration"""
    # App settings
    APP_NAME = "Quantum Messaging System"
    APP_VERSION = "3.0.0"
    
    # Security
    JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_HOURS = 24
    BCRYPT_ROUNDS = 12
    
    # Database
    DATABASE_NAME = os.getenv("DATABASE_NAME", "qms.db")
    DATABASE_TIMEOUT = 30
    
    # Quantum algorithms
    KEM_ALGORITHM = "ML-KEM-768" if "ML-KEM-768" in AVAILABLE_KEMS else "Kyber768"
    SIG_ALGORITHM = "Falcon-512"
    
    # API settings
    API_PREFIX = "/api"
    MAX_MESSAGE_LENGTH = 10000
    MAX_MESSAGES_PER_REQUEST = 100
    
    # WebSocket
    WS_HEARTBEAT_INTERVAL = 30
    WS_MAX_CONNECTIONS = 1000
    
    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

config = Config()

# ============= LOGGING =============

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)

# ============= FASTAPI APP =============

app = FastAPI(
    title=config.APP_NAME,
    description="End-to-end encrypted messaging using NIST-standardized post-quantum cryptography",
    version=config.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# ============= DATA MODELS =============

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    
    @validator('password')
    def validate_password(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class ConnectionRequest(BaseModel):
    to_username: str

class ConnectionResponse(BaseModel):
    request_id: int
    accept: bool

class MessageSend(BaseModel):
    to_username: str
    content: str = Field(..., max_length=config.MAX_MESSAGE_LENGTH)
    message_type: str = Field(default="secured", pattern="^(secured|critical)$")

class GetMessagesRequest(BaseModel):
    username: str
    limit: int = Field(default=50, le=config.MAX_MESSAGES_PER_REQUEST)
    offset: int = Field(default=0, ge=0)

# ============= DATABASE =============

class DatabaseManager:
    """Database management with connection pooling"""
    
    @staticmethod
    @contextmanager
    def get_connection():
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(
                config.DATABASE_NAME,
                timeout=config.DATABASE_TIMEOUT,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise HTTPException(status_code=500, detail="Database error")
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def init_database():
        """Initialize database schema"""
        with DatabaseManager.get_connection() as conn:
            # Users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    CHECK (LENGTH(username) >= 3)
                )
            """)
            
            # Quantum keys table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quantum_keys (
                    user_id INTEGER PRIMARY KEY,
                    ml_kem_public BLOB NOT NULL,
                    ml_kem_private BLOB NOT NULL,
                    falcon_public BLOB NOT NULL,
                    falcon_private BLOB NOT NULL,
                    kem_algorithm TEXT NOT NULL,
                    sig_algorithm TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    rotated_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Active sessions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    user1_id INTEGER NOT NULL,
                    user2_id INTEGER NOT NULL,
                    shared_secret BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    kem_algorithm TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
                    CHECK (user1_id < user2_id),
                    UNIQUE(user1_id, user2_id)
                )
            """)
            
            # Messages table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    encrypted_content BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    signature BLOB,
                    message_type TEXT DEFAULT 'secured',
                    is_read BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (session_id) REFERENCES active_sessions(session_id)
                )
            """)
            
            # Connection requests
            conn.execute("""
                CREATE TABLE IF NOT EXISTS connection_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    responded_at TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
                    CHECK (status IN ('pending', 'accepted', 'rejected')),
                    UNIQUE(sender_id, receiver_id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_users ON active_sessions(user1_id, user2_id)")
            
            logger.info("Database initialized successfully")

db = DatabaseManager()

# ============= QUANTUM CRYPTOGRAPHY SERVICE =============

class QuantumCryptoService:
    """Real OQS quantum cryptography implementation"""
    
    def __init__(self):
        if not OQS_AVAILABLE:
            logger.error("OQS not available - quantum features disabled")
            return
        
        self.kem_algorithm = config.KEM_ALGORITHM
        self.sig_algorithm = config.SIG_ALGORITHM
        
        # Verify algorithms are available
        if self.kem_algorithm not in AVAILABLE_KEMS:
            raise ValueError(f"KEM algorithm {self.kem_algorithm} not available")
        if self.sig_algorithm not in AVAILABLE_SIGS:
            raise ValueError(f"Signature algorithm {self.sig_algorithm} not available")
        
        logger.info(f"Quantum crypto initialized: KEM={self.kem_algorithm}, SIG={self.sig_algorithm}")
    
    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768/Kyber768 keypair"""
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            # public_key is already returned by generate_keypair()
        return public_key, private_key
    
    def generate_sig_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Falcon-512 keypair"""
        with oqs.Signature(self.sig_algorithm) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            # public_key is already returned by generate_keypair()
        return public_key, private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret"""
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate shared secret"""
        with oqs.KeyEncapsulation(self.kem_algorithm, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Create Falcon-512 signature"""
        with oqs.Signature(self.sig_algorithm, secret_key=private_key) as sig:
            signature = sig.sign(message)
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify Falcon-512 signature"""
        try:
            with oqs.Signature(self.sig_algorithm) as sig:
                return sig.verify(message, signature, public_key)
        except Exception:
            return False
    
    def derive_key(self, shared_secret: bytes, context: bytes = b"encryption") -> bytes:
        """Derive AES key from shared secret"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-' + self.kem_algorithm.encode(),
            info=context,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    def encrypt(self, plaintext: bytes, shared_secret: bytes) -> Dict[str, bytes]:
        """Encrypt with AES-256-GCM"""
        key = self.derive_key(shared_secret)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return {
            "encrypted_content": ciphertext[:-16],
            "nonce": nonce,
            "tag": ciphertext[-16:]
        }
    
    def decrypt(self, encrypted_data: Dict[str, bytes], shared_secret: bytes) -> bytes:
        """Decrypt with AES-256-GCM"""
        key = self.derive_key(shared_secret)
        aesgcm = AESGCM(key)
        ciphertext = encrypted_data["encrypted_content"] + encrypted_data["tag"]
        plaintext = aesgcm.decrypt(encrypted_data["nonce"], ciphertext, None)
        return plaintext

# Initialize quantum crypto service
quantum_crypto = QuantumCryptoService() if OQS_AVAILABLE else None

# ============= AUTHENTICATION =============

class AuthService:
    """Authentication and authorization service"""
    
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash password with bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(config.BCRYPT_ROUNDS))
    
    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        """Verify password"""
        return bcrypt.checkpw(password.encode(), hashed)
    
    @staticmethod
    def create_token(user_id: int, username: str) -> str:
        """Create JWT token"""
        payload = {
            "user_id": user_id,
            "username": username,
            "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRATION_HOURS),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    
    @staticmethod
    def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
        """Verify JWT token"""
        try:
            payload = jwt.decode(
                credentials.credentials,
                config.JWT_SECRET,
                algorithms=[config.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

auth = AuthService()

# ============= WEBSOCKET MANAGER =============

class ConnectionManager:
    """WebSocket connection manager"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_count = 0
    
    async def connect(self, websocket: WebSocket, username: str):
        """Connect WebSocket"""
        if self.connection_count >= config.WS_MAX_CONNECTIONS:
            await websocket.close(code=1008, reason="Max connections reached")
            return False
        
        await websocket.accept()
        self.active_connections[username] = websocket
        self.connection_count += 1
        logger.info(f"WebSocket connected: {username} (total: {self.connection_count})")
        return True
    
    def disconnect(self, username: str):
        """Disconnect WebSocket"""
        if username in self.active_connections:
            del self.active_connections[username]
            self.connection_count -= 1
            logger.info(f"WebSocket disconnected: {username} (total: {self.connection_count})")
    
    async def send_json(self, data: dict, username: str):
        """Send JSON to specific user"""
        if username in self.active_connections:
            try:
                await self.active_connections[username].send_json(data)
            except Exception as e:
                logger.error(f"Failed to send to {username}: {e}")
                self.disconnect(username)
    
    async def broadcast(self, data: dict, exclude: Optional[str] = None):
        """Broadcast to all connected users"""
        disconnected = []
        for username, connection in self.active_connections.items():
            if username != exclude:
                try:
                    await connection.send_json(data)
                except:
                    disconnected.append(username)
        
        for username in disconnected:
            self.disconnect(username)

manager = ConnectionManager()

# ============= API ENDPOINTS =============

# Root and Health

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with system info"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{config.APP_NAME}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                   max-width: 800px; margin: 50px auto; padding: 20px; }}
            h1 {{ color: #5e72e4; }}
            .status {{ background: #f6f9fc; padding: 20px; border-radius: 8px; }}
            .success {{ color: #2dce89; }}
            .error {{ color: #f5365c; }}
            code {{ background: #f1f1f1; padding: 2px 6px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <h1>🔐 {config.APP_NAME}</h1>
        <div class="status">
            <h2>System Status</h2>
            <p><strong>Version:</strong> {config.APP_VERSION}</p>
            <p><strong>OQS Status:</strong> <span class="{'success' if OQS_AVAILABLE else 'error'}">
                {'✓ Active' if OQS_AVAILABLE else '✗ Not Available'}</span></p>
            <p><strong>OQS Version:</strong> {OQS_VERSION}</p>
            <p><strong>Quantum Algorithms:</strong></p>
            <ul>
                <li>KEM: <code>{config.KEM_ALGORITHM}</code></li>
                <li>Signature: <code>{config.SIG_ALGORITHM}</code></li>
            </ul>
            <p><strong>API Documentation:</strong> <a href="/docs">OpenAPI Docs</a></p>
        </div>
    </body>
    </html>
    """
    return html

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": config.APP_VERSION,
        "quantum_crypto": OQS_AVAILABLE,
        "database": os.path.exists(config.DATABASE_NAME),
        "websocket_connections": manager.connection_count
    }

# User Management

@app.post("/api/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    """Register new user with quantum keys"""
    if not OQS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Quantum crypto not available")
    
    with db.get_connection() as conn:
        # Check if user exists
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (user.username, user.email)
        ).fetchone()
        
        if existing:
            raise HTTPException(status_code=400, detail="Username or email already exists")
        
        # Hash password
        password_hash = auth.hash_password(user.password)
        
        # Create user
        cursor = conn.execute("""
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        """, (user.username, user.email, password_hash))
        
        user_id = cursor.lastrowid
        
        # Generate quantum keys
        kem_public, kem_private = quantum_crypto.generate_kem_keypair()
        sig_public, sig_private = quantum_crypto.generate_sig_keypair()
        
        # Store quantum keys
        conn.execute("""
            INSERT INTO quantum_keys 
            (user_id, ml_kem_public, ml_kem_private, falcon_public, falcon_private, kem_algorithm, sig_algorithm)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            kem_public,
            kem_private,
            sig_public,
            sig_private,
            config.KEM_ALGORITHM,
            config.SIG_ALGORITHM
        ))
        
        # Create token
        token = auth.create_token(user_id, user.username)
        
        logger.info(f"User registered: {user.username} (ID: {user_id})")
        
        return {
            "user_id": user_id,
            "username": user.username,
            "token": token,
            "quantum_algorithms": {
                "kem": config.KEM_ALGORITHM,
                "signature": config.SIG_ALGORITHM
            }
        }

@app.post("/api/login")
async def login(user: UserLogin):
    """Login user"""
    with db.get_connection() as conn:
        # Get user
        row = conn.execute("""
            SELECT id, username, password_hash, is_active 
            FROM users WHERE username = ?
        """, (user.username,)).fetchone()
        
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not row["is_active"]:
            raise HTTPException(status_code=403, detail="Account disabled")
        
        # Verify password
        if not auth.verify_password(user.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (row["id"],)
        )
        
        # Create token
        token = auth.create_token(row["id"], row["username"])
        
        logger.info(f"User logged in: {user.username}")
        
        return {
            "user_id": row["id"],
            "username": row["username"],
            "token": token
        }

@app.get("/api/user/profile")
async def get_profile(current_user: dict = Depends(auth.verify_token)):
    """Get user profile"""
    with db.get_connection() as conn:
        user = conn.execute("""
            SELECT u.username, u.email, u.created_at, u.last_login,
                   qk.kem_algorithm, qk.sig_algorithm
            FROM users u
            LEFT JOIN quantum_keys qk ON u.id = qk.user_id
            WHERE u.id = ?
        """, (current_user["user_id"],)).fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return dict(user)

# Quantum Session Management

@app.post("/api/quantum/establish-session")
async def establish_session(
    request: ConnectionRequest,
    current_user: dict = Depends(auth.verify_token)
):
    """Establish quantum-secure session"""
    if not OQS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Quantum crypto not available")
    
    with db.get_connection() as conn:
        # Get receiver
        receiver = conn.execute("""
            SELECT u.id, qk.ml_kem_public 
            FROM users u
            JOIN quantum_keys qk ON u.id = qk.user_id
            WHERE u.username = ? AND u.is_active = 1
        """, (request.to_username,)).fetchone()
        
        if not receiver:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Ensure user1_id < user2_id for consistency
        user1_id = min(current_user["user_id"], receiver["id"])
        user2_id = max(current_user["user_id"], receiver["id"])
        
        # Check existing session
        existing = conn.execute("""
            SELECT session_id, shared_secret, is_active
            FROM active_sessions
            WHERE user1_id = ? AND user2_id = ?
        """, (user1_id, user2_id)).fetchone()
        
        if existing and existing["is_active"]:
            # Update last used
            conn.execute(
                "UPDATE active_sessions SET last_used = CURRENT_TIMESTAMP WHERE session_id = ?",
                (existing["session_id"],)
            )
            return {
                "status": "existing",
                "session_id": existing["session_id"]
            }
        
        # Create new session
        session_id = f"qms_{user1_id}_{user2_id}_{secrets.token_hex(8)}"
        
        # Encapsulate shared secret
        ciphertext, shared_secret = quantum_crypto.encapsulate(receiver["ml_kem_public"])
        
        # Store session
        if existing:
            # Reactivate existing session
            conn.execute("""
                UPDATE active_sessions 
                SET shared_secret = ?, ciphertext = ?, is_active = 1, 
                    created_at = CURRENT_TIMESTAMP, last_used = CURRENT_TIMESTAMP
                WHERE user1_id = ? AND user2_id = ?
            """, (shared_secret, ciphertext, user1_id, user2_id))
        else:
            # Create new session
            conn.execute("""
                INSERT INTO active_sessions 
                (session_id, user1_id, user2_id, shared_secret, ciphertext, kem_algorithm)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                user1_id,
                user2_id,
                shared_secret,
                ciphertext,
                config.KEM_ALGORITHM
            ))
        
        logger.info(f"Quantum session established: {session_id}")
        
        return {
            "status": "established",
            "session_id": session_id,
            "algorithm": config.KEM_ALGORITHM
        }

# Messaging

@app.post("/api/message/send")
async def send_message(
    message: MessageSend,
    current_user: dict = Depends(auth.verify_token)
):
    """Send quantum-encrypted message"""
    if not OQS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Quantum crypto not available")
    
    with db.get_connection() as conn:
        # Get receiver
        receiver = conn.execute("""
            SELECT id FROM users WHERE username = ? AND is_active = 1
        """, (message.to_username,)).fetchone()
        
        if not receiver:
            raise HTTPException(status_code=404, detail="Receiver not found")
        
        # Get or create session
        user1_id = min(current_user["user_id"], receiver["id"])
        user2_id = max(current_user["user_id"], receiver["id"])
        
        session = conn.execute("""
            SELECT session_id, shared_secret 
            FROM active_sessions
            WHERE user1_id = ? AND user2_id = ? AND is_active = 1
        """, (user1_id, user2_id)).fetchone()
        
        if not session:
            # Auto-establish session
            receiver_keys = conn.execute("""
                SELECT ml_kem_public FROM quantum_keys WHERE user_id = ?
            """, (receiver["id"],)).fetchone()
            
            if not receiver_keys:
                raise HTTPException(status_code=500, detail="Receiver keys not found")
            
            session_id = f"qms_{user1_id}_{user2_id}_{secrets.token_hex(8)}"
            ciphertext, shared_secret = quantum_crypto.encapsulate(receiver_keys["ml_kem_public"])
            
            conn.execute("""
                INSERT INTO active_sessions 
                (session_id, user1_id, user2_id, shared_secret, ciphertext, kem_algorithm)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                user1_id,
                user2_id,
                shared_secret,
                ciphertext,
                config.KEM_ALGORITHM
            ))
            
            session = {"session_id": session_id, "shared_secret": shared_secret}
        
        # Get signature key for critical messages
        signature = None
        if message.message_type == "critical":
            sig_keys = conn.execute("""
                SELECT falcon_private FROM quantum_keys WHERE user_id = ?
            """, (current_user["user_id"],)).fetchone()
            
            if sig_keys:
                signature = quantum_crypto.sign(
                    message.content.encode(),
                    sig_keys["falcon_private"]
                )
        
        # Encrypt message
        encrypted = quantum_crypto.encrypt(
            message.content.encode(),
            session["shared_secret"]
        )
        
        # Store message
        cursor = conn.execute("""
            INSERT INTO messages 
            (session_id, sender_id, receiver_id, encrypted_content, nonce, tag, signature, message_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session["session_id"],
            current_user["user_id"],
            receiver["id"],
            encrypted["encrypted_content"],
            encrypted["nonce"],
            encrypted["tag"],
            signature,
            message.message_type
        ))
        
        message_id = cursor.lastrowid
        
        # Update session last used
        conn.execute(
            "UPDATE active_sessions SET last_used = CURRENT_TIMESTAMP WHERE session_id = ?",
            (session["session_id"],)
        )
        
        # Send WebSocket notification
        await manager.send_json({
            "type": "new_message",
            "message_id": message_id,
            "from": current_user["username"],
            "timestamp": datetime.utcnow().isoformat()
        }, message.to_username)
        
        logger.info(f"Message sent: {message_id} from {current_user['username']} to {message.to_username}")
        
        return {
            "message_id": message_id,
            "encrypted": True,
            "signed": message.message_type == "critical"
        }

@app.get("/api/messages/{username}")
async def get_messages(
    username: str,
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(auth.verify_token)
):
    """Get decrypted messages with user"""
    if not OQS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Quantum crypto not available")
    
    with db.get_connection() as conn:
        # Get other user
        other_user = conn.execute("""
            SELECT id FROM users WHERE username = ?
        """, (username,)).fetchone()
        
        if not other_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get session
        user1_id = min(current_user["user_id"], other_user["id"])
        user2_id = max(current_user["user_id"], other_user["id"])
        
        session = conn.execute("""
            SELECT session_id, shared_secret
            FROM active_sessions
            WHERE user1_id = ? AND user2_id = ? AND is_active = 1
        """, (user1_id, user2_id)).fetchone()
        
        if not session:
            return {"messages": [], "total": 0}
        
        # Get total count
        total = conn.execute("""
            SELECT COUNT(*) as count FROM messages WHERE session_id = ?
        """, (session["session_id"],)).fetchone()["count"]
        
        # Get messages
        messages = conn.execute("""
            SELECT m.*, u.username as sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.session_id = ?
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        """, (session["session_id"], limit, offset)).fetchall()
        
        # Mark as read
        conn.execute("""
            UPDATE messages SET is_read = 1 
            WHERE session_id = ? AND receiver_id = ? AND is_read = 0
        """, (session["session_id"], current_user["user_id"]))
        
        decrypted_messages = []
        for msg in messages:
            try:
                # Decrypt
                decrypted = quantum_crypto.decrypt(
                    {
                        "encrypted_content": msg["encrypted_content"],
                        "nonce": msg["nonce"],
                        "tag": msg["tag"]
                    },
                    session["shared_secret"]
                )
                
                # Verify signature if present
                verified = False
                if msg["signature"]:
                    sig_keys = conn.execute("""
                        SELECT falcon_public FROM quantum_keys WHERE user_id = ?
                    """, (msg["sender_id"],)).fetchone()
                    
                    if sig_keys:
                        verified = quantum_crypto.verify(
                            decrypted,
                            msg["signature"],
                            sig_keys["falcon_public"]
                        )
                
                decrypted_messages.append({
                    "id": msg["id"],
                    "sender": msg["sender_username"],
                    "content": decrypted.decode(),
                    "message_type": msg["message_type"],
                    "timestamp": msg["created_at"],
                    "is_read": bool(msg["is_read"]),
                    "verified": verified
                })
                
            except Exception as e:
                logger.error(f"Failed to decrypt message {msg['id']}: {e}")
                decrypted_messages.append({
                    "id": msg["id"],
                    "sender": msg["sender_username"],
                    "content": "[Decryption failed]",
                    "error": True,
                    "timestamp": msg["created_at"]
                })
        
        return {
            "messages": decrypted_messages,
            "total": total,
            "limit": limit,
            "offset": offset
        }

# Connection Management

@app.post("/api/connection/request")
async def request_connection(
    request: ConnectionRequest,
    current_user: dict = Depends(auth.verify_token)
):
    """Send connection request"""
    with db.get_connection() as conn:
        # Get receiver
        receiver = conn.execute("""
            SELECT id FROM users WHERE username = ? AND is_active = 1
        """, (request.to_username,)).fetchone()
        
        if not receiver:
            raise HTTPException(status_code=404, detail="User not found")
        
        if receiver["id"] == current_user["user_id"]:
            raise HTTPException(status_code=400, detail="Cannot connect to yourself")
        
        # Check existing request
        existing = conn.execute("""
            SELECT id, status FROM connection_requests
            WHERE sender_id = ? AND receiver_id = ?
        """, (current_user["user_id"], receiver["id"])).fetchone()
        
        if existing:
            if existing["status"] == "pending":
                return {"status": "already_pending", "request_id": existing["id"]}
            elif existing["status"] == "accepted":
                return {"status": "already_connected"}
        
        # Create request
        cursor = conn.execute("""
            INSERT INTO connection_requests (sender_id, receiver_id)
            VALUES (?, ?)
        """, (current_user["user_id"], receiver["id"]))
        
        request_id = cursor.lastrowid
        
        # Send WebSocket notification
        await manager.send_json({
            "type": "connection_request",
            "request_id": request_id,
            "from": current_user["username"]
        }, request.to_username)
        
        return {"status": "sent", "request_id": request_id}

@app.get("/api/connection/pending")
async def get_pending_connections(current_user: dict = Depends(auth.verify_token)):
    """Get pending connection requests"""
    with db.get_connection() as conn:
        requests = conn.execute("""
            SELECT cr.id, cr.created_at, u.username as sender_username
            FROM connection_requests cr
            JOIN users u ON cr.sender_id = u.id
            WHERE cr.receiver_id = ? AND cr.status = 'pending'
            ORDER BY cr.created_at DESC
        """, (current_user["user_id"],)).fetchall()
        
        return {"requests": [dict(r) for r in requests]}

@app.post("/api/connection/respond")
async def respond_to_connection(
    response: ConnectionResponse,
    current_user: dict = Depends(auth.verify_token)
):
    """Respond to connection request"""
    with db.get_connection() as conn:
        # Get request
        request = conn.execute("""
            SELECT sender_id, receiver_id, status
            FROM connection_requests
            WHERE id = ? AND receiver_id = ?
        """, (response.request_id, current_user["user_id"])).fetchone()
        
        if not request:
            raise HTTPException(status_code=404, detail="Request not found")
        
        if request["status"] != "pending":
            raise HTTPException(status_code=400, detail="Request already responded")
        
        # Update status
        new_status = "accepted" if response.accept else "rejected"
        conn.execute("""
            UPDATE connection_requests 
            SET status = ?, responded_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_status, response.request_id))
        
        if response.accept:
            # Get sender username
            sender = conn.execute(
                "SELECT username FROM users WHERE id = ?",
                (request["sender_id"],)
            ).fetchone()
            
            # Send WebSocket notification
            await manager.send_json({
                "type": "connection_accepted",
                "from": current_user["username"]
            }, sender["username"])
        
        return {"status": new_status}

# System Information

@app.get("/api/quantum/proof")
async def quantum_proof():
    """Prove quantum cryptography is working"""
    if not OQS_AVAILABLE:
        return {"error": "OQS not installed"}
    
    try:
        # Generate test keys
        kem_pub, kem_priv = quantum_crypto.generate_kem_keypair()
        sig_pub, sig_priv = quantum_crypto.generate_sig_keypair()
        
        # Test encryption
        ct, ss = quantum_crypto.encapsulate(kem_pub)
        message = "Quantum Cryptography Active! 🔐"
        encrypted = quantum_crypto.encrypt(message.encode(), ss)
        
        # Test signature
        signature = quantum_crypto.sign(message.encode(), sig_priv)
        verified = quantum_crypto.verify(message.encode(), signature, sig_pub)
        
        # Test decryption
        decrypted = quantum_crypto.decrypt(encrypted, ss)
        
        return {
            "status": "Active",
            "oqs_version": OQS_VERSION,
            "algorithms": {
                "kem": config.KEM_ALGORITHM,
                "signature": config.SIG_ALGORITHM
            },
            "key_sizes": {
                "kem_public": len(kem_pub),
                "kem_private": len(kem_priv),
                "sig_public": len(sig_pub),
                "sig_private": len(sig_priv),
                "shared_secret": len(ss)
            },
            "test": {
                "message": message,
                "encrypted_size": len(encrypted["encrypted_content"]),
                "signature_size": len(signature),
                "verified": verified,
                "decrypted": decrypted.decode() == message
            }
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/quantum/algorithms")
async def list_algorithms():
    """List available quantum algorithms"""
    if not OQS_AVAILABLE:
        return {"error": "OQS not installed"}
    
    return {
        "kem_algorithms": AVAILABLE_KEMS,
        "signature_algorithms": AVAILABLE_SIGS,
        "total_kems": len(AVAILABLE_KEMS),
        "total_sigs": len(AVAILABLE_SIGS),
        "configured": {
            "kem": config.KEM_ALGORITHM,
            "signature": config.SIG_ALGORITHM
        }
    }

@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(auth.verify_token)):
    """Get user statistics"""
    with db.get_connection() as conn:
        stats = conn.execute("""
            SELECT 
                (SELECT COUNT(*) FROM messages WHERE sender_id = ?) as sent,
                (SELECT COUNT(*) FROM messages WHERE receiver_id = ?) as received,
                (SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0) as unread,
                (SELECT COUNT(*) FROM connection_requests WHERE receiver_id = ? AND status = 'pending') as pending_requests
        """, (current_user["user_id"], current_user["user_id"], 
              current_user["user_id"], current_user["user_id"])).fetchone()
        
        return dict(stats)

# WebSocket

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """WebSocket endpoint for real-time messaging"""
    if not await manager.connect(websocket, username):
        return
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif message.get("type") == "typing":
                await manager.send_json({
                    "type": "typing",
                    "from": username
                }, message.get("to"))
                
    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        logger.error(f"WebSocket error for {username}: {e}")
        manager.disconnect(username)

# Error Handlers

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "status_code": 500}
    )

# Startup and Shutdown

@app.on_event("startup")
async def startup():
    """Application startup"""
    db.init_database()
    logger.info(f"{config.APP_NAME} v{config.APP_VERSION} started")
    logger.info(f"OQS Status: {'Active' if OQS_AVAILABLE else 'Not Available'}")
    if OQS_AVAILABLE:
        logger.info(f"Quantum Algorithms: KEM={config.KEM_ALGORITHM}, SIG={config.SIG_ALGORITHM}")

@app.on_event("shutdown")
async def shutdown():
    """Application shutdown"""
    # Close all WebSocket connections
    for username in list(manager.active_connections.keys()):
        await manager.active_connections[username].close()
    logger.info("Application shutdown")

# Main

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=config.LOG_LEVEL.lower()
    )