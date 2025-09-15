"""
Quantum Messaging System - Fixed Database and WebSocket Implementation
"""

import os
import sqlite3
import json
import secrets
import base64
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import uuid
import asyncio

from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
import bcrypt
import jwt

# Import quantum crypto functions
from service import (
    generate_kem_keypair,
    generate_sig_keypair,
    perform_encapsulation,
    perform_decapsulation,
    encrypt_with_aes_gcm,
    decrypt_with_aes_gcm
)

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "test-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Use persistent database file
DB_PATH = "qms.db"  # This will persist data

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="QMS Backend", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        logger.info(f"WebSocket connected: {username}")
        
    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
            logger.info(f"WebSocket disconnected: {username}")
            
    async def send_personal_message(self, message: str, username: str):
        if username in self.active_connections:
            await self.active_connections[username].send_text(message)
            
    async def send_json(self, data: dict, username: str):
        if username in self.active_connections:
            await self.active_connections[username].send_json(data)
            
    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

# Database functions
def init_db():
    """Initialize database with proper schema"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Quantum keys table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS quantum_keys (
            user_id TEXT PRIMARY KEY,
            ml_kem_public BLOB,
            ml_kem_private BLOB,
            falcon_public BLOB,
            falcon_private BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Active sessions table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS active_sessions (
            id TEXT PRIMARY KEY,
            user1 TEXT NOT NULL,
            user2 TEXT NOT NULL,
            shared_secret BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Messages table with encryption fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            encrypted_content BLOB NOT NULL,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL,
            message_type TEXT DEFAULT 'secured',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES active_sessions(id)
        )
    ''')
    
    # Connection requests table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS connection_requests (
            id TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")

# Initialize database on startup
init_db()

# Helper functions
def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {"user_id": user_id, "username": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except:
        return None

async def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {"user_id": payload["user_id"], "username": payload["username"]}

# Pydantic models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class MessageSend(BaseModel):
    content: str
    message_type: str = "secured"

# API Endpoints
@app.get("/")
def root():
    return {"message": "QMS Backend", "database": DB_PATH, "websocket": "enabled"}

@app.get("/api/health")
def health_check():
    conn = get_db()
    try:
        conn.execute("SELECT 1")
        db_status = "connected"
    except:
        db_status = "error"
    finally:
        conn.close()
    
    return {
        "status": "healthy",
        "database": db_status,
        "websocket_connections": len(manager.active_connections),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/register")
async def register(user: UserRegister):
    conn = get_db()
    try:
        # Check if user exists
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (user.username, user.email)
        ).fetchone()
        
        if existing:
            raise HTTPException(status_code=400, detail="Username or email already exists")
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(user.password)
        
        conn.execute(
            "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
            (user_id, user.username, user.email, password_hash)
        )
        
        # Generate quantum keys
        kem_keys = generate_kem_keypair(user_id)
        sig_keys = generate_sig_keypair(user_id)
        
        # Store quantum keys
        conn.execute(
            """INSERT INTO quantum_keys 
               (user_id, ml_kem_public, ml_kem_private, falcon_public, falcon_private) 
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, kem_keys["public"], kem_keys["private"], 
             sig_keys["public"], sig_keys["private"])
        )
        
        conn.commit()
        
        token = create_token(user_id, user.username)
        
        logger.info(f"User registered: {user.username}")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "username": user.username,
            "quantum_ready": True
        }
        
    finally:
        conn.close()

@app.post("/api/login")
async def login(creds: UserLogin):
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (creds.username, creds.username)
        ).fetchone()
        
        if not user or not verify_password(creds.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_token(user["id"], user["username"])
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "username": user["username"],
            "quantum_ready": True
        }
        
    finally:
        conn.close()

@app.get("/api/users/available")
async def get_available_users(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    try:
        users = conn.execute(
            """SELECT u.username, 
                      CASE WHEN qk.user_id IS NOT NULL THEN 1 ELSE 0 END as has_quantum_keys,
                      CASE WHEN s.id IS NOT NULL THEN 1 ELSE 0 END as in_session
               FROM users u
               LEFT JOIN quantum_keys qk ON u.id = qk.user_id
               LEFT JOIN active_sessions s ON (s.user1 = u.username OR s.user2 = u.username) 
                                            AND s.is_active = 1
               WHERE u.username != ?""",
            (current_user["username"],)
        ).fetchall()
        
        available = []
        for user in users:
            available.append({
                "username": user["username"],
                "status": "busy" if user["in_session"] else "online",
                "can_connect": not user["in_session"],
                "has_quantum_keys": bool(user["has_quantum_keys"])
            })
        
        return available
        
    finally:
        conn.close()

@app.post("/api/quantum/generate_keys")
async def generate_keys(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    try:
        # Generate new keys
        kem_keys = generate_kem_keypair(current_user["user_id"])
        sig_keys = generate_sig_keypair(current_user["user_id"])
        
        # Update or insert keys
        conn.execute(
            """INSERT OR REPLACE INTO quantum_keys 
               (user_id, ml_kem_public, ml_kem_private, falcon_public, falcon_private) 
               VALUES (?, ?, ?, ?, ?)""",
            (current_user["user_id"], kem_keys["public"], kem_keys["private"],
             sig_keys["public"], sig_keys["private"])
        )
        conn.commit()
        
        return {
            "keys": {
                "ml_kem_public": base64.b64encode(kem_keys["public"]).decode(),
                "falcon_public": base64.b64encode(sig_keys["public"]).decode()
            }
        }
        
    finally:
        conn.close()

@app.post("/api/connection/request")
async def create_connection_request(
    receiver_username: str,
    current_user: dict = Depends(get_current_user)
):
    conn = get_db()
    try:
        request_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO connection_requests (id, sender, receiver) VALUES (?, ?, ?)",
            (request_id, current_user["username"], receiver_username)
        )
        conn.commit()
        
        # Notify via WebSocket
        await manager.send_json({
            "type": "connection_request",
            "sender": current_user["username"]
        }, receiver_username)
        
        return {"request_id": request_id}
        
    finally:
        conn.close()

@app.get("/api/connection/pending")
async def get_pending_requests(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    try:
        requests = conn.execute(
            "SELECT * FROM connection_requests WHERE receiver = ? AND status = 'pending'",
            (current_user["username"],)
        ).fetchall()
        
        return [dict(r) for r in requests]
        
    finally:
        conn.close()

@app.post("/api/connection/respond")
async def respond_to_connection(
    request_id: str,
    accept: bool,
    current_user: dict = Depends(get_current_user)
):
    conn = get_db()
    try:
        request = conn.execute(
            "SELECT * FROM connection_requests WHERE id = ?",
            (request_id,)
        ).fetchone()
        
        if not request:
            raise HTTPException(status_code=404, detail="Request not found")
        
        if accept:
            # Create session with shared secret
            session_id = str(uuid.uuid4())
            shared_secret = secrets.token_bytes(32)
            
            conn.execute(
                """INSERT INTO active_sessions (id, user1, user2, shared_secret) 
                   VALUES (?, ?, ?, ?)""",
                (session_id, request["sender"], current_user["username"], shared_secret)
            )
            
            conn.execute(
                "UPDATE connection_requests SET status = 'accepted' WHERE id = ?",
                (request_id,)
            )
            conn.commit()
            
            # Notify sender
            await manager.send_json({
                "type": "connection_accepted",
                "session_id": session_id
            }, request["sender"])
            
            return {"session_id": session_id, "peer_username": request["sender"]}
        else:
            conn.execute(
                "UPDATE connection_requests SET status = 'rejected' WHERE id = ?",
                (request_id,)
            )
            conn.commit()
            
            return {"status": "rejected"}
            
    finally:
        conn.close()

@app.get("/api/session/status")
async def get_session_status(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    try:
        session = conn.execute(
            """SELECT * FROM active_sessions 
               WHERE (user1 = ? OR user2 = ?) AND is_active = 1""",
            (current_user["username"], current_user["username"])
        ).fetchone()
        
        if session:
            peer = session["user2"] if session["user1"] == current_user["username"] else session["user1"]
            return {
                "active": True,
                "session_id": session["id"],
                "peer_username": peer
            }
        
        return {"active": False}
        
    finally:
        conn.close()

@app.post("/api/message/send")
async def send_message(
    message: MessageSend,
    current_user: dict = Depends(get_current_user)
):
    conn = get_db()
    try:
        # Get active session
        session = conn.execute(
            """SELECT * FROM active_sessions 
               WHERE (user1 = ? OR user2 = ?) AND is_active = 1""",
            (current_user["username"], current_user["username"])
        ).fetchone()
        
        if not session:
            raise HTTPException(status_code=400, detail="No active session")
        
        # Encrypt message
        plaintext = message.content.encode('utf-8')
        ciphertext, nonce, tag = encrypt_with_aes_gcm(plaintext, session["shared_secret"])
        
        # Store encrypted message
        message_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO messages 
               (id, session_id, sender, encrypted_content, nonce, tag, message_type) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (message_id, session["id"], current_user["username"], 
             ciphertext, nonce, tag, message.message_type)
        )
        conn.commit()
        
        # Notify peer via WebSocket
        peer = session["user2"] if session["user1"] == current_user["username"] else session["user1"]
        await manager.send_json({
            "type": "new_message",
            "message_id": message_id
        }, peer)
        
        return {"message_id": message_id, "encrypted": True}
        
    finally:
        conn.close()

@app.get("/api/messages")
async def get_messages(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    try:
        # Get active session
        session = conn.execute(
            """SELECT * FROM active_sessions 
               WHERE (user1 = ? OR user2 = ?) AND is_active = 1""",
            (current_user["username"], current_user["username"])
        ).fetchone()
        
        if not session:
            return []
        
        # Get messages
        messages = conn.execute(
            "SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp",
            (session["id"],)
        ).fetchall()
        
        # Decrypt messages
        decrypted = []
        for msg in messages:
            try:
                plaintext = decrypt_with_aes_gcm(
                    msg["encrypted_content"],
                    msg["nonce"],
                    msg["tag"],
                    session["shared_secret"]
                )
                
                decrypted.append({
                    "id": msg["id"],
                    "content": plaintext.decode('utf-8'),
                    "sender_username": msg["sender"],
                    "is_mine": msg["sender"] == current_user["username"],
                    "message_type": msg["message_type"],
                    "timestamp": msg["timestamp"]
                })
            except Exception as e:
                logger.error(f"Failed to decrypt message: {e}")
        
        return decrypted
        
    finally:
        conn.close()

@app.get("/api/debug/database")
async def debug_database(current_user: dict = Depends(get_current_user)):
    """Debug endpoint to inspect database state"""
    conn = get_db()
    try:
        # Get table info
        tables = {}
        for table in ['users', 'quantum_keys', 'active_sessions', 'messages']:
            count = conn.execute(f"SELECT COUNT(*) as count FROM {table}").fetchone()
            tables[table] = count["count"]
        
        # Get current user's session
        session = conn.execute(
            """SELECT id, user1, user2, LENGTH(shared_secret) as secret_size 
               FROM active_sessions 
               WHERE (user1 = ? OR user2 = ?) AND is_active = 1""",
            (current_user["username"], current_user["username"])
        ).fetchone()
        
        # Get message count in session
        message_count = 0
        if session:
            msg_count = conn.execute(
                "SELECT COUNT(*) as count FROM messages WHERE session_id = ?",
                (session["id"],)
            ).fetchone()
            message_count = msg_count["count"]
        
        return {
            "database": DB_PATH,
            "tables": tables,
            "current_session": dict(session) if session else None,
            "messages_in_session": message_count,
            "websocket_connections": list(manager.active_connections.keys())
        }
        
    finally:
        conn.close()

@app.post("/api/session/terminate")
async def terminate_session(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    try:
        conn.execute(
            """UPDATE active_sessions SET is_active = 0 
               WHERE (user1 = ? OR user2 = ?) AND is_active = 1""",
            (current_user["username"], current_user["username"])
        )
        conn.commit()
        
        return {"message": "Session terminated"}
        
    finally:
        conn.close()

# WebSocket endpoint
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await manager.connect(websocket, username)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle heartbeat
            if data == '{"type":"heartbeat"}':
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(username)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)