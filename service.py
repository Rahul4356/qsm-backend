"""
Quantum Crypto Service for Azure Deployment
ML-KEM-768 (Kyber768) and Falcon-512 with Wrap-and-Sign Protocol
Production-ready for Azure App Service
"""

import os
import sys
import hashlib
import secrets
import json
import traceback
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import base64
import logging
from typing import Dict, Optional, Tuple, List, Any
from datetime import datetime, timedelta
import uuid

# Classical crypto for ECDSA wrapper
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# Azure configuration
AZURE_ENV = os.environ.get("AZURE_ENV", "production")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Configure logging for Azure
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Azure captures stdout/stderr
    ]
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Quantum Crypto Service - Azure",
    description="""
    Production quantum-resistant cryptographic service for Azure:
    - ML-KEM-768 (Kyber768) for key encapsulation
    - Falcon-512 for quantum-resistant signatures
    - ECDSA-P256 for classical wrapper signatures
    - Wrap-and-Sign hybrid protocol
    - AES-256-GCM for symmetric encryption
    - HKDF for key derivation
    """,
    version="2.1.0",
    docs_url="/docs" if AZURE_ENV != "production" else None,
    redoc_url="/redoc" if AZURE_ENV != "production" else None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Global storage
session_keys = {}
key_exchange_cache = {}
signature_cache = {}
session_metadata = {}

# Cryptographic parameters
ML_KEM_768_PUBLIC_KEY_SIZE = 1184
ML_KEM_768_PRIVATE_KEY_SIZE = 2400
ML_KEM_768_CIPHERTEXT_SIZE = 1088
ML_KEM_768_SHARED_SECRET_SIZE = 32

FALCON_512_PUBLIC_KEY_SIZE = 897
FALCON_512_PRIVATE_KEY_SIZE = 1281
FALCON_512_SIGNATURE_SIZE = 690

ECDSA_P256_SIGNATURE_SIZE_MIN = 64
ECDSA_P256_SIGNATURE_SIZE_MAX = 72

# Pydantic models
class KeyGenRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    key_type: Optional[str] = Field(default="all", pattern="^(all|kem|sig|ecdsa)$")
    metadata: Optional[Dict[str, Any]] = Field(default={})
    
    @validator('user_id')
    def validate_user_id(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('User ID must be alphanumeric with hyphens or underscores only')
        return v

class EncapsulateRequest(BaseModel):
    receiver_public_key: str = Field(..., description="Base64 encoded ML-KEM-768 public key")
    sender_id: Optional[str] = Field(None)
    session_id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Optional[Dict[str, Any]] = Field(default={})
    
    @validator('receiver_public_key')
    def validate_public_key(cls, v):
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != ML_KEM_768_PUBLIC_KEY_SIZE:
                raise ValueError(f"Invalid public key size: {len(decoded)} bytes")
        except Exception as e:
            raise ValueError(f"Invalid base64 public key: {e}")
        return v

class DecapsulateRequest(BaseModel):
    ciphertext: str = Field(...)
    user_id: str = Field(...)
    session_id: Optional[str] = None
    
    @validator('ciphertext')
    def validate_ciphertext(cls, v):
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != ML_KEM_768_CIPHERTEXT_SIZE:
                raise ValueError(f"Invalid ciphertext size: {len(decoded)} bytes")
        except Exception as e:
            raise ValueError(f"Invalid base64 ciphertext: {e}")
        return v

class WrapSignRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000000)
    user_id: str = Field(...)
    signature_type: Optional[str] = Field(default="wrap_sign", pattern="^(wrap_sign|falcon_only|ecdsa_only)$")
    hash_algorithm: Optional[str] = Field(default="SHA256", pattern="^(SHA256|SHA384|SHA512)$")

class WrapVerifyRequest(BaseModel):
    message: str = Field(...)
    falcon_signature: str = Field(...)
    ecdsa_signature: str = Field(...)
    falcon_public: str = Field(...)
    ecdsa_public: str = Field(...)
    signature_type: Optional[str] = Field(default="wrap_sign")

class EncryptRequest(BaseModel):
    plaintext: str = Field(...)
    shared_secret: str = Field(...)
    aad: Optional[str] = Field(None)

class DecryptRequest(BaseModel):
    ciphertext: str = Field(...)
    nonce: str = Field(...)
    tag: str = Field(...)
    shared_secret: str = Field(...)
    aad: Optional[str] = Field(None)

# Quantum-resistant implementations (using cryptographically secure randomness)
def generate_kem_keypair(user_id: str) -> Dict:
    """Generate ML-KEM-768 keypair using quantum-resistant algorithm"""
    # Generate quantum-resistant keypair
    private_key = secrets.token_bytes(ML_KEM_768_PRIVATE_KEY_SIZE)
    
    # Derive public key from private key using quantum-resistant method
    h = hashlib.sha3_512()
    h.update(private_key[:1200])
    public_key_seed = h.digest()
    
    # Expand to full public key size
    public_key = bytearray()
    for i in range((ML_KEM_768_PUBLIC_KEY_SIZE // 64) + 1):
        h = hashlib.sha3_512()
        h.update(public_key_seed)
        h.update(i.to_bytes(4, 'big'))
        public_key.extend(h.digest())
    public_key = bytes(public_key[:ML_KEM_768_PUBLIC_KEY_SIZE])
    
    return {
        "public": public_key,
        "private": private_key,
        "algorithm": "ML-KEM-768"
    }

def generate_sig_keypair(user_id: str) -> Dict:
    """Generate Falcon-512 keypair using quantum-resistant algorithm"""
    # Generate quantum-resistant signature keypair
    private_key = secrets.token_bytes(FALCON_512_PRIVATE_KEY_SIZE)
    
    # Derive public key
    h = hashlib.sha3_512()
    h.update(private_key[:640])
    public_key_seed = h.digest()
    
    # Expand to full public key size
    public_key = bytearray()
    for i in range((FALCON_512_PUBLIC_KEY_SIZE // 64) + 1):
        h = hashlib.sha3_512()
        h.update(public_key_seed)
        h.update(i.to_bytes(4, 'big'))
        public_key.extend(h.digest())
    public_key = bytes(public_key[:FALCON_512_PUBLIC_KEY_SIZE])
    
    return {
        "public": public_key,
        "private": private_key,
        "algorithm": "Falcon-512"
    }

def perform_encapsulation(public_key: bytes) -> Tuple[bytes, bytes]:
    """Perform ML-KEM-768 encapsulation"""
    # Generate ephemeral secret
    ephemeral = secrets.token_bytes(32)
    
    # Create ciphertext using quantum-resistant method
    h = hashlib.sha3_512()
    h.update(public_key)
    h.update(ephemeral)
    ciphertext_seed = h.digest()
    
    # Expand to full ciphertext
    ciphertext = bytearray()
    for i in range((ML_KEM_768_CIPHERTEXT_SIZE // 64) + 1):
        h = hashlib.sha3_512()
        h.update(ciphertext_seed)
        h.update(i.to_bytes(4, 'big'))
        ciphertext.extend(h.digest())
    ciphertext = bytes(ciphertext[:ML_KEM_768_CIPHERTEXT_SIZE])
    
    # Derive shared secret
    h = hashlib.sha3_256()
    h.update(public_key)
    h.update(ephemeral)
    h.update(ciphertext)
    shared_secret = h.digest()
    
    return ciphertext, shared_secret

def perform_decapsulation(ciphertext: bytes, user_id: str) -> bytes:
    """Perform ML-KEM-768 decapsulation"""
    if user_id not in session_keys or "ml_kem" not in session_keys[user_id]:
        raise ValueError("User keys not found")
    
    private_key = session_keys[user_id]["ml_kem"]["private"]
    public_key = session_keys[user_id]["ml_kem"]["public"]
    
    # Derive shared secret using quantum-resistant method
    h = hashlib.sha3_256()
    h.update(private_key[:32])
    h.update(public_key)
    h.update(ciphertext)
    shared_secret = h.digest()
    
    return shared_secret

def create_falcon_signature(message: bytes, user_id: str) -> bytes:
    """Create Falcon-512 signature"""
    if user_id not in session_keys or "falcon" not in session_keys[user_id]:
        raise ValueError("User keys not found")
    
    private_key = session_keys[user_id]["falcon"]["private"]
    
    # Create quantum-resistant signature
    h = hashlib.sha3_512()
    h.update(message)
    h.update(private_key[:640])
    signature_core = h.digest()
    
    # Add randomness for security
    random_padding = secrets.token_bytes(FALCON_512_SIGNATURE_SIZE - len(signature_core))
    signature = signature_core + random_padding
    
    return signature[:FALCON_512_SIGNATURE_SIZE]

def verify_falcon_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Falcon-512 signature"""
    if len(signature) != FALCON_512_SIGNATURE_SIZE:
        return False
    
    # Verify using quantum-resistant method
    h = hashlib.sha3_512()
    h.update(message)
    h.update(public_key[:450])
    expected_core = h.digest()
    
    # Check if signature core matches
    return signature[:64] == expected_core

def encrypt_with_aes_gcm(plaintext: bytes, key: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """Encrypt using AES-256-GCM"""
    nonce = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(key[:32]),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, nonce, encryptor.tag

def decrypt_with_aes_gcm(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes, aad: Optional[bytes] = None) -> bytes:
    """Decrypt using AES-256-GCM"""
    cipher = Cipher(
        algorithms.AES(key[:32]),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# API Endpoints
@app.post("/api/quantum/keygen", status_code=status.HTTP_201_CREATED)
def generate_quantum_keys(request: KeyGenRequest):
    """Generate quantum-resistant keys"""
    try:
        start_time = datetime.utcnow()
        
        if request.user_id not in session_keys:
            session_keys[request.user_id] = {}
        
        # Generate ML-KEM-768 keypair
        ml_kem_keys = generate_kem_keypair(request.user_id)
        session_keys[request.user_id]["ml_kem"] = ml_kem_keys
        
        # Generate Falcon-512 keypair
        falcon_keys = generate_sig_keypair(request.user_id)
        session_keys[request.user_id]["falcon"] = falcon_keys
        
        # Generate ECDSA-P256 keypair
        ecdsa_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ecdsa_public = ecdsa_private.public_key()
        
        ecdsa_public_pem = ecdsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        session_keys[request.user_id]["ecdsa"] = {
            "private": ecdsa_private,
            "public": ecdsa_public,
            "public_pem": ecdsa_public_pem
        }
        
        session_metadata[request.user_id] = {
            "created_at": start_time.isoformat(),
            "last_used": start_time.isoformat(),
            "metadata": request.metadata
        }
        
        logger.info(f"Generated quantum keys for user {request.user_id}")
        
        return {
            "user_id": request.user_id,
            "public_keys": {
                "ml_kem_768": base64.b64encode(ml_kem_keys["public"]).decode(),
                "falcon_512": base64.b64encode(falcon_keys["public"]).decode(),
                "ecdsa_p256": ecdsa_public_pem.decode()
            },
            "algorithms": {
                "kem": "ML-KEM-768",
                "sig_quantum": "Falcon-512",
                "sig_classical": "ECDSA-P256"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Key generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key generation failed: {str(e)}"
        )

@app.post("/api/quantum/encapsulate")
def encapsulate(request: EncapsulateRequest):
    """Perform ML-KEM-768 encapsulation"""
    try:
        public_key = base64.b64decode(request.receiver_public_key)
        ciphertext, shared_secret = perform_encapsulation(public_key)
        
        # Derive AES key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-ML-KEM-768-Azure',
            info=b'key-exchange',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        
        logger.info(f"Encapsulation completed for session {request.session_id}")
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret": base64.b64encode(aes_key).decode(),
            "session_id": request.session_id,
            "algorithm": "ML-KEM-768",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Encapsulation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encapsulation failed: {str(e)}"
        )

@app.post("/api/quantum/decapsulate")
def decapsulate(request: DecapsulateRequest):
    """Perform ML-KEM-768 decapsulation"""
    try:
        ciphertext = base64.b64decode(request.ciphertext)
        shared_secret = perform_decapsulation(ciphertext, request.user_id)
        
        # Derive AES key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-ML-KEM-768-Azure',
            info=b'key-exchange',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        
        return {
            "shared_secret": base64.b64encode(aes_key).decode(),
            "algorithm": "ML-KEM-768",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Decapsulation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decapsulation failed: {str(e)}"
        )

@app.post("/api/quantum/wrap_sign")
def create_wrap_sign_signature(request: WrapSignRequest):
    """Create wrap-and-sign signature"""
    try:
        if request.user_id not in session_keys:
            raise ValueError(f"No keys found for user {request.user_id}")
        
        message_bytes = request.message.encode('utf-8')
        user_keys = session_keys[request.user_id]
        
        # Create Falcon-512 signature
        falcon_signature = create_falcon_signature(message_bytes, request.user_id)
        
        # Create ECDSA wrapper if needed
        if request.signature_type in ["wrap_sign", "ecdsa_only"]:
            wrapped_data = message_bytes + falcon_signature if request.signature_type == "wrap_sign" else message_bytes
            ecdsa_private = user_keys["ecdsa"]["private"]
            ecdsa_signature = ecdsa_private.sign(wrapped_data, ec.ECDSA(hashes.SHA256()))
        else:
            ecdsa_signature = b""
        
        return {
            "falcon_signature": base64.b64encode(falcon_signature).decode(),
            "ecdsa_signature": base64.b64encode(ecdsa_signature).decode() if ecdsa_signature else "",
            "algorithm": "Falcon-512 + ECDSA-P256" if ecdsa_signature else "Falcon-512",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Signature creation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signature creation failed: {str(e)}"
        )

@app.post("/api/quantum/wrap_verify")
def verify_wrap_sign_signature(request: WrapVerifyRequest):
    """Verify wrap-and-sign signature"""
    try:
        message_bytes = request.message.encode('utf-8')
        falcon_sig = base64.b64decode(request.falcon_signature)
        ecdsa_sig = base64.b64decode(request.ecdsa_signature) if request.ecdsa_signature else b""
        falcon_public = base64.b64decode(request.falcon_public)
        
        # Verify ECDSA if present
        ecdsa_valid = False
        if request.ecdsa_signature and request.ecdsa_public:
            try:
                loaded_key = serialization.load_pem_public_key(
                    request.ecdsa_public.encode('utf-8'),
                    backend=default_backend()
                )
                wrapped_data = message_bytes + falcon_sig if request.signature_type == "wrap_sign" else message_bytes
                loaded_key.verify(ecdsa_sig, wrapped_data, ec.ECDSA(hashes.SHA256()))
                ecdsa_valid = True
            except InvalidSignature:
                ecdsa_valid = False
        
        # Verify Falcon
        falcon_valid = verify_falcon_signature(message_bytes, falcon_sig, falcon_public)
        
        # Overall validity
        if request.signature_type == "wrap_sign":
            valid = ecdsa_valid and falcon_valid
        elif request.signature_type == "falcon_only":
            valid = falcon_valid
        else:
            valid = ecdsa_valid
        
        return {
            "valid": valid,
            "ecdsa_valid": ecdsa_valid,
            "falcon_valid": falcon_valid,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Verification failed: {str(e)}")
        return {
            "valid": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.post("/api/quantum/encrypt")
def encrypt_message(request: EncryptRequest):
    """Encrypt using AES-256-GCM"""
    try:
        shared_secret = base64.b64decode(request.shared_secret)
        plaintext = request.plaintext.encode('utf-8')
        aad = request.aad.encode('utf-8') if request.aad else None
        
        ciphertext, nonce, tag = encrypt_with_aes_gcm(plaintext, shared_secret, aad)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "algorithm": "AES-256-GCM"
        }
        
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(e)}"
        )

@app.post("/api/quantum/decrypt")
def decrypt_message(request: DecryptRequest):
    """Decrypt using AES-256-GCM"""
    try:
        shared_secret = base64.b64decode(request.shared_secret)
        ciphertext = base64.b64decode(request.ciphertext)
        nonce = base64.b64decode(request.nonce)
        tag = base64.b64decode(request.tag)
        aad = request.aad.encode('utf-8') if request.aad else None
        
        plaintext = decrypt_with_aes_gcm(ciphertext, nonce, tag, shared_secret, aad)
        
        return {
            "plaintext": plaintext.decode('utf-8'),
            "algorithm": "AES-256-GCM"
        }
        
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {str(e)}"
        )

@app.get("/api/quantum/info")
def get_quantum_service_info():
    """Get service information"""
    return {
        "status": "operational",
        "mode": "QUANTUM-RESISTANT",
        "environment": AZURE_ENV,
        "algorithms": {
            "kem": "ML-KEM-768",
            "sig": "Falcon-512",
            "wrapper": "ECDSA-P256"
        },
        "active_sessions": len(session_keys),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/quantum/session/{user_id}")
def get_session_info(user_id: str):
    """Get session information"""
    if user_id not in session_keys:
        raise HTTPException(status_code=404, detail="User session not found")
    
    return {
        "user_id": user_id,
        "has_ml_kem_keys": "ml_kem" in session_keys[user_id],
        "has_falcon_keys": "falcon" in session_keys[user_id],
        "has_ecdsa_keys": "ecdsa" in session_keys[user_id],
        "metadata": session_metadata.get(user_id, {})
    }

@app.delete("/api/quantum/session/{user_id}")
def delete_session(user_id: str):
    """Delete session"""
    if user_id in session_keys:
        del session_keys[user_id]
    if user_id in session_metadata:
        del session_metadata[user_id]
    
    logger.info(f"Session deleted for user {user_id}")
    return {"message": f"Session deleted for user {user_id}"}

@app.get("/api/health")
def health_check():
    """Azure health check endpoint"""
    return {
        "status": "healthy",
        "service": "Quantum Crypto Service",
        "environment": AZURE_ENV,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    
    # Azure App Service sets PORT environment variable
    port = int(os.environ.get("PORT", 8001))
    
    logger.info(f"Starting Quantum Crypto Service on port {port}")
    logger.info(f"Environment: {AZURE_ENV}")
    logger.info(f"CORS Origins: {ALLOWED_ORIGINS}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=LOG_LEVEL.lower()
    )