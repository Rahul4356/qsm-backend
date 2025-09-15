"""
Quantum Cryptography Service Module
Real OQS Implementation with ML-KEM-768 and Falcon-512
Version: 3.0.0
"""

import os
import secrets
import hashlib
import logging
import struct
import time
from typing import Tuple, Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

# Quantum-safe cryptography
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("WARNING: OQS not installed. Install with: pip install liboqs-python")

# Standard cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= CONFIGURATION =============

class CryptoConfig:
    """Cryptographic configuration"""
    # Quantum algorithms
    KEM_ALGORITHMS = {
        "ML-KEM-768": {"security_level": 3, "public_key_size": 1184, "ciphertext_size": 1088},
        "Kyber768": {"security_level": 3, "public_key_size": 1184, "ciphertext_size": 1088},
        "ML-KEM-512": {"security_level": 1, "public_key_size": 800, "ciphertext_size": 768},
        "ML-KEM-1024": {"security_level": 5, "public_key_size": 1568, "ciphertext_size": 1568}
    }
    
    SIG_ALGORITHMS = {
        "Falcon-512": {"security_level": 1, "public_key_size": 897, "signature_size": 690},
        "Falcon-1024": {"security_level": 5, "public_key_size": 1793, "signature_size": 1330},
        "Dilithium3": {"security_level": 3, "public_key_size": 1952, "signature_size": 3293}
    }
    
    # Classical encryption
    AES_KEY_SIZE = 32  # 256 bits
    AES_NONCE_SIZE = 12  # 96 bits for GCM
    AES_TAG_SIZE = 16  # 128 bits
    
    # Key derivation
    HKDF_SALT = b'QMS-QUANTUM-SALT-v3'
    PBKDF2_ITERATIONS = 100000
    
    # Protocol versioning
    PROTOCOL_VERSION = b'\x03\x00'  # Version 3.0

# ============= EXCEPTIONS =============

class QuantumCryptoError(Exception):
    """Base exception for quantum crypto operations"""
    pass

class KeyGenerationError(QuantumCryptoError):
    """Key generation failed"""
    pass

class EncryptionError(QuantumCryptoError):
    """Encryption operation failed"""
    pass

class DecryptionError(QuantumCryptoError):
    """Decryption operation failed"""
    pass

class SignatureError(QuantumCryptoError):
    """Signature operation failed"""
    pass

# ============= DATA CLASSES =============

@dataclass
class QuantumKeyPair:
    """Quantum key pair container"""
    public_key: bytes
    private_key: bytes
    algorithm: str
    generated_at: datetime
    
    def serialize(self) -> bytes:
        """Serialize key pair"""
        return b''.join([
            CryptoConfig.PROTOCOL_VERSION,
            struct.pack('>I', len(self.algorithm)),
            self.algorithm.encode(),
            struct.pack('>I', len(self.public_key)),
            self.public_key,
            struct.pack('>I', len(self.private_key)),
            self.private_key
        ])
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'QuantumKeyPair':
        """Deserialize key pair"""
        offset = 2  # Skip version
        
        alg_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        algorithm = data[offset:offset+alg_len].decode()
        offset += alg_len
        
        pub_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        public_key = data[offset:offset+pub_len]
        offset += pub_len
        
        priv_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        private_key = data[offset:offset+priv_len]
        
        return cls(public_key, private_key, algorithm, datetime.utcnow())

@dataclass
class EncryptedMessage:
    """Encrypted message container"""
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    signature: Optional[bytes] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "tag": self.tag
        }
        if self.signature:
            result["signature"] = self.signature
        if self.metadata:
            result["metadata"] = self.metadata
        return result

# ============= QUANTUM CRYPTO CORE =============

class QuantumCryptoCore:
    """Core quantum cryptography operations using OQS"""
    
    def __init__(self, kem_algorithm: str = "ML-KEM-768", sig_algorithm: str = "Falcon-512"):
        if not OQS_AVAILABLE:
            raise QuantumCryptoError("OQS library not available")
        
        # Validate algorithms
        available_kems = oqs.get_enabled_kem_mechanisms()
        available_sigs = oqs.get_enabled_sig_mechanisms()
        
        # Fallback for ML-KEM to Kyber
        if kem_algorithm == "ML-KEM-768" and kem_algorithm not in available_kems:
            if "Kyber768" in available_kems:
                logger.info("ML-KEM-768 not available, using Kyber768")
                kem_algorithm = "Kyber768"
            else:
                raise KeyGenerationError(f"Neither ML-KEM-768 nor Kyber768 available")
        
        if kem_algorithm not in available_kems:
            raise KeyGenerationError(f"KEM algorithm {kem_algorithm} not available")
        
        if sig_algorithm not in available_sigs:
            raise KeyGenerationError(f"Signature algorithm {sig_algorithm} not available")
        
        self.kem_algorithm = kem_algorithm
        self.sig_algorithm = sig_algorithm
        
        logger.info(f"QuantumCryptoCore initialized: KEM={kem_algorithm}, SIG={sig_algorithm}")
    
    # Key Generation
    
    def generate_kem_keypair(self) -> QuantumKeyPair:
        """Generate quantum-safe KEM key pair"""
        try:
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
                # No export_public_key needed - public_key is already returned by generate_keypair()
            
            return QuantumKeyPair(
                public_key=public_key,
                private_key=private_key,
                algorithm=self.kem_algorithm,
                generated_at=datetime.utcnow()
            )
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate KEM keypair: {e}")
    
    def generate_sig_keypair(self) -> Dict[str, bytes]:
        """Generate signature keypair"""
        try:
            sig = oqs.Signature(self.sig_algorithm)
            # generate_keypair() returns (public_key, secret_key)
            public_key, secret_key = sig.generate_keypair()
            
            logger.info(f"Generated signature keypair: pub={len(public_key)} bytes, sec={len(secret_key)} bytes")
            
            return {
                "public": public_key,
                "private": secret_key,
                "algorithm": self.sig_algorithm
            }
        except Exception as e:
            logger.error(f"Signature keypair generation failed: {e}")
            raise KeyGenerationError(f"Failed to generate signature keypair: {e}")
    
    # Key Exchange
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret using KEM public key"""
        try:
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
        except Exception as e:
            raise EncryptionError(f"Encapsulation failed: {e}")
    
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate shared secret using KEM private key"""
        try:
            with oqs.KeyEncapsulation(self.kem_algorithm, secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
        except Exception as e:
            raise DecryptionError(f"Decapsulation failed: {e}")
    
    # Digital Signatures
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message using quantum-safe signature"""
        try:
            with oqs.Signature(self.sig_algorithm, secret_key=private_key) as sig:
                signature = sig.sign(message)
            return signature
        except Exception as e:
            raise SignatureError(f"Signing failed: {e}")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify quantum-safe signature"""
        try:
            with oqs.Signature(self.sig_algorithm) as sig:
                is_valid = sig.verify(message, signature, public_key)
            return is_valid
        except Exception:
            return False

# ============= CLASSICAL CRYPTO =============

class ClassicalCrypto:
    """Classical cryptography operations"""
    
    @staticmethod
    def derive_key(shared_secret: bytes, salt: bytes = CryptoConfig.HKDF_SALT, 
                   info: bytes = b"encryption", length: int = 32) -> bytes:
        """Derive encryption key from shared secret using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    @staticmethod
    def derive_key_pbkdf2(password: bytes, salt: bytes, iterations: int = CryptoConfig.PBKDF2_ITERATIONS) -> bytes:
        """Derive key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> EncryptedMessage:
        """Encrypt using AES-256-GCM"""
        try:
            aesgcm = AESGCM(key)
            nonce = os.urandom(CryptoConfig.AES_NONCE_SIZE)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            return EncryptedMessage(
                ciphertext=ciphertext[:-16],
                nonce=nonce,
                tag=ciphertext[-16:]
            )
        except Exception as e:
            raise EncryptionError(f"AES-GCM encryption failed: {e}")
    
    @staticmethod
    def decrypt_aes_gcm(encrypted: EncryptedMessage, key: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        try:
            aesgcm = AESGCM(key)
            ciphertext = encrypted.ciphertext + encrypted.tag
            plaintext = aesgcm.decrypt(encrypted.nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise DecryptionError(f"AES-GCM decryption failed: {e}")
    
    @staticmethod
    def encrypt_chacha20(plaintext: bytes, key: bytes) -> EncryptedMessage:
        """Encrypt using ChaCha20-Poly1305"""
        try:
            chacha = ChaCha20Poly1305(key)
            nonce = os.urandom(12)
            ciphertext = chacha.encrypt(nonce, plaintext, None)
            
            return EncryptedMessage(
                ciphertext=ciphertext[:-16],
                nonce=nonce,
                tag=ciphertext[-16:]
            )
        except Exception as e:
            raise EncryptionError(f"ChaCha20-Poly1305 encryption failed: {e}")
    
    @staticmethod
    def decrypt_chacha20(encrypted: EncryptedMessage, key: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        try:
            chacha = ChaCha20Poly1305(key)
            ciphertext = encrypted.ciphertext + encrypted.tag
            plaintext = chacha.decrypt(encrypted.nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise DecryptionError(f"ChaCha20-Poly1305 decryption failed: {e}")
    
    @staticmethod
    def compute_hmac(message: bytes, key: bytes) -> bytes:
        """Compute HMAC-SHA256"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()
    
    @staticmethod
    def verify_hmac(message: bytes, signature: bytes, key: bytes) -> bool:
        """Verify HMAC-SHA256"""
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(message)
            h.verify(signature)
            return True
        except Exception:
            return False

# ============= HYBRID CRYPTO SYSTEM =============

class HybridCryptoSystem:
    """Hybrid quantum-classical cryptography system"""
    
    def __init__(self, kem_algorithm: str = "ML-KEM-768", sig_algorithm: str = "Falcon-512"):
        self.quantum = QuantumCryptoCore(kem_algorithm, sig_algorithm)
        self.classical = ClassicalCrypto()
        
    def generate_full_keypair(self) -> Dict[str, QuantumKeyPair]:
        """Generate complete set of quantum keys"""
        return {
            "kem": self.quantum.generate_kem_keypair(),
            "sig": self.quantum.generate_sig_keypair()
        }
    
    def establish_secure_channel(self, receiver_public_key: bytes) -> Dict[str, Any]:
        """Establish secure channel with receiver"""
        # Encapsulate shared secret
        ciphertext, shared_secret = self.quantum.encapsulate(receiver_public_key)
        
        # Derive multiple keys from shared secret
        encryption_key = self.classical.derive_key(shared_secret, info=b"encryption")
        mac_key = self.classical.derive_key(shared_secret, info=b"mac")
        
        return {
            "ciphertext": ciphertext,
            "shared_secret": shared_secret,
            "encryption_key": encryption_key,
            "mac_key": mac_key,
            "timestamp": datetime.utcnow()
        }
    
    def encrypt_and_sign(self, plaintext: bytes, encryption_key: bytes, 
                        signing_key: Optional[bytes] = None,
                        use_chacha: bool = False) -> EncryptedMessage:
        """Encrypt message and optionally sign it"""
        # Encrypt
        if use_chacha:
            encrypted = self.classical.encrypt_chacha20(plaintext, encryption_key)
        else:
            encrypted = self.classical.encrypt_aes_gcm(plaintext, encryption_key)
        
        # Sign if key provided
        if signing_key:
            encrypted.signature = self.quantum.sign(plaintext, signing_key)
        
        # Add metadata
        encrypted.metadata = {
            "algorithm": "ChaCha20-Poly1305" if use_chacha else "AES-256-GCM",
            "signed": signing_key is not None,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return encrypted
    
    def decrypt_and_verify(self, encrypted: EncryptedMessage, decryption_key: bytes,
                          verification_key: Optional[bytes] = None,
                          use_chacha: bool = False) -> bytes:
        """Decrypt message and optionally verify signature"""
        # Decrypt
        if use_chacha:
            plaintext = self.classical.decrypt_chacha20(encrypted, decryption_key)
        else:
            plaintext = self.classical.decrypt_aes_gcm(encrypted, decryption_key)
        
        # Verify signature if provided
        if encrypted.signature and verification_key:
            if not self.quantum.verify(plaintext, encrypted.signature, verification_key):
                raise SignatureError("Signature verification failed")
        
        return plaintext

# ============= KEY MANAGEMENT =============

class KeyManager:
    """Quantum key management system"""
    
    def __init__(self):
        self.keys: Dict[str, Dict[str, QuantumKeyPair]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
    def store_user_keys(self, user_id: str, keys: Dict[str, QuantumKeyPair]):
        """Store user's quantum keys"""
        self.keys[user_id] = keys
        logger.info(f"Stored keys for user {user_id}")
    
    def get_user_keys(self, user_id: str) -> Optional[Dict[str, QuantumKeyPair]]:
        """Get user's quantum keys"""
        return self.keys.get(user_id)
    
    def store_session(self, session_id: str, session_data: Dict[str, Any]):
        """Store session data"""
        self.sessions[session_id] = session_data
        logger.info(f"Stored session {session_id}")
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        return self.sessions.get(session_id)
    
    def rotate_keys(self, user_id: str, crypto_system: HybridCryptoSystem) -> Dict[str, QuantumKeyPair]:
        """Rotate user's quantum keys"""
        new_keys = crypto_system.generate_full_keypair()
        self.keys[user_id] = new_keys
        logger.info(f"Rotated keys for user {user_id}")
        return new_keys

# ============= MESSAGE PROTOCOL =============

class MessageProtocol:
    """Quantum-safe messaging protocol"""
    
    def __init__(self, crypto_system: HybridCryptoSystem):
        self.crypto = crypto_system
        self.key_manager = KeyManager()
    
    def create_secure_message(self, content: str, sender_id: str, receiver_id: str,
                            message_type: str = "standard") -> Dict[str, Any]:
        """Create quantum-encrypted message"""
        # Get sender's keys
        sender_keys = self.key_manager.get_user_keys(sender_id)
        if not sender_keys:
            raise ValueError(f"No keys found for sender {sender_id}")
        
        # Get or create session
        session_id = f"{min(sender_id, receiver_id)}:{max(sender_id, receiver_id)}"
        session = self.key_manager.get_session(session_id)
        
        if not session:
            raise ValueError(f"No session found for {session_id}")
        
        # Prepare message
        message_bytes = content.encode('utf-8')
        
        # Add timestamp and sender info
        full_message = b''.join([
            CryptoConfig.PROTOCOL_VERSION,
            struct.pack('>Q', int(time.time())),
            struct.pack('>I', len(sender_id)),
            sender_id.encode(),
            struct.pack('>I', len(message_bytes)),
            message_bytes
        ])
        
        # Encrypt and sign if critical
        signing_key = sender_keys["sig"].private_key if message_type == "critical" else None
        encrypted = self.crypto.encrypt_and_sign(
            full_message,
            session["encryption_key"],
            signing_key
        )
        
        return {
            "session_id": session_id,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "encrypted_message": encrypted.to_dict(),
            "message_type": message_type,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def process_secure_message(self, message_data: Dict[str, Any], 
                              receiver_id: str) -> str:
        """Process and decrypt quantum-encrypted message"""
        # Get session
        session = self.key_manager.get_session(message_data["session_id"])
        if not session:
            raise ValueError("Session not found")
        
        # Get sender's public key for verification if signed
        verification_key = None
        if message_data["message_type"] == "critical":
            sender_keys = self.key_manager.get_user_keys(message_data["sender_id"])
            if sender_keys:
                verification_key = sender_keys["sig"].public_key
        
        # Reconstruct encrypted message
        encrypted = EncryptedMessage(
            ciphertext=message_data["encrypted_message"]["ciphertext"],
            nonce=message_data["encrypted_message"]["nonce"],
            tag=message_data["encrypted_message"]["tag"],
            signature=message_data["encrypted_message"].get("signature")
        )
        
        # Decrypt and verify
        decrypted = self.crypto.decrypt_and_verify(
            encrypted,
            session["encryption_key"],
            verification_key
        )
        
        # Parse message
        offset = 2  # Skip version
        timestamp = struct.unpack('>Q', decrypted[offset:offset+8])[0]
        offset += 8
        
        sender_len = struct.unpack('>I', decrypted[offset:offset+4])[0]
        offset += 4
        sender = decrypted[offset:offset+sender_len].decode()
        offset += sender_len
        
        msg_len = struct.unpack('>I', decrypted[offset:offset+4])[0]
        offset += 4
        message = decrypted[offset:offset+msg_len].decode()
        
        return message

# ============= PUBLIC API =============

# Initialize global system
if OQS_AVAILABLE:
    _default_crypto_system = HybridCryptoSystem()
    _default_key_manager = KeyManager()
    _default_protocol = MessageProtocol(_default_crypto_system)
else:
    _default_crypto_system = None
    _default_key_manager = None
    _default_protocol = None

def initialize_quantum_crypto(kem_algorithm: str = "ML-KEM-768", 
                             sig_algorithm: str = "Falcon-512") -> bool:
    """Initialize quantum cryptography system"""
    global _default_crypto_system, _default_key_manager, _default_protocol
    
    if not OQS_AVAILABLE:
        logger.error("OQS not available")
        return False
    
    try:
        _default_crypto_system = HybridCryptoSystem(kem_algorithm, sig_algorithm)
        _default_key_manager = KeyManager()
        _default_protocol = MessageProtocol(_default_crypto_system)
        logger.info(f"Quantum crypto initialized: KEM={kem_algorithm}, SIG={sig_algorithm}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize quantum crypto: {e}")
        return False

def generate_quantum_keys(user_id: str) -> Dict[str, Any]:
    """Generate quantum keys for user"""
    if not _default_crypto_system:
        raise QuantumCryptoError("Quantum crypto not initialized")
    
    keys = _default_crypto_system.generate_full_keypair()
    _default_key_manager.store_user_keys(user_id, keys)
    
    return {
        "user_id": user_id,
        "ml_kem_public": keys["kem"].public_key,
        "ml_kem_private": keys["kem"].private_key,
        "falcon_public": keys["sig"].public_key,
        "falcon_private": keys["sig"].private_key,
        "algorithm": {
            "kem": keys["kem"].algorithm,
            "sig": keys["sig"].algorithm
        },
        "generated_at": datetime.utcnow().isoformat()
    }

def establish_quantum_session(sender_id: str, receiver_id: str,
                             receiver_kem_public: bytes) -> Dict[str, Any]:
    """Establish quantum-secure session"""
    if not _default_crypto_system:
        raise QuantumCryptoError("Quantum crypto not initialized")
    
    # Create secure channel
    channel = _default_crypto_system.establish_secure_channel(receiver_kem_public)
    
    # Store session
    session_id = f"{min(sender_id, receiver_id)}:{max(sender_id, receiver_id)}:{secrets.token_hex(8)}"
    _default_key_manager.store_session(session_id, channel)
    
    return {
        "session_id": session_id,
        "ciphertext": channel["ciphertext"],
        "shared_secret": channel["shared_secret"],
        "algorithm": _default_crypto_system.quantum.kem_algorithm
    }

def encrypt_with_quantum_key(message: str, shared_secret: bytes,
                            sender_sig_private: Optional[bytes] = None) -> Dict[str, str]:
    """Encrypt message using quantum-derived key"""
    if not _default_crypto_system:
        raise QuantumCryptoError("Quantum crypto not initialized")
    
    import base64
    
    # Derive encryption key
    encryption_key = _default_crypto_system.classical.derive_key(shared_secret)
    
    # Encrypt and optionally sign
    encrypted = _default_crypto_system.encrypt_and_sign(
        message.encode('utf-8'),
        encryption_key,
        sender_sig_private
    )
    
    result = {
        "encrypted_content": base64.b64encode(encrypted.ciphertext).decode(),
        "nonce": base64.b64encode(encrypted.nonce).decode(),
        "tag": base64.b64encode(encrypted.tag).decode()
    }
    
    if encrypted.signature:
        result["signature"] = base64.b64encode(encrypted.signature).decode()
    
    return result

def decrypt_with_quantum_key(encrypted_data: Dict[str, str], shared_secret: bytes,
                            sender_sig_public: Optional[bytes] = None) -> str:
    """Decrypt message using quantum-derived key"""
    if not _default_crypto_system:
        raise QuantumCryptoError("Quantum crypto not initialized")
    
    import base64
    
    # Derive decryption key
    decryption_key = _default_crypto_system.classical.derive_key(shared_secret)
    
    # Reconstruct encrypted message
    encrypted = EncryptedMessage(
        ciphertext=base64.b64decode(encrypted_data["encrypted_content"]),
        nonce=base64.b64decode(encrypted_data["nonce"]),
        tag=base64.b64decode(encrypted_data["tag"]),
        signature=base64.b64decode(encrypted_data["signature"]) if "signature" in encrypted_data else None
    )
    
    # Decrypt and optionally verify
    plaintext = _default_crypto_system.decrypt_and_verify(
        encrypted,
        decryption_key,
        sender_sig_public
    )
    
    return plaintext.decode('utf-8')

def get_algorithm_info() -> Dict[str, Any]:
    """Get information about available algorithms"""
    if not OQS_AVAILABLE:
        return {"error": "OQS not available"}
    
    return {
        "oqs_version": oqs.oqs_version(),
        "available_kems": oqs.get_enabled_kem_mechanisms(),
        "available_sigs": oqs.get_enabled_sig_mechanisms(),
        "configured": {
            "kem": _default_crypto_system.quantum.kem_algorithm if _default_crypto_system else None,
            "sig": _default_crypto_system.quantum.sig_algorithm if _default_crypto_system else None
        }
    }

def benchmark_quantum_operations(iterations: int = 100) -> Dict[str, float]:
    """Benchmark quantum crypto operations"""
    if not _default_crypto_system:
        raise QuantumCryptoError("Quantum crypto not initialized")
    
    import time
    results = {}
    
    # Benchmark KEM key generation
    start = time.time()
    for _ in range(iterations):
        _default_crypto_system.quantum.generate_kem_keypair()
    results["kem_keygen_ms"] = (time.time() - start) * 1000 / iterations
    
    # Benchmark signature key generation
    start = time.time()
    for _ in range(iterations):
        _default_crypto_system.quantum.generate_sig_keypair()
    results["sig_keygen_ms"] = (time.time() - start) * 1000 / iterations
    
    # Benchmark encapsulation
    kem_keys = _default_crypto_system.quantum.generate_kem_keypair()
    start = time.time()
    for _ in range(iterations):
        _default_crypto_system.quantum.encapsulate(kem_keys.public_key)
    results["encapsulation_ms"] = (time.time() - start) * 1000 / iterations
    
    # Benchmark signing
    sig_keys = _default_crypto_system.quantum.generate_sig_keypair()
    message = b"Benchmark message"
    start = time.time()
    for _ in range(iterations):
        _default_crypto_system.quantum.sign(message, sig_keys.private_key)
    results["signing_ms"] = (time.time() - start) * 1000 / iterations
    
    return results

# ============= TESTING =============

def test_quantum_crypto():
    """Comprehensive test of quantum crypto operations"""
    if not OQS_AVAILABLE:
        print("OQS not available - skipping tests")
        return False
    
    print("\n=== Testing Quantum Cryptography ===\n")
    
    try:
        # Initialize
        initialize_quantum_crypto()
        print("✓ Initialized quantum crypto system")
        
        # Generate keys for two users
        alice_keys = generate_quantum_keys("alice")
        bob_keys = generate_quantum_keys("bob")
        print(f"✓ Generated keys for Alice and Bob")
        print(f"  ML-KEM public key size: {len(alice_keys['ml_kem_public'])} bytes")
        print(f"  Falcon public key size: {len(alice_keys['falcon_public'])} bytes")
        
        # Establish session
        session = establish_quantum_session(
            "alice", "bob",
            bob_keys["ml_kem_public"]
        )
        print(f"✓ Established quantum session")
        print(f"  Session ID: {session['session_id']}")
        print(f"  Shared secret size: {len(session['shared_secret'])} bytes")
        
        # Test encryption/decryption
        message = "Hello Quantum World! 🔐🚀"
        
        # Standard message
        encrypted = encrypt_with_quantum_key(message, session["shared_secret"])
        decrypted = decrypt_with_quantum_key(encrypted, session["shared_secret"])
        assert message == decrypted
        print(f"✓ Standard encryption/decryption successful")
        
        # Critical message with signature
        encrypted_signed = encrypt_with_quantum_key(
            message,
            session["shared_secret"],
            alice_keys["falcon_private"]
        )
        decrypted_signed = decrypt_with_quantum_key(
            encrypted_signed,
            session["shared_secret"],
            alice_keys["falcon_public"]
        )
        assert message == decrypted_signed
        print(f"✓ Signed encryption/decryption successful")
        
        # Test signature verification with wrong key (should fail)
        try:
            decrypt_with_quantum_key(
                encrypted_signed,
                session["shared_secret"],
                bob_keys["falcon_public"]  # Wrong public key
            )
            print("✗ Signature verification should have failed")
            return False
        except SignatureError:
            print("✓ Signature verification correctly rejected invalid key")
        
        # Benchmark
        print("\n=== Performance Benchmarks ===")
        benchmarks = benchmark_quantum_operations(50)
        for op, time_ms in benchmarks.items():
            print(f"  {op}: {time_ms:.2f} ms")
        
        print("\n✅ All tests passed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# Initialize on module import if OQS is available
if OQS_AVAILABLE:
    initialize_quantum_crypto()
    logger.info("Quantum cryptography service ready")

if __name__ == "__main__":
    # Run tests when module is executed directly
    test_quantum_crypto()