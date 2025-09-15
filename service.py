"""
Production Quantum Cryptography Service
Using real liboqs library with ML-KEM-768 and Falcon-512
"""

import os
import logging
import secrets
import hashlib
from typing import Dict, Optional, Tuple, Any
from datetime import datetime
import base64

# Real quantum-safe cryptography
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProductionMLKEM768:
    """Production ML-KEM-768 using liboqs"""
    
    def __init__(self):
        self.algorithm = "Kyber768"
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 keypair using liboqs"""
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            public_key_bytes = kem.export_public_key()
            
        logger.info(f"Generated ML-KEM-768: pub={len(public_key_bytes)}B, priv={len(private_key)}B")
        return public_key_bytes, private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret using ML-KEM-768"""
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            
        logger.info(f"ML-KEM-768 encapsulated: ct={len(ciphertext)}B, ss={len(shared_secret)}B")
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate shared secret using ML-KEM-768"""
        with oqs.KeyEncapsulation(self.algorithm, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            
        logger.info(f"ML-KEM-768 decapsulated: ss={len(shared_secret)}B")
        return shared_secret

class ProductionFalcon512:
    """Production Falcon-512 using liboqs"""
    
    def __init__(self):
        self.algorithm = "Falcon-512"
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Falcon-512 keypair using liboqs"""
        with oqs.Signature(self.algorithm) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            public_key_bytes = sig.export_public_key()
            
        logger.info(f"Generated Falcon-512: pub={len(public_key_bytes)}B, priv={len(private_key)}B")
        return public_key_bytes, private_key
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message using Falcon-512"""
        with oqs.Signature(self.algorithm, secret_key=private_key) as sig:
            signature = sig.sign(message)
            
        logger.info(f"Falcon-512 signed: sig={len(signature)}B")
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify Falcon-512 signature"""
        try:
            with oqs.Signature(self.algorithm) as sig:
                is_valid = sig.verify(message, signature, public_key)
                
            logger.info(f"Falcon-512 verification: {is_valid}")
            return is_valid
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

class QuantumSecureProtocol:
    """Complete quantum-secure messaging protocol"""
    
    def __init__(self):
        self.kem = ProductionMLKEM768()
        self.sig = ProductionFalcon512()
        self.active_sessions = {}
        
    def create_user_identity(self, user_id: str) -> Dict[str, Any]:
        """Create complete quantum identity for user"""
        # Generate KEM keys for key exchange
        kem_public, kem_private = self.kem.generate_keypair()
        
        # Generate signature keys for authentication
        sig_public, sig_private = self.sig.generate_keypair()
        
        identity = {
            "user_id": user_id,
            "kem": {
                "public": base64.b64encode(kem_public).decode(),
                "private": base64.b64encode(kem_private).decode(),
                "algorithm": "ML-KEM-768"
            },
            "sig": {
                "public": base64.b64encode(sig_public).decode(),
                "private": base64.b64encode(sig_private).decode(),
                "algorithm": "Falcon-512"
            },
            "created_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Created quantum identity for user {user_id}")
        return identity
    
    def establish_secure_channel(
        self,
        initiator_id: str,
        responder_id: str,
        responder_kem_public: bytes
    ) -> Dict[str, Any]:
        """Establish quantum-secure channel between two parties"""
        
        # Initiator encapsulates to responder
        ciphertext, shared_secret = self.kem.encapsulate(responder_kem_public)
        
        # Create session
        session_id = f"{initiator_id}:{responder_id}:{secrets.token_hex(8)}"
        
        # Derive encryption and MAC keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'QMS-ML-KEM-768-v1',
            info=b'encryption+mac',
            backend=default_backend()
        )
        key_material = hkdf.derive(shared_secret)
        
        encryption_key = key_material[:32]
        mac_key = key_material[32:]
        
        self.active_sessions[session_id] = {
            "shared_secret": shared_secret,
            "encryption_key": encryption_key,
            "mac_key": mac_key,
            "initiator": initiator_id,
            "responder": responder_id,
            "created_at": datetime.utcnow().isoformat()
        }
        
        return {
            "session_id": session_id,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "algorithm": "ML-KEM-768",
            "key_size": len(shared_secret) * 8
        }
    
    def encrypt_message(
        self,
        plaintext: str,
        session_id: str,
        sender_sig_private: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Encrypt and optionally sign message"""
        
        if session_id not in self.active_sessions:
            raise ValueError(f"Invalid session: {session_id}")
        
        session = self.active_sessions[session_id]
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(session["encryption_key"])
        nonce = os.urandom(12)
        
        # Add authenticated data
        aad = f"{session_id}:{datetime.utcnow().isoformat()}".encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)
        
        result = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "aad": base64.b64encode(aad).decode(),
            "algorithm": "AES-256-GCM"
        }
        
        # Sign if private key provided
        if sender_sig_private:
            # Sign the entire encrypted payload
            payload = ciphertext + nonce + aad
            signature = self.sig.sign(payload, sender_sig_private)
            result["signature"] = base64.b64encode(signature).decode()
            result["signature_algorithm"] = "Falcon-512"
        
        return result
    
    def decrypt_message(
        self,
        encrypted_data: Dict[str, str],
        session_id: str,
        sender_sig_public: Optional[bytes] = None
    ) -> str:
        """Decrypt and verify message"""
        
        if session_id not in self.active_sessions:
            raise ValueError(f"Invalid session: {session_id}")
        
        session = self.active_sessions[session_id]
        
        # Decode components
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        aad = base64.b64decode(encrypted_data["aad"])
        
        # Verify signature if provided
        if "signature" in encrypted_data and sender_sig_public:
            signature = base64.b64decode(encrypted_data["signature"])
            payload = ciphertext + nonce + aad
            
            if not self.sig.verify(payload, signature, sender_sig_public):
                raise ValueError("Signature verification failed")
            
            logger.info("Message signature verified successfully")
        
        # Decrypt
        aesgcm = AESGCM(session["encryption_key"])
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
        
        return plaintext_bytes.decode('utf-8')

# Global instance
quantum_protocol = QuantumSecureProtocol()

# API functions for app.py
def initialize_quantum_system() -> Dict[str, Any]:
    """Initialize and test quantum cryptography system"""
    try:
        # List available algorithms
        kem_algs = oqs.get_enabled_kem_mechanisms()
        sig_algs = oqs.get_enabled_sig_mechanisms()
        
        # Verify our algorithms are available
        has_kyber = "Kyber768" in kem_algs
        has_falcon = "Falcon-512" in sig_algs
        
        return {
            "status": "operational",
            "ml_kem_768": has_kyber,
            "falcon_512": has_falcon,
            "available_kems": len(kem_algs),
            "available_sigs": len(sig_algs),
            "implementation": "liboqs",
            "version": oqs.oqs_version()
        }
    except Exception as e:
        logger.error(f"Quantum system initialization failed: {e}")
        return {"status": "error", "message": str(e)}

def create_quantum_identity(user_id: str) -> Dict:
    """Create quantum identity for user"""
    return quantum_protocol.create_user_identity(user_id)

def establish_quantum_channel(initiator: str, responder: str, responder_key: str) -> Dict:
    """Establish quantum-secure channel"""
    responder_key_bytes = base64.b64decode(responder_key)
    return quantum_protocol.establish_secure_channel(initiator, responder, responder_key_bytes)

def encrypt_quantum_message(message: str, session_id: str, sig_key: Optional[str] = None) -> Dict:
    """Encrypt message with quantum-derived keys"""
    sig_key_bytes = base64.b64decode(sig_key) if sig_key else None
    return quantum_protocol.encrypt_message(message, session_id, sig_key_bytes)

def decrypt_quantum_message(encrypted: Dict, session_id: str, sig_key: Optional[str] = None) -> str:
    """Decrypt message with quantum-derived keys"""
    sig_key_bytes = base64.b64decode(sig_key) if sig_key else None
    return quantum_protocol.decrypt_message(encrypted, session_id, sig_key_bytes)

# Initialize on import
logger.info("Production Quantum Cryptography System initialized")
status = initialize_quantum_system()
logger.info(f"System status: {status}")