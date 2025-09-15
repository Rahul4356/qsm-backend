#!/usr/bin/env python3
"""
Quantum Encryption Proof - Local Demonstration
This script proves that quantum encryption is working locally
"""

import sys
import os
import json
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    print("🔐 QUANTUM ENCRYPTION PROOF - LOCAL TEST 🔐")
    print("=" * 60)
    
    try:
        # Import our quantum crypto service
        from service import (
            generate_kem_keypair,
            generate_sig_keypair,
            perform_encapsulation,
            perform_decapsulation,
            encrypt_with_aes_gcm,
            decrypt_with_aes_gcm,
            create_falcon_signature,
            verify_falcon_signature
        )
        
        print("✅ Quantum crypto modules imported successfully")
        print()
        
        # Test 1: ML-KEM Key Exchange
        print("🔑 Test 1: ML-KEM-768 Key Exchange")
        print("-" * 40)
        
        # Generate keypair
        kem_keys = generate_kem_keypair("test_user")
        kem_public = kem_keys['public']
        kem_private = kem_keys['private']
        print(f"✅ Generated ML-KEM-768 keypair")
        print(f"   Public key size: {len(kem_public)} bytes")
        print(f"   Private key size: {len(kem_private)} bytes")
        print(f"   Public key preview: {kem_public.hex()[:32]}...")
        
        # Key encapsulation
        ciphertext, shared_secret = perform_encapsulation(kem_public)
        print(f"✅ Key encapsulation successful")
        print(f"   Shared secret size: {len(shared_secret)} bytes") 
        print(f"   Ciphertext size: {len(ciphertext)} bytes")
        print(f"   Shared secret: {shared_secret.hex()[:32]}...")
        
        # Key decapsulation
        recovered_secret = perform_decapsulation(ciphertext, kem_private, kem_public)
        key_exchange_success = shared_secret == recovered_secret
        print(f"✅ Key decapsulation: {'SUCCESS' if key_exchange_success else 'FAILED'}")
        print()
        
        # Test 2: Message Encryption
        print("🔒 Test 2: AES-256-GCM Message Encryption")
        print("-" * 40)
        
        test_message = "🛡️ This is a quantum-encrypted message proving end-to-end security! 🛡️"
        message_bytes = test_message.encode('utf-8')
        
        # Encrypt message
        encrypted_content, nonce, tag = encrypt_with_aes_gcm(message_bytes, shared_secret)
        print(f"✅ Message encrypted successfully")
        print(f"   Original message: {test_message}")
        print(f"   Original size: {len(message_bytes)} bytes")
        print(f"   Encrypted size: {len(encrypted_content)} bytes")
        print(f"   Encrypted content: {encrypted_content.hex()}")
        print(f"   Nonce: {nonce.hex()}")
        print(f"   Auth tag: {tag.hex()}")
        
        # Decrypt message
        decrypted_content = decrypt_with_aes_gcm(encrypted_content, nonce, tag, shared_secret)
        decrypted_message = decrypted_content.decode('utf-8')
        encryption_success = test_message == decrypted_message
        
        print(f"✅ Message decrypted: {'SUCCESS' if encryption_success else 'FAILED'}")
        print(f"   Decrypted message: {decrypted_message}")
        print()
        
        # Try with recovered secret to test key exchange
        try:
            recovered_decrypted = decrypt_with_aes_gcm(encrypted_content, nonce, tag, recovered_secret)
            key_exchange_encryption_test = test_message == recovered_decrypted.decode('utf-8')
            print(f"✅ Key exchange test: {'SUCCESS' if key_exchange_encryption_test else 'FAILED'}")
        except Exception as e:
            print(f"❌ Key exchange test failed: {e}")
            key_exchange_encryption_test = False
        
        # Test 3: Digital Signatures
        print("✍️ Test 3: Falcon-512 Digital Signatures")
        print("-" * 40)
        
        # Generate signature keypair
        falcon_keys = generate_sig_keypair("test_user")
        falcon_public = falcon_keys['public']
        falcon_private = falcon_keys['private']
        print(f"✅ Generated Falcon-512 signature keypair")
        print(f"   Public key size: {len(falcon_public)} bytes")
        print(f"   Private key size: {len(falcon_private)} bytes")
        
        # Sign message
        signature = create_falcon_signature(message_bytes, falcon_private)
        print(f"✅ Message signed successfully")
        print(f"   Signature size: {len(signature)} bytes")
        print(f"   Signature: {signature.hex()[:64]}...")
        
        # Verify signature
        signature_valid = verify_falcon_signature(message_bytes, signature, falcon_public)
        print(f"✅ Signature verification: {'VALID' if signature_valid else 'INVALID'}")
        print()
        
        # Summary
        print("📊 ENCRYPTION PROOF SUMMARY")
        print("=" * 60)
        
        proof_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "quantum_algorithms": {
                "key_exchange": "ML-KEM-768 (NIST Post-Quantum)",
                "signatures": "Falcon-512 (Quantum-Resistant)", 
                "symmetric_encryption": "AES-256-GCM"
            },
            "test_results": {
                "key_exchange": "SUCCESS" if key_exchange_success else "FAILED",
                "encryption_decryption": "SUCCESS" if encryption_success else "FAILED", 
                "digital_signatures": "VALID" if signature_valid else "INVALID"
            },
            "encryption_proof": {
                "original_message": test_message,
                "encrypted_hex": encrypted_content.hex(),
                "nonce_hex": nonce.hex(),
                "auth_tag_hex": tag.hex(),
                "decrypted_message": decrypted_message,
                "key_sizes": {
                    "ml_kem_public": len(kem_public),
                    "ml_kem_private": len(kem_private), 
                    "falcon_public": len(falcon_public),
                    "falcon_private": len(falcon_private),
                    "shared_secret": len(shared_secret),
                    "signature": len(signature)
                }
            }
        }
        
        # Display results
        all_tests_passed = all([
            key_exchange_success,
            encryption_success, 
            signature_valid
        ])
        
        if all_tests_passed:
            print("🎉 ALL TESTS PASSED - QUANTUM ENCRYPTION IS WORKING! 🎉")
        else:
            print("❌ SOME TESTS FAILED")
            
        print()
        print("🔍 Detailed proof data:")
        print(json.dumps(proof_data, indent=2))
        
        # Create proof file
        with open("local_encryption_proof.json", "w") as f:
            json.dump(proof_data, f, indent=2)
        print()
        print("💾 Proof data saved to: local_encryption_proof.json")
        
        return all_tests_passed
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all dependencies are installed:")
        print("pip install -r requirements.txt")
        return False
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)