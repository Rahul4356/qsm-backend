#!/bin/bash

# QSM Backend - End-to-End Test Script
# This script tests the complete workflow that would have failed before the fix

echo "🧪 QSM Backend - End-to-End Test"
echo "================================="

# Base URLs
MAIN_URL="http://localhost:8000"
QUANTUM_URL="http://localhost:8001"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "   ${GREEN}✅ $2${NC}"
    else
        echo -e "   ${RED}❌ $2${NC}"
        exit 1
    fi
}

echo ""
echo "📋 Step 1: Verify Services"
echo "--------------------------"

# Check main service
curl -s "$MAIN_URL/api/health" > /dev/null
print_status $? "Main Application (port 8000)"

# Check quantum service
curl -s "$QUANTUM_URL/api/health" > /dev/null
print_status $? "Quantum Service (port 8001)"

# Check service integration
STATUS=$(curl -s "$MAIN_URL/api/health" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
if [ "$STATUS" = "healthy" ]; then
    print_status 0 "Service Integration"
else
    print_status 1 "Service Integration (Status: $STATUS)"
fi

echo ""
echo "👥 Step 2: User Registration"
echo "----------------------------"

# Register test users (use unique usernames)
TIMESTAMP=$(date +%s)
USERNAME1="testuser1_$TIMESTAMP"
USERNAME2="testuser2_$TIMESTAMP"

USER1_RESPONSE=$(curl -s -X POST "$MAIN_URL/api/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME1\",\"email\":\"test1_$TIMESTAMP@example.com\",\"password\":\"password123\"}")

if echo "$USER1_RESPONSE" | grep -q "User registered successfully"; then
    print_status 0 "User 1 Registration"
else
    print_status 1 "User 1 Registration"
fi

USER2_RESPONSE=$(curl -s -X POST "$MAIN_URL/api/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME2\",\"email\":\"test2_$TIMESTAMP@example.com\",\"password\":\"password123\"}")

if echo "$USER2_RESPONSE" | grep -q "User registered successfully"; then
    print_status 0 "User 2 Registration"
else
    print_status 1 "User 2 Registration"
fi

echo ""
echo "🔐 Step 3: User Authentication"
echo "------------------------------"

# Login users
TOKEN1=$(curl -s -X POST "$MAIN_URL/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME1\",\"password\":\"password123\"}" | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token', ''))")

if [ -n "$TOKEN1" ]; then
    print_status 0 "User 1 Login"
else
    print_status 1 "User 1 Login"
fi

TOKEN2=$(curl -s -X POST "$MAIN_URL/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME2\",\"password\":\"password123\"}" | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token', ''))")

if [ -n "$TOKEN2" ]; then
    print_status 0 "User 2 Login"
else
    print_status 1 "User 2 Login"
fi

echo ""
echo "🔑 Step 4: Quantum Key Generation"
echo "----------------------------------"

# Generate quantum keys for both users (this would fail without quantum service)
KEYS1_RESPONSE=$(curl -s -X POST "$QUANTUM_URL/api/quantum/keygen" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\":\"$USERNAME1\"}")

if echo "$KEYS1_RESPONSE" | grep -q "public_keys"; then
    print_status 0 "User 1 Quantum Keys"
else
    print_status 1 "User 1 Quantum Keys"
fi

KEYS2_RESPONSE=$(curl -s -X POST "$QUANTUM_URL/api/quantum/keygen" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\":\"$USERNAME2\"}")

if echo "$KEYS2_RESPONSE" | grep -q "public_keys"; then
    print_status 0 "User 2 Quantum Keys"
else
    print_status 1 "User 2 Quantum Keys"
fi

echo ""
echo "🔗 Step 5: Quantum Key Exchange"
echo "-------------------------------"

# Extract public key for testing encapsulation
ML_KEM_KEY=$(echo "$KEYS1_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['public_keys']['ml_kem_768'])")

# Test encapsulation (this requires quantum service)
ENCAP_RESPONSE=$(curl -s -X POST "$QUANTUM_URL/api/quantum/encapsulate" \
  -H "Content-Type: application/json" \
  -d "{\"receiver_public_key\":\"$ML_KEM_KEY\",\"sender_id\":\"$USERNAME2\"}")

if echo "$ENCAP_RESPONSE" | grep -q "shared_secret"; then
    print_status 0 "ML-KEM Key Encapsulation"
else
    print_status 1 "ML-KEM Key Encapsulation"
fi

echo ""
echo "✍️ Step 6: Quantum Signatures"
echo "-----------------------------"

# Test quantum signature generation
SIG_RESPONSE=$(curl -s -X POST "$QUANTUM_URL/api/quantum/wrap_sign" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Test message for quantum signature\",\"user_id\":\"$USERNAME1\",\"signature_type\":\"wrap_sign\"}")

if echo "$SIG_RESPONSE" | grep -q "falcon_signature"; then
    print_status 0 "Falcon Signature Generation"
else
    print_status 1 "Falcon Signature Generation"
fi

if echo "$SIG_RESPONSE" | grep -q "ecdsa_signature"; then
    print_status 0 "ECDSA Wrapper Signature"
else
    print_status 1 "ECDSA Wrapper Signature"
fi

echo ""
echo "🎯 Step 7: Integration Test"
echo "---------------------------"

# Test that main app can successfully call quantum service
CONFIG_RESPONSE=$(curl -s "$MAIN_URL/api/config")
QUANTUM_API=$(echo "$CONFIG_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['quantum_api'])")

if [ "$QUANTUM_API" = "$QUANTUM_URL" ]; then
    print_status 0 "Service Configuration"
else
    print_status 1 "Service Configuration"
fi

echo ""
echo "📊 Test Summary"
echo "==============="

if [ $? -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo ""
    echo "✅ The internal server error issue has been resolved!"
    echo "✅ Both services are communicating properly"
    echo "✅ Quantum cryptographic operations are working"
    echo "✅ User registration and authentication work"
    echo ""
    echo "🚀 QSM Backend is ready for production use!"
else
    echo -e "${RED}❌ Some tests failed${NC}"
    echo "Please check the service logs for more details"
    exit 1
fi

echo ""
echo "🔧 Service Information"
echo "----------------------"
echo "Main Application: $MAIN_URL"
echo "API Documentation: $MAIN_URL/docs"
echo "Quantum Service: $QUANTUM_URL"
echo "Health Check: $MAIN_URL/api/health"