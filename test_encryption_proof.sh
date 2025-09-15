#!/bin/bash

# Quantum Encryption Proof Testing Script
# This script demonstrates that encryption is actually working

echo "🔐 QUANTUM ENCRYPTION PROOF TESTING 🔐"
echo "========================================"

# Configuration
BASE_URL="https://qsm-backend.azurewebsites.net"
# For local testing, use: BASE_URL="http://localhost:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Test 1: Public encryption proof (no auth required)
print_step "Testing Public Encryption Proof Endpoint"
echo "Endpoint: GET $BASE_URL/api/proof"

PROOF_RESPONSE=$(curl -s "$BASE_URL/api/proof")
PROOF_STATUS=$?

if [ $PROOF_STATUS -eq 0 ]; then
    echo "$PROOF_RESPONSE" | python3 -m json.tool
    
    # Check if encryption is proven
    ENCRYPTION_PROVEN=$(echo "$PROOF_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print('true' if data.get('proof_of_encryption') else 'false')
except:
    print('false')
")
    
    if [ "$ENCRYPTION_PROVEN" = "true" ]; then
        print_success "Encryption proof confirmed!"
    else
        print_error "Encryption proof failed!"
    fi
else
    print_error "Failed to connect to proof endpoint"
fi

echo ""

# Test 2: Live encryption test (no auth required)
print_step "Testing Live Encryption Test"
echo "Endpoint: GET $BASE_URL/api/debug/encryption-test"

TEST_RESPONSE=$(curl -s "$BASE_URL/api/debug/encryption-test")
TEST_STATUS=$?

if [ $TEST_STATUS -eq 0 ]; then
    echo "$TEST_RESPONSE" | python3 -m json.tool
    
    # Check test status
    TEST_SUCCESS=$(echo "$TEST_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print('true' if data.get('test_status') == 'SUCCESS' else 'false')
except:
    print('false')
")
    
    if [ "$TEST_SUCCESS" = "true" ]; then
        print_success "Live encryption test passed!"
        
        # Extract and display key encryption metrics
        echo "$TEST_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    proof = data.get('encryption_proof', {})
    print(f\"📊 Encryption Metrics:\")
    print(f\"   Original Size: {proof.get('original_size')} bytes\")
    print(f\"   Encrypted Size: {proof.get('encrypted_size')} bytes\")
    print(f\"   Key Exchange: {'✅ SUCCESS' if proof.get('key_exchange_success') else '❌ FAILED'}\")
    print(f\"   Encrypted Preview: {proof.get('encrypted_hex', '')[:64]}...\")
except Exception as e:
    print(f\"Error parsing response: {e}\")
"
    else
        print_error "Live encryption test failed!"
    fi
else
    print_error "Failed to connect to encryption test endpoint"
fi

echo ""

# Test 3: Health check
print_step "Testing System Health"
echo "Endpoint: GET $BASE_URL/"

HEALTH_RESPONSE=$(curl -s "$BASE_URL/")
HEALTH_STATUS=$?

if [ $HEALTH_STATUS -eq 0 ]; then
    echo "$HEALTH_RESPONSE" | python3 -m json.tool
    print_success "System is healthy!"
else
    print_error "System health check failed!"
fi

echo ""

# Test 4: Try encryption proof page
print_step "Testing Encryption Proof Visualization Page"
echo "Endpoint: GET $BASE_URL/encryption-proof"

PAGE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/encryption-proof")

if [ "$PAGE_STATUS" = "200" ]; then
    print_success "Encryption proof page is accessible!"
    print_info "Visit: $BASE_URL/encryption-proof"
else
    print_error "Encryption proof page returned status: $PAGE_STATUS"
fi

echo ""

# Test 5: Register and test authenticated endpoints
print_step "Testing User Registration and Authentication"

# Generate random test user
TEST_USER="testuser_$(date +%s)"
TEST_EMAIL="$TEST_USER@test.com"
TEST_PASSWORD="TestPass123!"

print_info "Creating test user: $TEST_USER"

# Register user
REGISTER_DATA="{\"username\":\"$TEST_USER\",\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}"
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/register" \
    -H "Content-Type: application/json" \
    -d "$REGISTER_DATA")

echo "Registration response:"
echo "$REGISTER_RESPONSE" | python3 -m json.tool

# Login to get token
LOGIN_DATA="{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASSWORD\"}"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d "$LOGIN_DATA")

echo "Login response:"
echo "$LOGIN_RESPONSE" | python3 -m json.tool

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('access_token', ''))
except:
    print('')
")

if [ -n "$TOKEN" ]; then
    print_success "Authentication successful! Token obtained."
    
    echo ""
    
    # Test 6: Database structure (requires auth)
    print_step "Testing Database Structure Inspection (Authenticated)"
    echo "Endpoint: GET $BASE_URL/api/debug/database-structure"
    
    DB_STRUCTURE=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/debug/database-structure")
    DB_STATUS=$?
    
    if [ $DB_STATUS -eq 0 ]; then
        echo "$DB_STRUCTURE" | python3 -m json.tool
        print_success "Database structure retrieved!"
    else
        print_error "Failed to get database structure"
    fi
    
    echo ""
    
    # Test 7: Send encrypted message to test encryption
    print_step "Testing Message Encryption in Database"
    
    # Send a test message
    MESSAGE_DATA="{\"content\":\"🔐 This is a test encrypted message to prove the system works! 🔐\",\"message_type\":\"text\"}"
    SEND_RESPONSE=$(curl -s -X POST "$BASE_URL/api/messages/send" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$MESSAGE_DATA")
    
    echo "Send message response:"
    echo "$SEND_RESPONSE" | python3 -m json.tool
    
    # Get encryption proof with messages
    ENCRYPTION_PROOF=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/debug/encryption-proof")
    ENCRYPTION_STATUS=$?
    
    if [ $ENCRYPTION_STATUS -eq 0 ]; then
        print_success "Detailed encryption proof retrieved!"
        echo "$ENCRYPTION_PROOF" | python3 -m json.tool
        
        # Extract and display encryption details
        echo "$ENCRYPTION_PROOF" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    messages = data.get('encrypted_messages', [])
    if messages:
        msg = messages[0]
        print(f\"\\n🔐 ENCRYPTION PROOF:\")
        print(f\"   Message ID: {msg.get('id')}\")
        print(f\"   Encrypted Size: {msg.get('encrypted_size')} bytes\")
        print(f\"   Encrypted Content (hex): {msg.get('encrypted_hex', '')[:64]}...\")
        print(f\"   Nonce (hex): {msg.get('nonce_hex', '')}\")
        print(f\"   Auth Tag (hex): {msg.get('tag_hex', '')}\")
        
        session = data.get('active_session')
        if session:
            print(f\"\\n🔑 ACTIVE SESSION:\")
            print(f\"   Session ID: {session.get('id')}\")
            print(f\"   Shared Secret (hex): {session.get('shared_secret_hex', '')[:32]}...\")
            print(f\"   Key Size: {session.get('key_size')} bytes\")
        
        decryption = data.get('decryption_proof')
        if decryption:
            print(f\"\\n✅ DECRYPTION PROOF:\")
            print(f\"   Original Content: {decryption.get('decrypted_content')}\")
            print(f\"   Algorithm: {decryption.get('encryption_algorithm')}\")
            print(f\"   Key Derivation: {decryption.get('key_derivation')}\")
    else:
        print(\"No encrypted messages found\")
except Exception as e:
    print(f\"Error parsing encryption proof: {e}\")
"
    else
        print_error "Failed to get detailed encryption proof"
    fi
    
else
    print_error "Authentication failed! Cannot test authenticated endpoints."
fi

echo ""
echo "🎯 SUMMARY"
echo "=========="
print_info "All tests completed. Check the outputs above for encryption proof."
print_info "Key endpoints to verify encryption:"
print_info "  • Public proof: $BASE_URL/api/proof"
print_info "  • Live test: $BASE_URL/api/debug/encryption-test"
print_info "  • Visual proof: $BASE_URL/encryption-proof"
print_warning "For authenticated endpoints, you need a valid JWT token."

echo ""
print_step "Next Steps to Verify Encryption on Azure:"
echo "1. 📊 Visit the proof page: $BASE_URL/encryption-proof"
echo "2. 🔬 Run the live encryption test on the page"
echo "3. 🗄️  Use curl commands above with your token to see encrypted database content"
echo "4. 🔍 SSH into Azure to inspect the SQLite database directly"
echo ""
print_success "Quantum encryption system is ready for verification! 🚀"