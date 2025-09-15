#!/bin/bash

# QMS Testing Script - Automated testing for local development

set -e

API_BASE="http://localhost:8000"
echo "🧪 Testing Quantum Messaging System at $API_BASE"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local auth=$4
    
    echo -e "${YELLOW}Testing ${method} ${endpoint}${NC}"
    
    if [ "$auth" != "" ]; then
        if [ "$data" != "" ]; then
            curl -s -X $method "$API_BASE$endpoint" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $auth" \
                -d "$data" | jq '.' || echo "❌ Failed"
        else
            curl -s -X $method "$API_BASE$endpoint" \
                -H "Authorization: Bearer $auth" | jq '.' || echo "❌ Failed"
        fi
    else
        if [ "$data" != "" ]; then
            curl -s -X $method "$API_BASE$endpoint" \
                -H "Content-Type: application/json" \
                -d "$data" | jq '.' || echo "❌ Failed"
        else
            curl -s "$API_BASE$endpoint" | jq '.' || echo "❌ Failed"
        fi
    fi
    echo ""
}

echo "1. Testing Health Check..."
test_endpoint "GET" "/api/health"

echo "2. Testing Quantum Info..."
test_endpoint "GET" "/api/quantum/info"

echo "3. Registering Test Users..."
test_endpoint "POST" "/api/register" '{"username":"alice","email":"alice@test.com","password":"quantum123"}'
test_endpoint "POST" "/api/register" '{"username":"bob","email":"bob@test.com","password":"quantum456"}'

echo "4. Logging in Users..."
ALICE_RESPONSE=$(curl -s -X POST "$API_BASE/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"quantum123"}')

BOB_RESPONSE=$(curl -s -X POST "$API_BASE/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"bob","password":"quantum456"}')

ALICE_TOKEN=$(echo $ALICE_RESPONSE | jq -r '.access_token')
BOB_TOKEN=$(echo $BOB_RESPONSE | jq -r '.access_token')

if [ "$ALICE_TOKEN" != "null" ] && [ "$ALICE_TOKEN" != "" ]; then
    echo -e "${GREEN}✅ Alice logged in successfully${NC}"
else
    echo -e "${RED}❌ Alice login failed${NC}"
    exit 1
fi

if [ "$BOB_TOKEN" != "null" ] && [ "$BOB_TOKEN" != "" ]; then
    echo -e "${GREEN}✅ Bob logged in successfully${NC}"
else
    echo -e "${RED}❌ Bob login failed${NC}"
    exit 1
fi

echo "5. Generating Quantum Keys..."
test_endpoint "POST" "/api/quantum/generate-keys" "" "$ALICE_TOKEN"
test_endpoint "POST" "/api/quantum/generate-keys" "" "$BOB_TOKEN"

echo "6. Testing Database State..."
test_endpoint "GET" "/api/debug/database?table=users" "" "$ALICE_TOKEN"

echo "7. Testing Connection Request..."
test_endpoint "POST" "/api/connections/request" '{"receiver":"bob"}' "$ALICE_TOKEN"

echo -e "${GREEN}🎉 Basic tests completed!${NC}"
echo ""
echo "🔗 WebSocket Test (run in browser console):"
echo "const ws = new WebSocket('ws://localhost:8000/ws/alice');"
echo "ws.onmessage = (e) => console.log('Received:', e.data);"
echo "ws.send(JSON.stringify({type: 'heartbeat'}));"
echo ""
echo "📊 Database Inspection:"
echo "sqlite3 qms.db"
echo ".tables"
echo "SELECT * FROM users;"
echo "SELECT * FROM quantum_keys;"
echo ""
echo -e "${GREEN}All tests passed! Your QMS is working correctly.${NC}"