# Quantum Messaging System - Testing Guide

## 🧪 Comprehensive Testing Instructions

Your QMS now features:
- ✅ **Quantum cryptography** (ML-KEM-768 + Falcon-512)
- ✅ **Encrypted message storage** with nonce/tag
- ✅ **WebSocket real-time messaging**
- ✅ **SQLite database** with quantum key management
- ✅ **Session-based encrypted communication**

## 🚀 Local Testing

### 1. Start the Server
```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### 2. Test Authentication Flow

#### Register Users
```bash
# Register Alice
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@quantum.com",
    "password": "quantum123"
  }'

# Register Bob
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bob", 
    "email": "bob@quantum.com",
    "password": "quantum456"
  }'
```

#### Login and Get Tokens
```bash
# Login Alice
ALICE_TOKEN=$(curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "quantum123"
  }' | jq -r '.access_token')

# Login Bob  
BOB_TOKEN=$(curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bob",
    "password": "quantum456"
  }' | jq -r '.access_token')

echo "Alice Token: $ALICE_TOKEN"
echo "Bob Token: $BOB_TOKEN"
```

### 3. Test Quantum Key Generation

#### Check Quantum Info
```bash
curl http://localhost:8000/api/quantum/info
```

#### Generate Keys for Users
```bash
# Generate keys for Alice
curl -X POST http://localhost:8000/api/quantum/generate-keys \
  -H "Authorization: Bearer $ALICE_TOKEN"

# Generate keys for Bob
curl -X POST http://localhost:8000/api/quantum/generate-keys \
  -H "Authorization: Bearer $BOB_TOKEN"
```

### 4. Test Database State

#### Check Database Contents
```bash
# View database state (requires authentication)
curl http://localhost:8000/api/debug/database \
  -H "Authorization: Bearer $ALICE_TOKEN"

# Check specific tables
curl "http://localhost:8000/api/debug/database?table=users" \
  -H "Authorization: Bearer $ALICE_TOKEN"

curl "http://localhost:8000/api/debug/database?table=quantum_keys" \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

#### Direct SQLite Inspection
```bash
# Open database directly
sqlite3 qms.db

# List tables
.tables

# Check users
SELECT username, email FROM users;

# Check quantum keys (encrypted)
SELECT user_id, length(ml_kem_public), length(falcon_public) FROM quantum_keys;

# Check messages (you'll see encrypted content)
SELECT sender, length(encrypted_content), length(nonce), length(tag) FROM messages;

# Exit SQLite
.quit
```

### 5. Test Connection Requests

#### Send Connection Request
```bash
# Alice requests connection to Bob
curl -X POST http://localhost:8000/api/connections/request \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"receiver": "bob"}'
```

#### Accept Connection
```bash
# Bob accepts Alice's request
curl -X POST "http://localhost:8000/api/connections/accept?request_id=REQUEST_ID" \
  -H "Authorization: Bearer $BOB_TOKEN"
```

### 6. Test WebSocket Messaging

#### JavaScript WebSocket Test (Browser Console)
```javascript
// Connect Alice
const wsAlice = new WebSocket('ws://localhost:8000/ws/alice');
wsAlice.onopen = () => console.log('Alice connected');
wsAlice.onmessage = (event) => {
    console.log('Alice received:', JSON.parse(event.data));
};

// Connect Bob
const wsBob = new WebSocket('ws://localhost:8000/ws/bob');
wsBob.onopen = () => console.log('Bob connected');
wsBob.onmessage = (event) => {
    console.log('Bob received:', JSON.parse(event.data));
};

// Send heartbeat
wsAlice.send(JSON.stringify({type: 'heartbeat'}));

// Send encrypted message (after session established)
wsAlice.send(JSON.stringify({
    type: 'message',
    receiver: 'bob',
    content: 'Hello from Alice!',
    session_id: 'SESSION_ID_HERE'
}));
```

#### Python WebSocket Test
```python
import asyncio
import websockets
import json

async def test_websocket():
    uri = "ws://localhost:8000/ws/alice"
    
    async with websockets.connect(uri) as websocket:
        # Send heartbeat
        await websocket.send(json.dumps({"type": "heartbeat"}))
        
        # Listen for messages
        async for message in websocket:
            data = json.loads(message)
            print(f"Received: {data}")
            break

asyncio.run(test_websocket())
```

### 7. Test Message Encryption

#### Send Encrypted Message
```bash
# Send message through HTTP endpoint
curl -X POST http://localhost:8000/api/messages/send \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "receiver": "bob",
    "content": "This is a quantum-secured message!",
    "session_id": "your-session-id"
  }'
```

#### Verify Encryption in Database
```bash
# Check that messages are encrypted
sqlite3 qms.db "SELECT sender, hex(encrypted_content), hex(nonce), hex(tag) FROM messages LIMIT 1;"
```

### 8. Test Health and Status

#### Health Check
```bash
curl http://localhost:8000/api/health
```

#### System Status
```bash
curl http://localhost:8000/api/status \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

## 🌐 Azure Production Testing

Once deployed to Azure, replace `localhost:8000` with your Azure URL:

```bash
AZURE_URL="https://qms-backend.azurewebsites.net"

# Test health
curl $AZURE_URL/api/health

# Test registration
curl -X POST $AZURE_URL/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"test123"}'

# WebSocket (in browser)
const ws = new WebSocket('wss://qms-backend.azurewebsites.net/ws/testuser');
```

## 🔍 Debugging Tips

### Check Logs
```bash
# Local development
tail -f app.log

# Azure
az webapp log tail --name qms-backend --resource-group qms-rg
```

### Common Issues
1. **WebSocket connection fails**: Check CORS settings
2. **Database locked**: Ensure proper connection cleanup
3. **Encryption errors**: Verify quantum keys are generated
4. **Token invalid**: Check JWT expiration and SECRET_KEY

### Verify Encryption is Working
```bash
# 1. Send a message
curl -X POST http://localhost:8000/api/messages/send \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"receiver":"bob","content":"Secret message","session_id":"session123"}'

# 2. Check database - content should be encrypted
sqlite3 qms.db "SELECT encrypted_content FROM messages WHERE sender='alice';"
# Should show binary/encrypted data, not plain text

# 3. Verify nonce and tag are stored
sqlite3 qms.db "SELECT length(nonce), length(tag) FROM messages;"
# Should show non-zero lengths (12 for nonce, 16 for tag)
```

## 🎯 Success Criteria

✅ **Authentication**: Users can register and login  
✅ **Quantum Keys**: ML-KEM and Falcon keys generated  
✅ **Database**: Messages stored encrypted with nonce/tag  
✅ **WebSocket**: Real-time connections established  
✅ **Encryption**: Messages are encrypted end-to-end  
✅ **Sessions**: Secure communication sessions created  

Your Quantum Messaging System is now fully functional with post-quantum cryptography! 🚀🔐