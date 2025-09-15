# QSM Backend - Quantum Messaging System

A production-ready quantum-resistant messaging platform featuring ML-KEM-768 key exchange, Falcon-512 signatures, and end-to-end encryption.

## Architecture

The QSM Backend consists of **two interdependent services** that must both be running:

### 1. Main Application (`app.py`) - Port 8000
- User authentication and session management
- Message storage and retrieval
- WebSocket real-time communication
- Database operations
- REST API endpoints

### 2. Quantum Crypto Service (`service.py`) - Port 8001
- ML-KEM-768 quantum-resistant key encapsulation
- Falcon-512 quantum-resistant digital signatures
- ECDSA-P256 classical signature wrapper
- AES-256-GCM symmetric encryption
- Cryptographic operations

## 🚨 Critical Setup Requirement

**BOTH SERVICES MUST BE RUNNING** for the application to function properly. Running only the main application will result in:
- ❌ Internal server errors during connection requests
- ❌ Message sending failures
- ❌ Quantum key exchange errors

## Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. **Clone and setup:**
```bash
git clone <repository-url>
cd qsm-backend
pip install -r requirements.txt
```

2. **Start all services (Recommended):**
```bash
# Use the automated startup script
./start_services.sh
```

This will:
- ✅ Start both services automatically
- ✅ Verify service health
- ✅ Show real-time logs
- ✅ Handle graceful shutdown

3. **Alternative: Manual startup:**
```bash
# Terminal 1: Start Quantum Crypto Service
python3 -m uvicorn service:app --host 0.0.0.0 --port 8001

# Terminal 2: Start Main Application
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
```

### Stopping Services

```bash
./stop_services.sh
```

## Service URLs

- **Main Application**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Quantum Service**: http://localhost:8001
- **Health Check**: http://localhost:8000/api/health

## Environment Variables

```bash
# Application Environment
AZURE_ENV=development              # development/production
DATABASE_URL=sqlite:////tmp/qms_quantum.db
JWT_SECRET=your-secret-key
ALLOWED_ORIGINS=*

# Service Communication
QUANTUM_API_URL=http://localhost:8001

# Features
ENABLE_WEBSOCKET=true
TOKEN_EXPIRE_MINUTES=1440
```

## Troubleshooting

### Internal Server Error

**Symptom**: Getting 500 Internal Server Error responses

**Most Common Cause**: Quantum crypto service is not running

**Solution**:
1. Check service status:
```bash
curl http://localhost:8000/api/health
curl http://localhost:8001/api/health
```

2. If quantum service is down:
```bash
# Stop all services
./stop_services.sh

# Restart all services
./start_services.sh
```

### Service Communication Issues

**Check service connectivity**:
```bash
# Test main app
curl http://localhost:8000/api/health

# Test quantum service
curl http://localhost:8001/api/health

# Test quantum service from main app
curl http://localhost:8000/api/config
```

### Port Conflicts

If ports 8000 or 8001 are in use:
```bash
# Find processes using the ports
lsof -i :8000
lsof -i :8001

# Kill conflicting processes or change ports in environment variables
```

## API Endpoints

### Main Application (Port 8000)

- `GET /` - Service information
- `GET /api/health` - Health check with service status
- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `POST /api/connection/request` - Create quantum connection
- `POST /api/message/send` - Send encrypted message

### Quantum Service (Port 8001)

- `GET /api/health` - Quantum service health
- `POST /api/quantum/keygen` - Generate quantum keys
- `POST /api/quantum/encapsulate` - ML-KEM key exchange
- `POST /api/quantum/wrap_sign` - Create quantum signatures

## Development

### Running Tests
```bash
# Test both services are running
curl http://localhost:8000/api/health
curl http://localhost:8001/api/health

# Test user registration
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'
```

### Logs

When using `./start_services.sh`, logs are available in:
- `logs/main_app.log` - Main application logs
- `logs/quantum_service.log` - Quantum service logs

### Development Mode

For development with auto-reload:
```bash
# Terminal 1: Quantum service with reload
python3 -m uvicorn service:app --host 0.0.0.0 --port 8001 --reload

# Terminal 2: Main app with reload
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

## Production Deployment

### Azure App Service

The application includes Azure-specific configurations:

1. **Web App 1** (Main Application):
   - Deploy `app.py`
   - Set PORT environment variable
   - Configure DATABASE_URL for PostgreSQL

2. **Web App 2** (Quantum Service):
   - Deploy `service.py`
   - Set PORT environment variable

3. **Environment Variables**:
```
AZURE_ENV=production
DATABASE_URL=postgresql://...
QUANTUM_API_URL=https://your-quantum-service.azurewebsites.net
JWT_SECRET=strong-production-secret
ALLOWED_ORIGINS=https://your-frontend.com
```

### Docker Deployment

```dockerfile
# Multi-stage Dockerfile example
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Use start_services.sh for both services
CMD ["./start_services.sh"]
```

## Security

- **Quantum-Resistant**: ML-KEM-768 and Falcon-512 algorithms
- **Perfect Forward Secrecy**: Session keys are ephemeral
- **End-to-End Encryption**: AES-256-GCM authenticated encryption
- **Message Authentication**: Hybrid quantum + classical signatures
- **Secure Tokens**: JWT with configurable expiration

## Support

If you encounter issues:

1. **Check logs**: `tail -f logs/*.log`
2. **Verify services**: Use health check endpoints
3. **Restart services**: `./stop_services.sh && ./start_services.sh`
4. **Check port availability**: `lsof -i :8000 -i :8001`

## License

[Your License Here]