#!/bin/bash

# QSM Backend - Complete Service Startup Script
# This script starts both the main application and quantum crypto service

set -e

echo "=============================================="
echo "QSM Backend - Starting All Services"
echo "=============================================="

# Function to check if a port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        echo "❌ Port $port is already in use"
        return 1
    else
        echo "✅ Port $port is available"
        return 0
    fi
}

# Function to wait for service to be ready
wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    local attempt=1
    
    echo "⏳ Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        echo "   Attempt $attempt/$max_attempts - waiting..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "❌ $service_name failed to start within timeout"
    return 1
}

# Check if ports are available
echo "Checking port availability..."
check_port 8000 || exit 1
check_port 8001 || exit 1

# Set environment variables for development
export AZURE_ENV=${AZURE_ENV:-development}
export DATABASE_URL=${DATABASE_URL:-sqlite:////tmp/qms_quantum.db}
export QUANTUM_API_URL=${QUANTUM_API_URL:-http://localhost:8001}
export JWT_SECRET=${JWT_SECRET:-quantum-secure-default-key-change-this-in-production}
export ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-*}

echo "Environment: $AZURE_ENV"
echo "Database: $DATABASE_URL"
echo "Quantum API: $QUANTUM_API_URL"

# Create log directory
mkdir -p logs

# Start Quantum Crypto Service (service.py) on port 8001
echo ""
echo "🚀 Starting Quantum Crypto Service on port 8001..."
python3 -m uvicorn service:app --host 0.0.0.0 --port 8001 --log-level info > logs/quantum_service.log 2>&1 &
QUANTUM_PID=$!
echo "   Quantum Service PID: $QUANTUM_PID"

# Wait for quantum service to be ready
if ! wait_for_service "http://localhost:8001/api/health" "Quantum Crypto Service"; then
    echo "❌ Failed to start Quantum Crypto Service"
    kill $QUANTUM_PID 2>/dev/null || true
    exit 1
fi

# Start Main Application (app.py) on port 8000
echo ""
echo "🚀 Starting Main Application on port 8000..."
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --log-level info > logs/main_app.log 2>&1 &
MAIN_PID=$!
echo "   Main Application PID: $MAIN_PID"

# Wait for main service to be ready
if ! wait_for_service "http://localhost:8000/api/health" "Main Application"; then
    echo "❌ Failed to start Main Application"
    kill $MAIN_PID 2>/dev/null || true
    kill $QUANTUM_PID 2>/dev/null || true
    exit 1
fi

# Save PIDs for shutdown script
echo $MAIN_PID > logs/main_app.pid
echo $QUANTUM_PID > logs/quantum_service.pid

echo ""
echo "=============================================="
echo "🎉 QSM Backend Services Started Successfully!"
echo "=============================================="
echo "📱 Main Application:     http://localhost:8000"
echo "⚛️  Quantum Service:      http://localhost:8001"
echo "📊 API Documentation:    http://localhost:8000/docs"
echo "🔍 Health Check:         http://localhost:8000/api/health"
echo ""
echo "📝 Logs are available in the 'logs' directory:"
echo "   - logs/main_app.log"
echo "   - logs/quantum_service.log"
echo ""
echo "🛑 To stop services, run: ./stop_services.sh"
echo ""
echo "✅ Both services are now running in the background."
echo "   Press Ctrl+C to view logs, or run 'tail -f logs/*.log'"

# Function to handle script termination
cleanup() {
    echo ""
    echo "🛑 Stopping services..."
    kill $MAIN_PID 2>/dev/null || true
    kill $QUANTUM_PID 2>/dev/null || true
    rm -f logs/*.pid
    echo "✅ Services stopped."
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Keep script running and show logs
echo "Showing live logs (Ctrl+C to stop services):"
echo "=============================================="
tail -f logs/main_app.log logs/quantum_service.log