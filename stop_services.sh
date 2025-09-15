#!/bin/bash

# QSM Backend - Service Shutdown Script

echo "🛑 Stopping QSM Backend Services..."

# Function to stop a service by PID file
stop_service() {
    local pid_file=$1
    local service_name=$2
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "   Stopping $service_name (PID: $pid)..."
            kill "$pid"
            
            # Wait for graceful shutdown
            local attempts=10
            while [ $attempts -gt 0 ] && ps -p "$pid" > /dev/null 2>&1; do
                sleep 1
                attempts=$((attempts - 1))
            done
            
            # Force kill if still running
            if ps -p "$pid" > /dev/null 2>&1; then
                echo "   Force stopping $service_name..."
                kill -9 "$pid" 2>/dev/null || true
            fi
            
            echo "   ✅ $service_name stopped"
        else
            echo "   ⚠️  $service_name was not running"
        fi
        rm -f "$pid_file"
    else
        echo "   ⚠️  No PID file found for $service_name"
    fi
}

# Stop services
if [ -d "logs" ]; then
    stop_service "logs/main_app.pid" "Main Application"
    stop_service "logs/quantum_service.pid" "Quantum Crypto Service"
else
    echo "   No logs directory found, attempting to stop by process name..."
    pkill -f "uvicorn app:app" 2>/dev/null || true
    pkill -f "uvicorn service:app" 2>/dev/null || true
    pkill -f "python3.*app.py" 2>/dev/null || true
    pkill -f "python3.*service.py" 2>/dev/null || true
fi

# Also stop any remaining uvicorn processes for these apps
pkill -f "uvicorn.*app:app" 2>/dev/null || true
pkill -f "uvicorn.*service:app" 2>/dev/null || true

echo "✅ All QSM Backend services have been stopped."