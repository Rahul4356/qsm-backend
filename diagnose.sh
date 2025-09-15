#!/bin/bash

# QSM Backend - Diagnostic Script
# This script helps diagnose common issues

echo "🔍 QSM Backend Diagnostic Tool"
echo "==============================="

# Function to check if a URL is responding
check_url() {
    local url=$1
    local service_name=$2
    
    echo -n "   Testing $service_name ($url)... "
    
    if curl -s --max-time 5 "$url" > /dev/null 2>&1; then
        echo "✅ OK"
        return 0
    else
        echo "❌ FAILED"
        return 1
    fi
}

# Function to check if port is in use
check_port() {
    local port=$1
    local service_name=$2
    
    echo -n "   Port $port ($service_name)... "
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "✅ IN USE"
        return 0
    else
        echo "❌ FREE"
        return 1
    fi
}

# Check system prerequisites
echo ""
echo "📋 System Prerequisites"
echo "------------------------"

echo -n "   Python 3... "
if command -v python3 >/dev/null 2>&1; then
    echo "✅ $(python3 --version)"
else
    echo "❌ NOT FOUND"
fi

echo -n "   pip... "
if command -v pip >/dev/null 2>&1; then
    echo "✅ Available"
else
    echo "❌ NOT FOUND"
fi

echo -n "   curl... "
if command -v curl >/dev/null 2>&1; then
    echo "✅ Available"
else
    echo "❌ NOT FOUND"
fi

# Check if required files exist
echo ""
echo "📁 Required Files"
echo "-----------------"

files=("app.py" "service.py" "requirements.txt" "start_services.sh" "stop_services.sh")
for file in "${files[@]}"; do
    echo -n "   $file... "
    if [ -f "$file" ]; then
        echo "✅ EXISTS"
    else
        echo "❌ MISSING"
    fi
done

# Check ports
echo ""
echo "🔌 Port Status"
echo "--------------"

check_port 8000 "Main Application"
check_port 8001 "Quantum Service"

# Check service endpoints
echo ""
echo "🌐 Service Health"
echo "-----------------"

main_ok=false
quantum_ok=false

if check_url "http://localhost:8000/api/health" "Main Application"; then
    main_ok=true
fi

if check_url "http://localhost:8001/api/health" "Quantum Service"; then
    quantum_ok=true
fi

# Overall status
echo ""
echo "📊 Overall Status"
echo "-----------------"

if $main_ok && $quantum_ok; then
    echo "✅ ALL SERVICES HEALTHY"
    echo ""
    echo "🎉 Your QSM Backend is fully operational!"
    echo "   Main App: http://localhost:8000"
    echo "   API Docs: http://localhost:8000/docs"
elif $main_ok && ! $quantum_ok; then
    echo "⚠️  PARTIAL SERVICE (QUANTUM SERVICE DOWN)"
    echo ""
    echo "❌ Issue: Quantum service is not running"
    echo "💡 Solution: Start the quantum service:"
    echo "   python3 -m uvicorn service:app --host 0.0.0.0 --port 8001"
    echo ""
    echo "   Or use the automated startup:"
    echo "   ./start_services.sh"
elif ! $main_ok && $quantum_ok; then
    echo "⚠️  PARTIAL SERVICE (MAIN APP DOWN)"
    echo ""
    echo "❌ Issue: Main application is not running"
    echo "💡 Solution: Start the main application:"
    echo "   python3 -m uvicorn app:app --host 0.0.0.0 --port 8000"
    echo ""
    echo "   Or use the automated startup:"
    echo "   ./start_services.sh"
else
    echo "❌ ALL SERVICES DOWN"
    echo ""
    echo "💡 Solution: Start all services:"
    echo "   ./start_services.sh"
    echo ""
    echo "   Or manually:"
    echo "   # Terminal 1:"
    echo "   python3 -m uvicorn service:app --host 0.0.0.0 --port 8001"
    echo "   # Terminal 2:"
    echo "   python3 -m uvicorn app:app --host 0.0.0.0 --port 8000"
fi

# Check for common issues
echo ""
echo "🔧 Troubleshooting"
echo "------------------"

# Check dependencies
echo -n "   Python dependencies... "
if python3 -c "import fastapi, uvicorn, sqlalchemy, cryptography" 2>/dev/null; then
    echo "✅ OK"
else
    echo "❌ MISSING"
    echo "   💡 Run: pip install -r requirements.txt"
fi

# Check logs if available
if [ -d "logs" ]; then
    echo "   📝 Logs available in:"
    for log in logs/*.log; do
        if [ -f "$log" ]; then
            echo "      - $log"
        fi
    done
    echo "   💡 View logs: tail -f logs/*.log"
fi

echo ""
echo "🆘 Need Help?"
echo "-------------"
echo "   1. Check the README.md for detailed instructions"
echo "   2. Restart services: ./stop_services.sh && ./start_services.sh"
echo "   3. Check logs for error details"
echo "   4. Verify no other services are using ports 8000/8001"
echo ""