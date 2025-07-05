#!/bin/bash
# Fix dashboard dependencies script

echo "🔧 Installing missing dependencies for ChastiPi dashboard..."

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "🐍 Activating virtual environment..."
    source venv/bin/activate
    PYTHON_CMD="python"
    PIP_CMD="pip"
elif [ -d ".venv" ]; then
    echo "🐍 Activating virtual environment..."
    source .venv/bin/activate
    PYTHON_CMD="python"
    PIP_CMD="pip"
else
    echo "⚠️  No virtual environment found, using system Python..."
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
fi

# Install required packages
echo "📦 Installing cryptography..."
$PIP_CMD install cryptography

echo "📦 Installing flask..."
$PIP_CMD install flask

echo "📦 Installing other required packages..."
$PIP_CMD install -r requirements.txt

echo "✅ Dependencies installed!"
echo "🔄 Please restart ChastiPi: ./start_chastipi.sh" 