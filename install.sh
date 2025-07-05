#!/bin/bash

# ChastiPi Dashboard Installation Script

echo "🔐 Installing ChastiPi Dashboard..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3 first."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Make run script executable
chmod +x run.py

echo "✅ Installation complete!"
echo ""
echo "🚀 To start ChastiPi:"
echo "   source .venv/bin/activate"
echo "   python run.py"
echo ""
echo "🌐 Access ChastiPi at: http://your-pi-ip:5000"
echo "" 