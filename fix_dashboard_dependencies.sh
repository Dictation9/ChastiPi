#!/bin/bash
# Fix dashboard dependencies script

echo "🔧 Installing missing dependencies for ChastiPi dashboard..."

# Install required packages
echo "📦 Installing cryptography..."
pip3 install cryptography

echo "📦 Installing flask..."
pip3 install flask

echo "📦 Installing other required packages..."
pip3 install -r requirements.txt

echo "✅ Dependencies installed!"
echo "🔄 Please restart ChastiPi: ./start_chastipi.sh" 