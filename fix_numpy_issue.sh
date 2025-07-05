#!/bin/bash

# Quick fix for NumPy compatibility issue on Raspberry Pi
# This script fixes the NumPy 2.x compatibility problem with OpenCV

echo "🔧 Fixing NumPy compatibility issue..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run the full installer first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

echo "📦 Downgrading NumPy to compatible version..."
pip uninstall numpy -y
pip install "numpy<2.0"

echo "📦 Reinstalling OpenCV with compatible NumPy..."
pip uninstall opencv-python opencv-python-headless -y
pip install opencv-python-headless

echo "✅ NumPy compatibility issue fixed!"
echo ""
echo "You can now run ChastiPi with:"
echo "source venv/bin/activate"
echo "python3 run.py" 