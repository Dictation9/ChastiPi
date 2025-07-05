#!/bin/bash

# ChastiPi Install Script (Legacy)
# This script is kept for backward compatibility.
# For Raspberry Pi users, use install_raspberry_pi.sh instead.

echo "⚠️  This is the legacy install script."
echo ""
echo "📖 For better installation experience:"
echo "   - Raspberry Pi users: Use ./install_raspberry_pi.sh"
echo "   - macOS users: Use ./mac_version/install_mac.sh"
echo ""
echo "🤔 Continue with legacy installation? (y/N)"
read -r response
if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled. Please use the recommended installer."
    exit 1
fi

set -e

# Step 1: Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not found. Please install Python 3."
    exit 1
fi

# Step 2: Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Step 3: Activate virtual environment
source venv/bin/activate

# Step 4: Upgrade pip
pip install --upgrade pip

# Step 5: Install dependencies with NumPy compatibility fix
echo "Installing dependencies with NumPy compatibility..."
pip install "numpy<2.0"
pip install opencv-python-headless

if [ -f "requirements.txt" ]; then
    echo "Installing other dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "requirements.txt not found!"
    exit 1
fi

# Step 6: Success message and usage
cat <<EOF

✅ ChastiPi installation complete!

To activate your virtual environment:
  source venv/bin/activate

To run the app:
  python run.py

📖 For better installation experience next time:
   - Raspberry Pi: Use ./install_raspberry_pi.sh
   - macOS: Use ./mac_version/install_mac.sh

EOF 