#!/bin/bash

# ChastiPi Install Script
# This script sets up a Python virtual environment and installs dependencies.

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

# Step 5: Install dependencies
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
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

EOF 