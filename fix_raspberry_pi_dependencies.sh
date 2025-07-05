#!/bin/bash

# Quick fix for Raspberry Pi dependency issues
# This script fixes common dependency problems on Raspberry Pi

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_header "ChastiPi Raspberry Pi Dependency Fix"

print_status "This script will fix common dependency issues on Raspberry Pi"

# Check if we're in the ChastiPi directory
if [ ! -f "run.py" ]; then
    print_error "Please run this script from the ChastiPi directory"
    exit 1
fi

# Fix 1: NumPy compatibility issue
print_header "Fixing NumPy Compatibility"

if [ -d "venv" ]; then
    print_status "Activating virtual environment..."
    source venv/bin/activate
    
    print_status "Uninstalling current NumPy..."
    pip uninstall -y numpy
    
    print_status "Installing NumPy < 2.0 for OpenCV compatibility..."
    pip install "numpy<2.0"
    
    print_status "Reinstalling OpenCV..."
    pip uninstall -y opencv-python opencv-python-headless
    pip install opencv-python-headless
    
    print_status "NumPy compatibility fix applied"
else
    print_warning "No virtual environment found. Please run the full installer first."
fi

# Fix 2: System package issues
print_header "Checking System Packages"

print_status "Updating package list..."
sudo apt update

print_status "Installing missing system packages..."
sudo apt install -y \
    python3-dev \
    python3-pip \
    python3-venv \
    libatlas-base-dev \
    libhdf5-dev \
    libhdf5-serial-dev \
    libgstreamer1.0-0 \
    libgstreamer-plugins-base1.0-0 \
    libgtk-3-0 \
    libavcodec-dev \
    libavformat-dev \
    libswscale-dev \
    libv4l-dev \
    libxvidcore-dev \
    libx264-dev \
    libjpeg-dev \
    libpng-dev \
            libtiff-dev \
        libtesseract-dev \
    tesseract-ocr \
    tesseract-ocr-eng \
    git \
    curl \
    wget \
    unzip \
    build-essential \
    cmake \
    pkg-config

print_status "System packages installed successfully"

# Fix 3: Test the installation
print_header "Testing Installation"

if [ -d "venv" ]; then
    source venv/bin/activate
    
    print_status "Testing Python imports..."
    python3 -c "
import numpy
print(f'NumPy version: {numpy.__version__}')
import cv2
print(f'OpenCV version: {cv2.__version__}')
import pytesseract
print('Tesseract imported successfully')
print('All dependencies working correctly!')
"
    
    if [ $? -eq 0 ]; then
        print_status "All tests passed! Installation is working correctly."
    else
        print_error "Some tests failed. Please check the error messages above."
    fi
else
    print_warning "No virtual environment found. Please run the full installer first."
fi

print_header "Fix Complete"

print_status "If you're still having issues:"
print_status "1. Try running: ./install_raspberry_pi.sh"
print_status "2. Check the logs in the logs/ directory"
print_status "3. Make sure you have enough disk space"
print_status "4. Ensure you have a stable internet connection"

print_status "You can now try running ChastiPi with: python run.py" 