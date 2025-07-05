#!/bin/bash

# ChastiPi Mac App Builder Launcher
# This script launches the Mac app builder from the main directory

echo "🍎 ChastiPi Mac App Builder"
echo "==========================="

# Check if mac_version directory exists
if [ ! -d "mac_version" ]; then
    echo "❌ mac_version directory not found!"
    echo "Please ensure you're in the main ChastiPi directory."
    exit 1
fi

# Navigate to mac_version and run the build script
cd mac_version

if [ -f "build_mac_app.sh" ]; then
    echo "🚀 Starting Mac app build process..."
    ./build_mac_app.sh
else
    echo "❌ build_mac_app.sh not found in mac_version directory!"
    exit 1
fi 