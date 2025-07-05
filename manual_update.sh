#!/bin/bash
# ChastiPi Manual Update Script
# Pulls latest code from GitHub and updates Python dependencies

set -e

# Print header
echo "==============================="
echo " ChastiPi Manual Update Script"
echo "==============================="

# Check if inside a git repo
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo "❌ Error: This directory is not a git repository."
    exit 1
fi

# Pull latest code
echo "\n🔄 Pulling latest code from GitHub..."
git pull
GIT_STATUS=$?
if [ $GIT_STATUS -ne 0 ]; then
    echo "❌ git pull failed."
    exit 1
fi

echo "\n📦 Installing/updating Python dependencies..."
pip3 install -r requirements.txt
PIP_STATUS=$?
if [ $PIP_STATUS -ne 0 ]; then
    echo "❌ pip install failed."
    exit 1
fi

echo "\n✅ Update complete!"
echo "If ChastiPi is running, please restart it to apply updates." 