#!/bin/bash

# ChastiPi Mac App Builder
# This script creates a complete Mac app bundle from the main ChastiPi codebase

set -e

echo "🍎 ChastiPi Mac App Builder"
echo "==========================="

# Check if we're in the right directory
if [ ! -f "create_mac_app.sh" ]; then
    echo "❌ Please run this script from the mac_version directory"
    exit 1
fi

# Get the parent directory (main ChastiPi folder)
PARENT_DIR="$(cd .. && pwd)"
echo "📁 Main ChastiPi directory: $PARENT_DIR"

# Step 1: Copy necessary files from main directory
echo "📦 Copying files from main ChastiPi directory..."

# Copy core application files
cp -r "$PARENT_DIR/chasti_pi" ./
cp -r "$PARENT_DIR/templates" ./
cp -r "$PARENT_DIR/static" ./
cp -r "$PARENT_DIR/docs" ./
cp -r "$PARENT_DIR/plugins" ./

# Copy core files
cp "$PARENT_DIR/run.py" ./
cp "$PARENT_DIR/requirements.txt" ./

echo "✅ Files copied successfully"

# Step 2: Create app icon
echo "🎨 Creating app icon..."
if command -v python3 &> /dev/null && python3 -c "import PIL" 2>/dev/null; then
    python3 create_app_icon.py
    echo "✅ App icon created"
else
    echo "⚠️  PIL not available, skipping icon creation"
fi

# Step 3: Create the app bundle
echo "📱 Creating Mac app bundle..."
./create_mac_app.sh

# Step 4: Create DMG installer
echo "📦 Creating DMG installer..."
./create_dmg.sh

echo ""
echo "✅ Mac app creation complete!"
echo ""
echo "📁 Generated files:"
echo "  - ChastiPi.app (Mac app bundle)"
echo "  - ChastiPi-$(date +%Y%m%d).dmg (DMG installer)"
echo ""
echo "📋 Next steps:"
echo "1. Test the app: open ChastiPi.app"
echo "2. Install to Applications: cp -R ChastiPi.app /Applications/"
echo "3. Distribute the DMG file"
echo ""
echo "🔧 To clean up temporary files:"
echo "  rm -rf chasti_pi templates static docs plugins run.py requirements.txt" 