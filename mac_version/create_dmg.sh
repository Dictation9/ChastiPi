#!/bin/bash

# Create a DMG installer for ChastiPi

echo "📦 Creating ChastiPi DMG Installer"
echo "=================================="

# Check if app exists
if [ ! -d "ChastiPi.app" ]; then
    echo "❌ ChastiPi.app not found. Run create_mac_app.sh first."
    exit 1
fi

# Create DMG
DMG_NAME="ChastiPi-$(date +%Y%m%d).dmg"
TEMP_DIR="temp_dmg"

# Clean up
rm -rf "$TEMP_DIR"
rm -f "$DMG_NAME"

# Create temp directory
mkdir -p "$TEMP_DIR"

# Copy app to temp directory
cp -R "ChastiPi.app" "$TEMP_DIR/"

# Create Applications symlink
ln -s /Applications "$TEMP_DIR/Applications"

# Create DMG
hdiutil create -volname "ChastiPi" -srcfolder "$TEMP_DIR" -ov -format UDZO "$DMG_NAME"

# Clean up
rm -rf "$TEMP_DIR"

echo "✅ DMG created: $DMG_NAME"
echo "📋 To install:"
echo "1. Double-click the DMG"
echo "2. Drag ChastiPi.app to Applications"
echo "3. Run from Applications folder" 