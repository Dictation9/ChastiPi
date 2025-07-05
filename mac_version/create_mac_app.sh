#!/bin/bash

# ChastiPi Mac App Creator
# Creates a proper macOS .app bundle

set -e

echo "🍎 Creating ChastiPi Mac App Bundle"
echo "==================================="

# Check if we're in the right directory
if [ ! -f "install_mac.sh" ]; then
    echo "❌ Please run this script from the ChastiPi root directory"
    exit 1
fi

# App name and bundle identifier
APP_NAME="ChastiPi"
BUNDLE_ID="com.chastipi.app"
VERSION="1.0.0"

# Create app bundle structure
APP_DIR="${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
FRAMEWORKS_DIR="${CONTENTS_DIR}/Frameworks"

# Clean up existing app
if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
fi

echo "📁 Creating app bundle structure..."

# Create directory structure
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"
mkdir -p "$FRAMEWORKS_DIR"

# Create Info.plist
cat > "$CONTENTS_DIR/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ChastiPi</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>ChastiPi</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSUIElement</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>NSAppleEventsUsageDescription</key>
    <string>ChastiPi needs to send notifications and access system features.</string>
</dict>
</plist>
EOF

# Create the main executable script
cat > "$MACOS_DIR/ChastiPi" << 'EOF'
#!/bin/bash

# ChastiPi Mac App Launcher
# This script is the main executable for the .app bundle

# Get the app bundle directory
APP_BUNDLE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RESOURCES_DIR="$APP_BUNDLE_DIR/Contents/Resources"

# Change to the resources directory
cd "$RESOURCES_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "🔧 First time setup..."
    echo "Installing ChastiPi..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    pip install --upgrade pip
    if [ -f "requirements_mac.txt" ]; then
        pip install -r requirements_mac.txt
    elif [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    fi
    
    # Create default config if it doesn't exist
    if [ ! -f "config_mac.json" ]; then
        cat > config_mac.json << 'CONFIG_EOF'
{
  "system": {
    "chastity_mode": "gentle",
    "debug": false,
    "host": "127.0.0.1",
    "port": 5000
  },
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email_address": "your-email@gmail.com",
    "email_password": "your-app-password",
    "use_tls": true
  },
  "security": {
    "encryption_key": "your-secure-encryption-key-here",
    "session_timeout": 3600
  },
  "features": {
    "cage_check_enabled": true,
    "punishment_enabled": true,
    "calendar_enabled": true,
    "time_verification_enabled": true,
    "photo_upload_enabled": true
  },
  "mac_specific": {
    "use_system_notifications": true,
    "auto_start_on_login": false,
    "minimize_to_tray": true
  }
}
CONFIG_EOF
        echo "✅ Created default configuration file"
    fi
    
    echo "✅ Installation complete!"
else
    # Activate existing virtual environment
    source venv/bin/activate
fi

# Run the application
python run_mac.py
EOF

chmod +x "$MACOS_DIR/ChastiPi"

# Copy application files to Resources
echo "📦 Copying application files..."

# Copy core application files
cp -r chasti_pi "$RESOURCES_DIR/"
cp -r templates "$RESOURCES_DIR/"
cp -r static "$RESOURCES_DIR/"
cp -r docs "$RESOURCES_DIR/"
cp -r plugins "$RESOURCES_DIR/"

# Copy Mac-specific files
cp run_mac.py "$RESOURCES_DIR/"
cp requirements_mac.txt "$RESOURCES_DIR/"
cp requirements.txt "$RESOURCES_DIR/"

# Create a simple configuration file
if [ ! -f "$RESOURCES_DIR/config_mac.json" ]; then
    cat > "$RESOURCES_DIR/config_mac.json" << 'EOF'
{
  "system": {
    "chastity_mode": "gentle",
    "debug": false,
    "host": "127.0.0.1",
    "port": 5000
  },
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email_address": "your-email@gmail.com",
    "email_password": "your-app-password",
    "use_tls": true
  },
  "security": {
    "encryption_key": "your-secure-encryption-key-here",
    "session_timeout": 3600
  },
  "features": {
    "cage_check_enabled": true,
    "punishment_enabled": true,
    "calendar_enabled": true,
    "time_verification_enabled": true,
    "photo_upload_enabled": true
  },
  "mac_specific": {
    "use_system_notifications": true,
    "auto_start_on_login": false,
    "minimize_to_tray": true
  }
}
EOF
fi

# Create app icon
echo "🎨 Creating app icon..."
if command -v python3 &> /dev/null && python3 -c "import PIL" 2>/dev/null; then
    python3 create_app_icon.py
    if [ -f "ChastiPi.icns" ]; then
        cp "ChastiPi.icns" "$RESOURCES_DIR/"
        echo "✅ App icon created and copied"
    else
        echo "⚠️  Could not create app icon, using placeholder"
        cat > "$RESOURCES_DIR/AppIcon.icns" << 'EOF'
# This is a placeholder for the app icon
# You can replace this with a proper .icns file
EOF
    fi
else
    echo "⚠️  PIL not available, using placeholder icon"
    cat > "$RESOURCES_DIR/AppIcon.icns" << 'EOF'
# This is a placeholder for the app icon
# You can replace this with a proper .icns file
EOF
fi

# Create a simple installer script
cat > "$RESOURCES_DIR/install_dependencies.sh" << 'EOF'
#!/bin/bash
# Install system dependencies for ChastiPi

echo "🍎 Installing ChastiPi Dependencies"
echo "==================================="

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install system dependencies
echo "Installing system dependencies..."
brew install tesseract
brew install opencv
brew install libmagic

echo "✅ System dependencies installed!"
echo "You can now run ChastiPi from the Applications folder."
EOF

chmod +x "$RESOURCES_DIR/install_dependencies.sh"

# Create README for the app
cat > "$RESOURCES_DIR/README.txt" << 'EOF'
ChastiPi Mac App
================

This is a standalone macOS application for ChastiPi.

First Run:
1. Double-click the app to start
2. It will automatically install dependencies on first run
3. Edit config_mac.json in the app bundle to configure

Manual Installation:
If you encounter issues, run the install_dependencies.sh script:
- Right-click the app
- Select "Show Package Contents"
- Navigate to Contents/Resources/
- Run install_dependencies.sh

Configuration:
- Edit config_mac.json in the app bundle
- Set your email settings
- Configure your preferences

Access:
- Web interface: http://localhost:5000
- Status bar icon: Click the 🔒 in the menu bar

Security:
- Runs on localhost only for security
- All data is encrypted and stored locally
EOF

# Create a simple uninstaller
cat > "$RESOURCES_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
# Uninstall ChastiPi

echo "🗑️  Uninstalling ChastiPi..."

# Remove virtual environment
rm -rf venv

# Remove configuration
rm -f config_mac.json

echo "✅ ChastiPi has been uninstalled."
echo "The app bundle can be safely deleted."
EOF

chmod +x "$RESOURCES_DIR/uninstall.sh"

# Create a DMG creation script
cat > "create_dmg.sh" << 'EOF'
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
EOF

chmod +x "create_dmg.sh"

echo ""
echo "✅ Mac App Bundle created successfully!"
echo "📁 App location: $APP_DIR"
echo ""
echo "📋 Next steps:"
echo "1. Test the app: open $APP_DIR"
echo "2. Create DMG installer: ./create_dmg.sh"
echo "3. Move to Applications: cp -R $APP_DIR /Applications/"
echo ""
echo "🔧 To install system dependencies:"
echo "   Right-click the app → Show Package Contents → Contents/Resources → install_dependencies.sh" 