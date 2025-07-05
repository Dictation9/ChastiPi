#!/bin/bash

# ChastiPi Mac Package Creator
# Creates a standalone Mac application bundle

set -e

echo "📦 Creating ChastiPi Mac Package"
echo "================================"

# Check if we're in the right directory
if [ ! -f "install_mac.sh" ]; then
    echo "❌ Please run this script from the ChastiPi root directory"
    exit 1
fi

# Create package directory
PACKAGE_DIR="ChastiPi-Mac"
if [ -d "$PACKAGE_DIR" ]; then
    rm -rf "$PACKAGE_DIR"
fi

mkdir -p "$PACKAGE_DIR"

echo "📁 Creating package structure..."

# Copy essential files
cp -r chasti_pi "$PACKAGE_DIR/"
cp -r templates "$PACKAGE_DIR/"
cp -r static "$PACKAGE_DIR/"
cp -r docs "$PACKAGE_DIR/"
cp -r plugins "$PACKAGE_DIR/"

# Copy Mac-specific files
cp install_mac.sh "$PACKAGE_DIR/"
cp run_mac.py "$PACKAGE_DIR/"
cp requirements_mac.txt "$PACKAGE_DIR/"
cp README_MAC.md "$PACKAGE_DIR/"

# Copy core files
cp run.py "$PACKAGE_DIR/"
cp requirements.txt "$PACKAGE_DIR/"
cp README.md "$PACKAGE_DIR/"

# Create Mac-specific config template
cat > "$PACKAGE_DIR/config_mac.json" << 'EOF'
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

# Create launcher script
cat > "$PACKAGE_DIR/launch_chastipi.command" << 'EOF'
#!/bin/bash
# ChastiPi Mac Launcher
cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "🔧 First time setup..."
    echo "Installing ChastiPi..."
    chmod +x install_mac.sh
    ./install_mac.sh
fi

# Activate virtual environment and run
source venv/bin/activate
python run_mac.py
EOF

chmod +x "$PACKAGE_DIR/launch_chastipi.command"

# Create README for the package
cat > "$PACKAGE_DIR/INSTALL.txt" << 'EOF'
ChastiPi Mac Edition - Installation Guide
=========================================

Quick Start:
1. Double-click "launch_chastipi.command"
2. Follow the installation prompts
3. Edit config_mac.json with your settings
4. Run again to start the application

For detailed instructions, see README_MAC.md

System Requirements:
- macOS 10.15 (Catalina) or later
- Homebrew (will be installed if needed)
- Internet connection for initial setup

Security Note:
This version runs on localhost only for security.
Access via: http://localhost:5000
EOF

# Create a simple installer
cat > "$PACKAGE_DIR/install.command" << 'EOF'
#!/bin/bash
# Simple installer for ChastiPi Mac

echo "🍎 ChastiPi Mac Edition Installer"
echo "================================="

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Run the Mac installer
chmod +x install_mac.sh
./install_mac.sh

echo ""
echo "✅ Installation complete!"
echo "Run 'launch_chastipi.command' to start the application"
EOF

chmod +x "$PACKAGE_DIR/install.command"

# Create a zip file
echo "📦 Creating distribution package..."
zip -r "ChastiPi-Mac-$(date +%Y%m%d).zip" "$PACKAGE_DIR"

echo ""
echo "✅ Package created successfully!"
echo "📁 Package location: ChastiPi-Mac-$(date +%Y%m%d).zip"
echo ""
echo "📋 To distribute:"
echo "1. Send the zip file to Mac users"
echo "2. They can extract and run install.command"
echo "3. Or double-click launch_chastipi.command for first-time setup" 