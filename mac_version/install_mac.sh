#!/bin/bash

# ChastiPi Mac Installation Script
# This script sets up ChastiPi specifically for macOS

set -e

echo "🍎 ChastiPi Mac Installation"
echo "=============================="

# Step 1: Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew is required but not found."
    echo "Please install Homebrew first:"
    echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    exit 1
fi

# Step 2: Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found."
    echo "Installing Python 3 via Homebrew..."
    brew install python@3.11
fi

# Step 3: Install system dependencies
echo "📦 Installing system dependencies..."
brew install tesseract
brew install opencv
brew install libmagic

# Step 4: Create virtual environment
if [ ! -d "venv" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Step 5: Activate virtual environment
source venv/bin/activate

# Step 6: Upgrade pip
pip install --upgrade pip

# Step 7: Install Python dependencies
if [ -f "requirements_mac.txt" ]; then
    echo "📚 Installing Mac-specific Python dependencies..."
    pip install -r requirements_mac.txt
elif [ -f "requirements.txt" ]; then
    echo "📚 Installing standard Python dependencies..."
    pip install -r requirements.txt
else
    echo "❌ No requirements file found!"
    exit 1
fi

# Step 8: Create Mac-specific config
if [ ! -f "config_mac.json" ]; then
    echo "⚙️  Creating Mac-specific configuration..."
    cat > config_mac.json << 'EOF'
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
    echo "✅ Created config_mac.json - please edit with your settings"
fi

# Step 9: Create Mac launcher script
cat > run_mac.sh << 'EOF'
#!/bin/bash
# ChastiPi Mac Launcher
cd "$(dirname "$0")"
source venv/bin/activate
python run_mac.py
EOF

chmod +x run_mac.sh

# Step 10: Create desktop shortcut (optional)
if command -v osascript &> /dev/null; then
    echo "🖥️  Creating desktop shortcut..."
    osascript << 'EOF'
tell application "System Events"
    make new alias file at desktop to POSIX file "'$(pwd)'/run_mac.sh" with properties {name:"ChastiPi"}
end tell
EOF
fi

# Step 11: Success message
cat << 'EOF'

✅ ChastiPi Mac installation complete!

📋 Next steps:
1. Edit config_mac.json with your email settings
2. Run the app: ./run_mac.sh
3. Access the web interface: http://localhost:5000

🖥️  Mac-specific features:
- System notifications for events
- Desktop shortcut created
- Optimized for macOS performance
- Local-only access (127.0.0.1) for security

🔧 To start the app:
  ./run_mac.sh

🌐 Web interface:
  http://localhost:5000

EOF 