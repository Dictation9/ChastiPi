# ChastiPi Mac Edition 🍎

A macOS-optimized version of ChastiPi with native system integration, notifications, and tray functionality.

## 🌟 Mac-Specific Features

### 🖥️ Native macOS Integration
- **System Notifications** - Native macOS notifications for all events
- **Status Bar Menu** - Quick access from the menu bar with tray icon
- **Desktop Shortcut** - Easy one-click launch
- **Auto-Start Option** - Launch automatically on login
- **Local-Only Access** - Secure localhost-only access by default

### 🔒 Enhanced Security
- **Local Network Only** - Runs on 127.0.0.1 by default for security
- **System Integration** - Uses macOS security features
- **Encrypted Storage** - All data encrypted using macOS keychain

### 📱 User Experience
- **Native UI Elements** - Uses macOS design patterns
- **System Tray** - Minimize to system tray with quick access
- **Notification Center** - Integrates with macOS Notification Center
- **Keyboard Shortcuts** - Standard macOS keyboard shortcuts

## 🚀 Quick Installation

### Prerequisites
- macOS 10.15 (Catalina) or later
- Homebrew (for package management)
- Python 3.8+

### Step 1: Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2: Clone and Install
```bash
# Clone the repository
git clone https://github.com/yourusername/ChastiPi.git
cd ChastiPi

# Run the Mac installation script
chmod +x install_mac.sh
./install_mac.sh
```

### Step 3: Configure
Edit `config_mac.json` with your settings:
```json
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
  "mac_specific": {
    "use_system_notifications": true,
    "auto_start_on_login": false,
    "minimize_to_tray": true
  }
}
```

### Step 4: Launch
```bash
# Method 1: Use the Mac launcher
./run_mac.sh

# Method 2: Use Python directly
python run_mac.py

# Method 3: Use the desktop shortcut (created during installation)
# Double-click the ChastiPi shortcut on your desktop
```

## 🖥️ Mac-Specific Usage

### Status Bar Menu
- Click the 🔒 icon in the menu bar
- **Dashboard** - Open the web interface
- **Quit** - Exit the application

### System Notifications
- All events (key requests, punishments, etc.) will show as native notifications
- Click notifications to open the relevant section
- Notifications are stored in Notification Center

### Auto-Start on Login
To enable auto-start:
1. Open System Preferences > Users & Groups
2. Select your user account
3. Click "Login Items"
4. Click "+" and add the `run_mac.sh` script

### Security Features
- **Local Access Only** - By default, only accessible from localhost
- **No External Access** - Prevents unauthorized network access
- **Encrypted Configuration** - Settings stored securely

## 🔧 Configuration Options

### Mac-Specific Settings
```json
{
  "mac_specific": {
    "use_system_notifications": true,    // Enable native notifications
    "auto_start_on_login": false,        // Start automatically on login
    "minimize_to_tray": true,            // Minimize to system tray
    "show_status_bar_icon": true,        // Show menu bar icon
    "notification_sound": "default"      // Notification sound preference
  }
}
```

### Network Settings
```json
{
  "system": {
    "host": "127.0.0.1",    // Local access only (recommended)
    "port": 5000,           // Port number
    "debug": false          // Debug mode
  }
}
```

## 🛠️ Troubleshooting

### Common Issues

**"Homebrew not found"**
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**"Python 3 not found"**
```bash
brew install python@3.11
```

**"Mac features not available"**
```bash
# Reinstall with Mac dependencies
pip install -r requirements_mac.txt
```

**"Permission denied"**
```bash
chmod +x install_mac.sh
chmod +x run_mac.sh
```

### Reset Configuration
```bash
# Remove Mac config and recreate
rm config_mac.json
./install_mac.sh
```

### Uninstall
```bash
# Remove virtual environment
rm -rf venv

# Remove Mac-specific files
rm -f config_mac.json run_mac.sh run_mac.py

# Remove desktop shortcut (manually delete from Desktop)
```

## 🔒 Security Notes

- **Local Access Only**: The Mac version runs on localhost by default for security
- **No External Network**: Prevents unauthorized access from other devices
- **System Integration**: Uses macOS security features and keychain
- **Encrypted Storage**: All sensitive data is encrypted

## 📱 Mobile Access

To access from your iPhone/iPad on the same network:
1. Change `host` in `config_mac.json` from `"127.0.0.1"` to `"0.0.0.0"`
2. Find your Mac's IP address: `ifconfig | grep "inet " | grep -v 127.0.0.1`
3. Access from mobile: `http://YOUR_MAC_IP:5000`

## 🆘 Support

For Mac-specific issues:
1. Check the troubleshooting section above
2. Ensure all dependencies are installed: `brew list`
3. Verify Python environment: `python --version`
4. Check logs in the application

## 🔄 Updates

To update the Mac version:
```bash
git pull origin main
./install_mac.sh
```

---

**Note**: This Mac edition is optimized for personal use on macOS. For production or multi-user environments, consider the standard Raspberry Pi version. 