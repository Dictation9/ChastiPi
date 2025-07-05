# ChastiPi Mac App Bundle Guide 🍎

This guide explains how to create a proper macOS `.app` bundle for ChastiPi that can be installed and run like a native Mac application.

## 🚀 Quick Start

### Create the Mac App Bundle
```bash
# Make scripts executable
chmod +x create_mac_app.sh create_app_icon.py

# Create the app bundle
./create_mac_app.sh
```

### Test the App
```bash
# Open the app bundle
open ChastiPi.app

# Or run from command line
./ChastiPi.app/Contents/MacOS/ChastiPi
```

### Create DMG Installer
```bash
# Create a DMG installer
./create_dmg.sh
```

## 📁 App Bundle Structure

The created `ChastiPi.app` bundle follows the standard macOS app structure:

```
ChastiPi.app/
├── Contents/
│   ├── Info.plist              # App metadata and settings
│   ├── MacOS/
│   │   └── ChastiPi           # Main executable
│   ├── Resources/
│   │   ├── chasti_pi/         # Core application
│   │   ├── templates/         # Web templates
│   │   ├── static/           # Static assets
│   │   ├── plugins/          # Plugin system
│   │   ├── docs/             # Documentation
│   │   ├── run_mac.py        # Mac-specific launcher
│   │   ├── requirements_mac.txt # Mac dependencies
│   │   ├── config_mac.json   # Configuration
│   │   ├── AppIcon.icns      # App icon
│   │   ├── install_dependencies.sh # System dependencies
│   │   ├── uninstall.sh      # Uninstaller
│   │   └── README.txt        # App documentation
│   └── Frameworks/           # (Empty, for future use)
```

## 🎨 App Icon

The app includes a custom icon with a lock symbol:

- **Design**: Modern lock icon with blue glow effect
- **Sizes**: 16x16 to 1024x1024 (all standard macOS sizes)
- **Format**: `.icns` (macOS icon format)
- **Retina Support**: Includes @2x versions for high-DPI displays

### Customizing the Icon
```bash
# Edit the icon design
nano create_app_icon.py

# Regenerate the icon
python3 create_app_icon.py

# Recreate the app bundle
./create_mac_app.sh
```

## ⚙️ App Configuration

### Info.plist Settings
The app bundle includes these macOS-specific settings:

- **LSUIElement**: `true` - Runs as background app (no dock icon)
- **NSHighResolutionCapable**: `true` - Supports Retina displays
- **LSMinimumSystemVersion**: `10.15` - Requires macOS Catalina+
- **NSAppleEventsUsageDescription**: Explains permission requirements

### First Run Behavior
1. **Auto-Installation**: Creates virtual environment and installs dependencies
2. **Configuration**: Creates default `config_mac.json` if none exists
3. **System Dependencies**: Prompts to install Homebrew packages if needed

## 🔧 Installation Methods

### Method 1: Direct App Bundle
```bash
# Copy to Applications
cp -R ChastiPi.app /Applications/

# Run from Applications
open /Applications/ChastiPi.app
```

### Method 2: DMG Installer
```bash
# Create DMG
./create_dmg.sh

# Distribute the DMG file
# Users can drag to Applications folder
```

### Method 3: Manual Installation
```bash
# Extract and run
./ChastiPi.app/Contents/MacOS/ChastiPi
```

## 🛠️ Development and Customization

### Modifying the App Bundle
```bash
# Show package contents
open ChastiPi.app

# Edit resources
nano ChastiPi.app/Contents/Resources/config_mac.json

# Rebuild after changes
./create_mac_app.sh
```

### Adding Custom Features
1. **Edit the launcher**: `ChastiPi.app/Contents/MacOS/ChastiPi`
2. **Modify resources**: Add files to `Contents/Resources/`
3. **Update Info.plist**: Add new keys as needed

### Debugging
```bash
# Run with debug output
./ChastiPi.app/Contents/MacOS/ChastiPi 2>&1 | tee debug.log

# Check app logs
Console.app → Search for "ChastiPi"
```

## 📦 Distribution

### Creating a Distribution Package
```bash
# Create DMG with custom branding
./create_dmg.sh

# The DMG includes:
# - ChastiPi.app
# - Applications folder shortcut
# - Custom background (optional)
```

### Code Signing (Optional)
```bash
# Sign the app bundle
codesign --deep --force --verify --verbose --sign "Developer ID Application: Your Name" ChastiPi.app

# Verify signature
codesign --verify --verbose ChastiPi.app
```

### Notarization (Optional)
```bash
# Notarize for distribution
xcrun altool --notarize-app --primary-bundle-id "com.chastipi.app" --username "your-apple-id" --password "app-specific-password" --file ChastiPi.dmg
```

## 🔒 Security Features

### App Sandboxing
- **Local Access Only**: Runs on 127.0.0.1 by default
- **No Network Access**: Prevents external connections
- **Encrypted Storage**: Uses macOS keychain integration

### Permissions
The app requests these permissions:
- **Notifications**: For system notifications
- **Accessibility**: For status bar integration
- **Network**: For local web server

## 🐛 Troubleshooting

### Common Issues

**"App can't be opened"**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine ChastiPi.app

# Or allow from System Preferences
# System Preferences → Security & Privacy → General
```

**"Python not found"**
```bash
# Install Python via Homebrew
brew install python@3.11

# Or run the dependency installer
./ChastiPi.app/Contents/Resources/install_dependencies.sh
```

**"Dependencies missing"**
```bash
# Run the dependency installer
./ChastiPi.app/Contents/Resources/install_dependencies.sh

# Or install manually
brew install tesseract opencv libmagic
```

**"Port already in use"**
```bash
# Change port in config
nano ChastiPi.app/Contents/Resources/config_mac.json
# Change "port": 5000 to "port": 5001
```

### Debug Mode
```bash
# Run with debug output
./ChastiPi.app/Contents/MacOS/ChastiPi --debug

# Check logs
tail -f ~/Library/Logs/ChastiPi.log
```

## 📱 Mobile Access

To access from iPhone/iPad on the same network:

1. **Enable Network Access**:
   ```json
   {
     "system": {
       "host": "0.0.0.0"
     }
   }
   ```

2. **Find Mac IP**:
   ```bash
   ifconfig | grep "inet " | grep -v 127.0.0.1
   ```

3. **Access from Mobile**:
   ```
   http://YOUR_MAC_IP:5000
   ```

## 🔄 Updates

### Updating the App Bundle
```bash
# Pull latest changes
git pull origin main

# Recreate app bundle
./create_mac_app.sh

# Create new DMG
./create_dmg.sh
```

### User Updates
Users can update by:
1. Downloading the new DMG
2. Replacing the old app bundle
3. Running the new version

## 📋 Best Practices

### For Developers
- **Test on Multiple macOS Versions**: 10.15, 11.0, 12.0, 13.0
- **Use Virtual Environments**: Keep dependencies isolated
- **Handle Permissions Gracefully**: Request only what's needed
- **Provide Clear Error Messages**: Help users troubleshoot

### For Users
- **Keep Updated**: Download latest versions
- **Backup Configuration**: Save `config_mac.json`
- **Check Permissions**: Allow notifications and accessibility
- **Use Local Access**: Keep `host` as `127.0.0.1` for security

## 🆘 Support

### Getting Help
1. **Check Logs**: `Console.app` → Search for "ChastiPi"
2. **Run Debug Mode**: Add `--debug` flag
3. **Check Dependencies**: Run `install_dependencies.sh`
4. **Reset Configuration**: Delete `config_mac.json` and restart

### Reporting Issues
Include:
- macOS version
- ChastiPi version
- Error messages
- Steps to reproduce

---

**Note**: This Mac app bundle provides a native macOS experience while maintaining all the security and functionality of the original ChastiPi system. 