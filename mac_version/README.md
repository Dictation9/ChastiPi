# ChastiPi Mac Version 🍎

This folder contains all the Mac-specific code and tools for creating a native macOS application bundle for ChastiPi.

📖 **See the [main README](../README.md) for general project information and features.**

## 📁 Folder Structure

```
mac_version/
├── build_mac_app.sh          # Main build script
├── create_mac_app.sh         # Creates .app bundle
├── create_app_icon.py        # Generates app icon
├── create_dmg.sh            # Creates DMG installer
├── install_mac.sh           # Mac installation script
├── package_mac.sh           # Creates distributable package
├── run_mac.py               # Mac-specific launcher
├── requirements_mac.txt     # Mac dependencies
├── mac_app.py               # Mac-specific app wrapper
├── README_MAC.md           # Mac installation guide
├── MAC_APP_GUIDE.md        # App bundle guide
└── README.md               # This file
```

## 🚀 Quick Start

### Create Mac App Bundle
```bash
# Navigate to mac_version folder
cd mac_version

# Make scripts executable
chmod +x *.sh *.py

# Build the complete Mac app
./build_mac_app.sh
```

This will:
1. Copy necessary files from the main ChastiPi directory
2. Create a custom app icon
3. Build the Mac app bundle
4. Create a DMG installer

### Individual Scripts

**Create App Bundle Only:**
```bash
./create_mac_app.sh
```

**Create App Icon Only:**
```bash
python3 create_app_icon.py
```

**Create DMG Installer:**
```bash
./create_dmg.sh
```

**Install Dependencies:**
```bash
./install_mac.sh
```

## 📱 Generated Files

After running `build_mac_app.sh`, you'll get:

- **`ChastiPi.app`** - Native macOS application bundle
- **`ChastiPi-YYYYMMDD.dmg`** - DMG installer for distribution

## 🔧 Usage

### Testing the App
```bash
# Open the app bundle
open ChastiPi.app

# Or run from command line
./ChastiPi.app/Contents/MacOS/ChastiPi
```

### Installing to Applications
```bash
# Copy to Applications folder
cp -R ChastiPi.app /Applications/

# Run from Applications
open /Applications/ChastiPi.app
```

### Distribution
```bash
# Share the DMG file
# Users can double-click and drag to Applications
```

## 🛠️ Development

### Modifying the App Bundle
```bash
# Edit the app launcher
nano ChastiPi.app/Contents/MacOS/ChastiPi

# Edit configuration
nano ChastiPi.app/Contents/Resources/config_mac.json

# Rebuild after changes
./create_mac_app.sh
```

### Customizing the Icon
```bash
# Edit icon design
nano create_app_icon.py

# Regenerate icon
python3 create_app_icon.py

# Rebuild app
./create_mac_app.sh
```

## 📋 Requirements

### System Requirements
- macOS 10.15 (Catalina) or later
- Homebrew (for dependencies)
- Python 3.8+

### Python Dependencies
- Flask and web dependencies
- OpenCV for image processing
- Tesseract for OCR
- PyObjC for macOS integration

## 🔒 Security Features

- **Local Access Only**: Runs on 127.0.0.1 by default
- **No External Network**: Prevents unauthorized access
- **Encrypted Storage**: Uses macOS keychain
- **System Integration**: Native macOS permissions

## 🐛 Troubleshooting

### Common Issues

**"App can't be opened"**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine ChastiPi.app
```

**"Dependencies missing"**
```bash
# Run dependency installer
./ChastiPi.app/Contents/Resources/install_dependencies.sh
```

**"Python not found"**
```bash
# Install Python via Homebrew
brew install python@3.11
```

### Debug Mode
```bash
# Run with debug output
./ChastiPi.app/Contents/MacOS/ChastiPi --debug
```

## 📚 Documentation

- **[Main ChastiPi README](../README.md)** - General project information and features
- **[Raspberry Pi Installation Guide](../README_RASPBERRY_PI.md)** - Pi setup instructions
- **`README_MAC.md`** - Complete Mac installation guide
- **`MAC_APP_GUIDE.md`** - Detailed app bundle guide

## 🔄 Updates

### Updating the Mac Version
```bash
# Pull latest changes from main repo
cd ..
git pull origin main

# Rebuild Mac app
cd mac_version
./build_mac_app.sh
```

### Version Management
- Update version in `create_mac_app.sh`
- Update bundle identifier if needed
- Test on multiple macOS versions

## 📦 Distribution

### Creating Distribution Package
```bash
# Create DMG with branding
./create_dmg.sh

# The DMG includes:
# - ChastiPi.app
# - Applications folder shortcut
```

### Code Signing (Optional)
```bash
# Sign the app bundle
codesign --deep --force --verify --verbose --sign "Developer ID Application: Your Name" ChastiPi.app
```

## 🆘 Support

### Getting Help
1. Check the troubleshooting section above
2. Review `MAC_APP_GUIDE.md` for detailed instructions
3. Check app logs in Console.app
4. Run with `--debug` flag for verbose output

### Reporting Issues
Include:
- macOS version
- ChastiPi version
- Error messages
- Steps to reproduce

---

**Note**: This Mac version provides a native macOS experience while maintaining all the security and functionality of the original ChastiPi system. 