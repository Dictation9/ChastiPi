# ChastiPi Raspberry Pi Installation Guide

This guide provides easy installation instructions for running ChastiPi on Raspberry Pi devices.

📖 **See the [main README](README.md) for general project information and features.**

🍎 **For macOS installation, see the [Mac Installation Guide](mac_version/README.md).**

## 🍓 Quick Start (Recommended)

### Option 1: Automated Installation
```bash
# Download and run the automated installer
wget https://raw.githubusercontent.com/your-repo/ChastiPi/main/install_raspberry_pi.sh
chmod +x install_raspberry_pi.sh
./install_raspberry_pi.sh
```

### Option 2: Manual Installation
```bash
# Clone the repository
git clone https://github.com/your-repo/ChastiPi.git
cd ChastiPi

# Run the installer
./install_raspberry_pi.sh
```

## 🔧 Quick Fix for NumPy Issues

If you encounter NumPy compatibility errors, run:
```bash
./fix_numpy_issue.sh
```

## 📋 System Requirements

- **Raspberry Pi:** Pi 3 or newer (recommended)
- **RAM:** At least 1GB (2GB+ recommended)
- **Storage:** At least 2GB free space
- **OS:** Raspberry Pi OS (Bullseye or newer)
- **Network:** Internet connection for installation

## 🚀 What the Installer Does

The automated installer performs the following steps:

1. **System Check**
   - Verifies Raspberry Pi hardware
   - Checks available memory and disk space
   - Validates Python installation

2. **Dependency Installation**
   - Installs system packages (OpenCV, Tesseract, etc.)
   - Creates Python virtual environment
   - Installs Python packages with Pi-optimized versions

3. **Configuration**
   - Creates necessary directories
   - Sets up default configuration
   - Configures Tesseract OCR

4. **Testing**
   - Tests Python imports
   - Validates video processing
   - Creates startup scripts

5. **Optional Setup**
   - Creates systemd service for auto-start
   - Sets up logging and monitoring

## 📁 Installation Files

- `install_raspberry_pi.sh` - Complete automated installer
- `fix_numpy_issue.sh` - Quick fix for NumPy compatibility
- `requirements_raspberry_pi.txt` - Pi-optimized dependencies
- `start_chastipi.sh` - Startup script (created by installer)

## 🎯 Post-Installation

### Starting the Application
```bash
# Method 1: Using startup script
./start_chastipi.sh

# Method 2: Manual start
source venv/bin/activate
python3 run.py
```

### Accessing the Web Interface
- **Local:** http://localhost:5000
- **Network:** http://your-pi-ip:5000

### Configuration
Edit `config.json` to customize settings:
- Network configuration
- Email settings
- Security options
- Video processing limits

## 🔄 Auto-Start Setup

To enable auto-start on boot:
```bash
# Enable systemd service (if created during installation)
sudo systemctl enable chastipi

# Start the service
sudo systemctl start chastipi

# Check status
sudo systemctl status chastipi
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. NumPy Compatibility Error
```bash
# Quick fix for NumPy 2.x compatibility issues
./fix_numpy_issue.sh
```

**Common Error:** `AttributeError: _ARRAY_API not found` or `numpy.core.multiarray failed to import`
**Solution:** The fix script automatically downgrades NumPy to a compatible version.

#### 2. Memory Issues
- Close unnecessary applications
- Increase swap space: `sudo dphys-swapfile swapoff && sudo dphys-swapfile setup && sudo dphys-swapfile swapon`

#### 3. Camera/Video Issues
- Ensure camera is enabled: `sudo raspi-config`
- Check camera permissions: `sudo usermod -a -G video $USER`

#### 4. Network Access Issues
- Check firewall: `sudo ufw status`
- Allow port 5000: `sudo ufw allow 5000`

### Logs and Debugging
```bash
# View application logs
tail -f logs/app.log

# Check system resources
htop

# Monitor disk space
df -h
```

## 📊 Performance Optimization

### For Pi 3/4 (1GB RAM)
- Reduce video processing quality
- Limit concurrent uploads
- Enable compression

### For Pi 4 (4GB+ RAM)
- Increase video processing quality
- Enable caching
- Run additional services

## 🔄 Updates

To update ChastiPi:
```bash
# Pull latest changes
git pull

# Re-run installer (will preserve data)
./install_raspberry_pi.sh
```

## 📞 Support

### Getting Help
1. Check the logs: `tail -f logs/app.log`
2. Review configuration: `cat config.json`
3. Test components: `python3 test_video_processing.py`

### Useful Commands
```bash
# Check system status
systemctl status chastipi

# View real-time logs
journalctl -u chastipi -f

# Restart service
sudo systemctl restart chastipi

# Check disk usage
du -sh data/ logs/ uploads/
```

## 🎉 Success!

Once installed, you can:
- ✅ Upload photos and videos for verification
- ✅ Process cage check requests
- ✅ Manage keyholder permissions
- ✅ Monitor system status
- ✅ Access web interface from any device

Your ChastiPi is now ready to use! 🚀 