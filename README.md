# ChastiPi - Digital Keyholder & Punishment Management System

A comprehensive system for managing chastity devices, punishments, and keyholder relationships with advanced automation and security features.

## 🌟 Features

### 🔐 Digital Keyholder System
- Encrypted key storage and email-based approval
- Temporary access tokens with automatic expiration
- Emergency release procedures and request history
- Remote management via email or web interface

### 📋 Punishment Management
- Unique QR code generation and PDF documentation
- Photo verification system with OCR recognition
- Customizable tasks and time tracking
- Secure verification with cryptographic hashes

### 🔒 Cage Check System
- Photo/video verification with random codes
- OCR code reading and email notifications
- Smart notifications and expiry management
- Complete audit trail of all verification attempts

### 📧 Email Integration
- Email-based management and automatic notifications
- Configuration via email attachments
- Webhook support and intelligent command parsing

### ⚙️ Configuration Management
- Complete settings customization and templates
- Import/export with real-time updates
- Audit trail and automatic validation

### 📅 Calendar & Scheduling
- Event management and progress tracking
- Reminder system and detailed analytics
- Integration with external calendar systems

### 🔍 Time Verification
- NTP time sync with drift detection
- Automatic correction and security logging
- Multiple NTP servers and alert system

### 📸 Photo Upload & Verification
- QR code scanning and OCR text recognition
- Multiple format support (JPG, PNG, GIF, BMP, MP4, MOV, AVI, WMV, FLV, WEBM)
- Video processing with frame extraction
- Verification dashboard with accuracy thresholds

### 🛡️ Security Features
- Encrypted storage and email verification
- Session management and access control
- Comprehensive audit logging and rate limiting

📖 **For detailed feature explanations, see the [Documentation Index](docs/README.md)**

## 🚀 Quick Start

### Prerequisites
- **Raspberry Pi** (3 or 4 recommended) or **macOS**
- Python 3.8+
- Internet connection for email and time sync
- Camera (optional, for photo verification)

### Installation Options

#### 🍓 Raspberry Pi (Recommended)
**For the easiest installation experience:**
```bash
# Clone the repository
git clone https://github.com/yourusername/ChastiPi.git
cd ChastiPi

# Run the automated installer
./install_raspberry_pi.sh
```

**For manual installation:**
```bash
# Clone and install manually
git clone https://github.com/yourusername/ChastiPi.git
cd ChastiPi
bash install.sh
source venv/bin/activate
python run.py
```

📖 **See [Raspberry Pi Installation Guide](README_RASPBERRY_PI.md) for detailed instructions.**

#### 🍎 macOS
**For native Mac app:**
```bash
# Clone the repository
git clone https://github.com/yourusername/ChastiPi.git
cd ChastiPi

# Build Mac app bundle
./mac_version/build_mac_app.sh

# Install and run
cp -R ChastiPi.app /Applications/
open /Applications/ChastiPi.app
```

**For command line installation:**
```bash
# Clone and install
git clone https://github.com/yourusername/ChastiPi.git
cd ChastiPi
./mac_version/install_mac.sh
source venv/bin/activate
python run.py
```

📖 **See [Mac Installation Guide](mac_version/README.md) for detailed instructions.**

### Access the Web Interface
- **Raspberry Pi:** `http://your-pi-ip:5000`
- **macOS:** `http://localhost:5000`

## 🧩 Modes System

ChastiPi supports multiple operation modes with different features and restrictions. Choose from built-in modes or create custom ones.

### Built-in Modes
- **gentle**: No punishments, gentle experience
- **timed_challenge**: Focus on timed challenges
- **random_discipline**: Random punishments or tasks
- **strict**: Stricter rules and consequences
- **extreme**: All strict features, maximum restrictions

### Quick Setup
Set your mode in `config.json`:
```json
{
  "system": {
    "chastity_mode": "gentle"
  }
}
```

📖 **For detailed mode explanations and custom mode creation, see [Modes System Guide](docs/modes_system.md)**

## 🔌 Plugin System

ChastiPi supports a community plugin system! You can add new features by dropping Python files into the `plugins/` folder.

- All plugins in the `plugins/` folder are auto-detected.
- Enable or disable plugins from the Keyholder Dashboard (or self-manage dashboard if self-hosting).
- Changes require a restart to take effect.

### Managing Plugins
- Go to the Keyholder Dashboard.
- Use the Plugin Management section to toggle plugins on or off.
- Enabled plugins are loaded at startup.

### Creating a Plugin
- Create a `.py` file in the `plugins/` folder.
- Define a function called `register_plugin(app)`.
- Example:

```python
# plugins/hello_plugin.py
def register_plugin(app):
    @app.route('/hello-plugin')
    def hello():
        return 'Hello from plugin!'
```

### Plugin Safety
- Only enable plugins you trust.
- Community plugins can extend or modify any part of the app.

## 📧 Email Configuration

### Setup Email Service
1. **Configure SMTP settings** in `config.json`:
   ```json
   {
     "email": {
       "smtp_server": "smtp.gmail.com",
       "smtp_port": 587,
       "username": "your-email@gmail.com",
       "password": "your-app-password",
       "use_tls": true
     }
   }
   ```

2. **Set up webhook** for email processing:
   - Configure your email service to send webhooks to `/webhook/email`
   - Test webhook functionality with `/webhook/test`

### Email Commands
Keyholders can manage the system via email:

- **`settings`** - Get configuration file to edit
- **`status`** - Get system status report
- **`help`** - Get command list
- **`approve`** - Approve pending requests
- **`deny`** - Deny pending requests
- **`extend 2 hours`** - Extend request duration
- **`reduce 1 hour`** - Reduce request duration
- **`emergency`** - Emergency key release
- **`check`** - Request cage/lock verification
- **`config`** - Get current configuration
- **`backup`** - Create configuration backup

### Time Units Supported
- **Hours**: `extend 2 hours`, `reduce 1 hour`
- **Days**: `extend 3 days`, `reduce 2 days`
- **Weeks**: `extend 1 week`, `reduce 1 week`
- **Months**: `extend 2 months`, `reduce 1 month`
- **Years**: `extend 1 year`, `reduce 6 months`

📖 **For detailed email setup, configuration, and troubleshooting, see [Email Configuration Guide](docs/email_configuration_system.md)**

## 🔧 Configuration Management

### Web Interface
1. **Access Configuration Dashboard**
   ```
   http://your-pi-ip:5000/keyholder/config
   ```

2. **Manage Settings**
   - Edit all system settings through web interface
   - Apply configuration templates
   - Export/import configurations

### Email-Based Configuration
1. **Request Configuration**
   - Reply to any ChastiPi email with "settings"
   - Receive `config.txt` file with current settings

2. **Edit Configuration**
   - Edit values in the text file
   - Keep keys unchanged
   - Save the file

3. **Apply Changes**
   - Reply with the updated file attached
   - Settings applied automatically
   - Receive confirmation email

### Configuration Sections
- **Cage Check Settings** - Verification timing and requirements
- **Notification Preferences** - Email, SMS, and alert settings
- **Punishment Configuration** - Generation rules and verification
- **Keyholder Management** - Approval rules and timeouts
- **Security Settings** - Access control and authentication
- **Appearance Preferences** - Theme, language, and display
- **Automation Rules** - Scheduled actions and auto-responses
- **Reporting Configuration** - Report types and delivery

## 📱 Quick Examples

### Keyholder Management
```bash
# Register device and request access
POST /keyholder/register
POST /keyholder/request
```

### Cage Check System
```bash
# Create verification request and upload photo
POST /cage-check/request
POST /cage-check/upload
```

### Email Commands
```bash
# Keyholder email commands
settings    # Get configuration
approve     # Approve pending requests
extend 2h   # Extend request duration
check       # Request verification
```

📖 **For detailed API documentation and examples, see the [Documentation Index](docs/README.md)**

## 🔒 Security & Monitoring

### Security Features
- Local network access by default
- Encrypted storage and email verification
- Comprehensive audit logging
- Rate limiting and access control

### Monitoring
- Status dashboard and log files
- Email notifications for system events
- Regular backups and configuration exports
- Performance monitoring and updates

📖 **For detailed security and monitoring information, see the [Documentation Index](docs/README.md)**

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch**
3. **Make changes and add tests**
4. **Submit pull request**

📖 **For development setup and guidelines, see the [Documentation Index](docs/README.md)**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- **[📚 Documentation Index](docs/README.md)** - Complete documentation guide
- **[🍓 Raspberry Pi Installation](README_RASPBERRY_PI.md)** - Complete Pi setup instructions
- **[🍎 Mac Installation](mac_version/README.md)** - macOS setup and app building

### Troubleshooting
- **Installation Issues:** Check platform-specific installation guides
- **NumPy Compatibility:** Use `./fix_numpy_issue.sh` (Raspberry Pi)
- **General Issues:** Check [Issues](../../issues) for known problems
- **System Issues:** Review logs in `logs/` directory

### Getting Help
- Create an issue for bugs or feature requests
- Check documentation for setup guides
- Review configuration examples

---

**ChastiPi** - Secure, flexible, and user-friendly chastity device management for the modern age.

*Built with ❤️ for the kink community*
