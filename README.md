# ChastiPi - Digital Keyholder & Punishment Management System

A comprehensive Raspberry Pi-based system for managing chastity devices, punishments, and keyholder relationships with advanced automation and security features.

## 🌟 Features

### 🔐 Digital Keyholder System
- **Encrypted Key Storage** - Securely store device key codes
- **Email-Based Approval** - Approve/deny requests via email or web interface
- **Temporary Access Tokens** - Time-limited key access with automatic expiration
- **Emergency Release** - Quick emergency access procedures
- **Request History** - Complete audit trail of all key requests
- **Remote Management** - Manage from anywhere via email or web
- **Timer Control** - Extend, reduce, or modify approved durations

### 📋 Punishment Management
- **Unique QR Code Generation** - Generate unique verification codes for each punishment
- **PDF Punishment Sheets** - Professional punishment documentation
- **Photo Verification System** - Upload photos to verify completion
- **OCR Number Recognition** - Read handwritten numbers from photos
- **Customizable Tasks** - Create personalized punishment requirements
- **Time Tracking** - Monitor completion times and deadlines
- **Verification Hashing** - Secure verification with cryptographic hashes

### 🔒 Cage Check System
- **Verification Requests** - Keyholders can request cage/lock verification
- **Random Code Generation** - Unique verification codes for each check
- **Photo Upload & Verification** - Upload photos with verification codes
- **OCR Code Reading** - Automatic code recognition from photos
- **Email Notifications** - Automatic reminders and status updates
- **Expiry Management** - Automatic expiration and escalation
- **Smart Notifications** - Intelligent reminder scheduling based on response patterns
- **Verification History** - Complete audit trail of all verification attempts

### 📧 Email Integration
- **Email-Based Management** - Control system entirely through email
- **Automatic Notifications** - Real-time email alerts for all events
- **Email Reply Processing** - Process keyholder responses via email
- **Configuration via Email** - Manage settings through email attachments
- **Webhook Support** - Integrate with email services and automation
- **Attachment Processing** - Handle configuration files and photos via email
- **Command Parsing** - Intelligent parsing of email commands and parameters

### ⚙️ Configuration Management
- **Keyholder Configuration System** - Complete settings customization
- **Email-Based Configuration** - Edit settings via email and file attachments
- **Configuration Templates** - Pre-built settings for common scenarios
- **Import/Export** - Backup and restore configurations
- **Real-Time Updates** - Settings applied immediately
- **Audit Trail** - Track all configuration changes
- **Validation** - Automatic validation of configuration changes
- **Backup Management** - Automatic configuration backups

### 📅 Calendar & Scheduling
- **Event Management** - Schedule punishments, checks, and releases
- **Progress Tracking** - Monitor completion and milestones
- **Reminder System** - Automatic notifications for upcoming events
- **Statistics & Reports** - Detailed activity reports and analytics
- **Integration** - Sync with external calendar systems

### 🔍 Time Verification
- **NTP Time Sync** - Verify system time against trusted servers
- **Drift Detection** - Monitor for time manipulation attempts
- **Automatic Correction** - Sync time automatically when drift detected
- **Security Logging** - Track all time verification attempts
- **Multiple NTP Servers** - Redundant time verification sources
- **Alert System** - Notify keyholders of time manipulation attempts

### 📸 Photo Upload & Verification
- **QR Code Scanning** - Automatic QR code detection from photos
- **OCR Text Recognition** - Read handwritten numbers and text
- **Multiple Format Support** - JPG, PNG, GIF, BMP support
- **Verification Dashboard** - Review and approve uploaded photos
- **Accuracy Thresholds** - Configurable verification accuracy
- **Image Processing** - Automatic image enhancement for better OCR
- **Batch Processing** - Handle multiple photos in single upload

### 🛡️ Security Features
- **Encrypted Storage** - All sensitive data encrypted at rest
- **Email Verification** - Verify keyholder identity via email
- **Session Management** - Secure session handling and timeouts
- **Access Control** - Role-based access control
- **Audit Logging** - Comprehensive security logging
- **Rate Limiting** - Prevent abuse and brute force attacks
- **Input Validation** - Sanitize all user inputs

## 🚀 Quick Start

### Prerequisites
- Raspberry Pi (3 or 4 recommended)
- Python 3.8+
- Internet connection for email and time sync
- Camera (optional, for photo verification)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ChastiPi.git
   cd ChastiPi
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the system**
   ```bash
   # Edit config.json with your settings
   nano config.json
   ```

4. **Run the application**
   ```bash
   python run.py
   ```

5. **Access the web interface**
   ```
   http://your-pi-ip:5000
   ```

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

## 📱 Usage Examples

### Keyholder Management
```bash
# Register a new device
POST /keyholder/register
{
  "device_id": "cage_001",
  "device_name": "My Chastity Cage",
  "keyholder_email": "keyholder@example.com",
  "key_codes": {"lock1": "1234", "lock2": "5678"}
}

# Request key release
POST /keyholder/request
{
  "device_id": "cage_001",
  "reason": "Medical appointment",
  "duration_hours": 2
}
```

### Cage Check System
```bash
# Create cage check request
POST /cage-check/request
{
  "keyholder_email": "keyholder@example.com",
  "wearer_email": "wearer@example.com",
  "device_name": "Chastity Cage",
  "check_type": "cage",
  "reason": "Random verification"
}

# Upload verification photo
POST /cage-check/upload
{
  "request_id": "CHECK_20231201_143022_1234",
  "photo": "base64_encoded_image"
}

# Get check status
GET /cage-check/status/CHECK_20231201_143022_1234

# List all checks
GET /cage-check/list?keyholder_email=keyholder@example.com
```

### Email Configuration
```bash
# Test email webhook
POST /webhook/email/test
{
  "from": {"email": "keyholder@example.com"},
  "subject": "Settings Request",
  "text": "settings"
}

# Test configuration import
POST /webhook/email/config-import
{
  "from": {"email": "keyholder@example.com"},
  "attachments": [{"filename": "config.txt", "content": "# Configuration..."}]
}
```

### Punishment Management
```bash
# Generate new punishment
POST /punishment/generate
{
  "task_description": "Write lines 100 times",
  "verification_required": true,
  "time_limit_hours": 24
}

# Upload punishment completion
POST /punishment/upload
{
  "punishment_id": "PUN_20231201_143022_5678",
  "photo": "base64_encoded_image",
  "completion_notes": "Task completed as requested"
}

# Get punishment statistics
GET /punishment/stats?period=month
```

### Configuration Management
```bash
# Export configuration
GET /keyholder/config/export

# Import configuration
POST /keyholder/config/import
{
  "config_data": "# Configuration file content...",
  "backup_existing": true
}

# Get configuration template
GET /keyholder/config/template?type=basic
```

### Time Verification
```bash
# Check system time
GET /time-verification/status

# Force time sync
POST /time-verification/sync

# Get time verification history
GET /time-verification/history?days=7
```

## 🔒 Security Considerations

### Network Security
- **Local Network Only** - Default configuration for local access
- **Port Forwarding** - Configure for remote access if needed
- **VPN Setup** - Recommended for secure remote access
- **HTTPS** - Use reverse proxy for encrypted connections

### Email Security
- **App Passwords** - Use app-specific passwords for email
- **Webhook Verification** - Verify webhook authenticity
- **Email Encryption** - Consider PGP for sensitive communications
- **Access Logging** - Monitor all email-based actions

### Data Protection
- **Encrypted Storage** - All sensitive data encrypted
- **Regular Backups** - Backup configurations and data
- **Access Control** - Limit access to authorized users
- **Audit Trail** - Log all system activities

## 📊 Monitoring & Maintenance

### System Health
- **Status Dashboard** - Monitor system health and status
- **Log Files** - Review logs in `logs/` directory
- **Email Notifications** - Get alerts for system events
- **Performance Monitoring** - Track system performance

### Backup & Recovery
- **Configuration Backup** - Export configurations regularly
- **Data Backup** - Backup `data/` directory
- **System Backup** - Full system image backup
- **Recovery Procedures** - Document recovery steps

### Updates & Maintenance
- **Regular Updates** - Keep system and dependencies updated
- **Security Patches** - Apply security updates promptly
- **Configuration Review** - Regular configuration audits
- **Performance Optimization** - Monitor and optimize performance

## 🤝 Contributing

### Development Setup
1. **Fork the repository**
2. **Create feature branch**
3. **Make changes**
4. **Add tests**
5. **Submit pull request**

### Code Style
- Follow PEP 8 guidelines
- Add type hints
- Include docstrings
- Write unit tests

### Testing
```bash
# Run tests
python -m pytest tests/

# Run linting
flake8 chasti_pi/

# Run type checking
mypy chasti_pi/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- [Cage Check System](docs/cage_check_system.md)
- [Email Configuration](docs/email_configuration_system.md)
- [Keyholder Configuration](docs/keyholder_configuration_system.md)
- [Time Verification](docs/time_verification_security.md)
- [Remote Access Setup](docs/remote_access_setup.md)
- [Cage Check Notifications](docs/cage_check_notifications.md)
- [Email First Approach](docs/email_first_approach.md)
- [Keyholder Timer Control](docs/keyholder_timer_control.md)

### Troubleshooting
- Check [Issues](../../issues) for known problems
- Review logs in `logs/` directory
- Test email configuration with `/webhook/test`
- Verify webhook setup with `/webhook/status`

### Getting Help
- Create an issue for bugs or feature requests
- Check documentation for setup guides
- Review configuration examples
- Test with sample data first

## 🔮 Roadmap

### Planned Features
- [ ] Mobile app for notifications
- [ ] Advanced analytics dashboard
- [ ] Integration with smart locks
- [ ] Voice command support
- [ ] Machine learning for verification
- [ ] Multi-user support
- [ ] Advanced scheduling
- [ ] API rate limiting

### Future Enhancements
- [ ] Blockchain integration
- [ ] Advanced encryption
- [ ] Cloud backup
- [ ] Multi-language support
- [ ] Accessibility improvements
- [ ] Performance optimizations

---

**ChastiPi** - Secure, flexible, and user-friendly chastity device management for the modern age.

*Built with ❤️ for the kink community*
