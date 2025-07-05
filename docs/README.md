# ChastiPi Documentation

Welcome to the ChastiPi documentation! This directory contains detailed guides for all aspects of the system.

## 📚 Quick Navigation

### 🚀 Installation Guides
- **[Main README](../README.md)** - Project overview and quick start
- **[Raspberry Pi Installation](../README_RASPBERRY_PI.md)** - Complete Pi setup guide
- **[Mac Installation](../mac_version/README.md)** - macOS setup and app building

### 🔧 System Components

#### Core Systems
- **[Cage Check System](cage_check_system.md)** - Photo/video verification system
- **[Email Configuration](email_configuration_system.md)** - Email-based management
- **[Keyholder Configuration](keyholder_configuration_system.md)** - Settings and permissions
- **[Time Verification](time_verification_security.md)** - Security and time sync

#### Advanced Features
- **[Remote Access Setup](remote_access_setup.md)** - Network configuration
- **[Cage Check Notifications](cage_check_notifications.md)** - Notification system
- **[Email First Approach](email_first_approach.md)** - Email-only workflow
- **[Keyholder Timer Control](keyholder_timer_control.md)** - Timer management

#### Reference Materials
- **[Time Unit Examples](time_unit_examples.md)** - Time format examples
- **[Setting Permissions System](setting_permissions_system.md)** - Permission management

## 🎯 Getting Started

### For New Users
1. **Choose your platform:**
   - **Raspberry Pi:** Start with [Raspberry Pi Installation Guide](../README_RASPBERRY_PI.md)
   - **macOS:** Start with [Mac Installation Guide](../mac_version/README.md)

2. **Learn the basics:**
   - Read [Cage Check System](cage_check_system.md) for photo verification
   - Read [Email Configuration](email_configuration_system.md) for email management

3. **Configure your system:**
   - Use [Keyholder Configuration](keyholder_configuration_system.md) for settings
   - Set up [Remote Access](remote_access_setup.md) if needed

### For Advanced Users
- **[Time Verification](time_verification_security.md)** - Security features
- **[Timer Control](keyholder_timer_control.md)** - Advanced timer management
- **[Email First Approach](email_first_approach.md)** - Email-only workflows

## 🔍 Troubleshooting

### Common Issues
- **NumPy compatibility:** Use `./fix_numpy_issue.sh` (Raspberry Pi)
- **Installation problems:** Check platform-specific installation guides
- **Email issues:** See [Email Configuration](email_configuration_system.md)
- **Network access:** See [Remote Access Setup](remote_access_setup.md)

### Getting Help
1. Check the relevant documentation file
2. Review logs in the `logs/` directory
3. Test with sample data first
4. Create an issue on GitHub for bugs

## 📖 Documentation Structure

```
docs/
├── README.md                    # This file - documentation index
├── cage_check_system.md         # Photo/video verification
├── email_configuration_system.md # Email-based management
├── keyholder_configuration_system.md # Settings and permissions
├── time_verification_security.md # Security and time sync
├── remote_access_setup.md       # Network configuration
├── cage_check_notifications.md  # Notification system
├── email_first_approach.md      # Email-only workflow
├── keyholder_timer_control.md   # Timer management
├── time_unit_examples.md        # Time format examples
└── setting_permissions_system.md # Permission management
```

## 🔄 Contributing to Documentation

### Adding New Documentation
1. Create a new `.md` file in the `docs/` directory
2. Add a link to it in this README.md
3. Follow the existing documentation style
4. Include examples and troubleshooting sections

### Documentation Style Guide
- Use clear, descriptive headings
- Include code examples
- Add troubleshooting sections
- Link to related documentation
- Keep content up to date

## 📞 Support

For additional help:
- Check the [main README](../README.md) for project overview
- Review platform-specific installation guides
- Create an issue on GitHub for bugs or feature requests
- Check logs in the `logs/` directory for errors

---

*This documentation is maintained alongside the ChastiPi project. For the latest updates, check the main repository.* 