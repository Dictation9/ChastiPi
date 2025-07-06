# 🔐 ChastiPi Dashboard

A modern, lightweight web dashboard for chastity device management and Raspberry Pi system monitoring with dual-dashboard architecture.

## Features

### 🔐 Device Management Dashboard
- **Device Status Monitoring**: Real-time lock status, time remaining, keyholder approval
- **Key Management**: Digital keys, backup keys, emergency access tracking
- **Access History**: Session tracking, statistics, and usage analytics
- **Notification System**: Email alerts, SMS, webhook integration
- **Quick Actions**: Request access, emergency release, device checks, history viewing

### 👑 Keyholder Dashboard (Password Protected)
- **Device Control**: Unlock, lock, and emergency release capabilities
- **Access Management**: View and manage device access history
- **Real-time Monitoring**: Live device status and activity tracking
- **Notification Center**: View and manage system notifications
- **Settings Management**: Configure device settings and security options
- **Session Statistics**: Track usage patterns and session durations

### 🖥️ System Monitor Dashboard
- **Real-time System Monitoring**: CPU, memory, and disk usage with live updates
- **Process Management**: View top processes by CPU usage
- **System Information**: Platform details, hostname, last update timestamps
- **Performance Analytics**: Color-coded alerts based on resource usage

### 🎨 User Experience
- **Triple Dashboard Architecture**: Separate interfaces for device management, system monitoring, and keyholder control
- **Password Protection**: Secure keyholder access with session management
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Raspberry Pi Optimized**: Lightweight and efficient for Pi hardware
- **Modern UI**: Clean, gradient-based design with smooth animations
- **Navigation System**: Easy switching between dashboards

## Screenshots

The dual-dashboard system provides:

### Device Management Dashboard
- Device status with lock indicators and time remaining
- Key management overview with digital, backup, and emergency keys
- Access history with session statistics
- Notification system status
- Quick action buttons for common tasks

### System Monitor Dashboard
- System overview cards with progress bars
- Real-time CPU, memory, and disk usage
- Top processes table with resource consumption
- System information display
- Color-coded performance alerts

## Installation

### Prerequisites

- Raspberry Pi (any model)
- Python 3.7 or higher
- Internet connection for initial setup

### Quick Start

1. **Clone or download this repository**
   ```bash
   git clone https://github.com/Dictation9/ChastiPi.git
   cd ChastiPi
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the dashboards**
   - Open your web browser
   - Navigate to `http://your-pi-ip:5000`
   - Example: `http://192.168.1.100:5000`
   - Use the navigation to switch between Device Dashboard and System Monitor
   - For keyholder access, click "👑 Keyholder Access" and use default credentials:
     - Username: `keyholder`
     - Password: `secure123`

## Updates

### Manual Update Script

The project includes a comprehensive update script (`update.sh`) that provides various update options:

#### Quick Update Commands

```bash
# Update dependencies only
./update.sh --deps

# Update code from git repository
./update.sh --code

# Update system packages (Raspberry Pi only)
./update.sh --system

# Perform full update (dependencies + code + system)
./update.sh --full

# Restart the application
./update.sh --restart

# Setup autostart (start on boot)
./update.sh --autostart

# Remove autostart configuration
./update.sh --remove-autostart

# Show current status
./update.sh --status

# Show help
./update.sh --help
```

#### Interactive Mode

Run the script without arguments for an interactive menu:

```bash
./update.sh
```

#### Update Features

- **Automatic Backups**: Creates timestamped backups before updates using the new backup system
- **Dependency Management**: Updates Python packages and generates new requirements.txt
- **Git Integration**: Pulls latest code changes and handles uncommitted changes
- **Smart Merging**: Automatically merges configuration files and handles conflicts
- **System Updates**: Updates Raspberry Pi system packages (when applicable)
- **Application Restart**: Safely stops and restarts the ChastiPi application
- **Autostart Configuration**: Sets up the application to start automatically on boot
- **Status Monitoring**: Shows current application status and system information
- **Error Handling**: Comprehensive error checking and colored output

#### Autostart Options

The update script provides two methods for autostart configuration:

**Raspberry Pi (systemd):**
- Creates a systemd service file for automatic startup
- Service automatically restarts if the application crashes
- Can be managed with standard systemctl commands

**Other Systems (crontab):**
- Uses crontab @reboot to start the application
- Creates a startup script in the project directory
- Can be easily removed via crontab -e

#### Smart Merging Features

The update script includes intelligent merging capabilities to handle conflicts gracefully:

**Configuration File Merging:**
- Automatically merges INI-style configuration files
- Preserves local customizations while adding new options
- Handles JSON and YAML files with appropriate warnings
- Creates backup versions for manual review

**Conflict Resolution:**
- Detects and resolves common merge conflicts automatically
- Uses git merge strategies to favor local changes
- Provides fallback mechanisms for different file types
- Creates detailed backups before attempting merges

**File Type Support:**
- **Python/JavaScript files**: Prefers newer versions while preserving local changes
- **INI/Config files**: Merges sections and preserves customizations
- **JSON/YAML files**: Warns about manual merging requirements
- **Text files**: Keeps both versions for manual review

**Backup Strategy:**
- Creates timestamped backups before any merge operations using the new backup system
- Preserves original files with `.conflict` extensions
- Provides clear instructions for manual resolution if needed

## Backup System

ChastiPi includes a comprehensive backup management system located in the `backups/` directory:

### Quick Backup Commands
```bash
# Create backup with timestamp
./backups/backup.sh create

# Create backup with custom name
./backups/backup.sh create --name my_backup

# List available backups
./backups/backup.sh list

# Restore from backup
./backups/backup.sh restore backup_name

# Create compressed backup
./backups/backup.sh zip --name important_backup
```

### Backup Features
- **Automated Backups**: Timestamped backups with metadata tracking
- **Comprehensive Coverage**: Backs up all application files and assets
- **Smart Exclusions**: Excludes temporary files and development artifacts
- **Restoration Safety**: Creates backup before restoration
- **Compression Support**: Create compressed zip backups
- **Integration**: Seamlessly integrates with the update system

For detailed backup documentation, see `backups/README.md`.

## Configuration

### Network Access

The app runs on `0.0.0.0:5000` by default, making it accessible from other devices on your network.

### Customization

You can modify the following in `app.py`:
- **Port**: Change `port=5000` to your preferred port
- **Update intervals**: Modify the JavaScript update intervals in `static/js/dashboard.js`
- **Process count**: Change the number of processes displayed in the API

### Security Considerations

For production use, consider:
- **Change default credentials**: Update `KEYHOLDER_USERNAME` and `KEYHOLDER_PASSWORD` in `app.py`
- **Use environment variables**: Set `SECRET_KEY`, `KEYHOLDER_USERNAME`, and `KEYHOLDER_PASSWORD` as environment variables
- **Enable HTTPS**: Use a reverse proxy (nginx) with SSL certificates
- **Firewall configuration**: Restrict access to trusted networks
- **Regular updates**: Keep the system and dependencies updated

## File Structure

```
chastipi-dashboard/
├── app.py                 # Main Flask application
├── backups/               # Backup management system
│   ├── backup_manager.py  # Python backup manager
│   ├── backup.sh         # Shell script wrapper
│   └── README.md         # Backup system documentation
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── run.py                # Startup script
├── install.sh            # Installation script
├── update.sh             # Manual update script
├── templates/
│   ├── index.html        # Device management dashboard
│   └── system.html       # System monitoring dashboard
└── static/
    ├── css/
    │   └── style.css     # Dashboard styles
    └── js/
        ├── dashboard.js  # Device dashboard updates
        └── system.js     # System monitor updates
```

## API Endpoints

### Device Management
- `GET /` - Device management dashboard
- `GET /api/chastity-status` - Device status and key information

### System Monitoring
- `GET /system` - System monitoring dashboard
- `GET /api/system-info` - System resource information
- `GET /api/processes` - Top processes by CPU usage

## Development

### Adding New Features

1. **New API endpoints**: Add routes to `app.py`
2. **Device dashboard components**: Modify `templates/index.html`
3. **System monitor components**: Modify `templates/system.html`
4. **Styling**: Update `static/css/style.css`
5. **Device dashboard functionality**: Extend `static/js/dashboard.js`
6. **System monitor functionality**: Extend `static/js/system.js`

### Testing

The application includes error handling and will display appropriate messages if:
- System information cannot be retrieved
- Processes cannot be listed
- Network connectivity is lost

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Find and kill the process using port 5000
   sudo lsof -i :5000
   sudo kill -9 <PID>
   ```

2. **Permission denied**
   ```bash
   # Make sure you have proper permissions
   sudo chmod +x app.py
   ```

3. **Cannot access from other devices**
   - Check your firewall settings
   - Verify the Pi's IP address
   - Ensure the app is running on `0.0.0.0`

### Performance Tips

- Device dashboard updates every 6 seconds by default
- System monitor updates every 2 seconds by default
- Process list updates every 4 seconds
- Adjust these intervals in the respective JavaScript files if needed
- Monitor your Pi's resources while running the dashboards

## Logs

All application, backup, and update actions are logged to the `logs/` directory:

- `logs/app.log`: Main application log (Flask app, API errors, startup, etc.)
- `logs/backup.log`: All backup actions (creation, restore, delete, errors)
- `logs/update.log`: All update script actions and errors

Log files are automatically rotated (up to 5 files, 1MB each for Python logs). Each invocation of backup or update scripts is marked with a timestamped header.

**Troubleshooting:**
- Check `logs/app.log` for Flask app errors or crashes
- Check `logs/backup.log` for backup/restore issues
- Check `logs/update.log` for update script problems

You can safely delete old log files if you need to free up space. For more detail, increase the log level in the Python code (e.g., to DEBUG).

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the dashboard!

---

**Note**: This dual-dashboard system is designed to be lightweight and efficient for Raspberry Pi hardware. It uses minimal resources while providing comprehensive device management and system monitoring capabilities. The separation of concerns allows users to focus on either device management or system performance as needed.