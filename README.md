# 🔐 ChastiPi Dashboard

A modern, lightweight web dashboard for chastity device management and Raspberry Pi system monitoring with dual-dashboard architecture.

## Features

### 🔐 Device Management Dashboard
- **Device Status Monitoring**: Real-time lock status, time remaining, keyholder approval
- **Key Management**: Digital keys, backup keys, emergency access tracking
- **Access History**: Session tracking, statistics, and usage analytics
- **Notification System**: Email alerts, SMS, webhook integration
- **Quick Actions**: Request access, emergency release, device checks, history viewing

### 🖥️ System Monitor Dashboard
- **Real-time System Monitoring**: CPU, memory, and disk usage with live updates
- **Process Management**: View top processes by CPU usage
- **System Information**: Platform details, hostname, last update timestamps
- **Performance Analytics**: Color-coded alerts based on resource usage

### 🎨 User Experience
- **Dual Dashboard Architecture**: Separate interfaces for device management and system monitoring
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
   git clone <your-repo-url>
   cd raspberry-pi-dashboard
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
- Adding authentication
- Using HTTPS
- Running behind a reverse proxy (nginx)
- Setting up a firewall

## File Structure

```
chastipi-dashboard/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── run.py                # Startup script
├── install.sh            # Installation script
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

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the dashboard!

---

**Note**: This dual-dashboard system is designed to be lightweight and efficient for Raspberry Pi hardware. It uses minimal resources while providing comprehensive device management and system monitoring capabilities. The separation of concerns allows users to focus on either device management or system performance as needed.