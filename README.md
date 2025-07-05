# 🔐 ChastiPi Dashboard

A modern, lightweight web dashboard for chastity device management and Raspberry Pi system monitoring.

## Features

- **Chastity Device Management**: Secure key storage and access control
- **Real-time System Monitoring**: CPU, memory, and disk usage with live updates
- **Process Management**: View top processes by CPU usage
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Raspberry Pi Optimized**: Lightweight and efficient for Pi hardware
- **Modern UI**: Clean, gradient-based design with smooth animations

## Screenshots

The dashboard provides:
- System overview cards with progress bars
- Real-time CPU, memory, and disk usage
- Top processes table
- System information display
- Responsive design for all devices

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

4. **Access the dashboard**
   - Open your web browser
   - Navigate to `http://your-pi-ip:5000`
   - Example: `http://192.168.1.100:5000`

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
raspberry-pi-dashboard/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/
│   └── index.html        # Main dashboard template
└── static/
    ├── css/
    │   └── style.css     # Dashboard styles
    └── js/
        └── dashboard.js   # Real-time updates
```

## API Endpoints

- `GET /` - Main dashboard page
- `GET /api/system-info` - System resource information
- `GET /api/processes` - Top processes by CPU usage

## Development

### Adding New Features

1. **New API endpoints**: Add routes to `app.py`
2. **UI components**: Modify `templates/index.html`
3. **Styling**: Update `static/css/style.css`
4. **Functionality**: Extend `static/js/dashboard.js`

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

- The dashboard updates every 2 seconds by default
- Process list updates every 4 seconds
- Adjust these intervals in `dashboard.js` if needed
- Monitor your Pi's resources while running the dashboard

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the dashboard!

---

**Note**: This dashboard is designed to be lightweight and efficient for Raspberry Pi hardware. It uses minimal resources while providing comprehensive system monitoring capabilities.