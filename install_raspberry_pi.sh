#!/bin/bash

# ChastiPi Raspberry Pi Installation Script
# This script automates the installation of ChastiPi on Raspberry Pi

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if running on Raspberry Pi
check_raspberry_pi() {
    if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        print_warning "This script is designed for Raspberry Pi. Continue anyway? (Y/N)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_error "Installation cancelled."
            exit 1
        fi
    fi
}

# Function to check system requirements
check_system_requirements() {
    print_header "Checking System Requirements"
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Installing..."
        sudo apt update
        sudo apt install -y python3 python3-pip python3-venv
    else
        print_status "Python 3 is installed"
    fi
    
    # Check available memory
    total_mem=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [ "$total_mem" -lt 1024 ]; then
        print_warning "Low memory detected (${total_mem}MB). ChastiPi requires at least 1GB RAM for optimal performance."
    else
        print_status "Memory: ${total_mem}MB (sufficient)"
    fi
    
    # Check available disk space
    available_space=$(df -m . | awk 'NR==2{printf "%.0f", $4}')
    if [ "$available_space" -lt 2048 ]; then
        print_warning "Low disk space detected (${available_space}MB). At least 2GB recommended."
    else
        print_status "Available disk space: ${available_space}MB (sufficient)"
    fi
}

# Function to install system dependencies
install_system_dependencies() {
    print_header "Installing System Dependencies"
    
    print_status "Updating package list..."
    sudo apt update
    
    print_status "Installing required system packages..."
    sudo apt install -y \
        python3-dev \
        python3-pip \
        python3-venv \
        libatlas-base-dev \
        libhdf5-dev \
        libhdf5-serial-dev \
        libatlas-base-dev \
        libgstreamer1.0-0 \
        libgstreamer-plugins-base1.0-0 \
        libgtk-3-0 \
        libavcodec-dev \
        libavformat-dev \
        libswscale-dev \
        libv4l-dev \
        libxvidcore-dev \
        libx264-dev \
        libjpeg-dev \
        libpng-dev \
        libtiff-dev \
        libatlas-base-dev \
        libtesseract-dev \
        tesseract-ocr \
        tesseract-ocr-eng \
        git \
        curl \
        wget \
        unzip \
        build-essential \
        cmake \
        pkg-config
    
    print_status "System dependencies installed successfully"
}

# Function to create virtual environment
setup_virtual_environment() {
    print_header "Setting Up Virtual Environment"
    
    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists. Remove it? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            print_status "Removing existing virtual environment..."
            rm -rf venv
        else
            print_status "Using existing virtual environment"
            return
        fi
    fi
    
    print_status "Creating virtual environment..."
    python3 -m venv venv
    
    print_status "Activating virtual environment..."
    source venv/bin/activate
    
    print_status "Upgrading pip..."
    pip install --upgrade pip setuptools wheel
}

# Function to install Python dependencies with compatibility fixes
install_python_dependencies() {
    print_header "Installing Python Dependencies"
    
    source venv/bin/activate
    
    print_status "Installing NumPy with compatibility..."
    pip install "numpy<2.0"
    
    print_status "Installing OpenCV..."
    pip install opencv-python-headless
    
    print_status "Installing other dependencies..."
    pip install -r requirements.txt
    
    # Install additional dependencies for Raspberry Pi
    print_status "Installing Raspberry Pi specific dependencies..."
    pip install \
        pillow \
        pytesseract \
        flask \
        werkzeug \
        requests \
        python-dateutil \
        pytz \
        psutil \
        schedule
    
    print_status "Python dependencies installed successfully"
}

# Function to configure Tesseract
configure_tesseract() {
    print_header "Configuring Tesseract OCR"
    
    # Check if Tesseract is installed
    if ! command -v tesseract &> /dev/null; then
        print_error "Tesseract not found. Installing..."
        sudo apt install -y tesseract-ocr tesseract-ocr-eng
    fi
    
    # Test Tesseract
    if tesseract --version &> /dev/null; then
        print_status "Tesseract is working correctly"
    else
        print_error "Tesseract installation failed"
        exit 1
    fi
}

# Function to create necessary directories
create_directories() {
    print_header "Creating Application Directories"
    
    mkdir -p data
    mkdir -p logs
    mkdir -p uploads
    mkdir -p static/images
    mkdir -p static/css
    mkdir -p static/js
    
    print_status "Directories created successfully"
}

# Function to set up configuration
setup_configuration() {
    print_header "Setting Up Configuration"
    
    if [ ! -f "config.json" ]; then
        print_status "Creating default configuration..."
        cp config.json.example config.json 2>/dev/null || {
            print_warning "No config.json.example found. Creating basic config..."
            cat > config.json << 'EOF'
{
    "device": {
        "device_id": "RASPBERRY_PI",
        "device_name": "ChastiPi Raspberry Pi",
        "location": "Home",
        "timezone": "UTC"
    },
    "network": {
        "host": "0.0.0.0",
        "port": 5000,
        "external_url": "http://your-pi-ip:5000",
        "webhook_url": "",
        "enable_remote_access": false,
        "allowed_networks": []
    },
    "email": {
        "enabled": false,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "use_tls": true,
        "from_address": "",
        "reply_to": "",
        "notification_emails": []
    },
    "security": {
        "enable_ssl": false,
        "require_auth": false,
        "allowed_ips": [],
        "session_timeout_minutes": 30,
        "max_login_attempts": 5,
        "password_min_length": 8,
        "enable_rate_limiting": true,
        "rate_limit_requests": 100,
        "rate_limit_window": 3600
    },
    "keyholder": {
        "default_keyholder_email": "",
        "approval_timeout_hours": 24,
        "emergency_timeout_minutes": 30,
        "max_request_duration_days": 30,
        "require_email_verification": true,
        "enable_auto_approval": false,
        "auto_approval_duration_hours": 2,
        "notification_frequency": "immediate"
    },
    "cage_check": {
        "enabled": true,
        "verification_code_length": 6,
        "verification_timeout_hours": 24,
        "reminder_interval_hours": 6,
        "max_reminders": 3,
        "require_photo": true,
        "ocr_accuracy_threshold": 0.8,
        "auto_escalation": true,
        "escalation_delay_hours": 48,
        "video_enabled": true,
        "max_video_duration": 300,
        "min_video_duration": 3,
        "video_frame_interval": 1
    },
    "punishment": {
        "enabled": true,
        "qr_code_size": 200,
        "pdf_template": "default",
        "verification_required": true,
        "ocr_accuracy_threshold": 0.8,
        "max_upload_size_mb": 10,
        "allowed_image_formats": ["jpg", "jpeg", "png", "gif", "bmp"],
        "auto_cleanup_days": 30,
        "enable_statistics": true
    },
    "time_verification": {
        "enabled": true,
        "ntp_servers": [
            "pool.ntp.org",
            "time.nist.gov",
            "time.google.com"
        ],
        "sync_interval_minutes": 60,
        "max_drift_seconds": 5,
        "auto_correct": true,
        "alert_on_drift": true,
        "drift_threshold_seconds": 10
    },
    "upload": {
        "max_file_size_mb": 10,
        "allowed_formats": ["jpg", "jpeg", "png", "gif", "bmp", "mp4", "mov", "avi", "wmv", "flv", "webm"],
        "storage_path": "uploads",
        "auto_cleanup": true,
        "cleanup_interval_days": 7,
        "enable_compression": true,
        "compression_quality": 85
    },
    "calendar": {
        "enabled": true,
        "default_view": "month",
        "enable_reminders": true,
        "reminder_advance_hours": 24,
        "max_events_per_page": 50,
        "enable_recurring_events": true
    },
    "logging": {
        "level": "INFO",
        "file_enabled": true,
        "file_path": "logs",
        "max_file_size_mb": 10,
        "backup_count": 5,
        "console_enabled": true,
        "email_enabled": false,
        "email_level": "ERROR"
    },
    "appearance": {
        "theme": "default",
        "language": "en",
        "date_format": "YYYY-MM-DD",
        "time_format": "HH:mm:ss",
        "timezone_display": "local",
        "enable_dark_mode": false,
        "custom_css": ""
    },
    "notifications": {
        "email_enabled": true,
        "sms_enabled": false,
        "webhook_enabled": false,
        "webhook_url": "",
        "notification_types": {
            "key_request": true,
            "cage_check": true,
            "punishment_complete": true,
            "time_drift": true,
            "system_error": true,
            "update_available": true
        },
        "quiet_hours": {
            "enabled": false,
            "start": "22:00",
            "end": "08:00"
        }
    },
    "automation": {
        "enabled": false,
        "auto_backup": true,
        "backup_interval_days": 7,
        "backup_retention_days": 30,
        "auto_update": false,
        "update_check_interval_days": 7,
        "auto_download_updates": false,
        "backup_before_update": true,
        "health_check_interval_minutes": 30
    },
    "development": {
        "debug": false,
        "test_mode": false,
        "mock_services": false,
        "log_requests": false,
        "enable_profiling": false
    }
}
EOF
        }
    else
        print_status "Configuration file already exists"
    fi
}

# Function to test the installation
test_installation() {
    print_header "Testing Installation"
    
    source venv/bin/activate
    
    print_status "Testing Python imports..."
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from chasti_pi.core.config import config
    from chasti_pi.services.cage_check_service import CageCheckService
    print('✅ Core modules imported successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"
    
    print_status "Testing video processing..."
    python3 test_video_processing.py 2>/dev/null || print_warning "Video processing test skipped (optional)"
    
    print_status "Installation test completed"
}

# Function to create startup script
create_startup_script() {
    print_header "Creating Startup Script"
    
    cat > start_chastipi.sh << 'EOF'
#!/bin/bash

# ChastiPi Startup Script for Raspberry Pi
# This script starts ChastiPi with proper environment setup

# Change to the ChastiPi directory
cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Set environment variables for Raspberry Pi
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
export OPENCV_VIDEOIO_PRIORITY_MSMF=0

# Start the application
echo "Starting ChastiPi..."
python3 run.py
EOF
    
    chmod +x start_chastipi.sh
    chmod +x manual_update.sh
    
    print_status "Startup script created: start_chastipi.sh"
    print_status "Manual update script made executable: manual_update.sh"
}

# Function to create systemd service
create_systemd_service() {
    print_header "Creating Systemd Service"
    
    print_warning "Create systemd service for auto-start? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        sudo tee /etc/systemd/system/chastipi.service > /dev/null << EOF
[Unit]
Description=ChastiPi Application
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/python3 $(pwd)/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        print_status "Systemd service created"
        print_status "To enable auto-start: sudo systemctl enable chastipi"
        print_status "To start service: sudo systemctl start chastipi"
        print_status "To check status: sudo systemctl status chastipi"
    fi
}

# Function to display final instructions
display_final_instructions() {
    print_header "Installation Complete!"
    
    echo -e "${GREEN}🎉 ChastiPi has been successfully installed on your Raspberry Pi!${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Configure your settings in config.json"
    echo "2. Start the application: ./start_chastipi.sh"
    echo "3. Access the web interface: http://your-pi-ip:5000"
    echo ""
    echo -e "${BLUE}Important Notes:${NC}"
    echo "- The application runs on port 5000 by default"
    echo "- Make sure your firewall allows connections to port 5000"
    echo "- For remote access, update the external_url in config.json"
    echo "- Check logs in the logs/ directory for any issues"
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "- Start: ./start_chastipi.sh"
    echo "- Stop: Ctrl+C (when running in foreground)"
    echo "- View logs: tail -f logs/app.log"
    echo "- Update: git pull && ./install_raspberry_pi.sh"
    echo ""
    echo -e "${YELLOW}For support, check the documentation or create an issue on GitHub.${NC}"
}

# Main installation function
main() {
    print_header "ChastiPi Raspberry Pi Installer"
    
    echo "This script will install ChastiPi on your Raspberry Pi with all necessary dependencies."
    echo ""
    echo -e "${YELLOW}Requirements:${NC}"
    echo "- Raspberry Pi (recommended: Pi 3 or newer)"
    echo "- At least 1GB RAM"
    echo "- At least 2GB free disk space"
    echo "- Internet connection"
    echo ""
    
    print_warning "Continue with installation? (y/N)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_error "Installation cancelled."
        exit 1
    fi
    
    # Run installation steps
    check_raspberry_pi
    check_system_requirements
    install_system_dependencies
    setup_virtual_environment
    install_python_dependencies
    configure_tesseract
    create_directories
    setup_configuration
    test_installation
    create_startup_script
    create_systemd_service
    display_final_instructions
}

# Run main function
main "$@" 