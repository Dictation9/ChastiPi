#!/bin/bash
# ChastiPi Manual Update Script
# Pulls latest code from GitHub and updates Python dependencies with comprehensive fixes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

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

print_header "ChastiPi Manual Update Script"

# Check if inside a git repo
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    print_error "This directory is not a git repository."
    exit 1
fi

# Check if virtual environment exists
if [ -d "venv" ]; then
    print_status "Activating virtual environment..."
    source venv/bin/activate
    PYTHON_CMD="python"
    PIP_CMD="pip"
elif [ -d ".venv" ]; then
    print_status "Activating virtual environment..."
    source .venv/bin/activate
    PYTHON_CMD="python"
    PIP_CMD="pip"
else
    print_warning "No virtual environment found, using system Python..."
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
fi

# Pull latest code
print_status "Pulling latest code from GitHub..."
git pull
GIT_STATUS=$?
if [ $GIT_STATUS -ne 0 ]; then
    print_error "git pull failed."
    exit 1
fi

# Install/update Python dependencies
print_status "Installing/updating Python dependencies..."
$PIP_CMD install -r requirements.txt
PIP_STATUS=$?
if [ $PIP_STATUS -ne 0 ]; then
    print_error "pip install failed."
    exit 1
fi

# Run comprehensive dependency check and fixes
print_header "Running Dependency Checks"

print_status "Testing dependency management system..."
$PYTHON_CMD -c "
import sys
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO)

try:
    from chasti_pi.core.dependencies import setup_dependencies, test_critical_dependencies
    
    print('✅ Dependency module imported successfully')
    
    # Test critical dependencies
    if test_critical_dependencies():
        print('✅ Critical dependencies working correctly')
    else:
        print('❌ Critical dependency test failed')
        sys.exit(1)
        
    # Setup dependencies (this will apply fixes if needed)
    if setup_dependencies():
        print('✅ All dependencies are ready!')
    else:
        print('❌ Dependency setup failed')
        sys.exit(1)
        
except ImportError as e:
    print(f'❌ Import error: {e}')
    print('📦 Attempting to install missing dependencies...')
    import subprocess
    import sys
    
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print('✅ Dependencies installed successfully')
    except Exception as dep_error:
        print(f'❌ Failed to install dependencies: {dep_error}')
        sys.exit(1)
        
except Exception as e:
    print(f'❌ Unexpected error: {e}')
    sys.exit(1)
"

DEPENDENCY_STATUS=$?
if [ $DEPENDENCY_STATUS -ne 0 ]; then
    print_error "Dependency check failed."
    exit 1
fi

# Test service fixes
print_status "Testing service fixes..."
$PYTHON_CMD -c "
try:
    from chasti_pi.services.service_fixes import apply_all_service_fixes
    apply_all_service_fixes()
    print('✅ Service fixes applied successfully')
except Exception as e:
    print(f'❌ Service fixes failed: {e}')
    exit(1)
"

SERVICE_STATUS=$?
if [ $SERVICE_STATUS -ne 0 ]; then
    print_error "Service fixes failed."
    exit 1
fi

print_header "Update Complete"

print_status "✅ Update completed successfully!"
print_status ""

# Check if ChastiPi is currently running
print_status "Checking if ChastiPi is currently running..."
RUNNING_PID=""
RUNNING_METHOD=""

# Check for different ways ChastiPi might be running
if pgrep -f "python.*run.py" > /dev/null; then
    RUNNING_PID=$(pgrep -f "python.*run.py" | head -1)
    RUNNING_METHOD="python"
    print_status "ChastiPi is running via Python (PID: $RUNNING_PID)"
elif pgrep -f "start_chastipi.sh" > /dev/null; then
    RUNNING_PID=$(pgrep -f "start_chastipi.sh" | head -1)
    RUNNING_METHOD="script"
    print_status "ChastiPi is running via startup script (PID: $RUNNING_PID)"
elif pgrep -f "chastipi" > /dev/null; then
    RUNNING_PID=$(pgrep -f "chastipi" | head -1)
    RUNNING_METHOD="systemd"
    print_status "ChastiPi is running via systemd service (PID: $RUNNING_PID)"
elif systemctl is-active --quiet chastipi; then
    RUNNING_METHOD="systemd"
    print_status "ChastiPi is running via systemd service"
else
    print_status "ChastiPi is not currently running."
fi
    
    # Ask user if they want to auto-restart
    echo ""
    read -p "Do you want to automatically restart ChastiPi to apply updates? (y/N): " -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        print_status "Stopping ChastiPi..."
        
        # Stop based on how it's running
        if [[ "$RUNNING_METHOD" == "systemd" ]]; then
            sudo systemctl stop chastipi
            sleep 2
        elif [[ -n "$RUNNING_PID" ]]; then
            kill $RUNNING_PID
            sleep 3
            
            # Check if process is still running
            if kill -0 $RUNNING_PID 2>/dev/null; then
                print_warning "Process didn't stop gracefully, forcing termination..."
                kill -9 $RUNNING_PID
                sleep 1
            fi
        fi
        
        print_status "Starting ChastiPi..."
        
        # Start based on how it was running
        if [[ "$RUNNING_METHOD" == "systemd" ]]; then
            sudo systemctl start chastipi
            sleep 2
            
            if systemctl is-active --quiet chastipi; then
                print_status "✅ ChastiPi restarted successfully via systemd!"
                print_status "📊 Access the web interface at: http://localhost:5000"
                print_status "📋 Check status with: sudo systemctl status chastipi"
            else
                print_error "❌ Failed to restart ChastiPi via systemd"
                print_status "Please check with: sudo systemctl status chastipi"
            fi
        else
            # Start with the same method it was running
            nohup python run.py > logs/chasti_pi.log 2>&1 &
            NEW_PID=$!
            
            # Wait a moment for the process to start
            sleep 2
            
            if kill -0 $NEW_PID 2>/dev/null; then
                print_status "✅ ChastiPi restarted successfully! (PID: $NEW_PID)"
                print_status "📊 Access the web interface at: http://localhost:5000"
                print_status "📋 Check logs with: tail -f logs/chasti_pi.log"
            else
                print_error "❌ Failed to restart ChastiPi"
                print_status "Please start manually with: python run.py"
            fi
        fi
    else
        print_status "ChastiPi was not restarted automatically."
        print_status "Please restart manually when ready:"
        if [[ "$RUNNING_METHOD" == "systemd" ]]; then
            print_status "  sudo systemctl restart chastipi"
        else
            print_status "  python run.py"
        fi
    fi
else
    print_status "ChastiPi is not currently running."
    print_status "You can start it with:"
    print_status "  python run.py"
    print_status "  or"
    print_status "  ./start_chastipi.sh"
fi

print_status ""
print_status "Or test everything with:"
print_status "  python test_all_fixes.py" 