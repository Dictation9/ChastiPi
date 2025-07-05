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
print_status "You can now start ChastiPi with:"
print_status "  python start_chastipi.py"
print_status ""
print_status "Or test everything with:"
print_status "  python test_all_fixes.py"
print_status ""
print_status "If ChastiPi is running, please restart it to apply updates." 