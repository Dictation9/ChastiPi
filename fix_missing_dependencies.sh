#!/bin/bash

# Quick fix for missing Python dependencies
# This script installs missing dependencies for ChastiPi

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

print_header "ChastiPi Missing Dependencies Fix"

# Check if we're in the ChastiPi directory
if [ ! -f "run.py" ]; then
    print_error "Please run this script from the ChastiPi directory"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_error "Virtual environment not found. Please run the installer first."
    exit 1
fi

print_status "Activating virtual environment..."
source venv/bin/activate

print_status "Installing missing dependencies..."

# Install fpdf
print_status "Installing fpdf..."
pip install fpdf==1.7.2

# Install any other missing dependencies
print_status "Installing other missing dependencies..."
pip install -r requirements.txt

# Test the installation
print_header "Testing Installation"

print_status "Testing Python imports..."
python3 -c "
try:
    import fpdf
    print('✅ fpdf imported successfully')
except ImportError as e:
    print(f'❌ fpdf import error: {e}')
    exit(1)

try:
    from chasti_pi.services.punishment_service import PunishmentService
    print('✅ PunishmentService imported successfully')
except ImportError as e:
    print(f'❌ PunishmentService import error: {e}')
    exit(1)

print('✅ All dependencies working correctly!')
"

if [ $? -eq 0 ]; then
    print_status "All tests passed! Dependencies are working correctly."
else
    print_error "Some tests failed. Please check the error messages above."
    exit 1
fi

print_header "Fix Complete"

print_status "You can now start ChastiPi with:"
print_status "./start_chastipi.sh"
print_status ""
print_status "Or run directly with:"
print_status "source venv/bin/activate && python run.py" 