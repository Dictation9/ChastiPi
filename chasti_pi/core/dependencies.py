"""
Dependency management for ChastiPi
Handles checking and installing required packages with comprehensive fixes
"""
import subprocess
import sys
import importlib
import logging
import platform
import os
from pathlib import Path
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

# Core dependencies that must be available
REQUIRED_DEPENDENCIES = [
    'flask',
    'cryptography',
    'werkzeug',
    'qrcode',
    'pillow',
    'reportlab',
    'fpdf',
    'numpy',
    'cv2',  # opencv-python-headless
    'pytesseract',
    'dateutil',
    'requests',
    'ntplib',
    'psutil',
    'schedule'
]

# System packages for Raspberry Pi
RASPBERRY_PI_SYSTEM_PACKAGES = [
    'python3-dev',
    'python3-pip',
    'python3-venv',
    'libatlas-base-dev',
    'libhdf5-dev',
    'libhdf5-serial-dev',
    'libgstreamer1.0-0',
    'libgstreamer-plugins-base1.0-0',
    'libgtk-3-0',
    'libavcodec-dev',
    'libavformat-dev',
    'libswscale-dev',
    'libv4l-dev',
    'libxvidcore-dev',
    'libx264-dev',
    'libjpeg-dev',
    'libpng-dev',
    'libtiff-dev',
    'libfreetype6-dev',
    'liblcms2-dev',
    'libwebp-dev',
    'tcl8.6-dev',
    'tk8.6-dev',
    'python3-tk',
    'zlib1g-dev',
    'libtesseract-dev',
    'tesseract-ocr',
    'tesseract-ocr-eng',
    'git',
    'curl',
    'wget',
    'unzip',
    'build-essential',
    'cmake',
    'pkg-config'
]

def check_dependency(module_name: str) -> bool:
    """Check if a dependency is available"""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False

def get_missing_dependencies() -> List[str]:
    """Get list of missing dependencies"""
    missing = []
    for dep in REQUIRED_DEPENDENCIES:
        if not check_dependency(dep):
            missing.append(dep)
    return missing

def install_package(package_name: str) -> bool:
    """Install a package using pip"""
    try:
        # Map module names to package names
        package_mapping = {
            'cv2': 'opencv-python-headless',
            'dateutil': 'python-dateutil',
            'pillow': 'Pillow',
            'qrcode': 'qrcode[pil]'
        }
        
        actual_package = package_mapping.get(package_name, package_name)
        
        logger.info(f"Installing {actual_package}...")
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', actual_package
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install {package_name}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error installing {package_name}: {e}")
        return False

def is_raspberry_pi() -> bool:
    """Check if running on Raspberry Pi"""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return 'Raspberry Pi' in f.read()
    except:
        return False

def install_system_packages() -> bool:
    """Install system packages for Raspberry Pi"""
    if not is_raspberry_pi():
        logger.info("Not running on Raspberry Pi, skipping system packages")
        return True
    
    try:
        logger.info("Installing system packages for Raspberry Pi...")
        subprocess.check_call([
            'sudo', 'apt', 'update'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        subprocess.check_call([
            'sudo', 'apt', 'install', '-y'
        ] + RASPBERRY_PI_SYSTEM_PACKAGES, 
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        logger.info("System packages installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install system packages: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error installing system packages: {e}")
        return False

def fix_numpy_compatibility() -> bool:
    """Fix NumPy compatibility issues with OpenCV"""
    try:
        logger.info("Fixing NumPy compatibility...")
        
        # Uninstall current NumPy
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'uninstall', '-y', 'numpy'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Install compatible NumPy version
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', 'numpy<2.0'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Reinstall OpenCV
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'uninstall', '-y', 'opencv-python', 'opencv-python-headless'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', 'opencv-python-headless'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        logger.info("NumPy compatibility fix applied")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fix NumPy compatibility: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error fixing NumPy compatibility: {e}")
        return False

def check_numpy_version() -> bool:
    """Check if NumPy version is compatible"""
    try:
        import numpy
        version = numpy.__version__
        major_version = int(version.split('.')[0])
        
        if major_version >= 2:
            logger.warning(f"NumPy version {version} may cause compatibility issues")
            return False
        return True
    except ImportError:
        return False
    except Exception as e:
        logger.error(f"Error checking NumPy version: {e}")
        return False

def install_missing_dependencies() -> Tuple[bool, List[str]]:
    """Install all missing dependencies"""
    missing = get_missing_dependencies()
    if not missing:
        return True, []
    
    logger.info(f"Found {len(missing)} missing dependencies: {', '.join(missing)}")
    
    failed_installations = []
    for dep in missing:
        if not install_package(dep):
            failed_installations.append(dep)
    
    return len(failed_installations) == 0, failed_installations

def verify_dependencies() -> bool:
    """Verify all dependencies are available, install if needed"""
    logger.info("Checking dependencies...")
    
    missing = get_missing_dependencies()
    if not missing:
        logger.info("All dependencies are available")
        return True
    
    logger.warning(f"Missing dependencies detected: {', '.join(missing)}")
    logger.info("Attempting to install missing dependencies...")
    
    success, failed = install_missing_dependencies()
    
    if success:
        logger.info("All dependencies installed successfully")
        return True
    else:
        logger.error(f"Failed to install dependencies: {', '.join(failed)}")
        logger.error("Please install missing dependencies manually:")
        for dep in failed:
            logger.error(f"  pip install {dep}")
        return False

def check_python_version() -> bool:
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        logger.error("Python 3.7 or higher is required")
        return False
    return True

def setup_dependencies() -> bool:
    """Main dependency setup function with comprehensive fixes"""
    logger.info("🔧 Setting up ChastiPi dependencies...")
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install system packages for Raspberry Pi
    if not install_system_packages():
        logger.warning("Failed to install system packages, continuing anyway...")
    
    # Check and fix NumPy compatibility
    if not check_numpy_version():
        logger.info("NumPy compatibility issues detected, applying fix...")
        if not fix_numpy_compatibility():
            logger.warning("Failed to fix NumPy compatibility, continuing anyway...")
    
    # Verify and install dependencies
    if not verify_dependencies():
        return False
    
    # Test critical dependencies
    if not test_critical_dependencies():
        logger.error("Critical dependency test failed")
        return False
    
    logger.info("✅ All dependencies are ready!")
    return True

def test_critical_dependencies() -> bool:
    """Test critical dependencies to ensure they work correctly"""
    try:
        logger.info("Testing critical dependencies...")
        
        # Test NumPy
        try:
            import numpy
            logger.info(f"NumPy version: {numpy.__version__}")
        except ImportError as e:
            logger.error(f"NumPy import failed: {e}")
            return False
        
        # Test OpenCV
        try:
            import cv2
            logger.info(f"OpenCV version: {cv2.__version__}")
        except ImportError as e:
            logger.error(f"OpenCV import failed: {e}")
            return False
        
        # Test Tesseract
        try:
            import pytesseract
            logger.info("Tesseract imported successfully")
        except ImportError as e:
            logger.error(f"Tesseract import failed: {e}")
            return False
        
        logger.info("All critical dependencies working correctly!")
        return True
        
    except Exception as e:
        logger.error(f"Error testing critical dependencies: {e}")
        return False 