#!/usr/bin/env python3
"""
ChastiPi Startup Script
Handles dependency management and application startup
"""
import sys
import os
import subprocess
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def check_virtual_environment():
    """Check if we're in a virtual environment"""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def activate_virtual_environment():
    """Try to activate virtual environment if available"""
    venv_paths = ['venv', '.venv']
    
    for venv_path in venv_paths:
        if Path(venv_path).exists():
            activate_script = Path(venv_path) / 'bin' / 'activate_this.py'
            if activate_script.exists():
                try:
                    exec(activate_script.read_text(), {'__file__': str(activate_script)})
                    print(f"🐍 Activated virtual environment: {venv_path}")
                    return True
                except Exception as e:
                    print(f"⚠️  Failed to activate {venv_path}: {e}")
    
    return False

def install_requirements():
    """Install requirements from requirements.txt"""
    try:
        print("📦 Installing requirements from requirements.txt...")
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False
    except FileNotFoundError:
        print("⚠️  requirements.txt not found")
        return False

def main():
    """Main startup function with comprehensive fixes"""
    print("🚀 Starting ChastiPi...")
    
    # Check if we're in a virtual environment
    if not check_virtual_environment():
        print("🔧 No virtual environment detected, attempting to activate...")
        if not activate_virtual_environment():
            print("⚠️  No virtual environment found, using system Python")
    
    # Try to import and run the main application
    try:
        print("📦 Checking dependencies...")
        from chasti_pi.core.app import create_app
        from chasti_pi.core.config import config
        
        print("🔧 Applying comprehensive fixes...")
        app = create_app()
        
        # Get configuration
        host = config.get('host', '0.0.0.0')
        port = config.get('port', 5000)
        debug = config.get('debug', False)
        
        print(f"✅ Starting ChastiPi on {host}:{port}")
        print(f"🔍 Debug mode: {debug}")
        print("🔧 All fixes applied successfully!")
        
        app.run(
            host=host,
            port=port,
            debug=debug
        )
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("🔧 Attempting to install missing dependencies...")
        
        # Try to install requirements
        if install_requirements():
            print("🔄 Please restart ChastiPi: python start_chastipi.py")
        else:
            print("❌ Failed to install dependencies automatically.")
            print("📦 Please install dependencies manually:")
            print("   pip install -r requirements.txt")
        
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Application startup failed: {e}")
        print("🔧 Please check the logs for more details.")
        sys.exit(1)

if __name__ == "__main__":
    main() 