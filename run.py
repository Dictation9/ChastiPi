#!/usr/bin/env python3
"""
Main entry point for ChastiPi application
"""
import sys
import logging

# Setup basic logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """Main application entry point"""
    try:
        from chasti_pi.core.app import create_app
        from chasti_pi.core.config import config
        
        print("🔧 Starting ChastiPi...")
        print("📦 Checking dependencies...")
        
        app = create_app()
        
        # Get configuration
        host = config.get('host', '0.0.0.0')
        port = config.get('port', 5000)
        debug = config.get('debug', False)
        
        print(f"✅ Starting ChastiPi on {host}:{port}")
        print(f"🔍 Debug mode: {debug}")
        
        app.run(
            host=host,
            port=port,
            debug=debug
        )
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("🔧 Attempting to install missing dependencies...")
        
        try:
            from chasti_pi.core.dependencies import setup_dependencies
            if setup_dependencies():
                print("✅ Dependencies installed successfully. Please restart ChastiPi.")
            else:
                print("❌ Failed to install dependencies automatically.")
                print("📦 Please run: pip install -r requirements.txt")
        except Exception as dep_error:
            print(f"❌ Dependency setup failed: {dep_error}")
            print("📦 Please install dependencies manually:")
            print("   pip install -r requirements.txt")
        
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Application startup failed: {e}")
        print("🔧 Please check the logs for more details.")
        sys.exit(1)

if __name__ == "__main__":
    main() 