#!/usr/bin/env python3
"""
Main entry point for ChastiPi application
"""
from chasti_pi.core.app import create_app
from chasti_pi.core.config import config

def main():
    """Main application entry point"""
    app = create_app()
    
    # Get configuration
    host = config.get('host', '0.0.0.0')
    port = config.get('port', 5000)
    debug = config.get('debug', False)
    
    print(f"Starting ChastiPi on {host}:{port}")
    print(f"Debug mode: {debug}")
    
    app.run(
        host=host,
        port=port,
        debug=debug
    )

if __name__ == "__main__":
    main() 