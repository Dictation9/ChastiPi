#!/usr/bin/env python3
"""
Mac-specific entry point for ChastiPi application
"""
import argparse
import json
import os
import sys

def load_config(config_file):
    """Load configuration from file"""
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    else:
        print(f"⚠️  Config file {config_file} not found, using defaults")
        return {
            "system": {
                "chastity_mode": "gentle",
                "debug": False,
                "host": "127.0.0.1",
                "port": 5000
            }
        }

def main():
    """Main Mac application entry point"""
    parser = argparse.ArgumentParser(description='ChastiPi Mac Application')
    parser.add_argument('--config', default='config_mac.json', 
                       help='Configuration file (default: config_mac.json)')
    parser.add_argument('--host', help='Host to bind to')
    parser.add_argument('--port', type=int, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override with command line arguments
    if args.host:
        config['system']['host'] = args.host
    if args.port:
        config['system']['port'] = args.port
    if args.debug:
        config['system']['debug'] = args.debug
    
    # Import after config is loaded
    from chasti_pi.core.app import create_app
    from chasti_pi.core.mac_app import run_mac_app
    
    print("🍎 Starting ChastiPi Mac Edition")
    print("=" * 40)
    
    # Create Flask app
    app = create_app()
    
    # Get configuration
    host = config['system'].get('host', '127.0.0.1')
    port = config['system'].get('port', 5000)
    debug = config['system'].get('debug', False)
    
    print(f"🌐 Server: http://{host}:{port}")
    print(f"🐛 Debug: {debug}")
    print(f"⚙️  Config: {args.config}")
    
    # Check if Mac features are available
    try:
        from chasti_pi.core.mac_app import MAC_FEATURES_AVAILABLE
        if MAC_FEATURES_AVAILABLE:
            print("✅ Mac-specific features enabled")
            run_mac_app(app, host=host, port=port, debug=debug)
        else:
            print("⚠️  Mac features not available, running in standard mode")
            app.run(host=host, port=port, debug=debug)
    except ImportError:
        print("⚠️  Mac features not available, running in standard mode")
        app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    main() 