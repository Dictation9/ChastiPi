#!/usr/bin/env python3
"""
Raspberry Pi Dashboard - Startup Script
"""

import os
import sys
from app import app

def main():
    """Start the dashboard application"""
    print("🔐 Starting ChastiPi Dashboard...")
    print("📊 Dashboard will be available at: http://0.0.0.0:5000")
    print("🌐 Access from other devices: http://<your-pi-ip>:5000")
    print("⏹️  Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 