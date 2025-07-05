"""
Mac-specific application wrapper for ChastiPi
Provides macOS-specific features like system notifications and tray functionality
"""
import os
import sys
import threading
import time
from datetime import datetime

try:
    from Foundation import NSUserNotification, NSUserNotificationCenter
    from AppKit import NSApplication, NSStatusBar, NSMenu, NSMenuItem, NSVariableStatusItemLength
    MAC_FEATURES_AVAILABLE = True
except ImportError:
    MAC_FEATURES_AVAILABLE = False
    print("⚠️  Mac-specific features not available. Install pyobjc packages for full functionality.")

class MacAppWrapper:
    """Wrapper for macOS-specific features"""
    
    def __init__(self, flask_app):
        self.flask_app = flask_app
        self.status_item = None
        self.menu = None
        self.notification_center = None
        
        if MAC_FEATURES_AVAILABLE:
            self._setup_mac_features()
    
    def _setup_mac_features(self):
        """Initialize macOS-specific features"""
        try:
            # Setup notification center
            self.notification_center = NSUserNotificationCenter.defaultUserNotificationCenter()
            
            # Setup status bar item
            self._setup_status_bar()
            
        except Exception as e:
            print(f"⚠️  Could not setup Mac features: {e}")
    
    def _setup_status_bar(self):
        """Setup the status bar menu"""
        try:
            status_bar = NSStatusBar.systemStatusBar()
            self.status_item = status_bar.statusItemWithLength_(NSVariableStatusItemLength)
            self.status_item.setTitle_("🔒")
            
            # Create menu
            self.menu = NSMenu.alloc().init()
            
            # Add menu items
            dashboard_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Dashboard", "open_dashboard", ""
            )
            self.menu.addItem_(dashboard_item)
            
            self.menu.addItem_(NSMenuItem.separatorItem())
            
            quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Quit ChastiPi", "quit_app", "q"
            )
            self.menu.addItem_(quit_item)
            
            self.status_item.setMenu_(self.menu)
            
        except Exception as e:
            print(f"⚠️  Could not setup status bar: {e}")
    
    def send_notification(self, title, message, subtitle=None):
        """Send a system notification"""
        if not MAC_FEATURES_AVAILABLE or not self.notification_center:
            print(f"📢 {title}: {message}")
            return
        
        try:
            notification = NSUserNotification.alloc().init()
            notification.setTitle_(title)
            notification.setInformativeText_(message)
            if subtitle:
                notification.setSubtitle_(subtitle)
            
            self.notification_center.deliverNotification_(notification)
            
        except Exception as e:
            print(f"⚠️  Could not send notification: {e}")
    
    def open_dashboard(self):
        """Open the web dashboard"""
        import webbrowser
        webbrowser.open('http://localhost:5000')
    
    def quit_app(self):
        """Quit the application"""
        print("🛑 Shutting down ChastiPi...")
        os._exit(0)

def create_mac_app(flask_app):
    """Create and return a Mac app wrapper"""
    return MacAppWrapper(flask_app)

def run_mac_app(flask_app, host='127.0.0.1', port=5000, debug=False):
    """Run the Flask app with Mac-specific features"""
    
    # Create Mac wrapper
    mac_app = create_mac_app(flask_app)
    
    # Send startup notification
    mac_app.send_notification(
        "ChastiPi Started",
        f"Server running on http://{host}:{port}",
        "Digital Keyholder System"
    )
    
    # Run Flask app in a separate thread
    def run_flask():
        flask_app.run(host=host, port=port, debug=debug, use_reloader=False)
    
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Keep the main thread alive for Mac features
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        mac_app.send_notification(
            "ChastiPi Stopped",
            "Digital keyholder system has been stopped",
            "System Status"
        ) 