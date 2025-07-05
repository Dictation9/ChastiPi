#!/usr/bin/env python3
"""
Test script for keyholder dashboard functionality
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_keyholder_dashboard():
    """Test the keyholder dashboard route"""
    try:
        print("🔧 Testing Keyholder Dashboard...")
        
        # Import required modules
        from chasti_pi.api.keyholder import dashboard
        from chasti_pi.services.key_storage_service import KeyStorageService
        from chasti_pi.services.config_service import ConfigService
        from chasti_pi.core.config import config
        
        print("✅ All imports successful")
        
        # Test key storage service
        key_storage = KeyStorageService()
        print("✅ KeyStorageService initialized")
        
        # Test config service
        config_service = ConfigService()
        print("✅ ConfigService initialized")
        
        # Test basic methods
        devices = key_storage.get_all_devices()
        print(f"✅ get_all_devices() returned {len(devices)} devices")
        
        pending_requests = key_storage.get_pending_requests()
        print(f"✅ get_pending_requests() returned {len(pending_requests)} requests")
        
        stats = key_storage.get_statistics()
        print(f"✅ get_statistics() returned: {stats}")
        
        active_requests = key_storage.get_active_requests()
        print(f"✅ get_active_requests() returned {len(active_requests)} requests")
        
        recent_activity = key_storage.get_recent_activity(limit=5)
        print(f"✅ get_recent_activity() returned {len(recent_activity)} items")
        
        print("\n🎉 All keyholder dashboard tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing keyholder dashboard: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_keyholder_dashboard()
    sys.exit(0 if success else 1) 