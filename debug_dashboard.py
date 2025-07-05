#!/usr/bin/env python3
"""
Debug script to identify dashboard errors
"""
import sys
import os
import traceback

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dashboard_route():
    """Test the dashboard route and catch specific errors"""
    try:
        print("🔧 Testing dashboard route...")
        
        # Import the dashboard route function
        from chasti_pi.api.main import dashboard
        
        # Test the dashboard function
        print("  ✅ Dashboard function imported successfully")
        
        # Test each service call individually
        print("\n🔧 Testing individual service calls...")
        
        # Test config
        from chasti_pi.core.config import config
        print("  ✅ Config imported")
        keyholder_registered = config.is_keyholder_registered()
        print(f"  ✅ is_keyholder_registered(): {keyholder_registered}")
        
        # Test KeyStorageService
        from chasti_pi.services.key_storage_service import KeyStorageService
        key_storage = KeyStorageService()
        print("  ✅ KeyStorageService created")
        active_requests = key_storage.get_active_requests()
        print(f"  ✅ get_active_requests(): {len(active_requests)}")
        
        # Test CageCheckService
        from chasti_pi.services.cage_check_service import CageCheckService
        cage_check = CageCheckService()
        print("  ✅ CageCheckService created")
        recent_checks = cage_check.get_recent_checks(limit=5)
        print(f"  ✅ get_recent_checks(): {len(recent_checks)}")
        
        # Test PunishmentService
        from chasti_pi.services.punishment_service import PunishmentService
        punishment = PunishmentService()
        print("  ✅ PunishmentService created")
        stats = punishment.get_statistics()
        print(f"  ✅ get_statistics(): {stats}")
        
        # Test TimeVerificationService
        from chasti_pi.services.time_verification_service import TimeVerificationService
        time_service = TimeVerificationService()
        print("  ✅ TimeVerificationService created")
        status = time_service.get_status()
        print(f"  ✅ get_status(): {status}")
        
        print("\n✅ All services working correctly!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\n📋 Full traceback:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔧 Debugging ChastiPi dashboard...")
    print("=" * 50)
    
    success = test_dashboard_route()
    
    if success:
        print("\n✅ Dashboard should work correctly!")
    else:
        print("\n❌ Dashboard has errors. Check the traceback above.")
        sys.exit(1) 