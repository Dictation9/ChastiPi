#!/usr/bin/env python3
"""
Test script to identify dashboard errors
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dashboard_components():
    """Test each component that the dashboard uses"""
    print("🔧 Testing dashboard components...")
    
    try:
        # Test config
        print("\n📋 Testing config...")
        from chasti_pi.core.config import config
        keyholder_registered = config.is_keyholder_registered()
        print(f"  ✅ is_keyholder_registered(): {keyholder_registered}")
        
        keyholder_email = config.get("keyholder.default_keyholder_email", "")
        print(f"  ✅ keyholder_email: {keyholder_email}")
        
    except Exception as e:
        print(f"  ❌ Config error: {e}")
        return False
    
    try:
        # Test KeyStorageService
        print("\n🔑 Testing KeyStorageService...")
        from chasti_pi.services.key_storage_service import KeyStorageService
        key_storage = KeyStorageService()
        
        active_requests = key_storage.get_active_requests()
        print(f"  ✅ get_active_requests(): {len(active_requests)} requests")
        
        keyholder_info = key_storage.get_keyholder_info()
        print(f"  ✅ get_keyholder_info(): {keyholder_info}")
        
    except Exception as e:
        print(f"  ❌ KeyStorageService error: {e}")
        return False
    
    try:
        # Test CageCheckService
        print("\n🔒 Testing CageCheckService...")
        from chasti_pi.services.cage_check_service import CageCheckService
        cage_check = CageCheckService()
        
        recent_checks = cage_check.get_recent_checks(limit=5)
        print(f"  ✅ get_recent_checks(): {len(recent_checks)} checks")
        
        stats = cage_check.get_statistics()
        print(f"  ✅ get_statistics(): {stats}")
        
    except Exception as e:
        print(f"  ❌ CageCheckService error: {e}")
        return False
    
    try:
        # Test PunishmentService
        print("\n⚖️ Testing PunishmentService...")
        from chasti_pi.services.punishment_service import PunishmentService
        punishment = PunishmentService()
        
        stats = punishment.get_statistics()
        print(f"  ✅ get_statistics(): {stats}")
        
    except Exception as e:
        print(f"  ❌ PunishmentService error: {e}")
        return False
    
    try:
        # Test TimeVerificationService
        print("\n🕐 Testing TimeVerificationService...")
        from chasti_pi.services.time_verification_service import TimeVerificationService
        time_service = TimeVerificationService()
        
        status = time_service.get_status()
        print(f"  ✅ get_status(): {status}")
        
    except Exception as e:
        print(f"  ❌ TimeVerificationService error: {e}")
        return False
    
    return True

def test_dashboard_route():
    """Test the dashboard route specifically"""
    print("\n🌐 Testing dashboard route...")
    
    try:
        from chasti_pi.api.main import main_bp
        from flask import Flask
        
        # Create a test Flask app
        app = Flask(__name__)
        app.register_blueprint(main_bp)
        
        # Test that the route exists
        with app.test_client() as client:
            response = client.get('/dashboard')
            print(f"  ✅ Dashboard route exists, status: {response.status_code}")
            
            if response.status_code != 200:
                print(f"  ❌ Dashboard returned status {response.status_code}")
                return False
                
    except Exception as e:
        print(f"  ❌ Dashboard route error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🔧 Testing ChastiPi dashboard for errors...")
    print("=" * 50)
    
    components_ok = test_dashboard_components()
    route_ok = test_dashboard_route()
    
    print("\n" + "=" * 50)
    if components_ok and route_ok:
        print("✅ All dashboard components working!")
        print("\n📋 If you're still getting errors, please:")
        print("1. Check the ChastiPi logs for specific error messages")
        print("2. Try accessing the dashboard again")
        print("3. Share the exact error message you see")
    else:
        print("❌ Dashboard has errors. Please check the output above.")
        sys.exit(1) 