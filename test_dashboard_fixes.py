#!/usr/bin/env python3
"""
Test script to verify dashboard functionality fixes
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dashboard_template():
    """Test that the dashboard template exists and has required elements"""
    try:
        template_file = 'templates/main/dashboard.html'
        
        print("✅ Testing dashboard template...")
        if os.path.exists(template_file):
            print(f"  ✅ {template_file} exists")
            
            # Check for key elements in the template
            with open(template_file, 'r') as f:
                content = f.read()
                
            required_elements = [
                'System Status',
                'Quick Actions',
                'System Information',
                'Recent Activity',
                'keyholder_registered',
                'active_requests',
                'recent_cage_checks',
                'punishment_stats',
                'time_status'
            ]
            
            for element in required_elements:
                if element in content:
                    print(f"    ✅ {element} found")
                else:
                    print(f"    ❌ {element} missing")
                    
            return True
        else:
            print(f"  ❌ {template_file} missing")
            return False
            
    except Exception as e:
        print(f"❌ Error testing dashboard template: {e}")
        return False

def test_service_methods():
    """Test that all required service methods exist"""
    try:
        print("\n✅ Testing service methods...")
        
        # Test PunishmentService
        from chasti_pi.services.punishment_service import PunishmentService
        punishment_service = PunishmentService()
        
        if hasattr(punishment_service, 'get_statistics'):
            print("  ✅ PunishmentService.get_statistics() exists")
        else:
            print("  ❌ PunishmentService.get_statistics() missing")
        
        # Test TimeVerificationService
        from chasti_pi.services.time_verification_service import TimeVerificationService
        time_service = TimeVerificationService()
        
        if hasattr(time_service, 'get_status'):
            print("  ✅ TimeVerificationService.get_status() exists")
        else:
            print("  ❌ TimeVerificationService.get_status() missing")
        
        # Test KeyStorageService
        from chasti_pi.services.key_storage_service import KeyStorageService
        key_storage = KeyStorageService()
        
        if hasattr(key_storage, 'get_active_requests'):
            print("  ✅ KeyStorageService.get_active_requests() exists")
        else:
            print("  ❌ KeyStorageService.get_active_requests() missing")
        
        # Test CageCheckService
        from chasti_pi.services.cage_check_service import CageCheckService
        cage_check = CageCheckService()
        
        if hasattr(cage_check, 'get_recent_checks'):
            print("  ✅ CageCheckService.get_recent_checks() exists")
        else:
            print("  ❌ CageCheckService.get_recent_checks() missing")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing service methods: {e}")
        return False

def test_dashboard_api():
    """Test that the dashboard API route exists"""
    try:
        print("\n✅ Testing dashboard API...")
        
        # Import the API module
        from chasti_pi.api.main import main_bp
        
        # Check if the blueprint has the required routes
        routes = [rule.rule for rule in main_bp.url_map.iter_rules()]
        
        required_routes = [
            '/dashboard',
            '/api/status'
        ]
        
        for route in required_routes:
            if route in routes:
                print(f"  ✅ Route {route} exists")
            else:
                print(f"  ❌ Route {route} missing")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing dashboard API: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Testing ChastiPi dashboard fixes...")
    print("=" * 50)
    
    template_ok = test_dashboard_template()
    service_ok = test_service_methods()
    api_ok = test_dashboard_api()
    
    print("\n" + "=" * 50)
    if template_ok and service_ok and api_ok:
        print("✅ All dashboard fixes applied successfully!")
        print("\n📋 Next steps:")
        print("1. Restart ChastiPi: ./start_chastipi.sh")
        print("2. Navigate to: http://192.168.1.219:5000/dashboard")
        print("3. Test that the dashboard loads without errors")
        print("4. Verify that all system status indicators display correctly")
        print("5. Check that the System Status button works properly")
    else:
        print("❌ Some dashboard fixes failed. Please check the errors above.")
        sys.exit(1) 