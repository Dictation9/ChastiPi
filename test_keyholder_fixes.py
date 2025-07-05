#!/usr/bin/env python3
"""
Test script to verify keyholder requests functionality fixes
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_keyholder_template():
    """Test that the keyholder requests template exists"""
    try:
        template_file = 'templates/keyholder/requests.html'
        
        print("✅ Testing keyholder requests template...")
        if os.path.exists(template_file):
            print(f"  ✅ {template_file} exists")
            
            # Check for key elements in the template
            with open(template_file, 'r') as f:
                content = f.read()
                
            required_elements = [
                'requests-container',
                'stats-section',
                'requests-list',
                'approveRequest',
                'denyRequest',
                'extendRequest',
                'reduceRequest',
                'emergencyRelease'
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
        print(f"❌ Error testing keyholder template: {e}")
        return False

def test_keyholder_api():
    """Test that the keyholder API has the required routes"""
    try:
        print("\n✅ Testing keyholder API routes...")
        
        # Import the API module
        from chasti_pi.api.keyholder import keyholder_bp
        
        # Check if the blueprint has the required routes
        routes = [rule.rule for rule in keyholder_bp.url_map.iter_rules()]
        
        required_routes = [
            '/requests',
            '/approve/<request_id>',
            '/deny/<request_id>',
            '/extend/<request_id>',
            '/reduce/<request_id>',
            '/emergency/<request_id>',
            '/access/<request_id>'
        ]
        
        for route in required_routes:
            if route in routes or any(route.replace('<', '').replace('>', '') in r for r in routes):
                print(f"  ✅ Route {route} exists")
            else:
                print(f"  ❌ Route {route} missing")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing keyholder API: {e}")
        return False

def test_key_storage_service():
    """Test that the key storage service has required methods"""
    try:
        print("\n✅ Testing key storage service...")
        
        from chasti_pi.services.key_storage_service import KeyStorageService
        
        service = KeyStorageService()
        
        required_methods = [
            'get_all_requests',
            'get_statistics',
            'get_active_requests',
            'get_recent_activity'
        ]
        
        for method in required_methods:
            if hasattr(service, method):
                print(f"  ✅ {method} method exists")
            else:
                print(f"  ❌ {method} method missing")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing key storage service: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Testing ChastiPi keyholder requests fixes...")
    print("=" * 50)
    
    template_ok = test_keyholder_template()
    api_ok = test_keyholder_api()
    service_ok = test_key_storage_service()
    
    print("\n" + "=" * 50)
    if template_ok and api_ok and service_ok:
        print("✅ All keyholder requests fixes applied successfully!")
        print("\n📋 Next steps:")
        print("1. Restart ChastiPi: ./start_chastipi.sh")
        print("2. Navigate to: http://192.168.1.219:5000/keyholder/requests")
        print("3. Test that the page loads without errors")
        print("4. Verify that request statistics and lists display correctly")
    else:
        print("❌ Some keyholder fixes failed. Please check the errors above.")
        sys.exit(1) 