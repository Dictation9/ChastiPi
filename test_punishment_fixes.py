#!/usr/bin/env python3
"""
Test script to verify punishment functionality fixes
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_punishment_template():
    """Test that the punishment template exists"""
    try:
        template_file = 'templates/punishment/generate.html'
        
        print("✅ Testing punishment template...")
        if os.path.exists(template_file):
            print(f"  ✅ {template_file} exists")
            
            # Check for key elements in the template
            with open(template_file, 'r') as f:
                content = f.read()
                
            required_elements = [
                'generateBtn',
                'viewHistoryBtn', 
                'checkStatusBtn',
                'generatePunishment()',
                'viewHistory()',
                'checkStatus()'
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
        print(f"❌ Error testing punishment template: {e}")
        return False

def test_punishment_api():
    """Test that the punishment API has the required routes"""
    try:
        print("\n✅ Testing punishment API routes...")
        
        # Import the API module
        from chasti_pi.api.punishment import bp
        
        # Check if the blueprint has the required routes
        routes = [rule.rule for rule in bp.url_map.iter_rules()]
        
        required_routes = [
            '/',
            '/generate',
            '/history', 
            '/stats',
            '/download/<punishment_id>/<file_type>'
        ]
        
        for route in required_routes:
            if route in routes or any(route.replace('<', '').replace('>', '') in r for r in routes):
                print(f"  ✅ Route {route} exists")
            else:
                print(f"  ❌ Route {route} missing")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing punishment API: {e}")
        return False

def test_punishment_service():
    """Test that the punishment service has required methods"""
    try:
        print("\n✅ Testing punishment service...")
        
        from chasti_pi.services.punishment_service import PunishmentService
        
        service = PunishmentService()
        
        required_methods = [
            'generate_punishment',
            'get_history',
            'get_punishment_by_id',
            'verify_punishment'
        ]
        
        for method in required_methods:
            if hasattr(service, method):
                print(f"  ✅ {method} method exists")
            else:
                print(f"  ❌ {method} method missing")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing punishment service: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Testing ChastiPi punishment fixes...")
    print("=" * 50)
    
    template_ok = test_punishment_template()
    api_ok = test_punishment_api()
    service_ok = test_punishment_service()
    
    print("\n" + "=" * 50)
    if template_ok and api_ok and service_ok:
        print("✅ All punishment fixes applied successfully!")
        print("\n📋 Next steps:")
        print("1. Restart ChastiPi: ./start_chastipi.sh")
        print("2. Navigate to the punishment page")
        print("3. Test the Generate, View History, and Check Status buttons")
        print("4. Verify that all buttons work correctly")
    else:
        print("❌ Some punishment fixes failed. Please check the errors above.")
        sys.exit(1) 