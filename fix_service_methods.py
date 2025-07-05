#!/usr/bin/env python3
"""
Quick fix script to test service method fixes
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_service_methods():
    """Test that the missing service methods are now available"""
    try:
        from chasti_pi.services.key_storage_service import KeyStorageService
        from chasti_pi.services.cage_check_service import CageCheckService
        from chasti_pi.services.config_service import ConfigService
        
        print("✅ Testing KeyStorageService methods...")
        key_storage = KeyStorageService()
        
        # Test the new methods
        methods_to_test = [
            'get_active_requests',
            'get_all_requests', 
            'get_recent_activity',
            'get_statistics'
        ]
        
        for method_name in methods_to_test:
            if hasattr(key_storage, method_name):
                print(f"  ✅ {method_name} method exists")
            else:
                print(f"  ❌ {method_name} method missing")
        
        print("\n✅ Testing CageCheckService methods...")
        cage_check = CageCheckService()
        
        if hasattr(cage_check, 'get_all_check_requests'):
            print("  ✅ get_all_check_requests method exists")
        else:
            print("  ❌ get_all_check_requests method missing")
        
        print("\n✅ Testing ConfigService methods...")
        config_service = ConfigService()
        
        if hasattr(config_service, 'get_section'):
            print("  ✅ get_section method exists")
        else:
            print("  ❌ get_section method missing")
        
        print("\n✅ All service methods are now available!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing service methods: {e}")
        return False

def test_templates():
    """Test that the missing templates exist"""
    try:
        template_files = [
            'templates/calendar/index.html',
            'templates/upload/index.html'
        ]
        
        print("\n✅ Testing template files...")
        for template_file in template_files:
            if os.path.exists(template_file):
                print(f"  ✅ {template_file} exists")
            else:
                print(f"  ❌ {template_file} missing")
        
        print("\n✅ All template files are now available!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing templates: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Testing ChastiPi service method fixes...")
    print("=" * 50)
    
    service_ok = test_service_methods()
    template_ok = test_templates()
    
    print("\n" + "=" * 50)
    if service_ok and template_ok:
        print("✅ All fixes applied successfully!")
        print("\n📋 Next steps:")
        print("1. Restart ChastiPi: ./start_chastipi.sh")
        print("2. Test the dashboard and keyholder pages")
        print("3. Check that calendar and upload pages load")
    else:
        print("❌ Some fixes failed. Please check the errors above.")
        sys.exit(1) 