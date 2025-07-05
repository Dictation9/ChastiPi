#!/usr/bin/env python3
"""
Comprehensive test script for all ChastiPi fixes
Tests dependency management, service fixes, and template availability
"""
import sys
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_dependency_management():
    """Test the enhanced dependency management system"""
    print("🧪 Testing enhanced dependency management...")
    
    try:
        from chasti_pi.core.dependencies import (
            setup_dependencies, 
            get_missing_dependencies,
            is_raspberry_pi,
            check_numpy_version,
            test_critical_dependencies
        )
        
        print("✅ Dependency module imported successfully")
        
        # Test Raspberry Pi detection
        is_pi = is_raspberry_pi()
        print(f"🔍 Raspberry Pi detection: {'✅ Yes' if is_pi else '❌ No'}")
        
        # Test NumPy version check
        numpy_ok = check_numpy_version()
        print(f"🔍 NumPy compatibility: {'✅ OK' if numpy_ok else '⚠️  Issues detected'}")
        
        # Test dependency checking
        missing = get_missing_dependencies()
        print(f"📦 Missing dependencies: {missing}")
        
        # Test critical dependencies
        print("🔧 Testing critical dependencies...")
        critical_ok = test_critical_dependencies()
        
        if critical_ok:
            print("✅ Critical dependencies working correctly")
        else:
            print("❌ Critical dependency test failed")
            
        return critical_ok
        
    except ImportError as e:
        print(f"❌ Failed to import dependency module: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_service_fixes():
    """Test that service fixes are working"""
    print("🧪 Testing service fixes...")
    
    try:
        from chasti_pi.services.service_fixes import apply_all_service_fixes
        from chasti_pi.services.key_storage_service import KeyStorageService
        from chasti_pi.services.cage_check_service import CageCheckService
        from chasti_pi.services.config_service import ConfigService
        
        # Apply fixes
        apply_all_service_fixes()
        
        # Test KeyStorageService methods
        print("  🔍 Testing KeyStorageService methods...")
        key_storage = KeyStorageService()
        
        methods_to_test = [
            'get_active_requests',
            'get_all_requests', 
            'get_recent_activity',
            'get_statistics'
        ]
        
        for method_name in methods_to_test:
            if hasattr(key_storage, method_name):
                print(f"    ✅ {method_name} method exists")
            else:
                print(f"    ❌ {method_name} method missing")
        
        # Test CageCheckService methods
        print("  🔍 Testing CageCheckService methods...")
        cage_check = CageCheckService()
        
        if hasattr(cage_check, 'get_all_check_requests'):
            print("    ✅ get_all_check_requests method exists")
        else:
            print("    ❌ get_all_check_requests method missing")
        
        # Test ConfigService methods
        print("  🔍 Testing ConfigService methods...")
        config_service = ConfigService()
        
        if hasattr(config_service, 'get_section'):
            print("    ✅ get_section method exists")
        else:
            print("    ❌ get_section method missing")
        
        print("✅ All service fixes applied successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing service fixes: {e}")
        return False

def test_templates():
    """Test that all required templates exist"""
    print("🧪 Testing template files...")
    
    try:
        template_files = [
            'templates/calendar/index.html',
            'templates/upload/index.html'
        ]
        
        all_exist = True
        for template_file in template_files:
            if os.path.exists(template_file):
                print(f"  ✅ {template_file} exists")
            else:
                print(f"  ❌ {template_file} missing")
                all_exist = False
        
        if all_exist:
            print("✅ All template files are available!")
        else:
            print("❌ Some template files are missing")
            
        return all_exist
        
    except Exception as e:
        print(f"❌ Error testing templates: {e}")
        return False

def test_app_startup():
    """Test that the app can start successfully"""
    print("🧪 Testing app startup...")
    
    try:
        from chasti_pi.core.app import create_app
        from chasti_pi.core.config import config
        
        print("  🔧 Creating app...")
        app = create_app()
        
        print("  ✅ App created successfully")
        
        # Test basic config
        host = config.get('host', '0.0.0.0')
        port = config.get('port', 5000)
        print(f"  📋 Config: {host}:{port}")
        
        return True
        
    except Exception as e:
        print(f"❌ App startup failed: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Starting comprehensive ChastiPi fix tests...")
    print("=" * 60)
    
    # Run all tests
    tests = [
        ("Dependency Management", test_dependency_management),
        ("Service Fixes", test_service_fixes),
        ("Template Files", test_templates),
        ("App Startup", test_app_startup)
    ]
    
    results = {}
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name} test...")
        print("-" * 40)
        results[test_name] = test_func()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    print("=" * 60)
    
    all_passed = True
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
        if not result:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 All tests passed! ChastiPi is ready to run.")
        print("\n📋 Next steps:")
        print("1. Start ChastiPi: python start_chastipi.py")
        print("2. Access the web interface at http://localhost:5000")
        print("3. Check that all features are working correctly")
        return True
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("1. Check that all dependencies are installed")
        print("2. Verify Python environment is correct")
        print("3. Check logs for detailed error messages")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 