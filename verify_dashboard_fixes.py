#!/usr/bin/env python3
"""
Simple verification script for dashboard fixes
"""
import os

def check_file_exists(filepath):
    """Check if a file exists"""
    if os.path.exists(filepath):
        print(f"✅ {filepath} exists")
        return True
    else:
        print(f"❌ {filepath} missing")
        return False

def check_file_content(filepath, required_strings):
    """Check if a file contains required strings"""
    if not os.path.exists(filepath):
        print(f"❌ {filepath} missing")
        return False
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        all_found = True
        for string in required_strings:
            if string in content:
                print(f"    ✅ '{string}' found")
            else:
                print(f"    ❌ '{string}' missing")
                all_found = False
        
        return all_found
    except Exception as e:
        print(f"❌ Error reading {filepath}: {e}")
        return False

def main():
    print("🔧 Verifying ChastiPi dashboard fixes...")
    print("=" * 50)
    
    # Check dashboard template
    print("\n📄 Checking dashboard template...")
    dashboard_template = 'templates/main/dashboard.html'
    dashboard_required = [
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
    
    template_ok = check_file_content(dashboard_template, dashboard_required)
    
    # Check TimeVerificationService
    print("\n🔧 Checking TimeVerificationService...")
    time_service_file = 'chasti_pi/services/time_verification_service.py'
    time_service_required = [
        'def get_status(self)',
        'return self.get_time_status()'
    ]
    
    time_service_ok = check_file_content(time_service_file, time_service_required)
    
    # Check PunishmentService
    print("\n🔧 Checking PunishmentService...")
    punishment_service_file = 'chasti_pi/services/punishment_service.py'
    punishment_service_required = [
        'def get_statistics(self)',
        'total = len(self.history)',
        'completed = sum(1 for record in self.history if record.get("completed", False))'
    ]
    
    punishment_service_ok = check_file_content(punishment_service_file, punishment_service_required)
    
    # Check KeyStorageService
    print("\n🔧 Checking KeyStorageService...")
    key_storage_file = 'chasti_pi/services/key_storage_service.py'
    key_storage_required = [
        'def get_active_requests(self)',
        'def get_keyholder_info(self)'
    ]
    
    key_storage_ok = check_file_content(key_storage_file, key_storage_required)
    
    # Check CageCheckService
    print("\n🔧 Checking CageCheckService...")
    cage_check_file = 'chasti_pi/services/cage_check_service.py'
    cage_check_required = [
        'def get_recent_checks(self, limit: int = 5)',
        'def get_statistics(self) -> Dict:'
    ]
    
    cage_check_ok = check_file_content(cage_check_file, cage_check_required)
    
    print("\n" + "=" * 50)
    if template_ok and time_service_ok and punishment_service_ok and key_storage_ok and cage_check_ok:
        print("✅ All dashboard fixes verified successfully!")
        print("\n📋 Dashboard fixes applied:")
        print("  ✅ Complete dashboard template created")
        print("  ✅ TimeVerificationService.get_status() method added")
        print("  ✅ PunishmentService.get_statistics() method added")
        print("  ✅ KeyStorageService methods added")
        print("  ✅ CageCheckService methods added")
        print("\n🚀 Next steps:")
        print("1. Restart ChastiPi: ./start_chastipi.sh")
        print("2. Navigate to: http://192.168.1.219:5000/dashboard")
        print("3. The System Status button should now work properly")
        print("4. All dashboard sections should display correctly")
    else:
        print("❌ Some dashboard fixes are missing. Please check the errors above.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 