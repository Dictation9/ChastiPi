#!/usr/bin/env python3
"""
Test script for the ChastiPi Key Storage System
"""

import os
import sys
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_key_storage():
    """Test the key storage functionality"""
    print("🔐 Testing ChastiPi Key Storage System")
    print("=" * 50)
    
    try:
        from key_storage import KeyStorage
        
        # Initialize key storage
        print("Initializing key storage...")
        storage = KeyStorage(storage_file='test_keys.enc')
        
        # Test adding keys
        print("\n📝 Adding test keys...")
        
        # Add a physical key for the Master Lock safe
        key1 = storage.add_key(
            key_name="Master Lock Key",
            key_description="Primary key for the Master Lock combination safe",
            key_location="Master Lock safe - Outdoor wall",
            key_type="physical",
            access_notes="Combination: 1234. Located on outdoor wall near front door.",
            emergency_access=True
        )
        print(f"✅ Added key: {key1['name']}")
        
        # Add a backup key
        key2 = storage.add_key(
            key_name="Backup Key",
            key_description="Emergency backup key for device access",
            key_location="Home office safe",
            key_type="physical",
            access_notes="Hidden in home office safe. Code: 5678",
            emergency_access=True
        )
        print(f"✅ Added key: {key2['name']}")
        
        # Add a digital key
        key3 = storage.add_key(
            key_name="Digital Access Code",
            key_description="Digital access code for emergency release",
            key_location="Password manager",
            key_type="digital",
            access_notes="Stored in password manager. Code: 9999",
            emergency_access=False
        )
        print(f"✅ Added key: {key3['name']}")
        
        # Test getting all keys
        print("\n📋 Retrieving all keys...")
        all_keys = storage.get_all_keys()
        print(f"✅ Found {len(all_keys)} keys")
        
        for key in all_keys:
            print(f"  - {key['name']} ({key['type']}) at {key['location']}")
        
        # Test accessing a key
        print(f"\n🔑 Accessing key: {key1['name']}")
        access_result = storage.access_key(key1['id'], "Testing key access functionality")
        print(f"✅ Key accessed successfully. Access count: {access_result['key']['access_count']}")
        
        # Test getting emergency keys
        print("\n🚨 Getting emergency keys...")
        emergency_keys = storage.get_emergency_keys()
        print(f"✅ Found {len(emergency_keys)} emergency keys")
        
        for key in emergency_keys:
            print(f"  - {key['name']} at {key['location']}")
        
        # Test getting keys by location
        print("\n📍 Getting keys by location...")
        master_lock_keys = storage.get_keys_by_location("Master Lock safe")
        print(f"✅ Found {len(master_lock_keys)} keys at Master Lock safe")
        
        # Test getting storage statistics
        print("\n📊 Getting storage statistics...")
        stats = storage.get_storage_stats()
        print(f"✅ Storage stats: {stats}")
        
        # Test getting access history
        print("\n📋 Getting access history...")
        history = storage.get_access_history(limit=10)
        print(f"✅ Found {len(history)} access records")
        
        # Test updating a key
        print(f"\n✏️ Updating key: {key1['name']}")
        updated_key = storage.update_key(key1['id'], description="Updated description for Master Lock key")
        print(f"✅ Key updated successfully")
        
        # Test deleting a key
        print(f"\n🗑️ Deleting key: {key3['name']}")
        storage.delete_key(key3['id'])
        print(f"✅ Key deleted successfully")
        
        # Final stats
        final_stats = storage.get_storage_stats()
        print(f"\n📊 Final storage stats: {final_stats}")
        
        # Clean up test file
        if os.path.exists('test_keys.enc'):
            os.remove('test_keys.enc')
            print("\n🧹 Cleaned up test file")
        
        print("\n🎉 All tests passed! Key storage system is working correctly.")
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import key storage: {e}")
        print("Make sure you have installed the required dependencies:")
        print("pip install cryptography bcrypt")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_key_storage()
    sys.exit(0 if success else 1) 