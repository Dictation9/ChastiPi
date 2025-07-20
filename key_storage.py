import os
import json
import base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

class KeyStorage:
    """
    Encrypted key storage system for ChastiPi
    Handles secure storage and retrieval of keys with encryption
    """
    
    def __init__(self, storage_file='keys.enc', master_password=None):
        self.storage_file = storage_file
        self.master_password = master_password or os.environ.get('MASTER_PASSWORD', 'default-master-key-change-in-production')
        self.fernet = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize encryption
        self._initialize_encryption()
        
        # Load existing keys or create new storage
        self.keys = self._load_keys()
    
    def _initialize_encryption(self):
        """Initialize the Fernet cipher for encryption/decryption"""
        try:
            # Generate a key from the master password
            salt = b'chastipi_salt_2024'  # In production, use a random salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            self.fernet = Fernet(key)
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
            raise
    
    def _encrypt_data(self, data):
        """Encrypt data using Fernet"""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            if isinstance(data, str):
                data = data.encode()
            return self.fernet.encrypt(data)
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def _decrypt_data(self, encrypted_data):
        """Decrypt data using Fernet"""
        try:
            decrypted = self.fernet.decrypt(encrypted_data)
            try:
                # Try to parse as JSON
                return json.loads(decrypted.decode())
            except json.JSONDecodeError:
                # Return as string if not JSON
                return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def _load_keys(self):
        """Load encrypted keys from storage file"""
        try:
            if not os.path.exists(self.storage_file):
                return {
                    'keys': [],
                    'metadata': {
                        'created': datetime.now().isoformat(),
                        'version': '1.0',
                        'total_keys': 0
                    }
                }
            
            with open(self.storage_file, 'rb') as f:
                encrypted_data = f.read()
            
            return self._decrypt_data(encrypted_data)
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            return {
                'keys': [],
                'metadata': {
                    'created': datetime.now().isoformat(),
                    'version': '1.0',
                    'total_keys': 0
                }
            }
    
    def _save_keys(self):
        """Save keys to encrypted storage file"""
        try:
            encrypted_data = self._encrypt_data(self.keys)
            with open(self.storage_file, 'wb') as f:
                f.write(encrypted_data)
            self.logger.info(f"Keys saved successfully to {self.storage_file}")
        except Exception as e:
            self.logger.error(f"Failed to save keys: {e}")
            raise
    
    def add_key(self, key_name, key_description, key_location, key_type='physical', 
                access_notes='', emergency_access=False):
        """
        Add a new key to the storage
        
        Args:
            key_name (str): Name/identifier for the key
            key_description (str): Description of what the key is for
            key_location (str): Physical location of the key (e.g., "Master Lock safe")
            key_type (str): Type of key ('physical', 'digital', 'backup')
            access_notes (str): Additional notes about accessing the key
            emergency_access (bool): Whether this key can be used for emergency access
        """
        try:
            key_data = {
                'id': len(self.keys['keys']) + 1,
                'name': key_name,
                'description': key_description,
                'location': key_location,
                'type': key_type,
                'access_notes': access_notes,
                'emergency_access': emergency_access,
                'created': datetime.now().isoformat(),
                'last_accessed': None,
                'access_count': 0,
                'status': 'available'
            }
            
            self.keys['keys'].append(key_data)
            self.keys['metadata']['total_keys'] = len(self.keys['keys'])
            self.keys['metadata']['last_updated'] = datetime.now().isoformat()
            
            self._save_keys()
            self.logger.info(f"Key '{key_name}' added successfully")
            return key_data
        except Exception as e:
            self.logger.error(f"Failed to add key: {e}")
            raise
    
    def get_key(self, key_id):
        """Get a specific key by ID"""
        try:
            for key in self.keys['keys']:
                if key['id'] == key_id:
                    return key
            return None
        except Exception as e:
            self.logger.error(f"Failed to get key {key_id}: {e}")
            return None
    
    def get_all_keys(self):
        """Get all keys (without sensitive access information)"""
        try:
            # Return keys without access notes for security
            safe_keys = []
            for key in self.keys['keys']:
                safe_key = key.copy()
                safe_key.pop('access_notes', None)
                safe_keys.append(safe_key)
            return safe_keys
        except Exception as e:
            self.logger.error(f"Failed to get all keys: {e}")
            return []
    
    def access_key(self, key_id, access_reason=''):
        """
        Record access to a key and return access information
        
        Args:
            key_id (int): ID of the key to access
            access_reason (str): Reason for accessing the key
        """
        try:
            key = self.get_key(key_id)
            if not key:
                raise ValueError(f"Key with ID {key_id} not found")
            
            # Update access information
            key['last_accessed'] = datetime.now().isoformat()
            key['access_count'] += 1
            
            # Log the access
            access_log = {
                'key_id': key_id,
                'key_name': key['name'],
                'access_time': datetime.now().isoformat(),
                'access_reason': access_reason,
                'accessor': 'keyholder'  # In a real system, this would be the actual user
            }
            
            # Add to access history if it doesn't exist
            if 'access_history' not in self.keys:
                self.keys['access_history'] = []
            
            self.keys['access_history'].append(access_log)
            
            self._save_keys()
            self.logger.info(f"Key '{key['name']}' accessed by keyholder")
            
            return {
                'key': key,
                'access_log': access_log
            }
        except Exception as e:
            self.logger.error(f"Failed to access key {key_id}: {e}")
            raise
    
    def update_key(self, key_id, **kwargs):
        """Update key information"""
        try:
            key = self.get_key(key_id)
            if not key:
                raise ValueError(f"Key with ID {key_id} not found")
            
            # Update allowed fields
            allowed_fields = ['name', 'description', 'location', 'type', 'access_notes', 'emergency_access', 'status']
            for field, value in kwargs.items():
                if field in allowed_fields:
                    key[field] = value
            
            key['last_updated'] = datetime.now().isoformat()
            self.keys['metadata']['last_updated'] = datetime.now().isoformat()
            
            self._save_keys()
            self.logger.info(f"Key '{key['name']}' updated successfully")
            return key
        except Exception as e:
            self.logger.error(f"Failed to update key {key_id}: {e}")
            raise
    
    def delete_key(self, key_id):
        """Delete a key from storage"""
        try:
            key = self.get_key(key_id)
            if not key:
                raise ValueError(f"Key with ID {key_id} not found")
            
            # Remove key from list
            self.keys['keys'] = [k for k in self.keys['keys'] if k['id'] != key_id]
            self.keys['metadata']['total_keys'] = len(self.keys['keys'])
            self.keys['metadata']['last_updated'] = datetime.now().isoformat()
            
            self._save_keys()
            self.logger.info(f"Key '{key['name']}' deleted successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete key {key_id}: {e}")
            raise
    
    def get_access_history(self, limit=50):
        """Get recent access history"""
        try:
            history = self.keys.get('access_history', [])
            return history[-limit:] if limit else history
        except Exception as e:
            self.logger.error(f"Failed to get access history: {e}")
            return []
    
    def get_emergency_keys(self):
        """Get all emergency access keys"""
        try:
            return [key for key in self.keys['keys'] if key.get('emergency_access', False)]
        except Exception as e:
            self.logger.error(f"Failed to get emergency keys: {e}")
            return []
    
    def get_keys_by_location(self, location):
        """Get all keys at a specific location"""
        try:
            return [key for key in self.keys['keys'] if key.get('location', '').lower() == location.lower()]
        except Exception as e:
            self.logger.error(f"Failed to get keys by location: {e}")
            return []
    
    def get_storage_stats(self):
        """Get storage statistics"""
        try:
            total_keys = len(self.keys['keys'])
            emergency_keys = len(self.get_emergency_keys())
            physical_keys = len([k for k in self.keys['keys'] if k.get('type') == 'physical'])
            digital_keys = len([k for k in self.keys['keys'] if k.get('type') == 'digital'])
            
            return {
                'total_keys': total_keys,
                'emergency_keys': emergency_keys,
                'physical_keys': physical_keys,
                'digital_keys': digital_keys,
                'last_updated': self.keys['metadata'].get('last_updated'),
                'storage_created': self.keys['metadata'].get('created')
            }
        except Exception as e:
            self.logger.error(f"Failed to get storage stats: {e}")
            return {} 

    def add_lockbox_code(self, user_id, code, label=None):
        """Manually add a lockbox code for a specific user"""
        if not user_id or not code:
            raise ValueError("user_id and code are required")

        user_entry = {
            "code": code,
            "label": label or "Unnamed Lockbox",
            "timestamp": datetime.now().isoformat()
        }

        self.keys[user_id] = user_entry
        self._save_keys()

    def get_lockbox_code(self, user_id):
        """Retrieve a user's lockbox code"""
        return self.keys.get(user_id)

    def _save_keys(self):
        """Save encrypted keys to file"""
        try:
            with open(self.storage_file, 'wb') as f:
                f.write(self._encrypt_data(self.keys))
        except Exception as e:
            self.logger.error(f"Failed to save keys: {e}")
            raise
