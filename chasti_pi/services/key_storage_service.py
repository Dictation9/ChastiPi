"""
Key Storage Service for ChastiPi
Handles encrypted storage and management of chastity device key codes
"""
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import Fernet
import base64

class KeyStorageService:
    """Service for managing encrypted key storage and release requests"""
    
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Key storage files
        self.keys_file = self.data_dir / "encrypted_keys.json"
        self.requests_file = self.data_dir / "key_requests.json"
        self.devices_file = self.data_dir / "device_registry.json"
        
        # Initialize encryption key
        self._init_encryption()
        
        # Load data
        self._load_data()
    
    def _init_encryption(self):
        """Initialize or load encryption key"""
        key_file = self.data_dir / "encryption.key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
        
        self.cipher = Fernet(self.encryption_key)
    
    def _load_data(self):
        """Load existing data"""
        # Load encrypted keys
        if self.keys_file.exists():
            with open(self.keys_file, 'r') as f:
                self.encrypted_keys = json.load(f)
        else:
            self.encrypted_keys = {}
        
        # Load key requests
        if self.requests_file.exists():
            with open(self.requests_file, 'r') as f:
                self.key_requests = json.load(f)
        else:
            self.key_requests = {}
        
        # Load device registry
        if self.devices_file.exists():
            with open(self.devices_file, 'r') as f:
                self.devices = json.load(f)
        else:
            self.devices = {}
    
    def _save_data(self):
        """Save data to files"""
        with open(self.keys_file, 'w') as f:
            json.dump(self.encrypted_keys, f, indent=2)
        
        with open(self.requests_file, 'w') as f:
            json.dump(self.key_requests, f, indent=2)
        
        with open(self.devices_file, 'w') as f:
            json.dump(self.devices, f, indent=2)
    
    def _encrypt_key(self, key_code):
        """Encrypt a key code"""
        encrypted = self.cipher.encrypt(key_code.encode())
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_key(self, encrypted_key):
        """Decrypt a key code"""
        encrypted_bytes = base64.b64decode(encrypted_key.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    def register_device(self, device_id, key_codes, keyholder_email, device_name=None):
        """Register a new chastity device with encrypted key codes"""
        if device_id in self.devices:
            return {"error": "Device already registered"}
        
        # Encrypt key codes
        encrypted_codes = {}
        for key_name, key_code in key_codes.items():
            encrypted_codes[key_name] = self._encrypt_key(key_code)
        
        # Store device information
        device_info = {
            "device_id": device_id,
            "device_name": device_name or f"Device {device_id}",
            "keyholder_email": keyholder_email,
            "registered_at": datetime.now().isoformat(),
            "locked": True,
            "locked_since": datetime.now().isoformat(),
            "total_keys": len(key_codes),
            "key_names": list(key_codes.keys())
        }
        
        self.devices[device_id] = device_info
        self.encrypted_keys[device_id] = encrypted_codes
        
        self._save_data()
        
        return {
            "success": True,
            "message": f"Device {device_id} registered successfully",
            "device_info": device_info
        }
    
    def get_device_info(self, device_id):
        """Get device information (without decrypted keys)"""
        if device_id not in self.devices:
            return None
        
        device_info = self.devices[device_id].copy()
        # Don't include encrypted keys in device info
        return device_info
    
    def request_key_release(self, device_id, reason, duration_hours=1, emergency=False):
        """Request temporary key release"""
        if device_id not in self.devices:
            return {"error": "Device not found"}
        
        # Generate request ID
        request_id = f"REQ_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        
        # Create request
        request = {
            "request_id": request_id,
            "device_id": device_id,
            "reason": reason,
            "duration_hours": duration_hours,
            "emergency": emergency,
            "requested_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),  # 24h to approve
            "status": "pending",
            "keyholder_email": self.devices[device_id]["keyholder_email"]
        }
        
        self.key_requests[request_id] = request
        self._save_data()
        
        return {
            "success": True,
            "request_id": request_id,
            "message": "Key release request created",
            "request": request
        }
    
    def approve_key_release(self, request_id, keyholder_token=None, modified_duration=None):
        """Approve a key release request"""
        if request_id not in self.key_requests:
            return {"error": "Request not found"}
        
        request = self.key_requests[request_id]
        
        # Check if request is expired
        if datetime.fromisoformat(request["expires_at"]) < datetime.now():
            return {"error": "Request has expired"}
        
        # Check if already processed
        if request["status"] != "pending":
            return {"error": f"Request already {request['status']}"}
        
        # Use modified duration if provided, otherwise use original
        duration_hours = modified_duration if modified_duration is not None else request["duration_hours"]
        
        # Approve request
        request["status"] = "approved"
        request["approved_at"] = datetime.now().isoformat()
        request["release_expires_at"] = (
            datetime.now() + timedelta(hours=duration_hours)
        ).isoformat()
        
        # Update duration if it was modified
        if modified_duration is not None:
            request["duration_hours"] = duration_hours
            request["duration_modified"] = True
            request["original_duration"] = request.get("original_duration", request["duration_hours"])
        
        # Generate temporary access token
        access_token = secrets.token_urlsafe(32)
        request["access_token"] = access_token
        
        self.key_requests[request_id] = request
        self._save_data()
        
        return {
            "success": True,
            "message": f"Key release approved for {duration_hours} hours",
            "access_token": access_token,
            "expires_at": request["release_expires_at"],
            "duration_hours": duration_hours,
            "request": request
        }
    
    def extend_request_duration(self, request_id, additional_hours):
        """Extend the duration of a pending request"""
        if request_id not in self.key_requests:
            return {"error": "Request not found"}
        
        request = self.key_requests[request_id]
        
        # Check if request is still pending
        if request["status"] != "pending":
            return {"error": f"Cannot modify {request['status']} request"}
        
        # Extend duration
        original_duration = request["duration_hours"]
        new_duration = original_duration + additional_hours
        
        request["duration_hours"] = new_duration
        request["duration_modified"] = True
        request["original_duration"] = request.get("original_duration", original_duration)
        request["modified_at"] = datetime.now().isoformat()
        
        self.key_requests[request_id] = request
        self._save_data()
        
        return {
            "success": True,
            "message": f"Request duration extended from {original_duration} to {new_duration} hours",
            "original_duration": original_duration,
            "new_duration": new_duration,
            "request": request
        }
    
    def reduce_request_duration(self, request_id, new_duration_hours):
        """Reduce the duration of a pending request"""
        if request_id not in self.key_requests:
            return {"error": "Request not found"}
        
        request = self.key_requests[request_id]
        
        # Check if request is still pending
        if request["status"] != "pending":
            return {"error": f"Cannot modify {request['status']} request"}
        
        # Validate new duration
        if new_duration_hours <= 0:
            return {"error": "Duration must be greater than 0"}
        
        original_duration = request["duration_hours"]
        
        # Reduce duration
        request["duration_hours"] = new_duration_hours
        request["duration_modified"] = True
        request["original_duration"] = request.get("original_duration", original_duration)
        request["modified_at"] = datetime.now().isoformat()
        
        self.key_requests[request_id] = request
        self._save_data()
        
        return {
            "success": True,
            "message": f"Request duration reduced from {original_duration} to {new_duration_hours} hours",
            "original_duration": original_duration,
            "new_duration": new_duration_hours,
            "request": request
        }
    
    def modify_approved_request_duration(self, request_id, new_duration_hours):
        """Modify duration of an already approved request"""
        if request_id not in self.key_requests:
            return {"error": "Request not found"}
        
        request = self.key_requests[request_id]
        
        # Check if request is approved
        if request["status"] != "approved":
            return {"error": f"Cannot modify {request['status']} request"}
        
        # Check if access hasn't expired yet
        if datetime.fromisoformat(request["release_expires_at"]) < datetime.now():
            return {"error": "Access has already expired"}
        
        original_duration = request["duration_hours"]
        
        # Update duration and expiration
        request["duration_hours"] = new_duration_hours
        request["release_expires_at"] = (
            datetime.now() + timedelta(hours=new_duration_hours)
        ).isoformat()
        request["duration_modified"] = True
        request["original_duration"] = request.get("original_duration", original_duration)
        request["modified_at"] = datetime.now().isoformat()
        
        self.key_requests[request_id] = request
        self._save_data()
        
        return {
            "success": True,
            "message": f"Access duration modified from {original_duration} to {new_duration_hours} hours",
            "original_duration": original_duration,
            "new_duration": new_duration_hours,
            "expires_at": request["release_expires_at"],
            "request": request
        }
    
    def deny_key_release(self, request_id, reason="Denied by keyholder"):
        """Deny a key release request"""
        if request_id not in self.key_requests:
            return {"error": "Request not found"}
        
        request = self.key_requests[request_id]
        request["status"] = "denied"
        request["denied_at"] = datetime.now().isoformat()
        request["denial_reason"] = reason
        
        self.key_requests[request_id] = request
        self._save_data()
        
        return {
            "success": True,
            "message": "Key release denied",
            "request": request
        }
    
    def get_key_codes(self, device_id, access_token):
        """Get decrypted key codes using access token"""
        # Find request with this token
        request = None
        for req in self.key_requests.values():
            if req.get("access_token") == access_token and req["device_id"] == device_id:
                request = req
                break
        
        if not request:
            return {"error": "Invalid access token"}
        
        if request["status"] != "approved":
            return {"error": "Request not approved"}
        
        # Check if access has expired
        if datetime.fromisoformat(request["release_expires_at"]) < datetime.now():
            return {"error": "Access has expired"}
        
        # Decrypt and return key codes
        encrypted_codes = self.encrypted_keys.get(device_id, {})
        decrypted_codes = {}
        
        for key_name, encrypted_key in encrypted_codes.items():
            decrypted_codes[key_name] = self._decrypt_key(encrypted_key)
        
        return {
            "success": True,
            "key_codes": decrypted_codes,
            "expires_at": request["release_expires_at"],
            "device_info": self.devices[device_id]
        }
    
    def get_pending_requests(self, keyholder_email=None):
        """Get pending key release requests"""
        pending = []
        for request in self.key_requests.values():
            if request["status"] == "pending":
                if keyholder_email is None or request["keyholder_email"] == keyholder_email:
                    pending.append(request)
        
        return pending
    
    def get_request_history(self, device_id=None):
        """Get key request history"""
        history = []
        for request in self.key_requests.values():
            if device_id is None or request["device_id"] == device_id:
                history.append(request)
        
        return sorted(history, key=lambda x: x["requested_at"], reverse=True)
    
    def lock_device(self, device_id):
        """Mark device as locked"""
        if device_id not in self.devices:
            return {"error": "Device not found"}
        
        self.devices[device_id]["locked"] = True
        self.devices[device_id]["locked_since"] = datetime.now().isoformat()
        
        self._save_data()
        
        return {
            "success": True,
            "message": f"Device {device_id} marked as locked"
        }
    
    def unlock_device(self, device_id):
        """Mark device as unlocked"""
        if device_id not in self.devices:
            return {"error": "Device not found"}
        
        self.devices[device_id]["locked"] = False
        self.devices[device_id]["unlocked_at"] = datetime.now().isoformat()
        
        self._save_data()
        
        return {
            "success": True,
            "message": f"Device {device_id} marked as unlocked"
        } 