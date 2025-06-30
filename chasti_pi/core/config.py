"""
Configuration management for ChastiPi
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from cryptography.fernet import Fernet
import base64

class Config:
    """Centralized configuration management with encryption support"""
    
    def __init__(self, config_path="config.json"):
        self.config_path = Path(config_path)
        self.key_path = Path("data/keys")
        self.key_path.mkdir(parents=True, exist_ok=True)
        self.config = self._load_config()
        self._setup_encryption()
    
    def _setup_encryption(self):
        """Setup encryption key for keyholder settings"""
        key_file = self.key_path / "config.key"
        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
        
        self.cipher = Fernet(self.encryption_key)
    
    def _load_config(self):
        """Load configuration from JSON file"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return self._get_default_config()
    
    def _get_default_config(self):
        """Return default configuration"""
        return {
            "system": {
                "setup_complete": False,
                "user_role": "wearer",
                "hosting_mode": "self-hosted",
                "chastity_mode": "gentle",
                "chastity_modes_available": [
                    "self-hosted-test",
                    "gentle",
                    "timed-challenge",
                    "random-discipline",
                    "strict"
                ]
            },
            "device": {
                "device_id": "KPI-XXXXXX",
                "device_name": "ChastiPi Device",
                "location": "Home",
                "timezone": "UTC"
            },
            "network": {
                "host": "0.0.0.0",
                "port": 5000,
                "external_url": "http://your-public-ip:5000",
                "webhook_url": "http://your-public-ip:5000/webhook/email",
                "enable_remote_access": False,
                "allowed_networks": []
            },
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "your-email@gmail.com",
                "password": "your-app-password",
                "use_tls": True,
                "from_address": "yourbot@example.com",
                "reply_to": "yourbot@example.com",
                "notification_emails": []
            },
            "security": {
                "enable_ssl": False,
                "require_auth": False,
                "allowed_ips": [],
                "session_timeout_minutes": 30,
                "max_login_attempts": 5,
                "password_min_length": 8,
                "enable_rate_limiting": True,
                "rate_limit_requests": 100,
                "rate_limit_window": 3600
            },
            "keyholder": {
                "mode": "keyholder_managed",
                "default_keyholder_email": "",
                "approval_timeout_hours": 24,
                "emergency_timeout_minutes": 30,
                "max_request_duration_days": 30,
                "require_email_verification": True,
                "enable_auto_approval": False,
                "auto_approval_duration_hours": 2,
                "notification_frequency": "immediate"
            },
            "cage_check": {
                "enabled": True,
                "verification_code_length": 6,
                "verification_timeout_hours": 24,
                "reminder_interval_hours": 6,
                "max_reminders": 3,
                "require_photo": True,
                "ocr_accuracy_threshold": 0.8,
                "auto_escalation": True,
                "escalation_delay_hours": 48
            },
            "punishment": {
                "enabled": True,
                "qr_code_size": 200,
                "pdf_template": "default",
                "verification_required": True,
                "ocr_accuracy_threshold": 0.8,
                "max_upload_size_mb": 10,
                "allowed_image_formats": ["jpg", "jpeg", "png", "gif", "bmp"],
                "auto_cleanup_days": 30,
                "enable_statistics": True
            },
            "time_verification": {
                "enabled": True,
                "ntp_servers": [
                    "pool.ntp.org",
                    "time.nist.gov",
                    "time.google.com"
                ],
                "sync_interval_minutes": 60,
                "max_drift_seconds": 5,
                "auto_correct": True,
                "alert_on_drift": True,
                "drift_threshold_seconds": 10
            },
            "upload": {
                "max_file_size_mb": 10,
                "allowed_formats": ["jpg", "jpeg", "png", "gif", "bmp"],
                "storage_path": "uploads",
                "auto_cleanup": True,
                "cleanup_interval_days": 7,
                "enable_compression": True,
                "compression_quality": 85
            },
            "calendar": {
                "enabled": True,
                "default_view": "month",
                "enable_reminders": True,
                "reminder_advance_hours": 24,
                "max_events_per_page": 50,
                "enable_recurring_events": True
            },
            "logging": {
                "level": "INFO",
                "file_enabled": True,
                "file_path": "logs",
                "max_file_size_mb": 10,
                "backup_count": 5,
                "console_enabled": True,
                "email_enabled": False,
                "email_level": "ERROR"
            },
            "appearance": {
                "theme": "default",
                "language": "en",
                "date_format": "YYYY-MM-DD",
                "time_format": "HH:mm:ss",
                "timezone_display": "local",
                "enable_dark_mode": False,
                "custom_css": ""
            },
            "notifications": {
                "email_enabled": True,
                "sms_enabled": False,
                "webhook_enabled": False,
                "webhook_url": "",
                "notification_types": {
                    "key_request": True,
                    "cage_check": True,
                    "punishment_complete": True,
                    "time_drift": True,
                    "system_error": True
                },
                "quiet_hours": {
                    "enabled": False,
                    "start": "22:00",
                    "end": "08:00"
                }
            },
            "automation": {
                "enabled": False,
                "auto_backup": True,
                "backup_interval_days": 7,
                "backup_retention_days": 30,
                "auto_update": False,
                "update_check_interval_days": 7,
                "health_check_interval_minutes": 30
            },
            "development": {
                "debug": False,
                "test_mode": False,
                "mock_services": False,
                "log_requests": False,
                "enable_profiling": False
            },
            "modes": {
                "self-hosted-test": {
                    "punishments_enabled": True,
                    "cage_check_enabled": True
                },
                "gentle": {
                    "punishments_enabled": False,
                    "cage_check_enabled": True
                },
                "timed-challenge": {
                    "punishments_enabled": True,
                    "cage_check_enabled": True,
                    "timed_challenges_enabled": True
                },
                "random-discipline": {
                    "punishments_enabled": True,
                    "cage_check_enabled": True,
                    "random_discipline_enabled": True
                },
                "strict": {
                    "punishments_enabled": True,
                    "cage_check_enabled": True,
                    "strict_mode_features_enabled": True
                }
            }
        }
    
    def get_setting_permissions(self) -> Dict[str, List[str]]:
        """Get setting permissions for different user types"""
        return {
            "wearer": [
                "email.enabled",
                "email.smtp_server", 
                "email.smtp_port",
                "email.username",
                "email.password",
                "email.use_tls",
                "email.from_address",
                "email.reply_to",
                "email.notification_emails",
                "network.host",
                "network.port",
                "network.external_url",
                "network.webhook_url",
                "network.enable_remote_access",
                "network.allowed_networks",
                "device.device_id",
                "device.device_name",
                "device.location",
                "appearance.theme",
                "appearance.language",
                "appearance.date_format",
                "appearance.time_format",
                "appearance.timezone_display",
                "appearance.enable_dark_mode",
                "appearance.custom_css",
                "system.user_role"
            ],
            "keyholder": [
                # All settings are accessible to keyholder
                "*"
            ],
            "admin": [
                # All settings are accessible to admin
                "*"
            ]
        }
    
    def can_access_setting(self, user_type: str, setting_key: str) -> bool:
        """Check if user type can access a specific setting"""
        permissions = self.get_setting_permissions()
        
        if user_type not in permissions:
            return False
        
        user_permissions = permissions[user_type]
        
        # Admin and keyholder have access to all settings
        if "*" in user_permissions:
            return True
        
        # Check specific permissions
        return setting_key in user_permissions
    
    def get_wearer_accessible_settings(self) -> Dict[str, Any]:
        """Get settings that the wearer can access and modify"""
        wearer_settings = {}
        permissions = self.get_setting_permissions()["wearer"]
        
        for section, settings in self.config.items():
            wearer_section = {}
            for key, value in settings.items():
                setting_key = f"{section}.{key}"
                if setting_key in permissions:
                    wearer_section[key] = value
            
            if wearer_section:
                wearer_settings[section] = wearer_section
        
        return wearer_settings
    
    def get_keyholder_settings(self) -> Dict[str, Any]:
        """Get encrypted keyholder-specific settings"""
        keyholder_sections = [
            "keyholder", "cage_check", "punishment", "time_verification",
            "security", "notifications", "automation"
        ]
        
        keyholder_settings = {}
        for section in keyholder_sections:
            if section in self.config:
                keyholder_settings[section] = self.config[section]
        
        return keyholder_settings
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt data using Fernet"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using Fernet"""
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data  # Return as-is if decryption fails
    
    def _encrypt_section(self, section_data: Dict[str, Any]) -> str:
        """Encrypt a configuration section"""
        json_data = json.dumps(section_data, indent=2)
        return self._encrypt_data(json_data)
    
    def _decrypt_section(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt a configuration section"""
        try:
            decrypted_data = self._decrypt_data(encrypted_data)
            return json.loads(decrypted_data)
        except Exception:
            return {}
    
    def save_config(self):
        """Save current configuration to file with encryption for keyholder settings"""
        # Separate wearer and keyholder settings
        wearer_settings = self.get_wearer_accessible_settings()
        keyholder_settings = self.get_keyholder_settings()
        
        # Create final config with encrypted keyholder settings
        final_config = wearer_settings.copy()
        
        # Encrypt keyholder settings
        for section, settings in keyholder_settings.items():
            encrypted_data = self._encrypt_section(settings)
            final_config[section] = {
                "_encrypted": True,
                "_data": encrypted_data
            }
        
        # Save to file
        with open(self.config_path, 'w') as f:
            json.dump(final_config, f, indent=4)
    
    def get(self, key: str, default: Any = None, user_type: str = "admin") -> Any:
        """Get configuration value using dot notation with permission checking"""
        if not self.can_access_setting(user_type, key):
            return default
        
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        # Handle encrypted sections
        if isinstance(value, dict) and value.get("_encrypted"):
            if user_type in ["keyholder", "admin"]:
                return self._decrypt_section(value["_data"])
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any, user_type: str = "admin"):
        """Set configuration value using dot notation with permission checking"""
        # Allow system settings to be modified during initial setup
        if key.startswith("system.") and not self.get("system.setup_complete"):
            pass
        elif not self.can_access_setting(user_type, key):
            raise PermissionError(f"User type '{user_type}' cannot modify setting '{key}'")
        
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
        self.save_config()
    
    def get_section(self, section: str, user_type: str = "admin") -> Dict[str, Any]:
        """Get entire configuration section with permission checking"""
        if not self.can_access_setting(user_type, f"{section}.*"):
            # Allow access to system section during setup
            if section == "system" and not self.get("system.setup_complete"):
                pass
            else:
                return {}
        
        section_data = self.config.get(section, {})
        
        # Handle encrypted sections
        if isinstance(section_data, dict) and section_data.get("_encrypted"):
            if user_type in ["keyholder", "admin"]:
                return self._decrypt_section(section_data["_data"])
            else:
                return {}
        
        return section_data
    
    def set_section(self, section: str, values: Dict[str, Any], user_type: str = "admin"):
        """Set entire configuration section with permission checking"""
        # Allow system section to be modified during initial setup
        if section == "system" and not self.get("system.setup_complete"):
            self.config[section] = values
            self.save_config()
            return

        if not self.can_access_setting(user_type, f"{section}.*"):
            raise PermissionError(f"User type '{user_type}' cannot modify section '{section}'")
        
        self.config[section] = values
        self.save_config()
    
    def get_all(self, user_type: str = "admin") -> Dict[str, Any]:
        """Get all configuration accessible to user type"""
        if user_type in ["keyholder", "admin"]:
            # Return all settings including decrypted keyholder settings
            all_config = {}
            for section, settings in self.config.items():
                if isinstance(settings, dict) and settings.get("_encrypted"):
                    all_config[section] = self._decrypt_section(settings["_data"])
                else:
                    all_config[section] = settings
            return all_config
        else:
            # Return only wearer-accessible settings
            return self.get_wearer_accessible_settings()
    
    def update(self, updates: Dict[str, Any], user_type: str = "admin"):
        """Update configuration with new values and permission checking"""
        for section, settings in updates.items():
            if isinstance(settings, dict):
                for key, value in settings.items():
                    config_key = f"{section}.{key}"
                    if self.can_access_setting(user_type, config_key):
                        self.set(config_key, value, user_type)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate required fields
        required_fields = [
            "device.device_id",
            "network.host",
            "network.port"
        ]
        
        for field in required_fields:
            if not self.get(field):
                errors.append(f"Missing required field: {field}")
        
        # Validate email configuration if enabled
        if self.get("email.enabled"):
            email_fields = [
                "email.smtp_server",
                "email.username",
                "email.password"
            ]
            for field in email_fields:
                if not self.get(field):
                    errors.append(f"Missing email field: {field}")
        
        # Validate port number
        port = self.get("network.port")
        if port and (not isinstance(port, int) or port < 1 or port > 65535):
            errors.append("Invalid port number")
        
        return errors
    
    def export_config(self, user_type: str = "admin") -> str:
        """Export configuration as formatted text with permission checking"""
        lines = ["# ChastiPi Configuration File", ""]
        
        config_data = self.get_all(user_type)
        
        for section, settings in config_data.items():
            lines.append(f"## {section.upper()}")
            for key, value in settings.items():
                if isinstance(value, dict):
                    lines.append(f"# {key}:")
                    for subkey, subvalue in value.items():
                        lines.append(f"{key}.{subkey} = {subvalue}")
                else:
                    lines.append(f"{key} = {value}")
            lines.append("")
        
        return "\n".join(lines)
    
    def import_config(self, config_text: str, user_type: str = "admin") -> List[str]:
        """Import configuration from text format with permission checking"""
        errors = []
        
        for line in config_text.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Check permission
                if not self.can_access_setting(user_type, key):
                    errors.append(f"Permission denied for setting: {key}")
                    continue
                
                # Parse value based on type
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                elif value.startswith('[') and value.endswith(']'):
                    # Handle list values
                    try:
                        value = json.loads(value)
                    except:
                        errors.append(f"Invalid list format: {value}")
                        continue
                
                # Set the value
                try:
                    self.set(key, value, user_type)
                except Exception as e:
                    errors.append(f"Error setting {key}: {str(e)}")
        
        return errors
    
    def is_keyholder_registered(self) -> bool:
        """Check if a keyholder email is registered"""
        keyholder_email = self.get("keyholder.default_keyholder_email")
        return bool(keyholder_email and keyholder_email.strip())
    
    def get_encryption_status(self) -> Dict[str, Any]:
        """Get encryption status and key information"""
        return {
            "encryption_enabled": True,
            "key_exists": (self.key_path / "config.key").exists(),
            "keyholder_registered": self.is_keyholder_registered(),
            "encrypted_sections": [
                "keyholder", "cage_check", "punishment", "time_verification",
                "security", "notifications", "automation"
            ]
        }

# Global configuration instance
config = Config() 