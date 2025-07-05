"""
Configuration Service
Manages all configuration settings using the centralized config system with permissions
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from chasti_pi.core.config import config

class ConfigService:
    """Service for managing all configuration settings with user permissions"""
    
    def __init__(self):
        self.config = config
        self.config_dir = Path("data/config")
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def get_all_settings(self, user_type: str = "admin") -> Dict[str, Any]:
        """Get all configuration settings organized by category based on user permissions"""
        if user_type == "wearer":
            return self._get_wearer_settings()
        elif user_type == "keyholder":
            return self._get_keyholder_settings()
        else:
            return self._get_admin_settings()
    
    def _get_wearer_settings(self) -> Dict[str, Any]:
        """Get settings accessible to wearer"""
        return {
            "device": self._get_device_settings_wearer(),
            "network": self._get_network_settings(),
            "email": self._get_email_settings(),
            "appearance": self._get_appearance_settings()
        }
    
    def _get_keyholder_settings(self) -> Dict[str, Any]:
        """Get all settings accessible to keyholder"""
        return {
            "device": self._get_device_settings(),
            "network": self._get_network_settings(),
            "email": self._get_email_settings(),
            "security": self._get_security_settings(),
            "keyholder": self._get_keyholder_settings_section(),
            "cage_check": self._get_cage_check_settings(),
            "punishment": self._get_punishment_settings(),
            "time_verification": self._get_time_verification_settings(),
            "upload": self._get_upload_settings(),
            "calendar": self._get_calendar_settings(),
            "logging": self._get_logging_settings(),
            "appearance": self._get_appearance_settings(),
            "notifications": self._get_notification_settings(),
            "automation": self._get_automation_settings(),
            "development": self._get_development_settings()
        }
    
    def _get_admin_settings(self) -> Dict[str, Any]:
        """Get all settings accessible to admin"""
        return self._get_keyholder_settings()
    
    def _get_device_settings(self) -> Dict[str, Any]:
        """Get device settings (full access)"""
        return {
            "device_id": self.config.get("device.device_id", "KPI-XXXXXX"),
            "device_name": self.config.get("device.device_name", "ChastiPi Device"),
            "location": self.config.get("device.location", "Home"),
            "timezone": self.config.get("device.timezone", "UTC")
        }
    
    def _get_device_settings_wearer(self) -> Dict[str, Any]:
        """Get device settings (wearer access - no timezone)"""
        return {
            "device_id": self.config.get("device.device_id", "KPI-XXXXXX"),
            "device_name": self.config.get("device.device_name", "ChastiPi Device"),
            "location": self.config.get("device.location", "Home")
        }
    
    def _get_network_settings(self) -> Dict[str, Any]:
        """Get network settings"""
        return {
            "host": self.config.get("network.host", "0.0.0.0"),
            "port": self.config.get("network.port", 5000),
            "external_url": self.config.get("network.external_url", ""),
            "webhook_url": self.config.get("network.webhook_url", ""),
            "enable_remote_access": self.config.get("network.enable_remote_access", False),
            "allowed_networks": self.config.get("network.allowed_networks", [])
        }
    
    def _get_email_settings(self) -> Dict[str, Any]:
        """Get email settings"""
        return {
            "enabled": self.config.get("email.enabled", False),
            "smtp_server": self.config.get("email.smtp_server", "smtp.gmail.com"),
            "smtp_port": self.config.get("email.smtp_port", 587),
            "username": self.config.get("email.username", ""),
            "password": self.config.get("email.password", ""),
            "use_tls": self.config.get("email.use_tls", True),
            "from_address": self.config.get("email.from_address", ""),
            "reply_to": self.config.get("email.reply_to", ""),
            "notification_emails": self.config.get("email.notification_emails", [])
        }
    
    def _get_security_settings(self) -> Dict[str, Any]:
        """Get security settings (keyholder/admin only)"""
        return {
            "enable_ssl": self.config.get("security.enable_ssl", False),
            "require_auth": self.config.get("security.require_auth", False),
            "allowed_ips": self.config.get("security.allowed_ips", []),
            "session_timeout_minutes": self.config.get("security.session_timeout_minutes", 30),
            "max_login_attempts": self.config.get("security.max_login_attempts", 5),
            "password_min_length": self.config.get("security.password_min_length", 8),
            "enable_rate_limiting": self.config.get("security.enable_rate_limiting", True),
            "rate_limit_requests": self.config.get("security.rate_limit_requests", 100),
            "rate_limit_window": self.config.get("security.rate_limit_window", 3600)
        }
    
    def _get_keyholder_settings_section(self) -> Dict[str, Any]:
        """Get keyholder settings (keyholder/admin only)"""
        return {
            "default_keyholder_email": self.config.get("keyholder.default_keyholder_email", ""),
            "approval_timeout_hours": self.config.get("keyholder.approval_timeout_hours", 24),
            "emergency_timeout_minutes": self.config.get("keyholder.emergency_timeout_minutes", 30),
            "max_request_duration_days": self.config.get("keyholder.max_request_duration_days", 30),
            "require_email_verification": self.config.get("keyholder.require_email_verification", True),
            "enable_auto_approval": self.config.get("keyholder.enable_auto_approval", False),
            "auto_approval_duration_hours": self.config.get("keyholder.auto_approval_duration_hours", 2),
            "notification_frequency": self.config.get("keyholder.notification_frequency", "immediate")
        }
    
    def _get_cage_check_settings(self) -> Dict[str, Any]:
        """Get cage check settings (keyholder/admin only)"""
        return {
            "enabled": self.config.get("cage_check.enabled", True),
            "verification_code_length": self.config.get("cage_check.verification_code_length", 6),
            "verification_timeout_hours": self.config.get("cage_check.verification_timeout_hours", 24),
            "reminder_interval_hours": self.config.get("cage_check.reminder_interval_hours", 6),
            "max_reminders": self.config.get("cage_check.max_reminders", 3),
            "require_photo": self.config.get("cage_check.require_photo", True),
            "ocr_accuracy_threshold": self.config.get("cage_check.ocr_accuracy_threshold", 0.8),
            "auto_escalation": self.config.get("cage_check.auto_escalation", True),
            "escalation_delay_hours": self.config.get("cage_check.escalation_delay_hours", 48)
        }
    
    def _get_punishment_settings(self) -> Dict[str, Any]:
        """Get punishment settings (keyholder/admin only)"""
        return {
            "enabled": self.config.get("punishment.enabled", True),
            "qr_code_size": self.config.get("punishment.qr_code_size", 200),
            "pdf_template": self.config.get("punishment.pdf_template", "default"),
            "verification_required": self.config.get("punishment.verification_required", True),
            "ocr_accuracy_threshold": self.config.get("punishment.ocr_accuracy_threshold", 0.8),
            "max_upload_size_mb": self.config.get("punishment.max_upload_size_mb", 10),
            "allowed_image_formats": self.config.get("punishment.allowed_image_formats", ["jpg", "jpeg", "png", "gif", "bmp"]),
            "auto_cleanup_days": self.config.get("punishment.auto_cleanup_days", 30),
            "enable_statistics": self.config.get("punishment.enable_statistics", True)
        }
    
    def _get_time_verification_settings(self) -> Dict[str, Any]:
        """Get time verification settings (keyholder/admin only)"""
        return {
            "enabled": self.config.get("time_verification.enabled", True),
            "ntp_servers": self.config.get("time_verification.ntp_servers", ["pool.ntp.org", "time.nist.gov", "time.google.com"]),
            "sync_interval_minutes": self.config.get("time_verification.sync_interval_minutes", 60),
            "max_drift_seconds": self.config.get("time_verification.max_drift_seconds", 5),
            "auto_correct": self.config.get("time_verification.auto_correct", True),
            "alert_on_drift": self.config.get("time_verification.alert_on_drift", True),
            "drift_threshold_seconds": self.config.get("time_verification.drift_threshold_seconds", 10)
        }
    
    def _get_upload_settings(self) -> Dict[str, Any]:
        """Get upload settings (keyholder/admin only)"""
        return {
            "max_file_size_mb": self.config.get("upload.max_file_size_mb", 10),
            "allowed_formats": self.config.get("upload.allowed_formats", ["jpg", "jpeg", "png", "gif", "bmp"]),
            "storage_path": self.config.get("upload.storage_path", "uploads"),
            "auto_cleanup": self.config.get("upload.auto_cleanup", True),
            "cleanup_interval_days": self.config.get("upload.cleanup_interval_days", 7),
            "enable_compression": self.config.get("upload.enable_compression", True),
            "compression_quality": self.config.get("upload.compression_quality", 85)
        }
    
    def _get_calendar_settings(self) -> Dict[str, Any]:
        """Get calendar settings (keyholder/admin only)"""
        return {
            "enabled": self.config.get("calendar.enabled", True),
            "default_view": self.config.get("calendar.default_view", "month"),
            "enable_reminders": self.config.get("calendar.enable_reminders", True),
            "reminder_advance_hours": self.config.get("calendar.reminder_advance_hours", 24),
            "max_events_per_page": self.config.get("calendar.max_events_per_page", 50),
            "enable_recurring_events": self.config.get("calendar.enable_recurring_events", True)
        }
    
    def _get_logging_settings(self) -> Dict[str, Any]:
        """Get logging settings (keyholder/admin only)"""
        return {
            "level": self.config.get("logging.level", "INFO"),
            "file_enabled": self.config.get("logging.file_enabled", True),
            "file_path": self.config.get("logging.file_path", "logs"),
            "max_file_size_mb": self.config.get("logging.max_file_size_mb", 10),
            "backup_count": self.config.get("logging.backup_count", 5),
            "console_enabled": self.config.get("logging.console_enabled", True),
            "email_enabled": self.config.get("logging.email_enabled", False),
            "email_level": self.config.get("logging.email_level", "ERROR")
        }
    
    def _get_appearance_settings(self) -> Dict[str, Any]:
        """Get appearance settings"""
        return {
            "theme": self.config.get("appearance.theme", "default"),
            "language": self.config.get("appearance.language", "en"),
            "date_format": self.config.get("appearance.date_format", "YYYY-MM-DD"),
            "time_format": self.config.get("appearance.time_format", "HH:mm:ss"),
            "timezone_display": self.config.get("appearance.timezone_display", "local"),
            "enable_dark_mode": self.config.get("appearance.enable_dark_mode", False),
            "custom_css": self.config.get("appearance.custom_css", "")
        }
    
    def _get_notification_settings(self) -> Dict[str, Any]:
        """Get notification settings (keyholder/admin only)"""
        return {
            "email_enabled": self.config.get("notifications.email_enabled", True),
            "sms_enabled": self.config.get("notifications.sms_enabled", False),
            "webhook_enabled": self.config.get("notifications.webhook_enabled", False),
            "webhook_url": self.config.get("notifications.webhook_url", ""),
            "notification_types": self.config.get("notifications.notification_types", {
                "key_request": True,
                "cage_check": True,
                "punishment_complete": True,
                "time_drift": True,
                "system_error": True
            }),
            "quiet_hours": self.config.get("notifications.quiet_hours", {
                "enabled": False,
                "start": "22:00",
                "end": "08:00"
            })
        }
    
    def _get_automation_settings(self) -> Dict[str, Any]:
        """Get automation settings (keyholder/admin only)"""
        return {
            "enabled": self.config.get("automation.enabled", False),
            "auto_backup": self.config.get("automation.auto_backup", True),
            "backup_interval_days": self.config.get("automation.backup_interval_days", 7),
            "backup_retention_days": self.config.get("automation.backup_retention_days", 30),
            "auto_update": self.config.get("automation.auto_update", False),
            "update_check_interval_days": self.config.get("automation.update_check_interval_days", 7),
            "health_check_interval_minutes": self.config.get("automation.health_check_interval_minutes", 30)
        }
    
    def _get_development_settings(self) -> Dict[str, Any]:
        """Get development settings (keyholder/admin only)"""
        return {
            "debug": self.config.get("development.debug", False),
            "test_mode": self.config.get("development.test_mode", False),
            "mock_services": self.config.get("development.mock_services", False),
            "log_requests": self.config.get("development.log_requests", False),
            "enable_profiling": self.config.get("development.enable_profiling", False)
        }
    
    def update_settings(self, updates: Dict[str, Any], user_type: str = "admin") -> List[str]:
        """Update configuration settings with permission checking"""
        errors = []
        
        # Update each section
        for section, settings in updates.items():
            if isinstance(settings, dict):
                for key, value in settings.items():
                    config_key = f"{section}.{key}"
                    try:
                        self.config.set(config_key, value, user_type)
                    except PermissionError as e:
                        errors.append(str(e))
                    except Exception as e:
                        errors.append(f"Error updating {config_key}: {str(e)}")
        
        # Validate configuration
        validation_errors = self.config.validate()
        errors.extend(validation_errors)
        
        return errors
    
    def export_config(self, user_type: str = "admin") -> str:
        """Export configuration as formatted text with permission checking"""
        return self.config.export_config(user_type)
    
    def import_config(self, config_text: str, user_type: str = "admin") -> List[str]:
        """Import configuration from text format with permission checking"""
        return self.config.import_config(config_text, user_type)
    
    def get_config_templates(self, user_type: str = "admin") -> Dict[str, str]:
        """Get available configuration templates based on user type"""
        if user_type == "wearer":
            return {
                "basic_wearer": self._get_basic_wearer_template(),
                "email_setup": self._get_email_setup_template()
            }
        else:
            return {
                "basic": self._get_basic_template(),
                "secure": self._get_secure_template(),
                "email_focused": self._get_email_focused_template(),
                "development": self._get_development_template()
            }
    
    def _get_basic_wearer_template(self) -> str:
        """Get basic wearer configuration template"""
        return """# Basic Wearer Configuration Template
## DEVICE
device_id = KPI-XXXXXX
device_name = ChastiPi Device
location = Home

## NETWORK
host = 0.0.0.0
port = 5000
enable_remote_access = false

## EMAIL
enabled = false
smtp_server = smtp.gmail.com
smtp_port = 587
username = your-email@gmail.com
password = your-app-password

## APPEARANCE
theme = default
language = en
enable_dark_mode = false"""
    
    def _get_email_setup_template(self) -> str:
        """Get email setup template for wearer"""
        return """# Email Setup Template
## EMAIL
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
use_tls = true
username = your-email@gmail.com
password = your-app-password
from_address = your-email@gmail.com
reply_to = your-email@gmail.com"""
    
    def _get_basic_template(self) -> str:
        """Get basic configuration template"""
        return """# Basic Configuration Template
## DEVICE
device_id = KPI-XXXXXX
device_name = ChastiPi Device
location = Home
timezone = UTC

## NETWORK
host = 0.0.0.0
port = 5000
enable_remote_access = false

## EMAIL
enabled = false
smtp_server = smtp.gmail.com
smtp_port = 587
username = your-email@gmail.com
password = your-app-password

## SECURITY
require_auth = false
enable_rate_limiting = true

## KEYHOLDER
approval_timeout_hours = 24
require_email_verification = true

## CAGE_CHECK
enabled = true
verification_timeout_hours = 24

## PUNISHMENT
enabled = true
verification_required = true

## TIME_VERIFICATION
enabled = true
auto_correct = true"""
    
    def _get_secure_template(self) -> str:
        """Get secure configuration template"""
        return """# Secure Configuration Template
## DEVICE
device_id = KPI-SECURE
device_name = Secure ChastiPi
location = Secure Location
timezone = UTC

## NETWORK
host = 127.0.0.1
port = 5000
enable_remote_access = false
allowed_networks = [192.168.1.0/24]

## EMAIL
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
use_tls = true

## SECURITY
require_auth = true
enable_ssl = true
enable_rate_limiting = true
rate_limit_requests = 50
session_timeout_minutes = 15

## KEYHOLDER
require_email_verification = true
enable_auto_approval = false
approval_timeout_hours = 12

## CAGE_CHECK
enabled = true
verification_timeout_hours = 12
auto_escalation = true

## PUNISHMENT
enabled = true
verification_required = true
ocr_accuracy_threshold = 0.9

## TIME_VERIFICATION
enabled = true
auto_correct = true
alert_on_drift = true
drift_threshold_seconds = 5"""
    
    def _get_email_focused_template(self) -> str:
        """Get email-focused configuration template"""
        return """# Email-Focused Configuration Template
## DEVICE
device_id = KPI-EMAIL
device_name = Email ChastiPi
location = Home
timezone = UTC

## NETWORK
host = 0.0.0.0
port = 5000
enable_remote_access = true

## EMAIL
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
use_tls = true
notification_emails = [keyholder@example.com]

## SECURITY
require_auth = false
enable_rate_limiting = true

## KEYHOLDER
default_keyholder_email = keyholder@example.com
require_email_verification = true
enable_auto_approval = false
notification_frequency = immediate

## CAGE_CHECK
enabled = true
verification_timeout_hours = 24
reminder_interval_hours = 6
max_reminders = 5

## PUNISHMENT
enabled = true
verification_required = true

## NOTIFICATIONS
email_enabled = true
notification_types.key_request = true
notification_types.cage_check = true
notification_types.punishment_complete = true

## TIME_VERIFICATION
enabled = true
auto_correct = true
alert_on_drift = true"""
    
    def _get_development_template(self) -> str:
        """Get development configuration template"""
        return """# Development Configuration Template
## DEVICE
device_id = KPI-DEV
device_name = Development ChastiPi
location = Development
timezone = UTC

## NETWORK
host = 0.0.0.0
port = 5000
enable_remote_access = true

## EMAIL
enabled = false

## SECURITY
require_auth = false
enable_rate_limiting = false

## KEYHOLDER
require_email_verification = false
enable_auto_approval = true

## CAGE_CHECK
enabled = true
verification_timeout_hours = 1

## PUNISHMENT
enabled = true
verification_required = false

## LOGGING
level = DEBUG
console_enabled = true
log_requests = true

## DEVELOPMENT
debug = true
test_mode = true
mock_services = true
enable_profiling = true

## TIME_VERIFICATION
enabled = false"""
    
    def backup_config(self) -> str:
        """Create a backup of current configuration"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.config_dir / f"config_backup_{timestamp}.json"
        
        with open(backup_file, 'w') as f:
            json.dump(self.config.get_all("admin"), f, indent=4)
        
        return str(backup_file)
    
    def restore_config(self, backup_file: str) -> bool:
        """Restore configuration from backup"""
        try:
            with open(backup_file, 'r') as f:
                backup_config = json.load(f)
            
            self.config.update(backup_config, "admin")
            return True
        except Exception:
            return False
    
    def get_config_info(self, user_type: str = "admin") -> Dict[str, Any]:
        """Get configuration information and statistics"""
        all_config = self.config.get_all(user_type)
        encryption_status = self.config.get_encryption_status()
        
        return {
            "total_sections": len(all_config),
            "total_settings": sum(len(section) for section in all_config.values()),
            "last_modified": datetime.fromtimestamp(self.config.config_path.stat().st_mtime).isoformat(),
            "file_size": self.config.config_path.stat().st_size,
            "validation_errors": self.config.validate(),
            "sections": list(all_config.keys()),
            "user_type": user_type,
            "encryption_enabled": encryption_status["encryption_enabled"],
            "keyholder_registered": encryption_status["keyholder_registered"],
            "encrypted_sections": encryption_status["encrypted_sections"] if user_type in ["keyholder", "admin"] else []
        }
    
    def get_permission_info(self) -> Dict[str, Any]:
        """Get information about setting permissions"""
        permissions = self.config.get_setting_permissions()
        
        return {
            "wearer_permissions": len(permissions["wearer"]),
            "keyholder_permissions": "unlimited",
            "admin_permissions": "unlimited",
            "wearer_accessible_sections": ["device", "network", "email", "appearance"],
            "keyholder_restricted_sections": ["device.timezone"],
            "encrypted_sections": [
                "keyholder", "cage_check", "punishment", "time_verification",
                "security", "notifications", "automation"
            ]
        }
    
    def get_section(self, section_name: str, user_type: str = "admin") -> Dict[str, Any]:
        """Get a specific configuration section based on user permissions"""
        if user_type == "wearer":
            if section_name in ["security", "keyholder", "punishment", "time_verification"]:
                return {}
            elif section_name == "device":
                return self._get_device_settings_wearer()
            elif section_name == "network":
                return self._get_network_settings()
            elif section_name == "email":
                return self._get_email_settings()
            elif section_name == "appearance":
                return self._get_appearance_settings()
            else:
                return {}
        else:
            # Keyholder and admin have full access
            if section_name == "device":
                return self._get_device_settings()
            elif section_name == "network":
                return self._get_network_settings()
            elif section_name == "email":
                return self._get_email_settings()
            elif section_name == "security":
                return self._get_security_settings()
            elif section_name == "keyholder":
                return self._get_keyholder_settings_section()
            elif section_name == "cage_check":
                return self._get_cage_check_settings()
            elif section_name == "punishment":
                return self._get_punishment_settings()
            elif section_name == "time_verification":
                return self._get_time_verification_settings()
            elif section_name == "upload":
                return self._get_upload_settings()
            elif section_name == "calendar":
                return self._get_calendar_settings()
            elif section_name == "logging":
                return self._get_logging_settings()
            elif section_name == "appearance":
                return self._get_appearance_settings()
            elif section_name == "notifications":
                return self._get_notification_settings()
            elif section_name == "automation":
                return self._get_automation_settings()
            elif section_name == "development":
                return self._get_development_settings()
            else:
                return {} 