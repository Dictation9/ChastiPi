# Setting Permissions System

## Overview

The ChastiPi system now implements a comprehensive permission-based configuration system that separates settings based on user roles and encrypts sensitive keyholder settings to prevent unauthorized access by the wearer.

## User Roles

### 1. Wearer
- **Access Level**: Limited
- **Can Modify**: Basic system settings only
- **Protected From**: Keyholder-specific settings

### 2. Keyholder
- **Access Level**: Full
- **Can Modify**: All settings including encrypted ones
- **Special Privileges**: Can manage protected settings

### 3. Admin
- **Access Level**: Full
- **Can Modify**: All settings
- **Special Privileges**: System administration

## Wearer-Accessible Settings

The wearer can modify the following settings:

### Device Settings
- `device.device_id` - Device identifier
- `device.device_name` - Device name
- `device.location` - Physical location
- **Note**: `device.timezone` is restricted to keyholder only

### Network Settings
- `network.host` - Host binding address
- `network.port` - Port number
- `network.external_url` - External access URL
- `network.webhook_url` - Webhook URL
- `network.enable_remote_access` - Remote access toggle
- `network.allowed_networks` - Allowed network ranges

### Email Settings
- `email.enabled` - Email functionality toggle
- `email.smtp_server` - SMTP server address
- `email.smtp_port` - SMTP port
- `email.username` - Email username
- `email.password` - Email password
- `email.use_tls` - TLS encryption toggle
- `email.from_address` - From email address
- `email.reply_to` - Reply-to email address
- `email.notification_emails` - Notification email list

### Appearance Settings
- `appearance.theme` - Interface theme
- `appearance.language` - Interface language
- `appearance.date_format` - Date format
- `appearance.time_format` - Time format
- `appearance.timezone_display` - Timezone display mode
- `appearance.enable_dark_mode` - Dark mode toggle
- `appearance.custom_css` - Custom CSS styling

## Keyholder-Protected Settings (Encrypted)

The following settings are encrypted and only accessible to keyholders:

### Security Settings
- `security.enable_ssl` - SSL encryption
- `security.require_auth` - Authentication requirement
- `security.allowed_ips` - Allowed IP addresses
- `security.session_timeout_minutes` - Session timeout
- `security.max_login_attempts` - Maximum login attempts
- `security.password_min_length` - Password minimum length
- `security.enable_rate_limiting` - Rate limiting
- `security.rate_limit_requests` - Rate limit requests
- `security.rate_limit_window` - Rate limit window

### Keyholder Settings
- `keyholder.default_keyholder_email` - Primary keyholder email
- `keyholder.approval_timeout_hours` - Approval timeout
- `keyholder.emergency_timeout_minutes` - Emergency timeout
- `keyholder.max_request_duration_days` - Maximum request duration
- `keyholder.require_email_verification` - Email verification requirement
- `keyholder.enable_auto_approval` - Auto approval toggle
- `keyholder.auto_approval_duration_hours` - Auto approval duration
- `keyholder.notification_frequency` - Notification frequency

### Cage Check Settings
- `cage_check.enabled` - Cage check functionality
- `cage_check.verification_code_length` - Verification code length
- `cage_check.verification_timeout_hours` - Verification timeout
- `cage_check.reminder_interval_hours` - Reminder interval
- `cage_check.max_reminders` - Maximum reminders
- `cage_check.require_photo` - Photo requirement
- `cage_check.ocr_accuracy_threshold` - OCR accuracy threshold
- `cage_check.auto_escalation` - Auto escalation
- `cage_check.escalation_delay_hours` - Escalation delay

### Punishment Settings
- `punishment.enabled` - Punishment functionality
- `punishment.qr_code_size` - QR code size
- `punishment.pdf_template` - PDF template
- `punishment.verification_required` - Verification requirement
- `punishment.ocr_accuracy_threshold` - OCR accuracy threshold
- `punishment.max_upload_size_mb` - Maximum upload size
- `punishment.allowed_image_formats` - Allowed image formats
- `punishment.auto_cleanup_days` - Auto cleanup days
- `punishment.enable_statistics` - Statistics toggle

### Time Verification Settings
- `time_verification.enabled` - Time verification
- `time_verification.ntp_servers` - NTP servers
- `time_verification.sync_interval_minutes` - Sync interval
- `time_verification.max_drift_seconds` - Maximum drift
- `time_verification.auto_correct` - Auto correction
- `time_verification.alert_on_drift` - Drift alerts
- `time_verification.drift_threshold_seconds` - Drift threshold

### Additional Protected Settings
- `upload.*` - Upload configuration
- `calendar.*` - Calendar settings
- `logging.*` - Logging configuration
- `notifications.*` - Notification settings
- `automation.*` - Automation rules
- `development.*` - Development settings

## Encryption System

### How It Works
1. **Key Generation**: A unique encryption key is generated on first run
2. **Key Storage**: The key is stored securely in `data/keys/config.key`
3. **Section Encryption**: Protected settings are encrypted as JSON strings
4. **Access Control**: Only keyholders and admins can decrypt settings

### Encryption Process
```python
# When saving configuration
for section in protected_sections:
    json_data = json.dumps(section_data)
    encrypted_data = cipher.encrypt(json_data.encode())
    final_config[section] = {
        "_encrypted": True,
        "_data": encrypted_data.decode()
    }
```

### Decryption Process
```python
# When accessing protected settings
if section_data.get("_encrypted"):
    if user_type in ["keyholder", "admin"]:
        decrypted_data = cipher.decrypt(encrypted_data.encode())
        return json.loads(decrypted_data.decode())
    else:
        return {}  # Wearer cannot access
```

## Configuration Files

### Main Configuration
- **File**: `config.json`
- **Format**: JSON with encrypted sections
- **Access**: All user types (with permission restrictions)

### Encryption Key
- **File**: `data/keys/config.key`
- **Format**: Binary Fernet key
- **Access**: System only

### Backup Files
- **Location**: `data/config/`
- **Format**: JSON with decrypted data
- **Access**: Keyholder and admin only

## API Endpoints

### Wearer Endpoints
- `GET /settings` - View wearer-accessible settings
- `POST /settings` - Update wearer-accessible settings
- `GET /api/config/export` - Export wearer settings
- `GET /api/config/info` - Get configuration info

### Keyholder Endpoints
- `GET /keyholder/config` - View all settings
- `POST /keyholder/config` - Update any settings
- `GET /keyholder/config/export` - Export all settings
- `POST /keyholder/config/import` - Import configuration
- `POST /keyholder/config/backup` - Create backup
- `POST /keyholder/config/restore` - Restore from backup

## Security Features

### Permission Validation
- All setting access is validated against user type
- Wearer attempts to access protected settings are blocked
- Permission errors are logged for security monitoring

### Encryption Security
- Uses industry-standard Fernet encryption
- Keys are stored separately from configuration
- Encrypted data cannot be read without the key

### Access Logging
- All configuration changes are logged
- Permission violations are recorded
- Audit trail for security monitoring

## Usage Examples

### Wearer Configuration
```python
# Wearer can only access basic settings
config.set("email.enabled", True, "wearer")  # ✅ Allowed
config.set("security.require_auth", True, "wearer")  # ❌ Permission denied
```

### Keyholder Configuration
```python
# Keyholder can access all settings
config.set("email.enabled", True, "keyholder")  # ✅ Allowed
config.set("security.require_auth", True, "keyholder")  # ✅ Allowed
config.set("keyholder.default_keyholder_email", "kh@example.com", "keyholder")  # ✅ Allowed
```

### Configuration Service
```python
# Get settings based on user type
wearer_settings = config_service.get_all_settings("wearer")
keyholder_settings = config_service.get_all_settings("keyholder")

# Update with permission checking
errors = config_service.update_settings(updates, "wearer")
```

## Migration from Old System

### Automatic Migration
- Existing configurations are automatically migrated
- Encryption keys are generated on first run
- Protected settings are encrypted during save

### Manual Migration
```python
# If manual migration is needed
from chasti_pi.core.config import config

# Load old configuration
old_config = load_old_config()

# Set with appropriate user type
for key, value in old_config.items():
    config.set(key, value, "keyholder")  # Use keyholder for full access
```

## Best Practices

### For Wearers
1. Only modify settings you understand
2. Contact keyholder for protected settings
3. Use email configuration for remote management
4. Keep device information updated

### For Keyholders
1. Regularly review security settings
2. Use strong encryption for sensitive data
3. Monitor access logs for unauthorized attempts
4. Create regular configuration backups
5. Test email configuration regularly

### For Administrators
1. Monitor permission violations
2. Review encryption key security
3. Maintain backup procedures
4. Update system regularly

## Troubleshooting

### Common Issues

#### Permission Denied Errors
```
PermissionError: User type 'wearer' cannot modify setting 'security.require_auth'
```
**Solution**: Contact keyholder to modify protected settings

#### Encryption Key Issues
```
Error: Encryption key not found
```
**Solution**: Check `data/keys/config.key` exists and has proper permissions

#### Configuration Import Errors
```
Error: Permission denied for setting: keyholder.default_keyholder_email
```
**Solution**: Import with keyholder user type: `config_service.import_config(text, "keyholder")`

### Recovery Procedures

#### Lost Encryption Key
1. Stop the application
2. Delete `data/keys/config.key`
3. Restart application (new key will be generated)
4. Reconfigure protected settings

#### Corrupted Configuration
1. Restore from backup: `config_service.restore_config(backup_file)`
2. If no backup, reset to defaults and reconfigure

#### Permission Issues
1. Check user type in configuration
2. Verify keyholder email is registered
3. Review access logs for violations

## Future Enhancements

### Planned Features
- Role-based access control (RBAC)
- Multi-keyholder support
- Configuration versioning
- Automated backup scheduling
- Configuration validation rules
- Audit trail improvements

### Security Improvements
- Hardware security module (HSM) integration
- Multi-factor authentication for keyholder access
- Configuration signing and verification
- Tamper detection and alerts 