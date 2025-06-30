# Keyholder Configuration System

## Overview

The Keyholder Configuration System allows keyholders to customize and manage all aspects of the ChastiPi program through a comprehensive configuration interface. Keyholders can export their settings, share configurations, and import settings from other systems.

## Features

### Configuration Management
- **Custom Settings**: Modify all program behaviors and preferences
- **Export/Import**: Backup and restore configurations
- **Templates**: Use pre-configured settings templates
- **Version Control**: Track configuration changes over time

### Configuration Sections

#### 1. Cage Check Settings
```json
{
  "cage_check": {
    "enabled": true,
    "reminder_delay_hours": 1,
    "final_warning_hours": 6,
    "expiry_warning_hours": 2,
    "code_expiry_hours": 24,
    "max_retries": 3,
    "auto_escalate": true
  }
}
```

#### 2. Notification Preferences
```json
{
  "notifications": {
    "email_enabled": true,
    "sms_enabled": false,
    "push_enabled": false,
    "notification_frequency": "standard",
    "custom_messages": {
      "initial": "Your keyholder has requested a verification check.",
      "reminder": "Please complete your verification check.",
      "final_warning": "This is your final warning to complete verification.",
      "expiry": "Your verification request has expired."
    }
  }
}
```

#### 3. Punishment Configuration
```json
{
  "punishment": {
    "auto_generate": false,
    "default_duration_hours": 24,
    "max_duration_hours": 168,
    "require_photo_verification": true,
    "qr_code_required": true,
    "ocr_verification": true,
    "ocr_accuracy_threshold": 0.8
  }
}
```

#### 4. Keyholder Management
```json
{
  "keyholder": {
    "auto_approve_emergency": false,
    "emergency_timeout_hours": 2,
    "require_reason": true,
    "max_concurrent_requests": 3,
    "request_history_days": 30,
    "email_notifications": true,
    "approval_timeout_hours": 24
  }
}
```

#### 5. Security Settings
```json
{
  "security": {
    "require_2fa": false,
    "session_timeout_hours": 12,
    "max_failed_attempts": 5,
    "lockout_duration_minutes": 30,
    "ip_whitelist": [],
    "device_whitelist": []
  }
}
```

#### 6. Appearance Preferences
```json
{
  "appearance": {
    "theme": "default",
    "language": "en",
    "timezone": "UTC",
    "date_format": "YYYY-MM-DD",
    "time_format": "24h"
  }
}
```

#### 7. Automation Rules
```json
{
  "automation": {
    "auto_lock_after_release": true,
    "auto_lock_delay_minutes": 30,
    "scheduled_checks": [],
    "auto_punishment_on_failure": false,
    "punishment_duration_hours": 48
  }
}
```

#### 8. Reporting Configuration
```json
{
  "reporting": {
    "daily_reports": false,
    "weekly_reports": true,
    "monthly_reports": true,
    "report_recipients": [],
    "include_statistics": true,
    "include_charts": true
  }
}
```

## Usage

### Accessing Configuration

1. **Via Web Interface**:
   - Go to Keyholder Dashboard
   - Click "🔧 Configuration" in navigation
   - Or click "🔧 System Configuration" in Quick Actions

2. **Direct URL**:
   ```
   /keyholder/config?keyholder_email=your-email@example.com
   ```

### Managing Settings

#### View Current Configuration
- Dashboard shows current settings overview
- Statistics and usage information
- Quick access to all configuration sections

#### Edit Settings
1. Click "⚙️ Manage Settings"
2. Modify values in the form
3. Save changes
4. Settings are applied immediately

#### Export Configuration
1. Click "📤 Export Configuration"
2. Choose export options:
   - Include import instructions
   - Include metadata
   - Include templates
   - Encrypt file (recommended)
3. Download JSON configuration file

#### Import Configuration
1. Click "📥 Import Configuration"
2. Upload JSON configuration file
3. Choose import options:
   - Backup current configuration
   - Validate before importing
   - Merge with existing settings
   - Restart services after import
4. Confirm import

### Configuration Templates

#### Using Templates
1. Browse available templates
2. Click "Apply Template" on desired template
3. Confirm application
4. Settings are updated immediately

#### Creating Templates
```python
# Via API
POST /keyholder/config/templates
{
  "template_name": "Strict Mode",
  "description": "Strict configuration with enhanced security",
  "settings": {
    "security": {
      "require_2fa": true,
      "max_failed_attempts": 3
    },
    "cage_check": {
      "reminder_delay_hours": 0.5,
      "auto_escalate": true
    }
  }
}
```

## API Endpoints

### Configuration Management
```
GET    /keyholder/config/                    # Configuration dashboard
GET    /keyholder/config/settings            # Manage settings form
POST   /keyholder/config/settings            # Update settings
GET    /keyholder/config/export              # Export configuration
POST   /keyholder/config/export              # Download configuration
GET    /keyholder/config/import              # Import configuration form
POST   /keyholder/config/import              # Upload configuration
```

### API Access
```
GET    /keyholder/config/api/settings/{email}     # Get settings
PUT    /keyholder/config/api/settings/{email}     # Update settings
GET    /keyholder/config/api/statistics           # Get statistics
```

### Templates
```
GET    /keyholder/config/templates               # List templates
POST   /keyholder/config/templates/{id}/apply    # Apply template
```

## Configuration File Format

### Export Format
```json
{
  "export_info": {
    "exported_at": "2023-12-01T14:30:22",
    "keyholder_email": "keyholder@example.com",
    "version": "1.0"
  },
  "configuration": {
    "cage_check": { ... },
    "notifications": { ... },
    "punishment": { ... },
    "keyholder": { ... },
    "security": { ... },
    "appearance": { ... },
    "automation": { ... },
    "reporting": { ... }
  },
  "instructions": "Import instructions..."
}
```

### Import Validation
- Validates JSON structure
- Checks required sections
- Verifies data types
- Ensures compatibility

## Security Features

### Configuration Security
- **Encryption**: Optional file encryption
- **Validation**: Input validation and sanitization
- **Backup**: Automatic backup before import
- **Audit Trail**: Track configuration changes

### Access Control
- **Email Verification**: Only keyholder can modify their config
- **Session Management**: Secure session handling
- **IP Restrictions**: Optional IP whitelisting
- **Rate Limiting**: Prevent abuse

## Best Practices

### For Keyholders

1. **Regular Backups**
   - Export configuration monthly
   - Store backups securely
   - Test restore procedures

2. **Incremental Changes**
   - Make small changes and test
   - Document custom settings
   - Use templates for consistency

3. **Security**
   - Enable 2FA if available
   - Use strong passwords
   - Monitor access logs

4. **Testing**
   - Test configurations in safe environment
   - Verify all features work correctly
   - Check notification delivery

### For Administrators

1. **Template Management**
   - Create standard templates
   - Document template purposes
   - Maintain template library

2. **Monitoring**
   - Track configuration usage
   - Monitor for unusual changes
   - Review access patterns

3. **Support**
   - Provide configuration guidance
   - Troubleshoot import issues
   - Maintain documentation

## Troubleshooting

### Common Issues

1. **Import Fails**
   - Check file format (must be JSON)
   - Verify file structure
   - Check for syntax errors
   - Ensure compatibility

2. **Settings Not Applied**
   - Check for validation errors
   - Verify keyholder email
   - Check permissions
   - Restart services if needed

3. **Export Issues**
   - Check file permissions
   - Verify disk space
   - Check encryption settings
   - Validate configuration

### Debug Commands

```python
# Check configuration status
from chasti_pi.services.keyholder_config_service import KeyholderConfigService
service = KeyholderConfigService()
config = service.get_keyholder_config('keyholder@example.com')

# Export configuration
export_data = service.export_config('keyholder@example.com')

# Apply template
service.apply_template('keyholder@example.com', 'template_id')
```

## Integration

### With Other Systems
- **Email Service**: Uses existing email configuration
- **Cage Check System**: Integrates with notification settings
- **Punishment System**: Uses punishment configuration
- **Keyholder System**: Shares keyholder settings

### External Tools
- **Configuration Management**: Ansible, Puppet, Chef
- **Backup Systems**: Automated backup integration
- **Monitoring**: Configuration change alerts
- **Version Control**: Git integration for configs

## Future Enhancements

### Planned Features
1. **Configuration Versioning**: Track changes over time
2. **Rollback Capability**: Revert to previous configurations
3. **Configuration Comparison**: Compare different configs
4. **Bulk Operations**: Apply configs to multiple keyholders
5. **Configuration Analytics**: Usage statistics and insights

### Advanced Features
1. **Conditional Logic**: Dynamic configuration based on conditions
2. **Scheduled Changes**: Automatically apply configs at specific times
3. **Configuration Inheritance**: Hierarchical configuration system
4. **Multi-Environment Support**: Different configs for different environments
5. **Configuration Validation**: Advanced validation rules

## Support

### Documentation
- This guide provides comprehensive information
- API documentation available
- Template examples included
- Troubleshooting guide provided

### Getting Help
- Check troubleshooting section
- Review configuration examples
- Test in safe environment
- Contact support if needed

The Keyholder Configuration System provides complete control over the ChastiPi program, allowing keyholders to customize every aspect of the system to their preferences while maintaining security and reliability. 