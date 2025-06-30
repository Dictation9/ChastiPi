# Email-Based Configuration System

## Overview

The Email-Based Configuration System allows keyholders to manage their ChastiPi settings entirely through email. Keyholders can request their current configuration, edit it in a simple text file, and email it back to automatically apply the changes.

## Features

### Email Commands
- **settings** - Request current configuration file
- **status** - Get system status report
- **help** - Get command list and instructions

### Configuration File Format
- Simple key=value format
- Easy to edit in any text editor
- Supports all major configuration sections
- Automatic validation and import

### File Processing
- Supports both .txt and .json files
- Automatic file type detection
- Base64 decoding for attachments
- Error handling and validation

## How It Works

### 1. Request Configuration
**Keyholder emails:** `settings`

**System responds with:**
- Email containing `config.txt` attachment
- Clear instructions for editing
- List of all available settings

### 2. Edit Configuration
**Keyholder edits config.txt:**
```txt
# Cage Check Settings
cage_check_enabled=true
reminder_delay=1
final_warning=6
code_expiry=24

# Notification Settings
email_enabled=true
sms_enabled=false
notification_frequency=standard
```

### 3. Return Configuration
**Keyholder replies with:**
- Updated `config.txt` file attached
- Any additional notes in email body

### 4. Automatic Import
**System processes:**
- Validates file format
- Converts to full configuration structure
- Applies settings immediately
- Sends confirmation email

## Configuration File Format

### File Structure
```txt
# ChastiPi Configuration File
# Generated: 2023-12-01 14:30:22
# Keyholder: keyholder@example.com
#
# Instructions:
# 1. Edit the values after the = sign
# 2. Keep the keys unchanged
# 3. Save and reply to this email with this file attached
# 4. Your settings will be applied automatically

# Cage Check Settings
cage_check_enabled=true
reminder_delay=1
final_warning=6
code_expiry=24

# Notification Settings
email_enabled=true
sms_enabled=false
notification_frequency=standard

# Punishment Settings
auto_punishment=false
punishment_duration=24
require_photo=true

# Keyholder Settings
auto_approve_emergency=false
require_reason=true
max_requests=3

# Security Settings
require_2fa=false
session_timeout=12

# Appearance Settings
theme=default
language=en
timezone=UTC

# Automation Settings
auto_lock=true

# Reporting Settings
daily_reports=false
weekly_reports=true
```

### Supported Values

#### Boolean Values
- `true`, `yes`, `on` → True
- `false`, `no`, `off` → False

#### Numeric Values
- `1`, `2`, `3` → Integer
- `1.5`, `2.0` → Float

#### String Values
- `standard`, `aggressive`, `relaxed` → String
- `default`, `dark`, `light` → String

## Email Commands

### Settings Command
**Usage:** Reply with "settings" to any ChastiPi email

**Response:**
- Email with `config.txt` attachment
- Current configuration values
- Editing instructions
- File format explanation

**Example:**
```
From: keyholder@example.com
To: chastipi@your-domain.com
Subject: Re: Key Release Request

settings
```

### Status Command
**Usage:** Reply with "status" to any ChastiPi email

**Response:**
- System statistics
- Device count
- Pending requests
- Recent activity
- Quick command reference

**Example:**
```
From: keyholder@example.com
To: chastipi@your-domain.com
Subject: Re: Key Release Request

status
```

### Help Command
**Usage:** Reply with "help" to any ChastiPi email

**Response:**
- Complete command list
- Usage examples
- Time unit support
- Configuration file instructions

**Example:**
```
From: keyholder@example.com
To: chastipi@your-domain.com
Subject: Re: Key Release Request

help
```

## Configuration Sections

### Cage Check Settings
```txt
cage_check_enabled=true          # Enable/disable cage checks
reminder_delay=1                 # Hours before first reminder
final_warning=6                  # Hours before final warning
code_expiry=24                   # Hours before code expires
```

### Notification Settings
```txt
email_enabled=true               # Enable email notifications
sms_enabled=false                # Enable SMS notifications
notification_frequency=standard  # standard/aggressive/relaxed
```

### Punishment Settings
```txt
auto_punishment=false            # Auto-generate punishments
punishment_duration=24           # Default duration in hours
require_photo=true               # Require photo verification
```

### Keyholder Settings
```txt
auto_approve_emergency=false     # Auto-approve emergency requests
require_reason=true              # Require reason for requests
max_requests=3                   # Max concurrent requests
```

### Security Settings
```txt
require_2fa=false                # Require two-factor authentication
session_timeout=12               # Session timeout in hours
```

### Appearance Settings
```txt
theme=default                    # default/dark/light/custom
language=en                      # Language code
timezone=UTC                     # Timezone
```

### Automation Settings
```txt
auto_lock=true                   # Auto-lock after release
```

### Reporting Settings
```txt
daily_reports=false              # Enable daily reports
weekly_reports=true              # Enable weekly reports
```

## Webhook Integration

### Email Webhook Endpoint
```
POST /webhook/email
```

### Webhook Data Format
```json
{
  "from": {
    "email": "keyholder@example.com",
    "name": "Keyholder Name"
  },
  "subject": "Re: Configuration Request",
  "text": "Here is my updated configuration",
  "html": "<p>Here is my updated configuration</p>",
  "attachments": [
    {
      "filename": "config.txt",
      "content_type": "text/plain",
      "content": "# ChastiPi Configuration File\ncage_check_enabled=true\n..."
    }
  ]
}
```

### Test Endpoints
```
GET  /webhook/status              # Get webhook status
POST /webhook/email/test          # Test email processing
POST /webhook/email/settings      # Test settings command
POST /webhook/email/config-import # Test config import
```

## Security Features

### Email Verification
- Only processes emails from registered keyholders
- Validates sender email against configuration
- Prevents unauthorized configuration changes

### File Validation
- Validates file format and structure
- Checks for required sections
- Ensures data type compatibility
- Prevents malformed configurations

### Audit Trail
- Logs all configuration imports
- Tracks changes by keyholder
- Records import timestamps
- Maintains change history

## Error Handling

### Common Errors
1. **Invalid File Format**
   - File must be .txt or .json
   - Proper key=value format required
   - Comments must start with #

2. **Missing Required Fields**
   - All sections must be present
   - Required keys cannot be empty
   - Default values used for missing fields

3. **Invalid Values**
   - Boolean values must be true/false
   - Numbers must be valid integers/floats
   - Strings must match allowed values

### Error Responses
```json
{
  "success": false,
  "error": "Invalid configuration format",
  "type": "config_import_error"
}
```

## Best Practices

### For Keyholders

1. **Backup Before Changes**
   - Save original config.txt before editing
   - Test changes in safe environment
   - Keep backup of working configurations

2. **Edit Carefully**
   - Only change values after = sign
   - Keep keys unchanged
   - Use valid value formats
   - Test one change at a time

3. **Verify Changes**
   - Check confirmation email
   - Review settings in web dashboard
   - Test affected features
   - Contact support if issues

### For Administrators

1. **Monitor Imports**
   - Check webhook logs regularly
   - Monitor for failed imports
   - Review configuration changes
   - Backup configurations regularly

2. **Test Webhook**
   - Use test endpoints
   - Verify email processing
   - Check attachment handling
   - Validate error responses

## Troubleshooting

### Common Issues

1. **Configuration Not Applied**
   - Check webhook logs
   - Verify file format
   - Ensure keyholder email matches
   - Check for validation errors

2. **File Not Processed**
   - Verify attachment format
   - Check file extension
   - Ensure proper encoding
   - Validate webhook endpoint

3. **Settings Not Working**
   - Restart affected services
   - Check configuration cache
   - Verify setting names
   - Review error logs

### Debug Commands

```python
# Test email processing
from chasti_pi.services.email_reply_service import EmailReplyService
service = EmailReplyService()

# Test settings request
result = service._handle_settings_request('keyholder@example.com')

# Test config import
success = service._process_text_config('keyholder@example.com', config_content)
```

## Integration

### With Existing Systems
- **Email Service**: Uses existing SMTP configuration
- **Configuration Service**: Integrates with keyholder config system
- **Web Interface**: Settings reflected in dashboard
- **Logging**: Integrated with application logs

### External Tools
- **Email Clients**: Works with any email client
- **Text Editors**: Edit with any text editor
- **File Managers**: Standard file operations
- **Backup Systems**: Standard file backup

## Future Enhancements

### Planned Features
1. **Configuration Templates**: Pre-built configurations
2. **Validation Rules**: Custom validation for settings
3. **Rollback Capability**: Revert to previous configuration
4. **Scheduled Imports**: Automatic configuration updates
5. **Configuration Comparison**: Compare different configs

### Advanced Features
1. **Conditional Logic**: Dynamic configuration based on conditions
2. **Configuration Inheritance**: Hierarchical configuration system
3. **Multi-Environment Support**: Different configs for different environments
4. **Configuration Analytics**: Usage statistics and insights
5. **API Integration**: Direct API configuration updates

## Support

### Documentation
- This guide provides comprehensive information
- Web interface includes help sections
- Email help command available
- Template examples provided

### Getting Help
- Use "help" command for quick reference
- Check webhook status endpoint
- Review error logs for issues
- Contact support if needed

The Email-Based Configuration System provides a simple, secure, and efficient way for keyholders to manage their ChastiPi settings through email, making configuration management accessible from any device with email capability. 