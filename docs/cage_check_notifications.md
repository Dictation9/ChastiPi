# Cage Check Notification System

## Overview

The cage check notification system automatically sends email reminders to wearers when they haven't responded to cage check requests within specified time intervals. This ensures wearers are properly notified and encourages timely responses.

## Features

### Automatic Email Notifications

1. **Initial Notification** - Sent immediately when a cage check request is created
2. **1-Hour Reminder** - Sent if no response after 1 hour
3. **6-Hour Warning** - Final warning sent after 6 hours
4. **Expiry Notification** - Sent when request expires (24 hours)

### Notification Types

- **Initial**: Contains verification code and instructions
- **Reminder**: Gentle reminder with time remaining
- **Final Warning**: Urgent warning with consequences
- **Expiry**: Notification of failure to both wearer and keyholder

## Configuration

### Notification Settings

```python
# In cage_check_service.py
self.reminder_delay_hours = 1      # Send reminder after 1 hour
self.final_warning_hours = 6       # Send final warning after 6 hours
self.expiry_warning_hours = 2      # Send expiry warning 2 hours before
self.code_expiry_hours = 24        # Total time before expiry
```

### Email Configuration

The system uses the existing email service configuration from `config.json`:

```json
{
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "use_tls": true
  }
}
```

## Usage

### Creating a Cage Check Request

When creating a cage check request, include the wearer's email address:

```python
# Example API call
POST /cage-check/request
{
  "keyholder_email": "keyholder@example.com",
  "wearer_email": "wearer@example.com",  # Optional but recommended
  "device_name": "Chastity Cage",
  "check_type": "cage",
  "reason": "Random verification check"
}
```

### Email Notifications Sent

#### Initial Notification
- **Subject**: 🔒 Cage Check Request: [Device Name]
- **Content**: Verification code, instructions, expiry time
- **Sent**: Immediately upon request creation

#### Reminder Notification
- **Subject**: ⏰ Reminder: Cage Check Pending - [Device Name]
- **Content**: Reminder with time remaining
- **Sent**: After 1 hour if no response

#### Final Warning
- **Subject**: 🚨 Final Warning: Cage Check Expiring Soon - [Device Name]
- **Content**: Urgent warning with consequences
- **Sent**: After 6 hours if no response

#### Expiry Notification
- **Subject**: ❌ Cage Check Expired - [Device Name]
- **Content**: Notification of failure
- **Sent**: When request expires (24 hours)

## Dashboard Integration

### Main Dashboard

The main dashboard (`/`) displays pending cage check notifications:

- Shows all pending requests for the wearer
- Color-coded by priority (normal, warning, urgent, expired)
- Auto-refreshes every 30 seconds
- Direct links to upload verification photos

### Cage Check Dashboard

The cage check dashboard (`/cage-check/dashboard`) shows:

- All requests (pending, completed, failed, expired)
- Statistics and status overview
- Request management tools

## API Endpoints

### Get Notifications
```
GET /cage-check/api/notifications?wearer_email=user@example.com
```

Response:
```json
{
  "notifications": [
    {
      "request_id": "CHECK_20231201_143022_1234",
      "device_name": "Chastity Cage",
      "check_type": "cage",
      "verification_code": "ABC123",
      "created_at": "2023-12-01T14:30:22",
      "expires_at": "2023-12-02T14:30:22",
      "priority": "warning",
      "message": "Expires in 5h 30m",
      "time_remaining": "5h 30m"
    }
  ]
}
```

### Check Notifications (Background Task)
```
POST /cage-check/api/check-notifications
```

Triggers manual notification check and sending.

## Background Scheduler

### Automatic Operation

The notification scheduler runs automatically in the background:

- **Check Interval**: Every 5 minutes
- **Thread**: Daemon thread (stops when app stops)
- **Logging**: All activities logged to `logs/app.log`

### Manual Control

```python
from chasti_pi.core.scheduler import run_notification_check

# Run single check
success = run_notification_check()
```

## Notification History

### Audit Trail

All notifications are logged with:

- Request ID
- Notification type (initial, reminder, final_warning, expired)
- Recipient email
- Timestamp
- Status

### Log File

Notifications are stored in `data/cage_check_notifications.json`:

```json
{
  "CHECK_20231201_143022_1234_initial_20231201_143022": {
    "request_id": "CHECK_20231201_143022_1234",
    "notification_type": "initial",
    "recipient_email": "wearer@example.com",
    "sent_at": "2023-12-01T14:30:22",
    "status": "sent"
  }
}
```

## Security Features

### Email Verification

- Only sends notifications to registered wearer email
- Validates email format before sending
- Logs all notification attempts

### Request Validation

- Verifies request exists and is pending
- Checks notification status to prevent duplicates
- Validates expiry times

## Error Handling

### Email Failures

- Logs email sending errors
- Continues processing other notifications
- Doesn't block the notification system

### System Errors

- Catches and logs all exceptions
- Continues running scheduler
- Graceful degradation

## Monitoring

### Log Files

- `logs/app.log` - Application logs
- `logs/chasti_pi.log` - System logs
- `data/cage_check_notifications.json` - Notification history

### Dashboard Monitoring

- Real-time notification status
- Request statistics
- System health indicators

## Best Practices

### For Keyholders

1. **Always include wearer email** when creating requests
2. **Monitor dashboard** for pending requests
3. **Set appropriate expiry times** based on situation
4. **Follow up manually** if needed

### For Wearers

1. **Check email regularly** for notifications
2. **Respond promptly** to avoid consequences
3. **Use dashboard** to see pending requests
4. **Contact keyholder** if having issues

### System Administration

1. **Monitor logs** for email delivery issues
2. **Configure email properly** in config.json
3. **Test notifications** periodically
4. **Backup notification history** regularly

## Troubleshooting

### Common Issues

1. **Emails not sending**
   - Check email configuration in config.json
   - Verify SMTP settings
   - Check firewall/network settings

2. **Notifications not appearing**
   - Check notification scheduler is running
   - Verify wearer email is provided
   - Check logs for errors

3. **Duplicate notifications**
   - Check notification status tracking
   - Verify request status
   - Review notification history

### Debug Commands

```python
# Check notification status
from chasti_pi.services.cage_check_service import CageCheckService
service = CageCheckService()
notifications = service.get_pending_notifications()

# Run manual check
from chasti_pi.core.scheduler import run_notification_check
run_notification_check()
```

## Future Enhancements

### Planned Features

1. **SMS notifications** for urgent requests
2. **Push notifications** via mobile app
3. **Custom notification schedules** per keyholder
4. **Notification preferences** for wearers
5. **Escalation procedures** for repeated failures

### Integration Opportunities

1. **Calendar integration** for scheduled checks
2. **Punishment system integration** for automatic consequences
3. **Keyholder system integration** for unified notifications
4. **Mobile app notifications** for real-time alerts 