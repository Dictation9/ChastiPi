# ChastiPi API Reference

This document provides comprehensive API documentation for all ChastiPi endpoints and functionality.

## 🔐 Keyholder Management API

### Register Device
Register a new device with key codes and keyholder information.

**Endpoint:** `POST /keyholder/register`

**Request Body:**
```json
{
  "device_id": "cage_001",
  "device_name": "My Chastity Cage",
  "keyholder_email": "keyholder@example.com",
  "key_codes": {
    "lock1": "1234",
    "lock2": "5678"
  },
  "wearer_email": "wearer@example.com",
  "location": "Home",
  "notes": "Primary device"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Device registered successfully",
  "data": {
    "device_id": "cage_001",
    "registration_id": "REG_20231201_143022_1234",
    "created_at": "2023-12-01T14:30:22Z"
  }
}
```

### Request Key Release
Request temporary access to a registered device.

**Endpoint:** `POST /keyholder/request`

**Request Body:**
```json
{
  "device_id": "cage_001",
  "reason": "Medical appointment",
  "duration_hours": 2,
  "emergency": false,
  "notes": "Doctor appointment at 3 PM"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Request submitted successfully",
  "data": {
    "request_id": "REQ_20231201_143022_5678",
    "status": "pending",
    "expires_at": "2023-12-01T16:30:22Z",
    "estimated_decision_time": "2023-12-01T15:30:22Z"
  }
}
```

### Get Request Status
Check the status of a key release request.

**Endpoint:** `GET /keyholder/request/{request_id}`

**Response:**
```json
{
  "success": true,
  "data": {
    "request_id": "REQ_20231201_143022_5678",
    "status": "approved",
    "approved_at": "2023-12-01T14:35:22Z",
    "approved_by": "keyholder@example.com",
    "expires_at": "2023-12-01T16:30:22Z",
    "key_codes": {
      "lock1": "1234",
      "lock2": "5678"
    }
  }
}
```

### List Pending Requests
Get all pending requests for a keyholder.

**Endpoint:** `GET /keyholder/requests?keyholder_email={email}`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "request_id": "REQ_20231201_143022_5678",
      "device_id": "cage_001",
      "device_name": "My Chastity Cage",
      "reason": "Medical appointment",
      "duration_hours": 2,
      "status": "pending",
      "created_at": "2023-12-01T14:30:22Z",
      "expires_at": "2023-12-01T16:30:22Z"
    }
  ]
}
```

### Approve Request
Approve a pending key release request.

**Endpoint:** `POST /keyholder/approve/{request_id}`

**Request Body:**
```json
{
  "keyholder_email": "keyholder@example.com",
  "notes": "Approved for medical appointment",
  "modify_duration": null
}
```

**Response:**
```json
{
  "success": true,
  "message": "Request approved successfully",
  "data": {
    "request_id": "REQ_20231201_143022_5678",
    "status": "approved",
    "approved_at": "2023-12-01T14:35:22Z",
    "key_codes": {
      "lock1": "1234",
      "lock2": "5678"
    }
  }
}
```

### Deny Request
Deny a pending key release request.

**Endpoint:** `POST /keyholder/deny/{request_id}`

**Request Body:**
```json
{
  "keyholder_email": "keyholder@example.com",
  "reason": "Request denied - not urgent enough",
  "notes": "Please provide more details about the emergency"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Request denied successfully",
  "data": {
    "request_id": "REQ_20231201_143022_5678",
    "status": "denied",
    "denied_at": "2023-12-01T14:35:22Z",
    "denial_reason": "Request denied - not urgent enough"
  }
}
```

### Modify Request Duration
Extend or reduce the duration of an approved request.

**Endpoint:** `POST /keyholder/modify/{request_id}`

**Request Body:**
```json
{
  "keyholder_email": "keyholder@example.com",
  "action": "extend",
  "duration": "2 hours",
  "notes": "Extended due to appointment running late"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Request duration modified successfully",
  "data": {
    "request_id": "REQ_20231201_143022_5678",
    "new_expires_at": "2023-12-01T18:30:22Z",
    "modification_reason": "Extended due to appointment running late"
  }
}
```

## 🔒 Cage Check API

### Create Cage Check Request
Create a new cage/lock verification request.

**Endpoint:** `POST /cage-check/request`

**Request Body:**
```json
{
  "keyholder_email": "keyholder@example.com",
  "wearer_email": "wearer@example.com",
  "device_name": "Chastity Cage",
  "check_type": "cage",
  "reason": "Random verification check",
  "urgency": "normal",
  "expires_hours": 24
}
```

**Response:**
```json
{
  "success": true,
  "message": "Cage check request created successfully",
  "data": {
    "request_id": "CHECK_20231201_143022_1234",
    "verification_code": "ABC123",
    "expires_at": "2023-12-02T14:30:22Z",
    "status": "pending"
  }
}
```

### Upload Verification Photo/Video
Upload a photo or video for verification.

**Endpoint:** `POST /cage-check/upload`

**Request Body (multipart/form-data):**
```
request_id: CHECK_20231201_143022_1234
photo: [file upload]
```

**Response:**
```json
{
  "success": true,
  "message": "Verification uploaded successfully",
  "data": {
    "request_id": "CHECK_20231201_143022_1234",
    "status": "completed",
    "verification_result": {
      "found": true,
      "expected_code": "ABC123",
      "found_codes": ["ABC123"],
      "confidence": 95.5
    },
    "ocr_result": {
      "success": true,
      "text": "ABC123",
      "confidence": 95.5,
      "words": ["ABC", "123"]
    },
    "video_processed": false,
    "processing_time": 2.3
  }
}
```

### Get Check Status
Check the status of a verification request.

**Endpoint:** `GET /cage-check/status/{request_id}`

**Response:**
```json
{
  "success": true,
  "data": {
    "request_id": "CHECK_20231201_143022_1234",
    "status": "completed",
    "verification_code": "ABC123",
    "created_at": "2023-12-01T14:30:22Z",
    "completed_at": "2023-12-01T14:32:22Z",
    "verification_result": {
      "found": true,
      "expected_code": "ABC123",
      "found_codes": ["ABC123"]
    }
  }
}
```

### List All Checks
Get all cage check requests for a keyholder.

**Endpoint:** `GET /cage-check/list?keyholder_email={email}`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "request_id": "CHECK_20231201_143022_1234",
      "device_name": "Chastity Cage",
      "check_type": "cage",
      "status": "completed",
      "created_at": "2023-12-01T14:30:22Z",
      "completed_at": "2023-12-01T14:32:22Z",
      "verification_result": {
        "found": true,
        "expected_code": "ABC123"
      }
    }
  ]
}
```

## 📋 Punishment Management API

### Generate Punishment
Generate a new punishment with verification requirements.

**Endpoint:** `POST /punishment/generate`

**Request Body:**
```json
{
  "task_description": "Write lines 100 times",
  "verification_required": true,
  "time_limit_hours": 24,
  "qr_code_required": true,
  "photo_verification": true,
  "notes": "Complete task and upload photo"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Punishment generated successfully",
  "data": {
    "punishment_id": "PUN_20231201_143022_5678",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "verification_code": "XYZ789",
    "expires_at": "2023-12-02T14:30:22Z",
    "pdf_url": "/punishment/pdf/PUN_20231201_143022_5678"
  }
}
```

### Upload Punishment Completion
Upload verification for punishment completion.

**Endpoint:** `POST /punishment/upload`

**Request Body (multipart/form-data):**
```
punishment_id: PUN_20231201_143022_5678
photo: [file upload]
completion_notes: Task completed as requested
```

**Response:**
```json
{
  "success": true,
  "message": "Punishment completion uploaded successfully",
  "data": {
    "punishment_id": "PUN_20231201_143022_5678",
    "status": "completed",
    "verification_result": {
      "found": true,
      "expected_code": "XYZ789",
      "found_codes": ["XYZ789"],
      "confidence": 92.3
    },
    "completion_time": "2023-12-01T16:45:22Z"
  }
}
```

### Get Punishment Statistics
Get punishment statistics and analytics.

**Endpoint:** `GET /punishment/stats?period=month`

**Response:**
```json
{
  "success": true,
  "data": {
    "total_punishments": 15,
    "completed_punishments": 12,
    "pending_punishments": 3,
    "average_completion_time": "4.5 hours",
    "success_rate": 80.0,
    "monthly_trends": {
      "generated": [5, 8, 12, 15],
      "completed": [4, 7, 10, 12]
    }
  }
}
```

## 📧 Email Integration API

### Test Email Webhook
Test email webhook functionality.

**Endpoint:** `POST /webhook/email/test`

**Request Body:**
```json
{
  "from": {"email": "keyholder@example.com"},
  "subject": "Settings Request",
  "text": "settings",
  "html": "<p>settings</p>"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Email webhook test successful",
  "data": {
    "command_parsed": "settings",
    "response_sent": true,
    "processing_time": 0.5
  }
}
```

### Process Email Configuration
Process configuration import via email.

**Endpoint:** `POST /webhook/email/config-import`

**Request Body:**
```json
{
  "from": {"email": "keyholder@example.com"},
  "attachments": [
    {
      "filename": "config.txt",
      "content": "# Configuration file content...",
      "content_type": "text/plain"
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration imported successfully",
  "data": {
    "settings_updated": 15,
    "validation_errors": [],
    "backup_created": true
  }
}
```

## ⚙️ Configuration Management API

### Export Configuration
Export current system configuration.

**Endpoint:** `GET /keyholder/config/export`

**Response:**
```json
{
  "success": true,
  "data": {
    "config_data": "# Configuration file content...",
    "exported_at": "2023-12-01T14:30:22Z",
    "version": "1.0.0"
  }
}
```

### Import Configuration
Import configuration from file.

**Endpoint:** `POST /keyholder/config/import`

**Request Body:**
```json
{
  "config_data": "# Configuration file content...",
  "backup_existing": true,
  "validate_only": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration imported successfully",
  "data": {
    "settings_updated": 15,
    "validation_errors": [],
    "backup_created": true,
    "imported_at": "2023-12-01T14:30:22Z"
  }
}
```

### Get Configuration Template
Get a configuration template for common scenarios.

**Endpoint:** `GET /keyholder/config/template?type=basic`

**Response:**
```json
{
  "success": true,
  "data": {
    "template_name": "Basic Configuration",
    "template_type": "basic",
    "config_data": "# Basic configuration template...",
    "description": "Basic configuration for new installations"
  }
}
```

## 🔍 Time Verification API

### Check System Time
Check current system time and NTP sync status.

**Endpoint:** `GET /time-verification/status`

**Response:**
```json
{
  "success": true,
  "data": {
    "current_time": "2023-12-01T14:30:22Z",
    "ntp_sync": true,
    "drift_seconds": 0.5,
    "last_sync": "2023-12-01T14:25:22Z",
    "ntp_servers": [
      {"server": "pool.ntp.org", "status": "active"},
      {"server": "time.nist.gov", "status": "active"}
    ]
  }
}
```

### Force Time Sync
Force a time synchronization with NTP servers.

**Endpoint:** `POST /time-verification/sync`

**Response:**
```json
{
  "success": true,
  "message": "Time sync completed successfully",
  "data": {
    "sync_time": "2023-12-01T14:30:22Z",
    "drift_corrected": 2.3,
    "servers_used": ["pool.ntp.org", "time.nist.gov"]
  }
}
```

### Get Time Verification History
Get time verification history and logs.

**Endpoint:** `GET /time-verification/history?days=7`

**Response:**
```json
{
  "success": true,
  "data": {
    "history": [
      {
        "timestamp": "2023-12-01T14:30:22Z",
        "action": "sync",
        "drift_seconds": 2.3,
        "servers_used": ["pool.ntp.org"]
      }
    ],
    "summary": {
      "total_syncs": 24,
      "average_drift": 1.2,
      "max_drift": 5.8
    }
  }
}
```

## 📱 Email Commands

### Available Commands
Keyholders can use these email commands to manage the system:

| Command | Description | Example |
|---------|-------------|---------|
| `settings` | Get current configuration | `settings` |
| `status` | Get system status | `status` |
| `help` | Get command list | `help` |
| `approve` | Approve pending requests | `approve REQ_123` |
| `deny` | Deny pending requests | `deny REQ_123` |
| `extend` | Extend request duration | `extend 2 hours` |
| `reduce` | Reduce request duration | `reduce 1 hour` |
| `emergency` | Emergency key release | `emergency` |
| `check` | Request verification | `check` |
| `config` | Get current configuration | `config` |
| `backup` | Create configuration backup | `backup` |

### Time Units Supported
- **Hours**: `extend 2 hours`, `reduce 1 hour`
- **Days**: `extend 3 days`, `reduce 2 days`
- **Weeks**: `extend 1 week`, `reduce 1 week`
- **Months**: `extend 2 months`, `reduce 1 month`
- **Years**: `extend 1 year`, `reduce 6 months`

## 🔧 Error Handling

### Common Error Responses

**400 Bad Request:**
```json
{
  "success": false,
  "error": "Invalid request parameters",
  "details": "Missing required field: device_id"
}
```

**401 Unauthorized:**
```json
{
  "success": false,
  "error": "Unauthorized access",
  "details": "Invalid keyholder email"
}
```

**404 Not Found:**
```json
{
  "success": false,
  "error": "Resource not found",
  "details": "Request ID not found: REQ_123"
}
```

**500 Internal Server Error:**
```json
{
  "success": false,
  "error": "Internal server error",
  "details": "Database connection failed"
}
```

## 📊 Rate Limiting

### Rate Limits
- **API Endpoints**: 100 requests per hour per IP
- **Email Commands**: 50 commands per hour per email
- **File Uploads**: 10 uploads per hour per user
- **Configuration Changes**: 20 changes per hour per keyholder

### Rate Limit Headers
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## 🔒 Authentication

### API Authentication
Most endpoints require authentication via:
- **Email-based**: Keyholder email verification
- **Session-based**: Web interface sessions
- **Token-based**: Temporary access tokens

### Security Headers
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

---

📖 **For implementation details and advanced usage, see the individual system documentation files.** 