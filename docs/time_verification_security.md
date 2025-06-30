# Time Verification Security System

## 🎯 **Overview**

The ChastiPi system includes a robust time verification system that prevents artificial date/time manipulation on the Raspberry Pi. This ensures that all timers, punishments, and keyholder requests operate with accurate, tamper-proof time.

## 🔒 **Security Features**

### **NTP Time Verification**
- ✅ **Multiple NTP Servers** - Checks against 6 trusted time sources
- ✅ **Time Drift Detection** - Alerts when system time differs from NTP
- ✅ **Automatic Validation** - Verifies timestamps against trusted time
- ✅ **Tamper Detection** - Identifies potential time manipulation

### **Trusted NTP Sources**
The system queries multiple authoritative time servers:
- `pool.ntp.org` - Network Time Protocol pool
- `time.google.com` - Google's time server
- `time.windows.com` - Microsoft's time server
- `time.apple.com` - Apple's time server
- `time.cloudflare.com` - Cloudflare's time server
- `time.nist.gov` - National Institute of Standards and Technology

### **Time Drift Tolerance**
- **Maximum Drift:** 30 seconds
- **Warning Level:** 60 seconds
- **Critical Level:** 300 seconds (5 minutes)
- **Tampering Alert:** >300 seconds

## 📊 **How It Works**

### **1. System Time Verification**
```python
# Check system time against NTP servers
verification = time_service.verify_system_time()

# Returns:
{
    'valid': True/False,
    'system_time': '2024-01-15T10:30:00',
    'ntp_time': '2024-01-15T10:30:02',
    'drift_seconds': 2.5,
    'max_drift_allowed': 30,
    'recommendation': 'System time is accurate'
}
```

### **2. Timestamp Validation**
```python
# Validate any timestamp against verified time
result = time_service.validate_timestamp(timestamp, max_age_hours=24)

# Returns:
{
    'valid': True/False,
    'timestamp': '2024-01-15T10:30:00',
    'current_time': '2024-01-15T11:30:00',
    'age_hours': 1.0
}
```

### **3. Automatic Time Sync**
```python
# Sync system time with NTP servers
result = time_service.sync_system_time()

# Returns:
{
    'success': True/False,
    'old_time': '2024-01-15T10:30:00',
    'new_time': '2024-01-15T10:30:02',
    'message': 'System time synchronized successfully'
}
```

## 🌐 **API Endpoints**

### **GET /api/time/status**
Get comprehensive time status including NTP verification.

**Response:**
```json
{
    "success": true,
    "data": {
        "verification": {
            "valid": true,
            "system_time": "2024-01-15T10:30:00",
            "ntp_time": "2024-01-15T10:30:02",
            "drift_seconds": 2.5,
            "max_drift_allowed": 30,
            "ntp_servers_checked": 6,
            "recommendation": "System time is accurate"
        },
        "ntp_service_enabled": true,
        "timezone": "UTC",
        "last_check": "2024-01-15T10:30:00",
        "recommendations": []
    }
}
```

### **GET /api/time/verify**
Quick time verification check.

**Response:**
```json
{
    "success": true,
    "data": {
        "valid": true,
        "system_time": "2024-01-15T10:30:00",
        "ntp_time": "2024-01-15T10:30:02",
        "drift_seconds": 2.5,
        "max_drift_allowed": 30,
        "recommendation": "System time is accurate"
    }
}
```

### **POST /api/time/sync**
Sync system time with NTP servers (requires sudo).

**Request:**
```json
{
    "force": false
}
```

**Response:**
```json
{
    "success": true,
    "message": "System time synchronized successfully",
    "data": {
        "old_time": "2024-01-15T10:30:00",
        "new_time": "2024-01-15T10:30:02"
    }
}
```

### **POST /api/time/validate**
Validate a timestamp against current verified time.

**Request:**
```json
{
    "timestamp": "2024-01-15T10:30:00",
    "max_age_hours": 24
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "valid": true,
        "timestamp": "2024-01-15T10:30:00",
        "current_time": "2024-01-15T11:30:00",
        "age_hours": 1.0
    }
}
```

### **GET /api/time/check**
Quick security check for time validation.

**Response:**
```json
{
    "success": true,
    "time_valid": true,
    "drift_seconds": 2.5,
    "system_time": "2024-01-15T10:30:00",
    "ntp_time": "2024-01-15T10:30:02",
    "warning": null
}
```

## 🖥️ **Web Interface**

### **Time Status Page**
Access via: `/time-status`

Features:
- ✅ **Real-time Status** - Live time verification display
- ✅ **Visual Indicators** - Color-coded status (green/red/yellow)
- ✅ **Time Comparison** - Side-by-side system vs NTP time
- ✅ **Drift Analysis** - Detailed drift information
- ✅ **Sync Controls** - Manual time synchronization
- ✅ **Timestamp Validation** - Test any timestamp
- ✅ **Recommendations** - System improvement suggestions

### **Dashboard Integration**
- 🔗 **Quick Access** - Link from main dashboard
- 📊 **Status Overview** - Time verification status
- ⚠️ **Alerts** - Warnings for time issues

## 🔧 **Setup & Configuration**

### **1. Install Dependencies**
```bash
pip install ntplib==0.4.0
```

### **2. Enable NTP Service**
```bash
# Enable systemd-timesyncd (recommended)
sudo systemctl enable systemd-timesyncd
sudo systemctl start systemd-timesyncd

# Or use chronyd (alternative)
sudo apt install chrony
sudo systemctl enable chronyd
sudo systemctl start chronyd
```

### **3. Configure Timezone**
```bash
# Set timezone
sudo timedatectl set-timezone UTC

# Or for your local timezone
sudo timedatectl set-timezone America/New_York
```

### **4. Grant Sudo Privileges**
For automatic time sync, add to sudoers:
```bash
# Edit sudoers file
sudo visudo

# Add line for your user
your_username ALL=(ALL) NOPASSWD: /bin/date
```

## 🚨 **Security Scenarios**

### **Scenario 1: Normal Operation**
```
System Time: 2024-01-15 10:30:00
NTP Time:    2024-01-15 10:30:02
Drift:       2 seconds
Status:      ✅ Valid
Action:      None needed
```

### **Scenario 2: Minor Drift**
```
System Time: 2024-01-15 10:30:00
NTP Time:    2024-01-15 10:30:45
Drift:       45 seconds
Status:      ⚠️ Warning
Action:      Consider syncing
```

### **Scenario 3: Significant Drift**
```
System Time: 2024-01-15 10:30:00
NTP Time:    2024-01-15 10:35:30
Drift:       330 seconds
Status:      ❌ Invalid
Action:      Sync immediately
```

### **Scenario 4: Possible Tampering**
```
System Time: 2024-01-15 10:30:00
NTP Time:    2024-01-15 12:30:00
Drift:       7200 seconds (2 hours)
Status:      🚨 Tampering Alert
Action:      Investigate and sync
```

## 📱 **Integration with Other Features**

### **Keyholder System**
- ✅ **Request Validation** - Verify request timestamps
- ✅ **Timer Accuracy** - Ensure accurate countdown
- ✅ **Email Timestamps** - Validate email timestamps

### **Punishment System**
- ✅ **PDF Generation** - Accurate timestamps in PDFs
- ✅ **QR Code Validation** - Verify completion timestamps
- ✅ **Expiration Checks** - Accurate expiration times

### **Upload System**
- ✅ **Photo Timestamps** - Validate uploaded photo times
- ✅ **OCR Verification** - Accurate time for verification

## 🔍 **Monitoring & Alerts**

### **Log Monitoring**
```bash
# Check time verification logs
tail -f logs/chasti_pi.log | grep "Time verification"

# Monitor for warnings
grep "Time verification failed" logs/chasti_pi.log
```

### **Automated Checks**
```python
# Programmatic time check
import requests

response = requests.get('http://localhost:5000/api/time/check')
if not response.json()['time_valid']:
    print("⚠️ Time verification failed!")
```

### **Cron Job Monitoring**
```bash
# Add to crontab for regular checks
*/5 * * * * curl -s http://localhost:5000/api/time/check | grep -q '"time_valid":true' || echo "Time verification failed at $(date)" >> /var/log/time_check.log
```

## 🛡️ **Security Benefits**

### **Prevents Time Manipulation**
- ✅ **Clock Tampering** - Detects manual clock changes
- ✅ **Date Manipulation** - Prevents date rollbacks
- ✅ **Timer Bypass** - Ensures accurate countdowns
- ✅ **Request Spoofing** - Validates request timestamps

### **Ensures System Integrity**
- ✅ **Audit Trail** - All timestamps verified
- ✅ **Trusted Time** - Multiple authoritative sources
- ✅ **Real-time Monitoring** - Continuous verification
- ✅ **Automatic Recovery** - Self-healing time sync

### **Compliance & Reliability**
- ✅ **Time Accuracy** - ±30 second precision
- ✅ **Multiple Sources** - Redundant verification
- ✅ **Automatic Sync** - Self-correcting system
- ✅ **Comprehensive Logging** - Full audit trail

## 🚀 **Best Practices**

### **1. Regular Monitoring**
- Check time status daily
- Monitor for drift warnings
- Review verification logs

### **2. Network Connectivity**
- Ensure stable internet connection
- Configure firewall for NTP (port 123)
- Use multiple NTP servers

### **3. System Maintenance**
- Keep system updated
- Monitor system resources
- Regular time sync verification

### **4. Security Hardening**
- Restrict sudo access for time commands
- Monitor for unauthorized changes
- Regular security audits

---

**The time verification system provides robust protection against time manipulation, ensuring the integrity and reliability of all ChastiPi features that depend on accurate time.** 