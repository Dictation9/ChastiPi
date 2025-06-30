# Keyholder Timer Control System

## 🔐 **Keyholder-Only Access**

**Only the registered keyholder email address can approve, deny, or modify key request timers.** This ensures complete security and prevents unauthorized access to key codes.

## ⏰ **Timer Control Features**

### **Full Timer Control**
As the registered keyholder, you have complete control over:
- ✅ **Approve requests** with original or modified duration
- ✅ **Deny requests** with optional reasons
- ✅ **Extend duration** by adding hours
- ✅ **Reduce duration** to specific hours
- ✅ **Modify approved requests** even after approval
- ✅ **Emergency release** for urgent situations

### **Email Commands for Timer Control**

#### **📈 Extend Duration**
```
EXTEND 2          - Add 2 hours to current duration
EXTEND 1          - Add 1 hour to current duration
EXTEND 30 min     - Add 30 minutes to current duration
EXTEND 1 day      - Add 1 day to current duration
EXTEND 20 days    - Add 20 days to current duration
EXTEND 1 week     - Add 1 week to current duration
EXTEND 2 months   - Add 2 months to current duration
EXTEND 1 year     - Add 1 year to current duration
```

#### **📉 Reduce Duration**
```
REDUCE 1          - Set duration to 1 hour
REDUCE 2          - Set duration to 2 hours
REDUCE 30 min     - Set duration to 30 minutes
REDUCE 1 day      - Set duration to 1 day
REDUCE 20 days    - Set duration to 20 days
REDUCE 1 week     - Set duration to 1 week
REDUCE 1 month    - Set duration to 1 month
```

#### **✅ Approve with Modified Duration**
```
APPROVE           - Approve with original duration
APPROVE 3         - Approve with 3 hours duration
APPROVE 30 min    - Approve with 30 minutes duration
APPROVE 1 day     - Approve with 1 day duration
APPROVE 20 days   - Approve with 20 days duration
APPROVE 1 week    - Approve with 1 week duration
APPROVE 2 months  - Approve with 2 months duration
APPROVE 1 year    - Approve with 1 year duration
```

#### **❌ Deny Requests**
```
DENY              - Deny the request
DENY - too busy   - Deny with reason
```

#### **🚨 Emergency Release**
```
EMERGENCY         - Immediate emergency release
```

## 🔒 **Security Implementation**

### **Email Verification**
```python
def _verify_keyholder(self, request_id, email):
    """Verify that the email matches the keyholder for this request"""
    request = self.key_storage.key_requests.get(request_id)
    if not request:
        return False
    
    return request.get('keyholder_email', '').lower() == email.lower()
```

### **Request Validation**
- ✅ **Email verification** - Only registered keyholder can respond
- ✅ **Request existence** - System verifies request exists
- ✅ **Status validation** - Can only modify pending requests
- ✅ **Duration limits** - Prevents invalid durations

### **Audit Trail**
All timer modifications are logged with:
- 📅 **Timestamp** of modification
- 👤 **Keyholder email** that made the change
- 📊 **Original duration** before modification
- 📊 **New duration** after modification
- 🔍 **Action type** (extend, reduce, approve, deny)

## 📊 **Timer Control Examples**

### **Scenario 1: Extend Duration**
```
User requests: 2 hours
Keyholder replies: "EXTEND 1"
Result: 3 hours total (2 + 1)
```

### **Scenario 2: Reduce Duration**
```
User requests: 4 hours
Keyholder replies: "REDUCE 1"
Result: 1 hour total
```

### **Scenario 3: Approve with Modification**
```
User requests: 2 hours
Keyholder replies: "APPROVE 3"
Result: 3 hours approved
```

### **Scenario 4: Modify Approved Request**
```
User has 2 hours approved
Keyholder replies: "EXTEND 1"
Result: 3 hours total, access extended
```

### **Scenario 5: Long-term Extension**
```
User requests: 1 day
Keyholder replies: "EXTEND 19 days"
Result: 20 days total (1 + 19)
```

### **Scenario 6: Week to Month**
```
User requests: 1 week
Keyholder replies: "EXTEND 3 weeks"
Result: 1 month total (1 week + 3 weeks)
```

### **Scenario 7: Month to Half Year**
```
User requests: 2 months
Keyholder replies: "EXTEND 4 months"
Result: 6 months total (2 + 4)
```

### **Scenario 8: Year Extension**
```
User requests: 1 year
Keyholder replies: "EXTEND 1 year"
Result: 2 years total (1 + 1)
```

### **Scenario 9: Reduce Long Duration**
```
User requests: 1 month
Keyholder replies: "REDUCE 1 week"
Result: 1 week total
```

### **Scenario 10: Approve with Long Duration**
```
User requests: 2 hours
Keyholder replies: "APPROVE 20 days"
Result: 20 days approved
```

## 🔧 **Technical Implementation**

### **Key Storage Service Methods**

#### **Extend Request Duration**
```python
def extend_request_duration(self, request_id, additional_hours):
    """Extend the duration of a pending request"""
    # Verify request exists and is pending
    # Add hours to current duration
    # Update request with new duration
    # Log the modification
```

#### **Reduce Request Duration**
```python
def reduce_request_duration(self, request_id, new_duration_hours):
    """Reduce the duration of a pending request"""
    # Verify request exists and is pending
    # Validate new duration is positive
    # Set new duration
    # Log the modification
```

#### **Modify Approved Request**
```python
def modify_approved_request_duration(self, request_id, new_duration_hours):
    """Modify duration of an already approved request"""
    # Verify request is approved and not expired
    # Update duration and expiration time
    # Log the modification
```

### **Email Reply Processing**
```python
def _process_action(self, request_id, action, body):
    """Process the keyholder action"""
    action_type = action.get('action')
    
    if action_type == 'extend':
        hours = action.get('hours', 1)
        result = self.key_storage.extend_request_duration(request_id, hours)
        
    elif action_type == 'reduce':
        hours = action.get('hours', 1)
        result = self.key_storage.reduce_request_duration(request_id, hours)
        
    elif action_type == 'approve':
        modified_duration = action.get('hours')
        result = self.key_storage.approve_key_release(request_id, modified_duration=modified_duration)
```

## 📱 **API Endpoints**

### **Timer Control Endpoints**
```
POST /keyholder/extend/<request_id>
POST /keyholder/reduce/<request_id>
POST /keyholder/modify-duration/<request_id>
```

### **Request Parameters**
```json
{
    "additional_hours": 2,    // For extend
    "new_duration": 1         // For reduce/modify
}
```

### **Response Format**
```json
{
    "success": true,
    "message": "Request duration extended from 2 to 4 hours",
    "original_duration": 2,
    "new_duration": 4,
    "request": {...}
}
```

## 🛡️ **Security Features**

### **Access Control**
- 🔐 **Email verification** - Only registered keyholder can respond
- 🔐 **Request ownership** - Can only modify your own devices
- 🔐 **Status validation** - Can only modify pending/approved requests
- 🔐 **Duration validation** - Prevents invalid durations

### **Data Protection**
- 🔒 **Encrypted storage** - All key codes are encrypted
- 🔒 **Audit logging** - All actions are logged
- 🔒 **Request tracking** - Unique request IDs for each request
- 🔒 **Expiration handling** - Automatic expiration of requests

### **Error Handling**
- ⚠️ **Invalid durations** - Rejected with error messages
- ⚠️ **Expired requests** - Cannot modify expired requests
- ⚠️ **Unauthorized access** - Rejected with security warnings
- ⚠️ **System errors** - Graceful error handling and logging

## 📧 **Email Integration**

### **Notification System**
- 📨 **Request notifications** - Immediate email when request made
- 📨 **Confirmation emails** - Confirm when action processed
- 📨 **Duration modification** - Notify when timers changed
- 📨 **Emergency alerts** - Urgent notifications for emergencies

### **Email Commands**
- ✅ **Simple commands** - Easy to type on mobile
- ✅ **Flexible syntax** - Multiple ways to express same action
- ✅ **Error handling** - Clear error messages for invalid commands
- ✅ **Confirmation** - Always get confirmation of actions

## 🎯 **Use Cases**

### **Remote Keyholder Management**
```
Keyholder at work receives email notification
Replies: "EXTEND 2"
System extends duration by 2 hours
User gets updated access time
```

### **Mobile Management**
```
Keyholder on vacation receives request
Replies from phone: "REDUCE 1"
System reduces duration to 1 hour
Confirmation sent to keyholder
```

### **Emergency Situations**
```
User needs emergency access
Keyholder receives urgent email
Replies: "EMERGENCY"
System immediately unlocks device
```

### **Flexible Duration Control**
```
User requests 4 hours for cleaning
Keyholder thinks 2 hours is enough
Replies: "REDUCE 2"
System approves with 2 hours
```

## 🔍 **Monitoring & Logs**

### **Activity Logging**
- 📊 **All modifications** are logged with timestamps
- 📊 **Original vs new** durations are tracked
- 📊 **Keyholder actions** are recorded
- 📊 **System responses** are documented

### **Dashboard Display**
- 📈 **Request history** shows all modifications
- 📈 **Duration changes** are highlighted
- 📈 **Keyholder actions** are visible
- 📈 **Current status** is always up to date

## 🚀 **Benefits**

### **For Keyholders**
- ✅ **Complete control** over timer durations
- ✅ **Remote access** from anywhere via email
- ✅ **Mobile friendly** - works on any device
- ✅ **Flexible management** - multiple ways to control
- ✅ **Security** - only you can modify your devices

### **For Users**
- ✅ **Transparent process** - see all modifications
- ✅ **Flexible requests** - can request any duration
- ✅ **Quick responses** - get answers via email
- ✅ **Secure access** - only authorized keyholder can approve

### **For System**
- ✅ **Audit trail** - complete logging of all actions
- ✅ **Security** - email verification prevents unauthorized access
- ✅ **Reliability** - email-based system is robust
- ✅ **Scalability** - works with multiple devices and keyholders

## ⏱️ **Supported Time Units**

The system supports flexible time units for maximum convenience:

### **Time Unit Conversions**
- **Minutes:** 30 min, 1 minute, 45 mins = 0.5, 0.0167, 0.75 hours
- **Hours:** 2 h, 3 hours, 1.5 hrs = 2, 3, 1.5 hours
- **Days:** 1 d, 5 days, 20 days = 24, 120, 480 hours
- **Weeks:** 1 w, 2 weeks, 1 wk = 168, 336, 168 hours
- **Months:** 1 m, 3 months, 6 mos = 730, 2190, 4380 hours
- **Years:** 1 y, 1 year, 2 yrs = 8760, 8760, 17520 hours

### **Flexible Syntax**
- **Full words:** "20 days", "1 week", "2 months"
- **Abbreviations:** "20 d", "1 w", "2 m", "1 y"
- **Mixed formats:** "1.5 hours", "2.5 days", "3.5 weeks"

---

**The keyholder timer control system ensures that only the registered keyholder can modify request durations, providing complete security while offering maximum flexibility for remote management.** 