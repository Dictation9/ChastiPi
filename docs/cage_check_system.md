# Cage/Lock Check Verification System

## 🎯 **Overview**

The Cage Check System allows keyholders to request verification photos from users, ensuring they are wearing their cage/lock as required. The system generates random verification codes that users must write on paper and include in their photos, which are then automatically verified using OCR (Optical Character Recognition).

## 🔒 **How It Works**

### **1. Keyholder Creates Request**
- Keyholder creates a verification request through the web interface
- System generates a unique 6-character verification code (A-Z, 0-9)
- Request is stored with 24-hour expiration

### **2. User Takes Photo**
- User writes the verification code on paper
- Places paper next to their cage/lock
- Takes a clear photo showing both the device and code
- Uploads photo through the verification system

### **3. Automatic Verification**
- System uses OCR to extract text from the uploaded photo
- Compares extracted text against the expected verification code
- Allows for minor OCR errors (1-2 character differences)
- Provides detailed verification results

## 🛡️ **Security Features**

### **Verification Code Security**
- ✅ **Random Generation** - 6-character codes using A-Z and 0-9
- ✅ **Unique Codes** - No duplicate codes across requests
- ✅ **Time-Limited** - 24-hour expiration prevents reuse
- ✅ **OCR Verification** - Automatic text extraction and comparison
- ✅ **Error Tolerance** - Allows for minor OCR reading errors

### **Photo Verification**
- ✅ **Multiple Formats** - Supports PNG, JPG, JPEG, GIF, BMP
- ✅ **Image Processing** - Automatic resizing and preprocessing
- ✅ **OCR Analysis** - Tesseract OCR with confidence scoring
- ✅ **Code Matching** - Exact and partial match detection
- ✅ **Detailed Results** - Shows what text was found vs expected

## 📊 **System Components**

### **CageCheckService**
Core service managing all cage check functionality:

```python
# Create a new check request
check_request = cage_check_service.create_cage_check_request(
    keyholder_email="keyholder@example.com",
    device_name="My Chastity Cage",
    check_type="cage",  # or "lock"
    reason="Weekly verification"
)

# Verify uploaded photo
result = cage_check_service.verify_uploaded_photo(
    request_id="CHECK_20240115_143022_1234",
    photo_path="uploads/cage_checks/photo.jpg"
)
```

### **API Endpoints**
- `POST /cage-check/api/create` - Create new check request
- `POST /cage-check/api/upload` - Upload and verify photo
- `GET /cage-check/api/checks` - Get check requests for keyholder
- `GET /cage-check/api/check/<id>` - Get specific check request
- `POST /cage-check/api/cancel/<id>` - Cancel check request
- `GET /cage-check/api/statistics` - Get check statistics
- `POST /cage-check/api/verify-code` - Manual code verification

### **Web Interface**
- **Dashboard** (`/cage-check/`) - Overview of all check requests
- **Request Creation** (`/cage-check/request`) - Create new verification requests
- **Photo Upload** (`/cage-check/upload`) - Upload verification photos

## 🔄 **Workflow Example**

### **Step 1: Keyholder Creates Request**
```
Keyholder: Creates cage check request
System: Generates code "A7B2X9"
Request ID: CHECK_20240115_143022_1234
Status: Pending
Expires: 2024-01-16 14:30:22
```

### **Step 2: User Takes Photo**
```
User: Writes "A7B2X9" on paper
User: Places paper next to cage
User: Takes photo showing both
User: Uploads photo to system
```

### **Step 3: System Verification**
```
OCR: Extracts text from photo
Found: "A7B2X9" (exact match)
Result: ✅ Verification Successful
Status: Completed
```

### **Step 4: Keyholder Notification**
```
System: Updates request status
Keyholder: Can view results in dashboard
User: Receives confirmation
```

## 📱 **User Interface**

### **Keyholder Dashboard**
- **Statistics Overview** - Total checks, pending, completed, success rate
- **Recent Requests** - List of all check requests with status
- **Action Buttons** - Create new request, upload photos
- **Request Management** - Cancel pending requests

### **Request Creation Page**
- **Form Fields** - Keyholder email, device name, check type, reason
- **Code Generation** - Automatic verification code creation
- **Instructions** - Clear steps for user to follow
- **Success Display** - Shows generated code and instructions

### **Photo Upload Page**
- **Drag & Drop** - Easy photo upload interface
- **File Preview** - Shows selected photo before upload
- **Request ID** - User enters the request ID from keyholder
- **Verification Results** - Detailed OCR and verification results

## 🔍 **Verification Process**

### **OCR Text Extraction**
```python
# Image preprocessing
image = cv2.imread(photo_path)
gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
# Resize if too large
# Apply threshold for better OCR
text = pytesseract.image_to_string(thresh, config='--psm 6')
```

### **Code Matching**
```python
# Exact match
if expected_code in extracted_text:
    return "exact match"

# Partial match (allowing OCR errors)
for word in extracted_words:
    if len(word) == len(expected_code):
        differences = sum(1 for a, b in zip(word, expected_code) if a != b)
        if differences <= 2:
            return "partial match"
```

### **Result Analysis**
- **Exact Match** - Perfect OCR reading
- **Partial Match** - Minor OCR errors allowed
- **No Match** - Code not found or too many errors
- **OCR Failed** - Image processing issues

## 📊 **Statistics & Monitoring**

### **Check Statistics**
```json
{
    "total_checks": 25,
    "pending": 3,
    "completed": 18,
    "failed": 2,
    "expired": 1,
    "cancelled": 1,
    "success_rate": 90.0
}
```

### **Request Details**
```json
{
    "request_id": "CHECK_20240115_143022_1234",
    "keyholder_email": "keyholder@example.com",
    "device_name": "My Chastity Cage",
    "check_type": "cage",
    "verification_code": "A7B2X9",
    "status": "completed",
    "created_at": "2024-01-15T14:30:22",
    "expires_at": "2024-01-16T14:30:22",
    "completed_at": "2024-01-15T15:45:30",
    "ocr_result": {
        "success": true,
        "text": "A7B2X9",
        "confidence": 95.2
    },
    "verification_result": {
        "found": true,
        "expected_code": "A7B2X9",
        "found_codes": ["A7B2X9"],
        "match_type": "exact"
    }
}
```

## 🚀 **Benefits**

### **For Keyholders**
- ✅ **Remote Verification** - Check compliance from anywhere
- ✅ **Automated Process** - No manual photo review needed
- ✅ **Tamper-Proof** - Random codes prevent fake photos
- ✅ **Time-Limited** - Prevents code reuse
- ✅ **Detailed Results** - See exactly what was verified

### **For Users**
- ✅ **Simple Process** - Just write code and take photo
- ✅ **Clear Instructions** - Step-by-step guidance
- ✅ **Immediate Results** - Instant verification feedback
- ✅ **Privacy Maintained** - Only verification code needed
- ✅ **Multiple Attempts** - Can retry if verification fails

### **For System**
- ✅ **Scalable** - Handles multiple requests simultaneously
- ✅ **Reliable** - OCR with error tolerance
- ✅ **Secure** - Unique codes and time limits
- ✅ **Auditable** - Complete verification history
- ✅ **User-Friendly** - Intuitive web interface

## 🔧 **Setup & Configuration**

### **Dependencies**
```bash
pip install opencv-python pytesseract Pillow numpy
```

### **OCR Setup**
```bash
# Install Tesseract OCR
sudo apt install tesseract-ocr

# Verify installation
tesseract --version
```

### **File Structure**
```
uploads/
└── cage_checks/
    ├── CHECK_20240115_143022_1234_photo1.jpg
    ├── CHECK_20240115_143022_1234_photo2.jpg
    └── ...

data/
├── cage_checks.json
└── verification_codes.json
```

## 🎯 **Use Cases**

### **Regular Verification**
- **Weekly checks** - Ensure continued compliance
- **Monthly reviews** - Long-term verification
- **Random spot checks** - Unpredictable verification

### **Special Circumstances**
- **Travel verification** - Remote compliance checks
- **Medical appointments** - Temporary removal verification
- **Maintenance checks** - Device condition verification

### **Training & Trust Building**
- **New relationships** - Build trust through verification
- **Long-distance** - Remote relationship management
- **Group dynamics** - Multiple keyholder scenarios

## 🔒 **Privacy & Security**

### **Data Protection**
- ✅ **Local Storage** - All data stored on Raspberry Pi
- ✅ **No Cloud Upload** - Photos processed locally
- ✅ **Temporary Files** - Photos can be automatically deleted
- ✅ **Encrypted Storage** - Sensitive data encrypted
- ✅ **Access Control** - Only authorized keyholders can access

### **Verification Integrity**
- ✅ **Random Codes** - Prevents prediction or reuse
- ✅ **Time Limits** - Prevents delayed verification
- ✅ **OCR Verification** - Automated, unbiased checking
- ✅ **Audit Trail** - Complete verification history
- ✅ **Error Handling** - Graceful failure management

## 📈 **Future Enhancements**

### **Advanced Features**
- **QR Code Support** - Generate QR codes instead of text
- **Multiple Photos** - Require photos from different angles
- **Video Verification** - Short video clips for verification
- **AI Analysis** - Advanced image recognition
- **Biometric Verification** - Additional security layers

### **Integration Features**
- **Email Notifications** - Automatic status updates
- **Calendar Integration** - Scheduled verification reminders
- **Mobile App** - Dedicated mobile interface
- **API Access** - Third-party integration capabilities
- **Webhook Support** - Real-time status updates

---

**The Cage Check System provides a secure, automated, and user-friendly way for keyholders to verify compliance remotely, ensuring trust and accountability in chastity relationships.** 