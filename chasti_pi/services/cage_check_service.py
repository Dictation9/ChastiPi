import json
import random
import string
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import cv2
import pytesseract
from PIL import Image
import numpy as np
import os
import tempfile
from chasti_pi.core.config import config
from ..services.email_service import EmailService
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

class CageCheckService:
    """Service for managing cage/lock check requests with verification codes"""
    
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # File paths
        self.checks_file = self.data_dir / "cage_checks.json"
        self.codes_file = self.data_dir / "verification_codes.json"
        self.notifications_file = self.data_dir / "cage_check_notifications.json"
        
        # Load existing data
        self.cage_checks = self._load_cage_checks()
        self.verification_codes = self._load_verification_codes()
        self.notifications = self._load_notifications()
        
        # Code generation settings
        self.code_length = 6
        self.code_chars = string.ascii_uppercase + string.digits  # A-Z, 0-9
        self.code_expiry_hours = 24
        
        # Notification settings
        self.reminder_delay_hours = 1  # Send reminder after 1 hour
        self.final_warning_hours = 6   # Send final warning after 6 hours
        self.expiry_warning_hours = 2  # Send expiry warning 2 hours before
        
        # Video processing settings
        self.video_frame_interval = config.get("cage_check.video_frame_interval", 1)  # Extract frame every 1 second
        self.max_video_duration = config.get("cage_check.max_video_duration", 300)   # Maximum video duration in seconds (5 minutes)
        self.min_video_duration = config.get("cage_check.min_video_duration", 3)     # Minimum video duration in seconds
        
        # Initialize email service
        self.email_service = EmailService()
        
    def _load_cage_checks(self) -> Dict:
        """Load cage check requests from file"""
        try:
            if self.checks_file.exists():
                with open(self.checks_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading cage checks: {str(e)}")
        return {}
    
    def _save_cage_checks(self):
        """Save cage check requests to file"""
        try:
            with open(self.checks_file, 'w') as f:
                json.dump(self.cage_checks, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving cage checks: {str(e)}")
    
    def _load_verification_codes(self) -> Dict:
        """Load verification codes from file"""
        try:
            if self.codes_file.exists():
                with open(self.codes_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading verification codes: {str(e)}")
        return {}
    
    def _save_verification_codes(self):
        """Save verification codes to file"""
        try:
            with open(self.codes_file, 'w') as f:
                json.dump(self.verification_codes, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving verification codes: {str(e)}")
    
    def _load_notifications(self) -> Dict:
        """Load notification history from file"""
        try:
            if self.notifications_file.exists():
                with open(self.notifications_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading notifications: {str(e)}")
        return {}
    
    def _save_notifications(self):
        """Save notification history to file"""
        try:
            with open(self.notifications_file, 'w') as f:
                json.dump(self.notifications, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving notifications: {str(e)}")
    
    def generate_verification_code(self) -> str:
        """Generate a random verification code"""
        while True:
            code = ''.join(random.choices(self.code_chars, k=self.code_length))
            # Ensure code is unique
            if code not in self.verification_codes:
                return code
    
    def create_cage_check_request(self, keyholder_email: str, device_name: str, 
                                 check_type: str = "cage", reason: str = None,
                                 wearer_email: str = None) -> Dict:
        """Create a new cage/lock check request with email notification"""
        try:
            # Generate unique request ID
            request_id = f"CHECK_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
            
            # Generate verification code
            verification_code = self.generate_verification_code()
            
            # Create check request
            check_request = {
                'request_id': request_id,
                'keyholder_email': keyholder_email,
                'wearer_email': wearer_email,
                'device_name': device_name,
                'check_type': check_type,  # 'cage' or 'lock'
                'reason': reason or f"{check_type.title()} verification requested",
                'verification_code': verification_code,
                'status': 'pending',  # pending, completed, failed, expired
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(hours=self.code_expiry_hours)).isoformat(),
                'completed_at': None,
                'uploaded_photo': None,
                'ocr_result': None,
                'verification_result': None,
                'notes': None,
                'notifications_sent': {
                    'initial': False,
                    'reminder': False,
                    'final_warning': False,
                    'expiry_warning': False
                },
                'last_notification_sent': None
            }
            
            # Store the request
            self.cage_checks[request_id] = check_request
            
            # Store verification code
            self.verification_codes[verification_code] = {
                'request_id': request_id,
                'created_at': datetime.now().isoformat(),
                'expires_at': check_request['expires_at'],
                'used': False
            }
            
            # Save data
            self._save_cage_checks()
            self._save_verification_codes()
            
            # Send initial notification to wearer
            if wearer_email:
                self._send_initial_notification(check_request)
            
            logger.info(f"Created cage check request {request_id} with code {verification_code}")
            
            return check_request
            
        except Exception as e:
            logger.error(f"Error creating cage check request: {str(e)}")
            return None
    
    def _send_initial_notification(self, check_request: Dict):
        """Send initial notification to wearer"""
        try:
            if not check_request.get('wearer_email'):
                return
            
            subject = f"🔒 Cage Check Request: {check_request['device_name']}"
            
            body = f"""
🔐 **Cage Check Verification Required**

Your keyholder has requested a verification check for your {check_request['check_type']}.

**Details:**
- **Device:** {check_request['device_name']}
- **Request ID:** {check_request['request_id']}
- **Verification Code:** {check_request['verification_code']}
- **Reason:** {check_request['reason']}
- **Expires:** {datetime.fromisoformat(check_request['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}

**Instructions:**
1. Write the verification code **{check_request['verification_code']}** on a piece of paper
2. Place the paper next to your {check_request['check_type']}
3. Take a clear photo showing both the {check_request['check_type']} and the code
4. Upload the photo at: http://your-pi-ip:5000/cage-check/upload
5. Enter the Request ID: **{check_request['request_id']}**

**Important:**
- You have **{self.code_expiry_hours} hours** to complete this verification
- The code will expire automatically after this time
- Failure to respond may result in consequences set by your keyholder

**Need Help?**
If you have trouble with the verification process, contact your keyholder.

---
*This is an automated notification from your ChastiPi system.*
"""
            
            # Send email
            self.email_service.send_email(
                to_email=check_request['wearer_email'],
                subject=subject,
                body=body
            )
            
            # Update notification status
            check_request['notifications_sent']['initial'] = True
            check_request['last_notification_sent'] = datetime.now().isoformat()
            self._save_cage_checks()
            
            # Log notification
            self._log_notification(check_request['request_id'], 'initial', check_request['wearer_email'])
            
            logger.info(f"Sent initial notification for request {check_request['request_id']}")
            
        except Exception as e:
            logger.error(f"Error sending initial notification: {str(e)}")
    
    def _send_reminder_notification(self, check_request: Dict):
        """Send reminder notification to wearer"""
        try:
            if not check_request.get('wearer_email'):
                return
            
            subject = f"⏰ Reminder: Cage Check Pending - {check_request['device_name']}"
            
            body = f"""
⏰ **Cage Check Reminder**

You have not yet completed the verification check for your {check_request['check_type']}.

**Request Details:**
- **Device:** {check_request['device_name']}
- **Request ID:** {check_request['request_id']}
- **Verification Code:** {check_request['verification_code']}
- **Created:** {datetime.fromisoformat(check_request['created_at']).strftime('%Y-%m-%d %H:%M:%S')}
- **Expires:** {datetime.fromisoformat(check_request['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}

**Please complete the verification now:**
1. Write code **{check_request['verification_code']}** on paper
2. Place next to your {check_request['check_type']}
3. Take photo and upload at: http://your-pi-ip:5000/cage-check/upload
4. Use Request ID: **{check_request['request_id']}**

**Time Remaining:** {self._get_time_remaining(check_request['expires_at'])}
**Status:** ⚠️ Pending Response

---
*This is an automated reminder from your ChastiPi system.*
"""
            
            # Send email
            self.email_service.send_email(
                to_email=check_request['wearer_email'],
                subject=subject,
                body=body
            )
            
            # Update notification status
            check_request['notifications_sent']['reminder'] = True
            check_request['last_notification_sent'] = datetime.now().isoformat()
            self._save_cage_checks()
            
            # Log notification
            self._log_notification(check_request['request_id'], 'reminder', check_request['wearer_email'])
            
            logger.info(f"Sent reminder notification for request {check_request['request_id']}")
            
        except Exception as e:
            logger.error(f"Error sending reminder notification: {str(e)}")
    
    def _send_final_warning_notification(self, check_request: Dict):
        """Send final warning notification to wearer"""
        try:
            if not check_request.get('wearer_email'):
                return
            
            subject = f"🚨 Final Warning: Cage Check Expiring Soon - {check_request['device_name']}"
            
            body = f"""
🚨 **Final Warning: Verification Expiring Soon**

Your cage check verification is about to expire. This is your final warning.

**Request Details:**
- **Device:** {check_request['device_name']}
- **Request ID:** {check_request['request_id']}
- **Verification Code:** {check_request['verification_code']}
- **Expires:** {datetime.fromisoformat(check_request['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}

**URGENT: Complete verification immediately:**
1. Write code **{check_request['verification_code']}** on paper
2. Place next to your {check_request['check_type']}
3. Take photo and upload at: http://your-pi-ip:5000/cage-check/upload
4. Use Request ID: **{check_request['request_id']}**

**Time Remaining:** {self._get_time_remaining(check_request['expires_at'])}
**Status:** 🚨 EXPIRING SOON

**Consequences:**
Failure to complete this verification may result in:
- Extended lock time
- Additional punishments
- Loss of privileges
- Other consequences set by your keyholder

---
*This is an automated final warning from your ChastiPi system.*
"""
            
            # Send email
            self.email_service.send_email(
                to_email=check_request['wearer_email'],
                subject=subject,
                body=body
            )
            
            # Update notification status
            check_request['notifications_sent']['final_warning'] = True
            check_request['last_notification_sent'] = datetime.now().isoformat()
            self._save_cage_checks()
            
            # Log notification
            self._log_notification(check_request['request_id'], 'final_warning', check_request['wearer_email'])
            
            logger.info(f"Sent final warning notification for request {check_request['request_id']}")
            
        except Exception as e:
            logger.error(f"Error sending final warning notification: {str(e)}")
    
    def _send_expiry_notification(self, check_request: Dict):
        """Send notification when request expires"""
        try:
            if not check_request.get('wearer_email'):
                return
            
            subject = f"❌ Cage Check Expired - {check_request['device_name']}"
            
            body = f"""
❌ **Verification Request Expired**

Your cage check verification request has expired without completion.

**Request Details:**
- **Device:** {check_request['device_name']}
- **Request ID:** {check_request['request_id']}
- **Verification Code:** {check_request['verification_code']}
- **Created:** {datetime.fromisoformat(check_request['created_at']).strftime('%Y-%m-%d %H:%M:%S')}
- **Expired:** {datetime.fromisoformat(check_request['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}

**Status:** ❌ EXPIRED - No verification completed

**Next Steps:**
- Contact your keyholder immediately
- Be prepared for consequences
- Wait for new verification request if needed

**Note:** Your keyholder has been notified of this failure.

---
*This is an automated notification from your ChastiPi system.*
"""
            
            # Send email to wearer
            self.email_service.send_email(
                to_email=check_request['wearer_email'],
                subject=subject,
                body=body
            )
            
            # Send notification to keyholder
            self._send_keyholder_expiry_notification(check_request)
            
            # Update notification status
            check_request['notifications_sent']['expiry_warning'] = True
            check_request['last_notification_sent'] = datetime.now().isoformat()
            self._save_cage_checks()
            
            # Log notification
            self._log_notification(check_request['request_id'], 'expired', check_request['wearer_email'])
            
            logger.info(f"Sent expiry notification for request {check_request['request_id']}")
            
        except Exception as e:
            logger.error(f"Error sending expiry notification: {str(e)}")
    
    def _send_keyholder_expiry_notification(self, check_request: Dict):
        """Send notification to keyholder when request expires"""
        try:
            subject = f"❌ Cage Check Expired: {check_request['device_name']}"
            
            body = f"""
❌ **Cage Check Request Expired**

A verification request has expired without completion.

**Request Details:**
- **Device:** {check_request['device_name']}
- **Request ID:** {check_request['request_id']}
- **Wearer Email:** {check_request.get('wearer_email', 'Not provided')}
- **Created:** {datetime.fromisoformat(check_request['created_at']).strftime('%Y-%m-%d %H:%M:%S')}
- **Expired:** {datetime.fromisoformat(check_request['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}

**Status:** ❌ EXPIRED - No verification completed

**Actions Taken:**
- Wearer has been notified of expiration
- Request marked as expired in system
- Available for review in dashboard

**Next Steps:**
- Review the situation with your wearer
- Consider creating a new verification request
- Set appropriate consequences if needed

---
*This is an automated notification from your ChastiPi system.*
"""
            
            # Send email to keyholder
            self.email_service.send_email(
                to_email=check_request['keyholder_email'],
                subject=subject,
                body=body
            )
            
            logger.info(f"Sent keyholder expiry notification for request {check_request['request_id']}")
            
        except Exception as e:
            logger.error(f"Error sending keyholder expiry notification: {str(e)}")
    
    def _get_time_remaining(self, expires_at: str) -> str:
        """Get formatted time remaining until expiration"""
        try:
            expires = datetime.fromisoformat(expires_at)
            now = datetime.now()
            remaining = expires - now
            
            if remaining.total_seconds() <= 0:
                return "EXPIRED"
            
            hours = int(remaining.total_seconds() // 3600)
            minutes = int((remaining.total_seconds() % 3600) // 60)
            
            if hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"
                
        except Exception:
            return "Unknown"
    
    def _log_notification(self, request_id: str, notification_type: str, recipient_email: str):
        """Log notification for audit trail"""
        notification_id = f"{request_id}_{notification_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.notifications[notification_id] = {
            'request_id': request_id,
            'notification_type': notification_type,
            'recipient_email': recipient_email,
            'sent_at': datetime.now().isoformat(),
            'status': 'sent'
        }
        
        self._save_notifications()
    
    def check_and_send_notifications(self):
        """Check all pending requests and send appropriate notifications"""
        try:
            current_time = datetime.now()
            
            for request_id, check_request in self.cage_checks.items():
                if check_request['status'] != 'pending':
                    continue
                
                created_at = datetime.fromisoformat(check_request['created_at'])
                expires_at = datetime.fromisoformat(check_request['expires_at'])
                
                # Calculate time differences
                hours_since_created = (current_time - created_at).total_seconds() / 3600
                hours_until_expiry = (expires_at - current_time).total_seconds() / 3600
                
                notifications = check_request['notifications_sent']
                
                # Send reminder after 1 hour if not sent
                if (hours_since_created >= self.reminder_delay_hours and 
                    not notifications['reminder'] and 
                    check_request.get('wearer_email')):
                    self._send_reminder_notification(check_request)
                
                # Send final warning after 6 hours if not sent
                elif (hours_since_created >= self.final_warning_hours and 
                      not notifications['final_warning'] and 
                      check_request.get('wearer_email')):
                    self._send_final_warning_notification(check_request)
                
                # Send expiry warning 2 hours before if not sent
                elif (hours_until_expiry <= self.expiry_warning_hours and 
                      hours_until_expiry > 0 and 
                      not notifications['expiry_warning'] and 
                      check_request.get('wearer_email')):
                    self._send_final_warning_notification(check_request)
                
                # Mark as expired if past expiry time
                elif current_time > expires_at:
                    check_request['status'] = 'expired'
                    self._save_cage_checks()
                    
                    # Send expiry notification if not sent
                    if not notifications['expiry_warning'] and check_request.get('wearer_email'):
                        self._send_expiry_notification(check_request)
            
            logger.info("Completed notification check for pending cage check requests")
            
        except Exception as e:
            logger.error(f"Error checking and sending notifications: {str(e)}")
    
    def get_pending_notifications(self, wearer_email: str = None) -> List[Dict]:
        """Get pending notifications for dashboard display"""
        try:
            pending_notifications = []
            current_time = datetime.now()
            
            for request_id, check_request in self.cage_checks.items():
                if check_request['status'] != 'pending':
                    continue
                
                # Filter by wearer email if provided
                if wearer_email and check_request.get('wearer_email') != wearer_email:
                    continue
                
                expires_at = datetime.fromisoformat(check_request['expires_at'])
                hours_until_expiry = (expires_at - current_time).total_seconds() / 3600
                
                # Determine notification priority
                if hours_until_expiry <= 0:
                    priority = 'expired'
                    message = 'Request has expired'
                elif hours_until_expiry <= 2:
                    priority = 'urgent'
                    message = f'Expires in {self._get_time_remaining(check_request["expires_at"])}'
                elif hours_until_expiry <= 6:
                    priority = 'warning'
                    message = f'Expires in {self._get_time_remaining(check_request["expires_at"])}'
                else:
                    priority = 'normal'
                    message = f'Expires in {self._get_time_remaining(check_request["expires_at"])}'
                
                pending_notifications.append({
                    'request_id': request_id,
                    'device_name': check_request['device_name'],
                    'check_type': check_request['check_type'],
                    'verification_code': check_request['verification_code'],
                    'created_at': check_request['created_at'],
                    'expires_at': check_request['expires_at'],
                    'priority': priority,
                    'message': message,
                    'time_remaining': self._get_time_remaining(check_request['expires_at'])
                })
            
            # Sort by priority and expiry time
            priority_order = {'expired': 0, 'urgent': 1, 'warning': 2, 'normal': 3}
            pending_notifications.sort(key=lambda x: (priority_order[x['priority']], x['expires_at']))
            
            return pending_notifications
            
        except Exception as e:
            logger.error(f"Error getting pending notifications: {str(e)}")
            return []
    
    def get_check_request(self, request_id: str) -> Optional[Dict]:
        """Get a specific check request"""
        return self.cage_checks.get(request_id)
    
    def get_pending_checks(self, keyholder_email: str = None) -> List[Dict]:
        """Get pending check requests"""
        checks = []
        for check in self.cage_checks.values():
            if check['status'] == 'pending':
                if keyholder_email is None or check['keyholder_email'] == keyholder_email:
                    checks.append(check)
        return checks
    
    def get_all_checks(self, keyholder_email: str = None) -> List[Dict]:
        """Get all check requests for a keyholder"""
        checks = []
        for check in self.cage_checks.values():
            if keyholder_email is None or check['keyholder_email'] == keyholder_email:
                checks.append(check)
        return sorted(checks, key=lambda x: x['created_at'], reverse=True)
    
    def verify_cage_check(self, request_id: str, uploaded_file) -> Dict:
        """Verify uploaded photo/video for cage check"""
        try:
            # Get the check request
            check_request = self.get_check_request(request_id)
            if not check_request:
                return {
                    'success': False,
                    'error': 'Check request not found'
                }
            
            if check_request['status'] != 'pending':
                return {
                    'success': False,
                    'error': f'Check request is {check_request["status"]}, cannot verify'
                }
            
            # Check if expired
            expires_at = datetime.fromisoformat(check_request['expires_at'])
            if datetime.now() > expires_at:
                check_request['status'] = 'expired'
                self._save_cage_checks()
                return {
                    'success': False,
                    'error': 'Verification code has expired'
                }
            
            # Save uploaded file
            filename = secure_filename(uploaded_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_extension = Path(filename).suffix.lower()
            
            # Create unique filename
            unique_filename = f"cage_check_{request_id}_{timestamp}{file_extension}"
            upload_path = Path(UPLOAD_FOLDER)
            upload_path.mkdir(exist_ok=True)
            file_path = upload_path / unique_filename
            
            # Save file
            uploaded_file.save(str(file_path))
            
            # Process file based on type
            if self._is_video_file(str(file_path)):
                # Process video
                result = self._process_video_for_verification(str(file_path), check_request['verification_code'])
            else:
                # Process image
                ocr_result = self._extract_text_from_image(str(file_path))
                if ocr_result['success']:
                    verification_result = self._find_verification_code(ocr_result, check_request['verification_code'])
                    result = {
                        'success': True,
                        'video_processed': False,
                        'ocr_result': ocr_result,
                        'verification_result': verification_result
                    }
                else:
                    result = {
                        'success': False,
                        'error': ocr_result['error']
                    }
            
            # Update check request
            check_request['uploaded_photo'] = str(file_path)
            check_request['ocr_result'] = result.get('ocr_result', {})
            check_request['verification_result'] = result.get('verification_result', {})
            check_request['completed_at'] = datetime.now().isoformat()
            
            if result.get('success') and result.get('verification_result', {}).get('found'):
                check_request['status'] = 'completed'
                # Mark code as used
                if check_request['verification_code'] in self.verification_codes:
                    self.verification_codes[check_request['verification_code']]['used'] = True
            else:
                check_request['status'] = 'failed'
            
            self._save_cage_checks()
            self._save_verification_codes()
            
            return {
                'success': True,
                'data': {
                    'status': check_request['status'],
                    'verification_result': result.get('verification_result', {}),
                    'ocr_result': result.get('ocr_result', {}),
                    'video_processed': result.get('video_processed', False),
                    'total_frames': result.get('total_frames', 0),
                    'best_frame': result.get('best_frame', 0)
                }
            }
            
        except Exception as e:
            logger.error(f"Error verifying cage check: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_text_from_image(self, image_path: str) -> Dict:
        """Extract text from image using OCR"""
        try:
            # Read image
            image = cv2.imread(image_path)
            if image is None:
                return {
                    'success': False,
                    'error': 'Could not read image file'
                }
            
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply preprocessing
            # Resize if too large
            height, width = gray.shape
            if width > 2000 or height > 2000:
                scale = min(2000/width, 2000/height)
                new_width = int(width * scale)
                new_height = int(height * scale)
                gray = cv2.resize(gray, (new_width, new_height))
            
            # Apply threshold to get black text on white background
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # Extract text using Tesseract
            text = pytesseract.image_to_string(thresh, config='--psm 6')
            
            # Get confidence scores
            data = pytesseract.image_to_data(thresh, output_type=pytesseract.Output.DICT)
            confidences = [int(conf) for conf in data['conf'] if int(conf) > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            # Extract individual words
            words = text.split()
            
            return {
                'success': True,
                'text': text.strip(),
                'words': words,
                'confidence': avg_confidence,
                'word_count': len(words)
            }
            
        except Exception as e:
            logger.error(f"Error extracting text from image: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _is_video_file(self, file_path: str) -> bool:
        """Check if file is a video based on extension"""
        video_extensions = {'.mp4', '.mov', '.avi', '.wmv', '.flv', '.webm'}
        return Path(file_path).suffix.lower() in video_extensions
    
    def _extract_frames_from_video(self, video_path: str) -> List[str]:
        """Extract frames from video at regular intervals"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise Exception("Could not open video file")
            
            # Get video properties
            fps = cap.get(cv2.CAP_PROP_FPS)
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration = total_frames / fps if fps > 0 else 0
            
            # Check video duration
            if duration > self.max_video_duration:
                raise Exception(f"Video too long ({duration:.1f}s). Maximum allowed: {self.max_video_duration}s")
            if duration < self.min_video_duration:
                raise Exception(f"Video too short ({duration:.1f}s). Minimum required: {self.min_video_duration}s")
            
            # Calculate frame interval
            frame_interval = int(fps * self.video_frame_interval)
            if frame_interval < 1:
                frame_interval = 1
            
            frame_paths = []
            frame_count = 0
            extracted_count = 0
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # Extract frame at intervals
                if frame_count % frame_interval == 0:
                    # Save frame to temporary file
                    frame_filename = f"frame_{extracted_count:03d}.jpg"
                    frame_path = os.path.join(tempfile.gettempdir(), frame_filename)
                    
                    # Save frame
                    cv2.imwrite(frame_path, frame)
                    frame_paths.append(frame_path)
                    extracted_count += 1
                    
                    # Limit number of frames to process
                    if extracted_count >= 10:  # Max 10 frames
                        break
                
                frame_count += 1
            
            cap.release()
            
            if not frame_paths:
                raise Exception("No frames could be extracted from video")
            
            logger.info(f"Extracted {len(frame_paths)} frames from video")
            return frame_paths
            
        except Exception as e:
            logger.error(f"Error extracting frames from video: {str(e)}")
            raise e
    
    def _process_video_for_verification(self, video_path: str, expected_code: str) -> Dict:
        """Process video file for verification code detection"""
        try:
            # Extract frames from video
            frame_paths = self._extract_frames_from_video(video_path)
            
            best_result = None
            best_confidence = 0
            all_ocr_results = []
            
            # Process each frame
            for i, frame_path in enumerate(frame_paths):
                try:
                    # Extract text from frame
                    ocr_result = self._extract_text_from_image(frame_path)
                    all_ocr_results.append({
                        'frame': i + 1,
                        'path': frame_path,
                        'result': ocr_result
                    })
                    
                    if ocr_result['success']:
                        # Check if verification code is found in this frame
                        code_found = self._find_verification_code(ocr_result, expected_code)
                        
                        if code_found['found'] and code_found['confidence'] > best_confidence:
                            best_result = {
                                'frame': i + 1,
                                'frame_path': frame_path,
                                'ocr_result': ocr_result,
                                'code_found': code_found
                            }
                            best_confidence = code_found['confidence']
                    
                except Exception as e:
                    logger.error(f"Error processing frame {i + 1}: {str(e)}")
                    continue
            
            # Clean up frame files
            for frame_path in frame_paths:
                try:
                    os.remove(frame_path)
                except:
                    pass
            
            if best_result:
                return {
                    'success': True,
                    'video_processed': True,
                    'total_frames': len(frame_paths),
                    'best_frame': best_result['frame'],
                    'ocr_result': best_result['ocr_result'],
                    'verification_result': best_result['code_found'],
                    'all_frames_processed': len(all_ocr_results)
                }
            else:
                return {
                    'success': False,
                    'video_processed': True,
                    'total_frames': len(frame_paths),
                    'error': 'Verification code not found in any frame',
                    'all_frames_processed': len(all_ocr_results)
                }
                
        except Exception as e:
            logger.error(f"Error processing video for verification: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _find_verification_code(self, ocr_result: Dict, expected_code: str) -> Dict:
        """Find verification code in OCR result"""
        if not ocr_result.get('success', False):
            return {
                'found': False,
                'error': ocr_result.get('error', 'OCR failed'),
                'expected_code': expected_code,
                'found_codes': []
            }
        
        text = ocr_result.get('text', '').upper()
        words = ocr_result.get('words', [])
        
        # Look for exact match
        if expected_code in text:
            return {
                'found': True,
                'expected_code': expected_code,
                'found_codes': [expected_code],
                'match_type': 'exact',
                'confidence': ocr_result.get('confidence', 0)
            }
        
        # Look for partial matches (allowing for OCR errors)
        found_codes = []
        for word in words:
            word_upper = word.upper()
            # Check if word contains the expected code
            if expected_code in word_upper:
                found_codes.append(word_upper)
            # Check for similar codes (allowing 1-2 character differences)
            elif len(word_upper) == len(expected_code):
                differences = sum(1 for a, b in zip(word_upper, expected_code) if a != b)
                if differences <= 2:  # Allow up to 2 character differences
                    found_codes.append(word_upper)
        
        if found_codes:
            return {
                'found': True,
                'expected_code': expected_code,
                'found_codes': found_codes,
                'match_type': 'partial',
                'confidence': ocr_result.get('confidence', 0)
            }
        
        return {
            'found': False,
            'expected_code': expected_code,
            'found_codes': [],
            'confidence': ocr_result.get('confidence', 0)
        }
    
    def cancel_check_request(self, request_id: str, keyholder_email: str) -> Dict:
        """Cancel a check request (only by the requesting keyholder)"""
        try:
            check_request = self.get_check_request(request_id)
            if not check_request:
                return {
                    'success': False,
                    'error': 'Check request not found'
                }
            
            if check_request['keyholder_email'] != keyholder_email:
                return {
                    'success': False,
                    'error': 'Unauthorized to cancel this request'
                }
            
            if check_request['status'] != 'pending':
                return {
                    'success': False,
                    'error': f'Cannot cancel {check_request["status"]} request'
                }
            
            # Mark as cancelled
            check_request['status'] = 'cancelled'
            check_request['completed_at'] = datetime.now().isoformat()
            
            # Remove verification code
            verification_code = check_request['verification_code']
            if verification_code in self.verification_codes:
                del self.verification_codes[verification_code]
            
            self._save_cage_checks()
            self._save_verification_codes()
            
            return {
                'success': True,
                'message': 'Check request cancelled successfully'
            }
            
        except Exception as e:
            logger.error(f"Error cancelling check request: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_check_statistics(self, keyholder_email: str = None) -> Dict:
        """Get statistics for check requests"""
        try:
            all_checks = self.get_all_checks(keyholder_email)
            
            stats = {
                'total_checks': len(all_checks),
                'pending': 0,
                'completed': 0,
                'failed': 0,
                'expired': 0,
                'cancelled': 0,
                'success_rate': 0
            }
            
            for check in all_checks:
                status = check['status']
                if status in stats:
                    stats[status] += 1
            
            # Calculate success rate
            if stats['completed'] + stats['failed'] > 0:
                stats['success_rate'] = (stats['completed'] / (stats['completed'] + stats['failed'])) * 100
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting check statistics: {str(e)}")
            return {}
    
    def cleanup_expired_codes(self):
        """Remove expired verification codes"""
        try:
            current_time = datetime.now()
            expired_codes = []
            
            for code, code_data in self.verification_codes.items():
                expires_at = datetime.fromisoformat(code_data['expires_at'])
                if current_time > expires_at:
                    expired_codes.append(code)
            
            for code in expired_codes:
                del self.verification_codes[code]
            
            if expired_codes:
                self._save_verification_codes()
                logger.info(f"Cleaned up {len(expired_codes)} expired verification codes")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired codes: {str(e)}")
    
    def get_all_check_requests(self) -> List[Dict]:
        """Get all cage check requests (alias for get_all_checks)"""
        return self.get_all_checks()
    
    def get_recent_checks(self, limit: int = 5) -> List[Dict]:
        """Get recent cage check requests"""
        all_checks = list(self.cage_checks.values())
        # Sort by created_at (newest first)
        all_checks.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return all_checks[:limit] 