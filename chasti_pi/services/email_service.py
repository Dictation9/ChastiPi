"""
Email service for ChastiPi - handles keyholder notifications and email-based management
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging
from datetime import datetime, timedelta
from chasti_pi.core.config import config
from typing import Optional, List, Dict
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class EmailService:
    """Handles email communication for keyholder management"""
    
    def __init__(self, config_file="config.json"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        self.smtp_server = None
        self.smtp_port = None
        self.email_address = None
        self.password = None
        self.use_tls = True
        self.external_url = config.get('external_url', 'http://localhost:5000')
        
        if self.config:
            self._setup_smtp()
    
    def _load_config(self) -> Optional[Dict]:
        """Load email configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    return config.get('email', {})
        except Exception as e:
            logger.error(f"Error loading email config: {str(e)}")
        return None
    
    def _setup_smtp(self):
        """Setup SMTP configuration"""
        if self.config:
            self.smtp_server = self.config.get('smtp_server')
            self.smtp_port = self.config.get('smtp_port', 587)
            self.email_address = self.config.get('email_address')
            self.password = self.config.get('email_password')
            self.use_tls = self.config.get('use_tls', True)
    
    def is_configured(self) -> bool:
        """Check if email service is properly configured"""
        return all([
            self.smtp_server,
            self.email_address,
            self.password
        ])
    
    def send_key_request_email(self, keyholder_email, device_name, request_id, duration_hours, reason=""):
        """Send key request notification to keyholder with email-first approach"""
        try:
            subject = f"🔐 Key Request: {device_name} - {duration_hours}h"
            
            # Create email content prioritizing email replies
            body = self._create_key_request_body(device_name, request_id, duration_hours, reason)
            
            # Send email
            self._send_email(keyholder_email, subject, body)
            
            logger.info(f"Key request email sent to {keyholder_email} for device {device_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send key request email: {e}")
            return False
    
    def _create_key_request_body(self, device_name, request_id, duration_hours, reason):
        """Create email body prioritizing email replies for remote access"""
        web_url = f"{self.external_url}/keyholder/approve/{request_id}"
        
        # Convert hours to human-readable format
        duration_text = self._format_duration(duration_hours)
        
        body = f"""
🔐 **Key Request for {device_name}**

**Duration:** {duration_text}
**Request ID:** {request_id}
**Reason:** {reason or "No reason provided"}

---

## 📧 **Reply via Email (Works from anywhere!)**

Simply reply to this email with one of these commands:

**✅ APPROVE** - Approve the request
**❌ DENY** - Deny the request  
**⏰ EXTEND 2** - Extend by 2 hours
**⏰ EXTEND 3 days** - Extend by 3 days
**⏰ EXTEND 1 week** - Extend by 1 week
**⏰ EXTEND 2 months** - Extend by 2 months
**⏱️ REDUCE 1** - Reduce to 1 hour
**⏱️ REDUCE 2 days** - Reduce to 2 days
**🚨 EMERGENCY** - Emergency release

**Examples:**
- Reply with: "APPROVE"
- Reply with: "EXTEND 3" 
- Reply with: "EXTEND 20 days"
- Reply with: "EXTEND 1 week"
- Reply with: "EXTEND 2 months"
- Reply with: "REDUCE 1"
- Reply with: "REDUCE 1 day"
- Reply with: "DENY - not enough time"

**Supported Time Units:**
- **Minutes:** 30 min, 1 minute
- **Hours:** 2 h, 3 hours
- **Days:** 1 d, 5 days
- **Weeks:** 1 w, 2 weeks
- **Months:** 1 m, 3 months
- **Years:** 1 y, 1 year

---

## 🌐 **Web Interface (Local network only)**

If you're on the same WiFi network as the device:
{web_url}

**Note:** Web interface only works when connected to the same network as the Raspberry Pi.

---

## 📱 **Mobile Access**

You can reply to this email from your phone's email app. No special setup required!

---

**Device:** {device_name}
**Request Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Expires:** {(datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')}
"""
        return body
    
    def _format_duration(self, hours):
        """Convert hours to human-readable format"""
        if hours < 1:
            minutes = int(hours * 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        elif hours < 24:
            return f"{hours:.1f} hour{'s' if hours != 1 else ''}"
        elif hours < 168:  # 7 days
            days = hours / 24
            return f"{days:.1f} day{'s' if days != 1 else ''}"
        elif hours < 730:  # ~30 days
            weeks = hours / 168
            return f"{weeks:.1f} week{'s' if weeks != 1 else ''}"
        elif hours < 8760:  # ~365 days
            months = hours / 730
            return f"{months:.1f} month{'s' if months != 1 else ''}"
        else:
            years = hours / 8760
            return f"{years:.1f} year{'s' if years != 1 else ''}"
    
    def send_approval_confirmation(self, keyholder_email, device_name, request_id, action, duration=None):
        """Send confirmation email when keyholder responds"""
        try:
            subject = f"✅ Key Request {action.upper()}: {device_name}"
            
            body = f"""
✅ **Key Request {action.upper()}**

**Device:** {device_name}
**Request ID:** {request_id}
**Action:** {action.upper()}
{f"**Duration:** {duration} hours" if duration else ""}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Your response has been processed successfully.

---
*This is an automated confirmation from ChastiPi*
"""
            
            self._send_email(keyholder_email, subject, body)
            logger.info(f"Approval confirmation sent to {keyholder_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send approval confirmation: {e}")
            return False
    
    def send_emergency_notification(self, keyholder_email, device_name, reason=""):
        """Send emergency notification to keyholder"""
        try:
            subject = f"🚨 EMERGENCY: {device_name} - Immediate Action Required"
            
            body = f"""
🚨 **EMERGENCY NOTIFICATION**

**Device:** {device_name}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Reason:** {reason or "Emergency release requested"}

**IMMEDIATE ACTION REQUIRED**

The device has been released due to an emergency situation.

Please check on the device owner and ensure their safety.

---
*This is an automated emergency notification from ChastiPi*
"""
            
            self._send_email(keyholder_email, subject, body)
            logger.info(f"Emergency notification sent to {keyholder_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send emergency notification: {e}")
            return False
    
    def _send_email(self, to_email, subject, body):
        """Send email using configured SMTP settings"""
        if not self.email_address or not self.password:
            logger.error("Email credentials not configured")
            return False
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Create SMTP session
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            
            # Login and send
            server.login(self.email_address, self.password)
            text = msg.as_string()
            server.sendmail(self.email_address, to_email, text)
            server.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def is_remote_access_required(self, client_ip):
        """Check if remote access is required based on client IP"""
        # This is a simplified check - in production you'd want more sophisticated network detection
        local_networks = [
            '192.168.1.', '192.168.0.', '10.0.0.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.', '127.0.0.1', 'localhost'
        ]
        
        for network in local_networks:
            if client_ip.startswith(network):
                return False
        
        return True
    
    def configure_email(self, smtp_server, smtp_port, email_address, password, use_tls=True):
        """Configure email settings"""
        config.set('smtp_server', smtp_server)
        config.set('smtp_port', smtp_port)
        config.set('email_address', email_address)
        config.set('email_password', password)
        config.set('use_tls', use_tls)
        
        # Update instance variables
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.email_address = email_address
        self.password = password
        self.use_tls = use_tls
        
        return {"success": True, "message": "Email configuration saved"}
    
    def send_email_with_attachment(self, to_email: str, subject: str, body: str, 
                                 attachment_name: str, attachment_content: str, 
                                 attachment_type: str = "text/plain") -> bool:
        """Send email with attachment"""
        try:
            if not self.is_configured():
                logger.error("Email service not configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Add attachment
            attachment = MIMEText(attachment_content, attachment_type)
            attachment.add_header('Content-Disposition', 'attachment', filename=attachment_name)
            msg.attach(attachment)
            
            # Send email
            return self._send_message(msg)
            
        except Exception as e:
            logger.error(f"Error sending email with attachment: {str(e)}")
            return False
    
    def send_email_with_multiple_attachments(self, to_email: str, subject: str, body: str, 
                                           attachments: List[Dict]) -> bool:
        """Send email with multiple attachments"""
        try:
            if not self.is_configured():
                logger.error("Email service not configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Add attachments
            for attachment_info in attachments:
                attachment_name = attachment_info.get('name', 'attachment')
                attachment_content = attachment_info.get('content', '')
                attachment_type = attachment_info.get('type', 'text/plain')
                
                attachment = MIMEText(attachment_content, attachment_type)
                attachment.add_header('Content-Disposition', 'attachment', filename=attachment_name)
                msg.attach(attachment)
            
            # Send email
            return self._send_message(msg)
            
        except Exception as e:
            logger.error(f"Error sending email with multiple attachments: {str(e)}")
            return False
    
    def _send_message(self, msg: MIMEMultipart) -> bool:
        """Send message via SMTP"""
        try:
            # Connect to SMTP server
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            
            if self.use_tls:
                server.starttls()
            
            # Login
            server.login(self.email_address, self.password)
            
            # Send email
            text = msg.as_string()
            server.sendmail(self.email_address, msg['To'], text)
            
            # Close connection
            server.quit()
            
            logger.info(f"Email sent successfully to {msg['To']}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            return False
    
    def send_key_release_request(self, keyholder_email: str, request_data: Dict, approval_url: str) -> Dict:
        """Send key release request notification to keyholder"""
        try:
            subject = f"🔑 Key Release Request: {request_data.get('device_name', 'Device')}"
            
            body = f"""
🔐 **Key Release Request**

A request has been made for temporary access to your keys.

**Request Details:**
- **Device:** {request_data.get('device_name', 'Unknown')}
- **Request ID:** {request_data.get('request_id', 'Unknown')}
- **Duration:** {request_data.get('duration_hours', 0)} hours
- **Reason:** {request_data.get('reason', 'No reason provided')}
- **Requested:** {request_data.get('requested_at', 'Unknown')}

**Quick Actions:**
- **Approve:** {approval_url}?action=approve&request_id={request_data.get('request_id')}
- **Deny:** {approval_url}?action=deny&request_id={request_data.get('request_id')}

**Email Commands:**
You can also reply to this email with:
- "approve" - to approve this request
- "deny" - to deny this request
- "extend 2 hours" - to extend the duration
- "reduce 1 hour" - to reduce the duration
- "emergency" - for emergency release

**Note:** This request will expire in 24 hours if not responded to.

---
*This is an automated notification from your ChastiPi system.*
"""
            
            success = self.send_email(keyholder_email, subject, body)
            
            return {
                'success': success,
                'message': 'Key release request sent successfully' if success else 'Failed to send request'
            }
            
        except Exception as e:
            logger.error(f"Error sending key release request: {str(e)}")
            return {
                'success': False,
                'error': f'Error sending request: {str(e)}'
            }
    
    def send_key_approved_notification(self, user_email: str, request_data: Dict, access_token: str, base_url: str) -> Dict:
        """Send key approved notification to user"""
        try:
            subject = "✅ Key Release Approved"
            
            access_url = f"{base_url}/keyholder/access?token={access_token}&device_id={request_data.get('device_id')}"
            
            body = f"""
✅ **Key Release Approved**

Your request for temporary key access has been approved.

**Request Details:**
- **Device:** {request_data.get('device_name', 'Unknown')}
- **Duration:** {request_data.get('duration_hours', 0)} hours
- **Expires:** {request_data.get('expires_at', 'Unknown')}

**Access Your Keys:**
{access_url}

**Important:**
- Your access token expires at {request_data.get('expires_at', 'Unknown')}
- Keep this email secure
- Contact your keyholder if you need assistance

---
*This is an automated notification from your ChastiPi system.*
"""
            
            success = self.send_email(user_email, subject, body)
            
            return {
                'success': success,
                'message': 'Approval notification sent successfully' if success else 'Failed to send notification'
            }
            
        except Exception as e:
            logger.error(f"Error sending approval notification: {str(e)}")
            return {
                'success': False,
                'error': f'Error sending notification: {str(e)}'
            }
    
    def send_key_denied_notification(self, user_email: str, request_data: Dict) -> Dict:
        """Send key denied notification to user"""
        try:
            subject = "❌ Key Release Denied"
            
            body = f"""
❌ **Key Release Denied**

Your request for temporary key access has been denied.

**Request Details:**
- **Device:** {request_data.get('device_name', 'Unknown')}
- **Request ID:** {request_data.get('request_id', 'Unknown')}
- **Reason:** {request_data.get('denial_reason', 'No reason provided')}

**Next Steps:**
- Contact your keyholder for more information
- Wait for a new request approval
- Ensure you follow all rules and guidelines

---
*This is an automated notification from your ChastiPi system.*
"""
            
            success = self.send_email(user_email, subject, body)
            
            return {
                'success': success,
                'message': 'Denial notification sent successfully' if success else 'Failed to send notification'
            }
            
        except Exception as e:
            logger.error(f"Error sending denial notification: {str(e)}")
            return {
                'success': False,
                'error': f'Error sending notification: {str(e)}'
            }
    
    def test_email_configuration(self, test_email: str) -> Dict:
        """Test email configuration by sending a test email"""
        try:
            subject = "🧪 ChastiPi Email Configuration Test"
            
            body = f"""
🧪 **Email Configuration Test**

This is a test email to verify your ChastiPi email configuration is working correctly.

**Test Details:**
- **Sent:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **SMTP Server:** {self.smtp_server}
- **Username:** {self.email_address}
- **TLS Enabled:** {self.use_tls}

**If you received this email:**
✅ Your email configuration is working correctly
✅ You can receive notifications from ChastiPi
✅ Keyholder management via email is available

**Next Steps:**
1. Configure your keyholder settings
2. Test key request notifications
3. Set up email reply processing

---
*This is an automated test from your ChastiPi system.*
"""
            
            success = self.send_email(test_email, subject, body)
            
            return {
                'success': success,
                'message': 'Test email sent successfully' if success else 'Failed to send test email'
            }
            
        except Exception as e:
            logger.error(f"Error sending test email: {str(e)}")
            return {
                'success': False,
                'error': f'Error sending test email: {str(e)}'
            } 