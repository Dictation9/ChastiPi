"""
Email Reply Service for ChastiPi
Handles incoming email replies for keyholder management
"""
import re
import json
from datetime import datetime, timedelta
from pathlib import Path
from email.parser import Parser
from email import message_from_string
import logging
from typing import Dict, List, Optional, Tuple

from .key_storage_service import KeyStorageService
from .email_service import EmailService
from .keyholder_config_service import KeyholderConfigService

logger = logging.getLogger(__name__)

class EmailReplyService:
    """Service for processing email replies from keyholders"""
    
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize other services
        self.key_storage = KeyStorageService()
        self.email_service = EmailService()
        self.config_service = KeyholderConfigService()
        
        # Load reply patterns
        self.reply_patterns = self._load_reply_patterns()
        
        # Command patterns
        self.command_patterns = {
            'approve': r'\b(approve|yes|ok|accept)\b',
            'deny': r'\b(deny|no|reject|decline)\b',
            'extend': r'\bextend\s+(\d+)\s*(hours?|days?|weeks?|months?|years?)\b',
            'reduce': r'\breduce\s+(\d+)\s*(hours?|days?|weeks?|months?|years?)\b',
            'emergency': r'\b(emergency|urgent|help)\b',
            'settings': r'\b(settings|config|configuration)\b',
            'status': r'\b(status|info|information)\b',
            'help': r'\b(help|commands|what)\b'
        }
        
        # Time unit multipliers
        self.time_multipliers = {
            'hour': 1,
            'hours': 1,
            'day': 24,
            'days': 24,
            'week': 168,
            'weeks': 168,
            'month': 720,
            'months': 720,
            'year': 8760,
            'years': 8760
        }
    
    def _load_reply_patterns(self):
        """Load email reply patterns and commands"""
        return {
            'approve': [
                r'\b(approve|yes|ok|grant|allow)\b',
                r'\b✅\b',
                r'\b👍\b',
                r'\b(yes|ok|grant|allow)\s+(?:the\s+)?(?:key\s+)?(?:release\s+)?(?:request)?\b'
            ],
            'deny': [
                r'\b(deny|no|reject|decline|refuse)\b',
                r'\b❌\b',
                r'\b👎\b',
                r'\b(no|reject|decline|refuse)\s+(?:the\s+)?(?:key\s+)?(?:release\s+)?(?:request)?\b'
            ],
            'extend': [
                r'\b(extend|more\s+time|longer|additional)\b',
                # Hours
                r'\b(?:extend|give|add)\s+(?:me\s+)?(\d+(?:\.\d+)?)\s*(?:hours?|hrs?|h)\b',
                # Days
                r'\b(?:extend|give|add)\s+(?:me\s+)?(\d+(?:\.\d+)?)\s*(?:days?|d)\b',
                # Weeks
                r'\b(?:extend|give|add)\s+(?:me\s+)?(\d+(?:\.\d+)?)\s*(?:weeks?|wks?|w)\b',
                # Months
                r'\b(?:extend|give|add)\s+(?:me\s+)?(\d+(?:\.\d+)?)\s*(?:months?|mos?|m)\b',
                # Years
                r'\b(?:extend|give|add)\s+(?:me\s+)?(\d+(?:\.\d+)?)\s*(?:years?|yrs?|y)\b',
                # Minutes
                r'\b(?:extend|give|add)\s+(?:me\s+)?(\d+(?:\.\d+)?)\s*(?:minutes?|mins?|min)\b'
            ],
            'reduce': [
                r'\b(reduce|less\s+time|shorter|cut)\b',
                # Hours
                r'\b(?:reduce|cut|set)\s+(?:to\s+)?(\d+(?:\.\d+)?)\s*(?:hours?|hrs?|h)\b',
                # Days
                r'\b(?:reduce|cut|set)\s+(?:to\s+)?(\d+(?:\.\d+)?)\s*(?:days?|d)\b',
                # Weeks
                r'\b(?:reduce|cut|set)\s+(?:to\s+)?(\d+(?:\.\d+)?)\s*(?:weeks?|wks?|w)\b',
                # Months
                r'\b(?:reduce|cut|set)\s+(?:to\s+)?(\d+(?:\.\d+)?)\s*(?:months?|mos?|m)\b',
                # Years
                r'\b(?:reduce|cut|set)\s+(?:to\s+)?(\d+(?:\.\d+)?)\s*(?:years?|yrs?|y)\b',
                # Minutes
                r'\b(?:reduce|cut|set)\s+(?:to\s+)?(\d+(?:\.\d+)?)\s*(?:minutes?|mins?|min)\b'
            ],
            'emergency': [
                r'\b(emergency|urgent|asap|immediately)\b',
                r'\b🚨\b',
                r'\b⚠️\b'
            ]
        }
    
    def _parse_time_unit(self, text, value):
        """Parse time value and unit from text, return hours"""
        text_lower = text.lower()
        
        # Check for different time units
        if any(unit in text_lower for unit in ['year', 'yr', 'y']):
            return float(value) * 8760  # 365 days * 24 hours
        elif any(unit in text_lower for unit in ['month', 'mo', 'm']):
            return float(value) * 730   # 30.4 days * 24 hours
        elif any(unit in text_lower for unit in ['week', 'wk', 'w']):
            return float(value) * 168   # 7 days * 24 hours
        elif any(unit in text_lower for unit in ['day', 'd']):
            return float(value) * 24    # 24 hours
        elif any(unit in text_lower for unit in ['hour', 'hr', 'h']):
            return float(value)         # Already in hours
        elif any(unit in text_lower for unit in ['minute', 'min']):
            return float(value) / 60    # Convert to hours
        else:
            # Default to hours if no unit specified
            return float(value)
    
    def process_email_reply(self, email_content, from_email):
        """Process an email reply from a keyholder"""
        try:
            # Parse email content
            email_data = self._parse_email(email_content)
            
            # Extract key information
            subject = email_data.get('subject', '')
            body = email_data.get('body', '')
            reply_to = email_data.get('reply_to', '')
            
            # Find request ID from subject or body
            request_id = self._extract_request_id(subject, body)
            if not request_id:
                logger.warning(f"No request ID found in email from {from_email}")
                return {"error": "No request ID found in email"}
            
            # Verify keyholder email matches request
            if not self._verify_keyholder(request_id, from_email):
                logger.warning(f"Email {from_email} not authorized for request {request_id}")
                return {"error": "Unauthorized email address"}
            
            # Analyze reply content
            action = self._analyze_reply(body)
            if not action:
                return {"error": "Could not determine action from email reply"}
            
            # Process the action
            return self._process_action(request_id, action, body)
            
        except Exception as e:
            logger.error(f"Error processing email reply: {str(e)}")
            return {"error": f"Failed to process email reply: {str(e)}"}
    
    def _parse_email(self, email_content):
        """Parse email content and extract key information"""
        try:
            # Parse email using email parser
            email_message = message_from_string(email_content)
            
            # Extract subject
            subject = email_message.get('subject', '')
            
            # Extract body (handle multipart emails)
            body = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
            else:
                body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            # Clean up body (remove quoted text, signatures, etc.)
            body = self._clean_email_body(body)
            
            return {
                'subject': subject,
                'body': body,
                'reply_to': email_message.get('reply-to', '')
            }
            
        except Exception as e:
            logger.error(f"Error parsing email: {str(e)}")
            return {'subject': '', 'body': '', 'reply_to': ''}
    
    def _clean_email_body(self, body):
        """Clean email body by removing quoted text, signatures, etc."""
        lines = body.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Skip quoted text (lines starting with >)
            if line.strip().startswith('>'):
                continue
            
            # Skip common email signature patterns
            if any(pattern in line.lower() for pattern in [
                'sent from my', 'get outlook', 'sent from iphone', 
                'sent from mobile', 'best regards', 'sincerely',
                'thank you', 'thanks', 'cheers'
            ]):
                continue
            
            # Stop at common email endings
            if any(pattern in line.lower() for pattern in [
                '---', '___', 'sent from', 'get outlook'
            ]):
                break
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines).strip()
    
    def _extract_request_id(self, subject, body):
        """Extract request ID from email subject or body"""
        # Look for request ID pattern: REQ_YYYYMMDD_HHMMSS_XXXX
        request_pattern = r'REQ_\d{8}_\d{6}_[a-f0-9]{8}'
        
        # Check subject first
        subject_match = re.search(request_pattern, subject)
        if subject_match:
            return subject_match.group(0)
        
        # Check body
        body_match = re.search(request_pattern, body)
        if body_match:
            return body_match.group(0)
        
        return None
    
    def _verify_keyholder(self, request_id, email):
        """Verify that the email matches the keyholder for this request"""
        request = self.key_storage.key_requests.get(request_id)
        if not request:
            return False
        
        return request.get('keyholder_email', '').lower() == email.lower()
    
    def _analyze_reply(self, body):
        """Analyze email body to determine the action"""
        body_lower = body.lower()
        
        # Check for approve patterns
        for pattern in self.reply_patterns['approve']:
            if re.search(pattern, body_lower):
                return {'action': 'approve'}
        
        # Check for deny patterns
        for pattern in self.reply_patterns['deny']:
            if re.search(pattern, body_lower):
                return {'action': 'deny', 'reason': self._extract_denial_reason(body)}
        
        # Check for extend patterns with time units
        for pattern in self.reply_patterns['extend']:
            match = re.search(pattern, body_lower)
            if match:
                if match.groups():
                    value = match.group(1)
                    hours = self._parse_time_unit(body_lower, value)
                    return {'action': 'extend', 'hours': hours}
                else:
                    return {'action': 'extend', 'hours': 1}
        
        # Check for reduce patterns with time units
        for pattern in self.reply_patterns['reduce']:
            match = re.search(pattern, body_lower)
            if match:
                if match.groups():
                    value = match.group(1)
                    hours = self._parse_time_unit(body_lower, value)
                    return {'action': 'reduce', 'hours': hours}
                else:
                    return {'action': 'reduce', 'hours': 1}
        
        # Check for emergency patterns
        for pattern in self.reply_patterns['emergency']:
            if re.search(pattern, body_lower):
                return {'action': 'emergency'}
        
        return None
    
    def _extract_denial_reason(self, body):
        """Extract denial reason from email body"""
        # Look for common denial reason patterns
        reason_patterns = [
            r'(?:because|reason|why|since)\s*:?\s*(.+)',
            r'(?:denied|rejected|declined)\s+(?:because|since|as)\s+(.+)',
            r'(?:not\s+allowed|not\s+approved)\s+(?:because|since|as)\s+(.+)'
        ]
        
        for pattern in reason_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                reason = match.group(1).strip()
                # Clean up the reason
                reason = re.sub(r'[^\w\s\-.,!?]', '', reason)
                return reason[:200]  # Limit length
        
        return "Denied by keyholder"
    
    def _process_action(self, request_id, action, body):
        """Process the keyholder action"""
        try:
            action_type = action.get('action')
            
            if action_type == 'approve':
                # Handle approval with potential duration modification
                modified_duration = action.get('hours')
                result = self.key_storage.approve_key_release(request_id, modified_duration=modified_duration)
                
                if result.get('success'):
                    self._send_approval_notification(result)
                
                return result
                
            elif action_type == 'deny':
                reason = action.get('reason', 'Denied by keyholder')
                result = self.key_storage.deny_key_release(request_id, reason)
                
                if result.get('success'):
                    self._send_denial_notification(result)
                
                return result
                
            elif action_type == 'extend':
                hours = action.get('hours', 1)
                result = self.key_storage.extend_request_duration(request_id, hours)
                
                if result.get('success'):
                    self._send_duration_modification_notification(result, 'extended')
                
                return result
                
            elif action_type == 'reduce':
                hours = action.get('hours', 1)
                result = self.key_storage.reduce_request_duration(request_id, hours)
                
                if result.get('success'):
                    self._send_duration_modification_notification(result, 'reduced')
                
                return result
                
            elif action_type == 'emergency':
                result = self._mark_emergency(request_id)
                
                if result.get('success'):
                    self._send_emergency_notification(result)
                
                return result
                
            else:
                return {"error": f"Unknown action: {action_type}"}
                
        except Exception as e:
            logger.error(f"Error processing action: {str(e)}")
            return {"error": f"Failed to process action: {str(e)}"}
    
    def _send_duration_modification_notification(self, result, modification_type):
        """Send notification about duration modification"""
        try:
            request = result['request']
            device_id = request['device_id']
            device_info = self.key_storage.get_device_info(device_id)
            
            if device_info:
                keyholder_email = device_info['keyholder_email']
                
                subject = f"⏰ Duration {modification_type.title()}: {device_info['device_name']}"
                
                body = f"""
⏰ **Duration {modification_type.upper()}**

**Device:** {device_info['device_name']}
**Request ID:** {request['request_id']}
**Action:** Duration {modification_type}
**Original Duration:** {result.get('original_duration', 'Unknown')} hours
**New Duration:** {result.get('new_duration', 'Unknown')} hours
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

The request duration has been {modification_type} successfully.

---
*This is an automated confirmation from ChastiPi*
"""
                
                self.email_service._send_email(keyholder_email, subject, body)
                logger.info(f"Duration modification notification sent to {keyholder_email}")
                
        except Exception as e:
            logger.error(f"Failed to send duration modification notification: {e}")
    
    def _mark_emergency(self, request_id):
        """Mark a request as emergency"""
        request = self.key_storage.key_requests.get(request_id)
        if not request:
            return {"error": "Request not found"}
        
        if request["status"] != "pending":
            return {"error": "Can only modify pending requests"}
        
        # Mark as emergency
        request["emergency"] = True
        self.key_storage._save_data()
        
        return {
            "success": True,
            "message": "Request marked as emergency"
        }
    
    def _send_approval_notification(self, result):
        """Send notification when request is approved via email"""
        if not self.email_service.is_configured():
            return
        
        # Get user email (you might need to store this in the request)
        user_email = "user@example.com"  # This should come from the request
        base_url = "http://localhost:5000"  # This should come from config
        
        self.email_service.send_key_approved_notification(
            user_email,
            result["request"],
            result["access_token"],
            base_url
        )
    
    def _send_denial_notification(self, result):
        """Send notification when request is denied via email"""
        if not self.email_service.is_configured():
            return
        
        # Get user email (you might need to store this in the request)
        user_email = "user@example.com"  # This should come from the request
        
        self.email_service.send_key_denied_notification(user_email, result["request"])
    
    def create_webhook_endpoint(self, app):
        """Create a webhook endpoint for receiving emails"""
        @app.route('/webhook/email', methods=['POST'])
        def email_webhook():
            """Webhook endpoint for receiving email replies"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({"error": "No data received"}), 400
                
                email_content = data.get('email_content')
                from_email = data.get('from_email')
                
                if not email_content or not from_email:
                    return jsonify({"error": "Missing email content or sender"}), 400
                
                # Process the email reply
                result = self.process_email_reply(email_content, from_email)
                
                if "error" in result:
                    return jsonify(result), 400
                
                return jsonify(result)
                
            except Exception as e:
                logger.error(f"Webhook error: {str(e)}")
                return jsonify({"error": "Internal server error"}), 500
        
        return email_webhook

    def process_email_reply(self, from_email: str, subject: str, body: str, attachments: List[Dict] = None) -> Dict:
        """Process an email reply from a keyholder"""
        try:
            logger.info(f"Processing email reply from {from_email}")
            
            # Check if this is a configuration file attachment
            if attachments and self._is_config_file(attachments):
                return self._process_config_file(from_email, attachments)
            
            # Extract commands from email body
            commands = self._extract_commands(body.lower())
            
            if not commands:
                return {
                    'success': False,
                    'error': 'No valid commands found in email'
                }
            
            # Process each command
            results = []
            for command in commands:
                result = self._process_command(from_email, command)
                results.append(result)
            
            return {
                'success': True,
                'commands_processed': len(commands),
                'results': results
            }
            
        except Exception as e:
            logger.error(f"Error processing email reply: {str(e)}")
            return {
                'success': False,
                'error': f'Error processing email: {str(e)}'
            }

    def _is_config_file(self, attachments: List[Dict]) -> bool:
        """Check if attachments contain a configuration file"""
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            if filename.endswith('.json') or filename.endswith('.txt'):
                return True
        return False

    def _process_config_file(self, from_email: str, attachments: List[Dict]) -> Dict:
        """Process a configuration file attachment"""
        try:
            for attachment in attachments:
                filename = attachment.get('filename', '').lower()
                content = attachment.get('content', '')
                
                if filename.endswith('.json'):
                    # Process JSON configuration
                    config_data = json.loads(content)
                    success = self.config_service.import_config(from_email, config_data)
                    
                    if success:
                        # Send confirmation email
                        self._send_config_import_confirmation(from_email, filename)
                        return {
                            'success': True,
                            'message': f'Configuration imported successfully from {filename}',
                            'type': 'config_import'
                        }
                    else:
                        return {
                            'success': False,
                            'error': f'Failed to import configuration from {filename}',
                            'type': 'config_import_error'
                        }
                
                elif filename.endswith('.txt'):
                    # Process text configuration
                    success = self._process_text_config(from_email, content)
                    
                    if success:
                        self._send_config_import_confirmation(from_email, filename)
                        return {
                            'success': True,
                            'message': f'Configuration imported successfully from {filename}',
                            'type': 'config_import'
                        }
                    else:
                        return {
                            'success': False,
                            'error': f'Failed to import configuration from {filename}',
                            'type': 'config_import_error'
                        }
            
            return {
                'success': False,
                'error': 'No valid configuration file found in attachments',
                'type': 'config_import_error'
            }
            
        except Exception as e:
            logger.error(f"Error processing config file: {str(e)}")
            return {
                'success': False,
                'error': f'Error processing configuration file: {str(e)}',
                'type': 'config_import_error'
            }

    def _process_text_config(self, keyholder_email: str, content: str) -> bool:
        """Process a text-based configuration file"""
        try:
            # Parse simple key=value format
            config = {}
            lines = content.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Convert value to appropriate type
                        if value.lower() in ['true', 'yes', 'on']:
                            value = True
                        elif value.lower() in ['false', 'no', 'off']:
                            value = False
                        elif value.isdigit():
                            value = int(value)
                        elif value.replace('.', '').isdigit():
                            value = float(value)
                        
                        config[key] = value
            
            # Convert simple config to full configuration structure
            full_config = self._convert_simple_to_full_config(config)
            
            return self.config_service.import_config(keyholder_email, full_config)
            
        except Exception as e:
            logger.error(f"Error processing text config: {str(e)}")
            return False

    def _convert_simple_to_full_config(self, simple_config: Dict) -> Dict:
        """Convert simple key=value config to full configuration structure"""
        full_config = {
            'configuration': {
                'cage_check': {},
                'notifications': {},
                'punishment': {},
                'keyholder': {},
                'security': {},
                'appearance': {},
                'automation': {},
                'reporting': {}
            }
        }
        
        # Map simple keys to full configuration structure
        key_mapping = {
            'cage_check_enabled': ('cage_check', 'enabled'),
            'reminder_delay': ('cage_check', 'reminder_delay_hours'),
            'final_warning': ('cage_check', 'final_warning_hours'),
            'code_expiry': ('cage_check', 'code_expiry_hours'),
            'email_enabled': ('notifications', 'email_enabled'),
            'sms_enabled': ('notifications', 'sms_enabled'),
            'notification_frequency': ('notifications', 'notification_frequency'),
            'auto_punishment': ('punishment', 'auto_generate'),
            'punishment_duration': ('punishment', 'default_duration_hours'),
            'require_photo': ('punishment', 'require_photo_verification'),
            'auto_approve_emergency': ('keyholder', 'auto_approve_emergency'),
            'require_reason': ('keyholder', 'require_reason'),
            'max_requests': ('keyholder', 'max_concurrent_requests'),
            'require_2fa': ('security', 'require_2fa'),
            'session_timeout': ('security', 'session_timeout_hours'),
            'theme': ('appearance', 'theme'),
            'language': ('appearance', 'language'),
            'timezone': ('appearance', 'timezone'),
            'auto_lock': ('automation', 'auto_lock_after_release'),
            'daily_reports': ('reporting', 'daily_reports'),
            'weekly_reports': ('reporting', 'weekly_reports')
        }
        
        for simple_key, value in simple_config.items():
            if simple_key in key_mapping:
                section, key = key_mapping[simple_key]
                full_config['configuration'][section][key] = value
        
        return full_config

    def _extract_commands(self, body: str) -> List[Dict]:
        """Extract commands from email body"""
        commands = []
        
        for command_type, pattern in self.command_patterns.items():
            matches = re.finditer(pattern, body, re.IGNORECASE)
            for match in matches:
                if command_type in ['extend', 'reduce']:
                    # Extract time value and unit
                    time_value = int(match.group(1))
                    time_unit = match.group(2).lower()
                    hours = time_value * self.time_multipliers.get(time_unit, 1)
                    
                    commands.append({
                        'type': command_type,
                        'hours': hours,
                        'original_text': match.group(0)
                    })
                else:
                    commands.append({
                        'type': command_type,
                        'original_text': match.group(0)
                    })
        
        return commands

    def _process_command(self, keyholder_email: str, command: Dict) -> Dict:
        """Process a single command"""
        command_type = command['type']
        
        try:
            if command_type == 'settings':
                return self._handle_settings_request(keyholder_email)
            
            elif command_type == 'status':
                return self._handle_status_request(keyholder_email)
            
            elif command_type == 'help':
                return self._handle_help_request(keyholder_email)
            
            elif command_type == 'approve':
                return self._handle_approve_request(keyholder_email)
            
            elif command_type == 'deny':
                return self._handle_deny_request(keyholder_email)
            
            elif command_type == 'extend':
                return self._handle_extend_request(keyholder_email, command['hours'])
            
            elif command_type == 'reduce':
                return self._handle_reduce_request(keyholder_email, command['hours'])
            
            elif command_type == 'emergency':
                return self._handle_emergency_request(keyholder_email)
            
            else:
                return {
                    'success': False,
                    'error': f'Unknown command: {command_type}'
                }
                
        except Exception as e:
            logger.error(f"Error processing command {command_type}: {str(e)}")
            return {
                'success': False,
                'error': f'Error processing {command_type} command: {str(e)}'
            }

    def _handle_settings_request(self, keyholder_email: str) -> Dict:
        """Handle settings request - send configuration file"""
        try:
            # Get current configuration
            config = self.config_service.get_keyholder_config(keyholder_email)
            
            if not config:
                # Create default configuration
                config = self.config_service.create_keyholder_config(keyholder_email)
            
            # Generate simple text configuration
            text_config = self._generate_text_config(config)
            
            # Send configuration file via email
            subject = "ChastiPi Configuration File"
            body = f"""
🔧 **ChastiPi Configuration File**

Your current configuration settings are attached.

**Instructions:**
1. Edit the attached config.txt file
2. Save your changes
3. Reply to this email with the updated file attached
4. Your settings will be applied automatically

**Configuration Sections:**
- Cage Check Settings
- Notification Preferences  
- Punishment Configuration
- Keyholder Management
- Security Settings
- Appearance Preferences
- Automation Rules
- Reporting Configuration

**Note:** Only modify the values after the = sign. Keep the keys unchanged.

---
*This is an automated response from your ChastiPi system.*
"""
            
            # Send email with configuration file
            success = self.email_service.send_email_with_attachment(
                to_email=keyholder_email,
                subject=subject,
                body=body,
                attachment_name="config.txt",
                attachment_content=text_config,
                attachment_type="text/plain"
            )
            
            if success:
                return {
                    'success': True,
                    'message': 'Configuration file sent successfully',
                    'type': 'settings_sent'
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to send configuration file',
                    'type': 'settings_error'
                }
                
        except Exception as e:
            logger.error(f"Error handling settings request: {str(e)}")
            return {
                'success': False,
                'error': f'Error processing settings request: {str(e)}',
                'type': 'settings_error'
            }

    def _generate_text_config(self, config: Dict) -> str:
        """Generate a simple text configuration file"""
        settings = config.get('settings', {})
        
        text_config = f"""# ChastiPi Configuration File
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Keyholder: {config.get('keyholder_email', 'Unknown')}
#
# Instructions:
# 1. Edit the values after the = sign
# 2. Keep the keys unchanged
# 3. Save and reply to this email with this file attached
# 4. Your settings will be applied automatically
#
# Valid values:
# - true/false for boolean settings
# - numbers for time/duration settings
# - text for string settings

# Cage Check Settings
cage_check_enabled={settings.get('cage_check', {}).get('enabled', True)}
reminder_delay={settings.get('cage_check', {}).get('reminder_delay_hours', 1)}
final_warning={settings.get('cage_check', {}).get('final_warning_hours', 6)}
code_expiry={settings.get('cage_check', {}).get('code_expiry_hours', 24)}

# Notification Settings
email_enabled={settings.get('notifications', {}).get('email_enabled', True)}
sms_enabled={settings.get('notifications', {}).get('sms_enabled', False)}
notification_frequency={settings.get('notifications', {}).get('notification_frequency', 'standard')}

# Punishment Settings
auto_punishment={settings.get('punishment', {}).get('auto_generate', False)}
punishment_duration={settings.get('punishment', {}).get('default_duration_hours', 24)}
require_photo={settings.get('punishment', {}).get('require_photo_verification', True)}

# Keyholder Settings
auto_approve_emergency={settings.get('keyholder', {}).get('auto_approve_emergency', False)}
require_reason={settings.get('keyholder', {}).get('require_reason', True)}
max_requests={settings.get('keyholder', {}).get('max_concurrent_requests', 3)}

# Security Settings
require_2fa={settings.get('security', {}).get('require_2fa', False)}
session_timeout={settings.get('security', {}).get('session_timeout_hours', 12)}

# Appearance Settings
theme={settings.get('appearance', {}).get('theme', 'default')}
language={settings.get('appearance', {}).get('language', 'en')}
timezone={settings.get('appearance', {}).get('timezone', 'UTC')}

# Automation Settings
auto_lock={settings.get('automation', {}).get('auto_lock_after_release', True)}

# Reporting Settings
daily_reports={settings.get('reporting', {}).get('daily_reports', False)}
weekly_reports={settings.get('reporting', {}).get('weekly_reports', True)}
"""
        
        return text_config

    def _send_config_import_confirmation(self, keyholder_email: str, filename: str):
        """Send confirmation email for configuration import"""
        subject = "Configuration Import Successful"
        body = f"""
✅ **Configuration Import Successful**

Your configuration has been successfully imported from {filename}.

**What was updated:**
- Cage check settings
- Notification preferences
- Punishment configuration
- Keyholder management settings
- Security settings
- Appearance preferences
- Automation rules
- Reporting configuration

**Next Steps:**
1. Review your new settings in the web dashboard
2. Test the configuration to ensure everything works
3. Contact support if you encounter any issues

**Note:** Some settings may require a system restart to take full effect.

---
*This is an automated confirmation from your ChastiPi system.*
"""
        
        self.email_service.send_email(
            to_email=keyholder_email,
            subject=subject,
            body=body
        )

    def _handle_status_request(self, keyholder_email: str) -> Dict:
        """Handle status request - send system status"""
        try:
            # Get system status information
            devices = self.key_storage.devices
            pending_requests = self.key_storage.get_pending_requests()
            config_stats = self.config_service.get_config_statistics()
            
            status_body = f"""
📊 **ChastiPi System Status**

**Registered Devices:** {len(devices)}
**Pending Requests:** {len(pending_requests)}
**Active Configurations:** {config_stats.get('active_configs', 0)}

**Recent Activity:**
- Configuration updates: {config_stats.get('recent_updates', 0)} in last 7 days
- Total configurations: {config_stats.get('total_configs', 0)}
- Available templates: {config_stats.get('total_templates', 0)}

**Quick Commands:**
- Reply with "settings" to get configuration file
- Reply with "help" for command list
- Reply with "approve" to approve pending requests
- Reply with "deny" to deny pending requests

---
*This is an automated status report from your ChastiPi system.*
"""
            
            success = self.email_service.send_email(
                to_email=keyholder_email,
                subject="ChastiPi System Status",
                body=status_body
            )
            
            return {
                'success': success,
                'message': 'Status report sent successfully' if success else 'Failed to send status report',
                'type': 'status_sent'
            }
            
        except Exception as e:
            logger.error(f"Error handling status request: {str(e)}")
            return {
                'success': False,
                'error': f'Error processing status request: {str(e)}',
                'type': 'status_error'
            }

    def _handle_help_request(self, keyholder_email: str) -> Dict:
        """Handle help request - send command list"""
        try:
            help_body = """
📖 **ChastiPi Email Commands**

**Configuration Management:**
- "settings" - Get configuration file to edit
- "status" - Get system status report

**Key Request Management:**
- "approve" - Approve pending key requests
- "deny" - Deny pending key requests
- "extend 2 hours" - Extend request by 2 hours
- "reduce 1 hour" - Reduce request to 1 hour
- "emergency" - Emergency key release

**Time Units Supported:**
- hours, days, weeks, months, years

**Examples:**
- "extend 3 days"
- "reduce 2 hours"
- "approve all requests"

**Configuration File:**
- Reply with "settings" to receive config.txt
- Edit the file and reply with it attached
- Settings will be applied automatically

---
*This is an automated help message from your ChastiPi system.*
"""
            
            success = self.email_service.send_email(
                to_email=keyholder_email,
                subject="ChastiPi Email Commands Help",
                body=help_body
            )
            
            return {
                'success': success,
                'message': 'Help sent successfully' if success else 'Failed to send help',
                'type': 'help_sent'
            }
            
        except Exception as e:
            logger.error(f"Error handling help request: {str(e)}")
            return {
                'success': False,
                'error': f'Error processing help request: {str(e)}',
                'type': 'help_error'
            }

    # ... existing code for other command handlers ... 