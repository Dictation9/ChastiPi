import ntplib
import time
import logging
import socket
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class TimeVerificationService:
    """Service for verifying system time against trusted NTP servers"""
    
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.ntp_client = ntplib.NTPClient()
        
        # Trusted NTP servers (multiple for redundancy)
        self.ntp_servers = [
            'pool.ntp.org',
            'time.google.com',
            'time.windows.com',
            'time.apple.com',
            'time.cloudflare.com',
            'time.nist.gov'
        ]
        
        # Time drift tolerance (in seconds)
        self.max_drift_seconds = 30
        
        # Cache for NTP responses (to avoid too many requests)
        self.ntp_cache = {}
        self.cache_duration = 300  # 5 minutes
        
    def verify_system_time(self) -> Dict:
        """Verify system time against trusted NTP servers"""
        try:
            # Get system time
            system_time = datetime.now()
            
            # Get NTP time from multiple servers
            ntp_times = self._get_ntp_times()
            
            if not ntp_times:
                return {
                    'valid': False,
                    'error': 'Could not reach any NTP servers',
                    'system_time': system_time.isoformat(),
                    'drift_seconds': None,
                    'recommendation': 'Check internet connection and try again'
                }
            
            # Calculate average NTP time
            avg_ntp_time = self._calculate_average_time(ntp_times)
            
            # Calculate time drift
            drift_seconds = abs((system_time - avg_ntp_time).total_seconds())
            
            # Check if drift is within tolerance
            is_valid = drift_seconds <= self.max_drift_seconds
            
            result = {
                'valid': is_valid,
                'system_time': system_time.isoformat(),
                'ntp_time': avg_ntp_time.isoformat(),
                'drift_seconds': round(drift_seconds, 2),
                'max_drift_allowed': self.max_drift_seconds,
                'ntp_servers_checked': len(ntp_times),
                'recommendation': self._get_recommendation(drift_seconds, is_valid)
            }
            
            # Log the verification
            if is_valid:
                logger.info(f"Time verification passed: drift {drift_seconds:.2f}s")
            else:
                logger.warning(f"Time verification failed: drift {drift_seconds:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Error verifying system time: {str(e)}")
            return {
                'valid': False,
                'error': str(e),
                'system_time': datetime.now().isoformat(),
                'recommendation': 'Check system configuration and network connectivity'
            }
    
    def _get_ntp_times(self) -> List[datetime]:
        """Get time from multiple NTP servers"""
        ntp_times = []
        
        for server in self.ntp_servers:
            try:
                # Check cache first
                cache_key = f"{server}_{int(time.time() // self.cache_duration)}"
                if cache_key in self.ntp_cache:
                    ntp_times.append(self.ntp_cache[cache_key])
                    continue
                
                # Query NTP server
                response = self.ntp_client.request(server, timeout=5)
                ntp_time = datetime.fromtimestamp(response.tx_time)
                
                # Cache the result
                self.ntp_cache[cache_key] = ntp_time
                ntp_times.append(ntp_time)
                
                logger.debug(f"Got time from {server}: {ntp_time}")
                
            except Exception as e:
                logger.warning(f"Failed to get time from {server}: {str(e)}")
                continue
        
        return ntp_times
    
    def _calculate_average_time(self, times: List[datetime]) -> datetime:
        """Calculate average time from multiple sources"""
        if not times:
            raise ValueError("No valid times provided")
        
        # Convert to timestamps for averaging
        timestamps = [t.timestamp() for t in times]
        avg_timestamp = sum(timestamps) / len(timestamps)
        
        return datetime.fromtimestamp(avg_timestamp)
    
    def _get_recommendation(self, drift_seconds: float, is_valid: bool) -> str:
        """Get recommendation based on time drift"""
        if is_valid:
            return "System time is accurate"
        elif drift_seconds < 60:
            return "Minor time drift detected, consider syncing with NTP"
        elif drift_seconds < 300:  # 5 minutes
            return "Significant time drift detected, sync with NTP immediately"
        else:
            return "Major time drift detected - possible tampering! Sync with NTP immediately"
    
    def sync_system_time(self) -> Dict:
        """Attempt to sync system time with NTP servers"""
        try:
            # Get NTP time
            ntp_times = self._get_ntp_times()
            if not ntp_times:
                return {
                    'success': False,
                    'error': 'Could not reach any NTP servers'
                }
            
            avg_ntp_time = self._calculate_average_time(ntp_times)
            
            # Set system time (requires root privileges)
            try:
                # Format time for date command
                time_str = avg_ntp_time.strftime('%Y-%m-%d %H:%M:%S')
                
                # Set system date/time
                result = subprocess.run(
                    ['sudo', 'date', '-s', time_str],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    logger.info(f"System time synced to {time_str}")
                    return {
                        'success': True,
                        'old_time': datetime.now().isoformat(),
                        'new_time': avg_ntp_time.isoformat(),
                        'message': 'System time synchronized successfully'
                    }
                else:
                    logger.error(f"Failed to sync time: {result.stderr}")
                    return {
                        'success': False,
                        'error': f"Failed to set system time: {result.stderr}",
                        'recommendation': 'Run with sudo privileges or use timedatectl'
                    }
                    
            except subprocess.TimeoutExpired:
                return {
                    'success': False,
                    'error': 'Timeout while setting system time',
                    'recommendation': 'Check system permissions'
                }
            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'date command not found',
                    'recommendation': 'Install coreutils package'
                }
                
        except Exception as e:
            logger.error(f"Error syncing system time: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_time_status(self) -> Dict:
        """Get comprehensive time status"""
        verification = self.verify_system_time()
        
        # Get additional system time info
        try:
            # Check if NTP is enabled
            ntp_enabled = self._check_ntp_service()
            
            # Get timezone info
            timezone = self._get_timezone()
            
            status = {
                'verification': verification,
                'ntp_service_enabled': ntp_enabled,
                'timezone': timezone,
                'last_check': datetime.now().isoformat(),
                'recommendations': self._get_system_recommendations(verification, ntp_enabled)
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting time status: {str(e)}")
            return {
                'verification': verification,
                'error': str(e)
            }
    
    def _check_ntp_service(self) -> bool:
        """Check if NTP service is enabled and running"""
        try:
            # Check systemd-timesyncd (common on modern Linux)
            result = subprocess.run(
                ['systemctl', 'is-active', 'systemd-timesyncd'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip() == 'active':
                return True
            
            # Check chronyd (alternative NTP daemon)
            result = subprocess.run(
                ['systemctl', 'is-active', 'chronyd'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip() == 'active':
                return True
            
            return False
            
        except Exception:
            return False
    
    def _get_timezone(self) -> str:
        """Get current timezone"""
        try:
            result = subprocess.run(
                ['timedatectl', 'show', '--property=Timezone', '--value'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "Unknown"
                
        except Exception:
            return "Unknown"
    
    def _get_system_recommendations(self, verification: Dict, ntp_enabled: bool) -> List[str]:
        """Get system recommendations based on time status"""
        recommendations = []
        
        if not verification.get('valid', False):
            recommendations.append("System time appears to be incorrect")
            
            if not ntp_enabled:
                recommendations.append("Enable NTP service for automatic time synchronization")
                recommendations.append("Run: sudo systemctl enable systemd-timesyncd")
            else:
                recommendations.append("NTP service is enabled but time is still incorrect")
                recommendations.append("Check NTP server configuration")
        
        if not ntp_enabled:
            recommendations.append("Enable automatic time synchronization")
            recommendations.append("Run: sudo systemctl enable systemd-timesyncd")
        
        return recommendations
    
    def validate_timestamp(self, timestamp: datetime, max_age_hours: int = 24) -> Dict:
        """Validate a timestamp against current verified time"""
        try:
            # Verify system time first
            time_status = self.verify_system_time()
            
            if not time_status.get('valid', False):
                return {
                    'valid': False,
                    'error': 'System time cannot be verified',
                    'recommendation': 'Sync system time with NTP servers'
                }
            
            # Get current verified time
            current_time = datetime.now()
            
            # Check if timestamp is in the future
            if timestamp > current_time:
                return {
                    'valid': False,
                    'error': 'Timestamp is in the future',
                    'timestamp': timestamp.isoformat(),
                    'current_time': current_time.isoformat(),
                    'recommendation': 'Check timestamp generation'
                }
            
            # Check if timestamp is too old
            age_hours = (current_time - timestamp).total_seconds() / 3600
            if age_hours > max_age_hours:
                return {
                    'valid': False,
                    'error': f'Timestamp is too old ({age_hours:.1f} hours)',
                    'timestamp': timestamp.isoformat(),
                    'current_time': current_time.isoformat(),
                    'max_age_hours': max_age_hours,
                    'recommendation': 'Generate new timestamp'
                }
            
            return {
                'valid': True,
                'timestamp': timestamp.isoformat(),
                'current_time': current_time.isoformat(),
                'age_hours': round(age_hours, 2)
            }
            
        except Exception as e:
            logger.error(f"Error validating timestamp: {str(e)}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def get_status(self) -> Dict:
        """Get current time verification status (alias for get_time_status)"""
        return self.get_time_status() 