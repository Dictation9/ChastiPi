"""
Self-Management Service
Handles the logic for self-managed locks, acting as an automated keyholder.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from chasti_pi.services.key_storage_service import KeyStorageService
from chasti_pi.core.config import config

class SelfManageService:
    def __init__(self):
        self.key_storage_service = KeyStorageService()
        self.user_identifier = "self-managed-user"

    def start_lock(self, duration: int, duration_unit: str) -> Dict[str, Any]:
        """
        Starts a new self-managed lock.
        This creates a request and immediately auto-approves it.
        """
        if not self._is_self_managed_mode():
            return {"error": "Not in self-managed mode."}

        # Step 1: Create a lock request for the self-managed user
        reason = f"Self-managed lock for {duration} {duration_unit}"
        request_data = self.key_storage_service.create_request(
            user_identifier=self.user_identifier,
            reason=reason
        )
        request_id = request_data['request_id']

        # Step 2: Auto-approve the request
        self.key_storage_service.approve_request(request_id, duration, duration_unit)
        
        return self.get_lock_status()

    def get_lock_status(self) -> Optional[Dict[str, Any]]:
        """
        Gets the status of the current active self-managed lock.
        """
        if not self._is_self_managed_mode():
            return None

        active_requests = self.key_storage_service.get_active_requests(self.user_identifier)
        if not active_requests:
            return None

        # Return the first active request (should only be one for self-managed)
        status = active_requests[0]
        
        # Check if the lock has expired
        now = datetime.now()
        expires_at = datetime.fromisoformat(status['expires_at'])
        
        if now >= expires_at:
            status['is_unlocked'] = True
            status['key_code'] = self.key_storage_service.get_key_code(status['request_id'])
            status['time_remaining'] = "0s"
        else:
            status['is_unlocked'] = False
            status['key_code'] = None
            time_remaining = expires_at - now
            status['time_remaining'] = self._format_timedelta(time_remaining)
            
        return status

    def start_emergency_release(self) -> Dict[str, Any]:
        """
        Starts the emergency release process for a self-managed lock.
        This sets a future release time based on the emergency timeout setting.
        """
        status = self.get_lock_status()
        if not status:
            return {"error": "No active lock to release."}
        
        if status.get('is_unlocked'):
            return {"error": "Lock is already unlocked."}

        request_id = status['request_id']
        emergency_timeout_minutes = config.get("keyholder.emergency_timeout_minutes", 30)

        # Use the emergency release function from the key storage service
        self.key_storage_service.emergency_release(request_id)
        
        new_status = self.get_lock_status()
        
        return {
            "message": f"Emergency release initiated. Key will be available in {emergency_timeout_minutes} minutes.",
            "release_at": new_status.get('expires_at')
        }

    def _is_self_managed_mode(self) -> bool:
        """Checks if the system is in self-managed mode."""
        return config.get('keyholder.mode') == 'self_managed'

    def _format_timedelta(self, td: timedelta) -> str:
        """Formats a timedelta into a human-readable string."""
        days = td.days
        hours, rem = divmod(td.seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
            
        return " ".join(parts) 