"""
Update Service for ChastiPi
Handles version checking, update notifications, and update management
"""
import requests
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import logging

from ..core.config import config

logger = logging.getLogger(__name__)

class UpdateService:
    """Service for handling system updates and version management"""
    
    def __init__(self):
        self.current_version = "2.0.0"
        self.update_check_url = "https://api.github.com/repos/Dictation9/ChastiPi/releases/latest"
        self.last_check_file = Path("data/last_update_check.json")
        self.update_settings = self._get_update_settings()
    
    def _get_update_settings(self) -> Dict[str, Any]:
        """Get update-related settings from configuration"""
        return {
            "auto_check": config.get("automation.auto_update", False),
            "check_interval_days": config.get("automation.update_check_interval_days", 7),
            "notify_on_update": config.get("notifications.update_notifications", True),
            "auto_download": config.get("automation.auto_download_updates", False),
            "backup_before_update": config.get("automation.backup_before_update", True)
        }
    
    def should_check_for_updates(self) -> bool:
        """Check if it's time to check for updates based on settings"""
        if not self.update_settings["auto_check"]:
            return False
        
        if not self.last_check_file.exists():
            return True
        
        try:
            with open(self.last_check_file, 'r') as f:
                last_check_data = json.load(f)
                last_check_time = datetime.fromisoformat(last_check_data.get("last_check", "1970-01-01T00:00:00"))
                interval_days = self.update_settings["check_interval_days"]
                
                return datetime.now() - last_check_time > timedelta(days=interval_days)
        except Exception as e:
            logger.error(f"Error reading last update check: {e}")
            return True
    
    def check_for_updates(self, force: bool = False) -> Dict[str, Any]:
        """Check for available updates"""
        try:
            if not force and not self.should_check_for_updates():
                return self._get_cached_update_info()
            
            # Simulate checking for updates (replace with actual API call)
            update_info = self._check_github_releases()
            
            # Cache the result
            self._cache_update_info(update_info)
            
            return update_info
            
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return {
                "error": str(e),
                "current_version": self.current_version,
                "update_available": False,
                "last_check": datetime.now().isoformat()
            }
    
    def _check_github_releases(self) -> Dict[str, Any]:
        """Check GitHub releases for updates (simulated)"""
        try:
            # For now, simulate a response - replace with actual GitHub API call
            # response = requests.get(self.update_check_url, timeout=10)
            # latest_release = response.json()
            
            # Simulated response
            latest_version = "2.1.0"  # Simulate newer version
            is_newer = self._compare_versions(latest_version, self.current_version) > 0
            
            return {
                "current_version": self.current_version,
                "latest_version": latest_version,
                "update_available": is_newer,
                "release_notes": "Bug fixes and performance improvements",
                "download_url": "https://github.com/Dictation9/ChastiPi/releases/latest",
                "published_at": datetime.now().isoformat(),
                "last_check": datetime.now().isoformat(),
                "error": None
            }
            
        except Exception as e:
            logger.error(f"Error checking GitHub releases: {e}")
            return {
                "current_version": self.current_version,
                "latest_version": self.current_version,
                "update_available": False,
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings"""
        def version_to_tuple(version):
            return tuple(int(x) for x in version.split('.'))
        
        v1_tuple = version_to_tuple(version1)
        v2_tuple = version_to_tuple(version2)
        
        if v1_tuple > v2_tuple:
            return 1
        elif v1_tuple < v2_tuple:
            return -1
        else:
            return 0
    
    def _cache_update_info(self, update_info: Dict[str, Any]):
        """Cache update information"""
        try:
            self.last_check_file.parent.mkdir(exist_ok=True)
            with open(self.last_check_file, 'w') as f:
                json.dump(update_info, f, indent=2)
        except Exception as e:
            logger.error(f"Error caching update info: {e}")
    
    def _get_cached_update_info(self) -> Dict[str, Any]:
        """Get cached update information"""
        try:
            if self.last_check_file.exists():
                with open(self.last_check_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error reading cached update info: {e}")
        
        return {
            "current_version": self.current_version,
            "latest_version": self.current_version,
            "update_available": False,
            "last_check": datetime.now().isoformat()
        }
    
    def get_update_status(self) -> Dict[str, Any]:
        """Get current update status for dashboard"""
        update_info = self.check_for_updates()
        
        return {
            "current_version": update_info.get("current_version", self.current_version),
            "latest_version": update_info.get("latest_version", self.current_version),
            "update_available": update_info.get("update_available", False),
            "last_check": update_info.get("last_check", datetime.now().isoformat()),
            "release_notes": update_info.get("release_notes", ""),
            "download_url": update_info.get("download_url", ""),
            "error": update_info.get("error"),
            "auto_check_enabled": self.update_settings["auto_check"],
            "check_interval_days": self.update_settings["check_interval_days"]
        }
    
    def download_update(self) -> Dict[str, Any]:
        """Download the latest update"""
        try:
            update_info = self.check_for_updates(force=True)
            
            if not update_info.get("update_available"):
                return {
                    "success": False,
                    "error": "No update available"
                }
            
            # Simulate download process
            # In a real implementation, you would:
            # 1. Download the update file
            # 2. Verify checksum
            # 3. Create backup if enabled
            # 4. Extract and prepare for installation
            
            return {
                "success": True,
                "message": "Update downloaded successfully",
                "version": update_info.get("latest_version"),
                "file_path": "/tmp/chasti-pi-update.zip"
            }
            
        except Exception as e:
            logger.error(f"Error downloading update: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def install_update(self) -> Dict[str, Any]:
        """Install the downloaded update"""
        try:
            # Simulate installation process
            # In a real implementation, you would:
            # 1. Stop the application
            # 2. Backup current installation
            # 3. Extract new files
            # 4. Update version information
            # 5. Restart the application
            
            return {
                "success": True,
                "message": "Update installed successfully",
                "restart_required": True
            }
            
        except Exception as e:
            logger.error(f"Error installing update: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_update_history(self) -> List[Dict[str, Any]]:
        """Get update history"""
        try:
            history_file = Path("data/update_history.json")
            if history_file.exists():
                with open(history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error reading update history: {e}")
        
        return []
    
    def record_update(self, version: str, success: bool, notes: str = ""):
        """Record an update in history"""
        try:
            history_file = Path("data/update_history.json")
            history = self.get_update_history()
            
            history.append({
                "version": version,
                "installed_at": datetime.now().isoformat(),
                "success": success,
                "notes": notes
            })
            
            # Keep only last 10 updates
            history = history[-10:]
            
            history_file.parent.mkdir(exist_ok=True)
            with open(history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error recording update: {e}") 