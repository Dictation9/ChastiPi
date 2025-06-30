"""
Lock status service for ChastiPi
"""
import json
from datetime import datetime, timedelta
from pathlib import Path

class LockService:
    """Service for managing lock status and history"""
    
    def __init__(self, data_file="data/lock_history.json"):
        self.data_file = Path(data_file)
        self.data_file.parent.mkdir(exist_ok=True)
        self._load_data()
    
    def _load_data(self):
        """Load lock history data"""
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {
                "current_status": {
                    "locked": True,
                    "since": "2025-06-01",
                    "next_photo_due": "2025-06-27"
                },
                "history": []
            }
            self._save_data()
    
    def _save_data(self):
        """Save lock history data"""
        with open(self.data_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def get_status(self):
        """Get current lock status"""
        return self.data.get("current_status", {
            "locked": True,
            "since": "2025-06-01",
            "next_photo_due": "2025-06-27"
        })
    
    def update_status(self, locked, since=None, next_photo_due=None):
        """Update lock status"""
        if since is None:
            since = datetime.now().strftime("%Y-%m-%d")
        
        self.data["current_status"] = {
            "locked": locked,
            "since": since,
            "next_photo_due": next_photo_due
        }
        
        # Add to history
        self.data["history"].append({
            "timestamp": datetime.now().isoformat(),
            "action": "locked" if locked else "unlocked",
            "since": since
        })
        
        self._save_data()
        return self.data["current_status"] 