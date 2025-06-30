"""
Calendar service for ChastiPi
"""
from datetime import datetime, timedelta
import json
from pathlib import Path

class CalendarService:
    """Service for managing calendar events"""
    
    def __init__(self, data_file="data/calendar_events.json"):
        self.data_file = Path(data_file)
        self.data_file.parent.mkdir(exist_ok=True)
        self._load_events()
    
    def _load_events(self):
        """Load calendar events"""
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                self.events = json.load(f)
        else:
            self.events = [
                {"date": "2025-06-01", "event": "Locked", "type": "lock"},
                {"date": "2025-06-15", "event": "Photo Check", "type": "check"}
            ]
            self._save_events()
    
    def _save_events(self):
        """Save calendar events"""
        with open(self.data_file, 'w') as f:
            json.dump(self.events, f, indent=2)
    
    def get_events(self):
        """Get all calendar events"""
        return self.events
    
    def add_event(self, date, event, event_type="general"):
        """Add new calendar event"""
        new_event = {
            "date": date,
            "event": event,
            "type": event_type,
            "created": datetime.now().isoformat()
        }
        self.events.append(new_event)
        self._save_events()
        return new_event 