import threading
import time
import logging
from datetime import datetime
from ..services.cage_check_service import CageCheckService

logger = logging.getLogger(__name__)

class NotificationScheduler:
    """Background scheduler for sending cage check notifications"""
    
    def __init__(self, check_interval_minutes=5):
        self.check_interval_minutes = check_interval_minutes
        self.running = False
        self.thread = None
        self.cage_service = CageCheckService()
        
    def start(self):
        """Start the notification scheduler"""
        if self.running:
            logger.warning("Notification scheduler is already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        logger.info(f"Notification scheduler started (check interval: {self.check_interval_minutes} minutes)")
    
    def stop(self):
        """Stop the notification scheduler"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Notification scheduler stopped")
    
    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            try:
                logger.debug("Running notification check...")
                self.cage_service.check_and_send_notifications()
                
                # Sleep for the specified interval
                time.sleep(self.check_interval_minutes * 60)
                
            except Exception as e:
                logger.error(f"Error in notification scheduler: {str(e)}")
                # Sleep for a shorter interval on error
                time.sleep(60)
    
    def run_once(self):
        """Run notification check once (for manual triggering)"""
        try:
            logger.info("Running manual notification check...")
            self.cage_service.check_and_send_notifications()
            return True
        except Exception as e:
            logger.error(f"Error in manual notification check: {str(e)}")
            return False

# Global scheduler instance
notification_scheduler = NotificationScheduler()

def start_notification_scheduler():
    """Start the global notification scheduler"""
    notification_scheduler.start()

def stop_notification_scheduler():
    """Stop the global notification scheduler"""
    notification_scheduler.stop()

def run_notification_check():
    """Run a single notification check"""
    return notification_scheduler.run_once() 