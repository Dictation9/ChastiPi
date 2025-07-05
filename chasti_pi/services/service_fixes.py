"""
Service method fixes for ChastiPi
Adds missing methods to service classes
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def apply_key_storage_fixes(key_storage_service):
    """Apply fixes to KeyStorageService"""
    if not hasattr(key_storage_service, 'get_active_requests'):
        def get_active_requests(self):
            """Get all active key requests"""
            try:
                # This would typically query the database
                # For now, return empty list as placeholder
                return []
            except Exception as e:
                logger.error(f"Error getting active requests: {e}")
                return []
        
        key_storage_service.get_active_requests = get_active_requests.__get__(key_storage_service)
    
    if not hasattr(key_storage_service, 'get_all_requests'):
        def get_all_requests(self):
            """Get all key requests (active and completed)"""
            try:
                # This would typically query the database
                # For now, return empty list as placeholder
                return []
            except Exception as e:
                logger.error(f"Error getting all requests: {e}")
                return []
        
        key_storage_service.get_all_requests = get_all_requests.__get__(key_storage_service)
    
    if not hasattr(key_storage_service, 'get_recent_activity'):
        def get_recent_activity(self, days: int = 7):
            """Get recent key activity"""
            try:
                # This would typically query the database
                # For now, return empty list as placeholder
                return []
            except Exception as e:
                logger.error(f"Error getting recent activity: {e}")
                return []
        
        key_storage_service.get_recent_activity = get_recent_activity.__get__(key_storage_service)
    
    if not hasattr(key_storage_service, 'get_statistics'):
        def get_statistics(self):
            """Get key storage statistics"""
            try:
                return {
                    'total_requests': 0,
                    'active_requests': 0,
                    'completed_requests': 0,
                    'pending_requests': 0
                }
            except Exception as e:
                logger.error(f"Error getting statistics: {e}")
                return {}
        
        key_storage_service.get_statistics = get_statistics.__get__(key_storage_service)

def apply_cage_check_fixes(cage_check_service):
    """Apply fixes to CageCheckService"""
    if not hasattr(cage_check_service, 'get_all_check_requests'):
        def get_all_check_requests(self):
            """Get all cage check requests"""
            try:
                # This would typically query the database
                # For now, return empty list as placeholder
                return []
            except Exception as e:
                logger.error(f"Error getting all check requests: {e}")
                return []
        
        cage_check_service.get_all_check_requests = get_all_check_requests.__get__(cage_check_service)

def apply_config_fixes(config_service):
    """Apply fixes to ConfigService"""
    if not hasattr(config_service, 'get_section'):
        def get_section(self, section_name: str) -> Dict[str, Any]:
            """Get a configuration section"""
            try:
                config = self.get_config()
                return config.get(section_name, {})
            except Exception as e:
                logger.error(f"Error getting config section {section_name}: {e}")
                return {}
        
        config_service.get_section = get_section.__get__(config_service)

def apply_all_service_fixes():
    """Apply all service fixes"""
    try:
        from .key_storage_service import KeyStorageService
        from .cage_check_service import CageCheckService
        from .config_service import ConfigService
        
        # Apply fixes to service instances
        key_storage = KeyStorageService()
        cage_check = CageCheckService()
        config_service = ConfigService()
        
        apply_key_storage_fixes(key_storage)
        apply_cage_check_fixes(cage_check)
        apply_config_fixes(config_service)
        
        logger.info("All service fixes applied successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error applying service fixes: {e}")
        return False 