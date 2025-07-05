"""
Enhanced Logging Service for ChastiPi
Provides comprehensive logging for better bug checking and debugging
"""
import logging
import logging.handlers
import json
import traceback
import time
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
from functools import wraps
import threading
from collections import defaultdict, deque

from chasti_pi.core.config import config

class EnhancedLogger:
    """Enhanced logging service with detailed bug checking capabilities"""
    
    def __init__(self):
        self.log_dir = Path('logs')
        self.log_dir.mkdir(exist_ok=True)
        
        # Performance tracking
        self.performance_data = defaultdict(list)
        self.error_counts = defaultdict(int)
        self.request_times = deque(maxlen=1000)
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Setup loggers
        self._setup_loggers()
        
    def _setup_loggers(self):
        """Setup different loggers for different purposes"""
        log_level = config.get('logging.level', 'INFO')
        log_level = getattr(logging, log_level.upper())
        
        # Main application logger
        self.app_logger = self._create_logger(
            'chasti_pi.app',
            self.log_dir / 'app.log',
            log_level,
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        
        # Error logger
        self.error_logger = self._create_logger(
            'chasti_pi.errors',
            self.log_dir / 'errors.log',
            logging.ERROR,
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s'
        )
        
        # Request logger
        self.request_logger = self._create_logger(
            'chasti_pi.requests',
            self.log_dir / 'requests.log',
            logging.INFO,
            '%(asctime)s - %(message)s'
        )
        
        # Performance logger
        self.performance_logger = self._create_logger(
            'chasti_pi.performance',
            self.log_dir / 'performance.log',
            logging.INFO,
            '%(asctime)s - %(message)s'
        )
        
        # Debug logger
        self.debug_logger = self._create_logger(
            'chasti_pi.debug',
            self.log_dir / 'debug.log',
            logging.DEBUG,
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s'
        )
        
        # Security logger
        self.security_logger = self._create_logger(
            'chasti_pi.security',
            self.log_dir / 'security.log',
            logging.WARNING,
            '%(asctime)s - %(message)s'
        )
        
    def _create_logger(self, name: str, log_file: Path, level: int, format_str: str) -> logging.Logger:
        """Create a logger with file and console handlers"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        # Formatter
        formatter = logging.Formatter(format_str)
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_request(self, request_info: Dict[str, Any]):
        """Log detailed request information"""
        with self._lock:
            start_time = time.time()
            
            # Log request details
            self.request_logger.info(
                f"REQUEST: {request_info.get('method', 'UNKNOWN')} {request_info.get('path', 'UNKNOWN')} "
                f"from {request_info.get('ip', 'UNKNOWN')} "
                f"User-Agent: {request_info.get('user_agent', 'UNKNOWN')} "
                f"Status: {request_info.get('status', 'UNKNOWN')} "
                f"Duration: {request_info.get('duration', 0):.3f}s"
            )
            
            # Track performance
            self.request_times.append({
                'timestamp': datetime.now(),
                'duration': request_info.get('duration', 0),
                'path': request_info.get('path', ''),
                'method': request_info.get('method', ''),
                'status': request_info.get('status', '')
            })
            
            # Log slow requests
            if request_info.get('duration', 0) > 1.0:  # More than 1 second
                self.performance_logger.warning(
                    f"SLOW REQUEST: {request_info.get('method')} {request_info.get('path')} "
                    f"took {request_info.get('duration'):.3f}s"
                )
    
    def log_error(self, error: Exception, context: Dict[str, Any] = None):
        """Log detailed error information"""
        with self._lock:
            error_type = type(error).__name__
            error_msg = str(error)
            
            # Increment error count
            self.error_counts[error_type] += 1
            
            # Create detailed error log
            error_details = {
                'timestamp': datetime.now().isoformat(),
                'error_type': error_type,
                'error_message': error_msg,
                'traceback': traceback.format_exc(),
                'context': context or {},
                'error_count': self.error_counts[error_type]
            }
            
            # Log to error file
            self.error_logger.error(
                f"ERROR [{error_type}]: {error_msg}\n"
                f"Context: {json.dumps(context or {}, indent=2)}\n"
                f"Traceback:\n{traceback.format_exc()}"
            )
            
            # Log to main app logger
            self.app_logger.error(f"Error occurred: {error_type} - {error_msg}")
            
            # Log to debug file for detailed analysis
            self.debug_logger.error(json.dumps(error_details, indent=2))
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security-related events"""
        with self._lock:
            security_event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'details': details
            }
            
            self.security_logger.warning(
                f"SECURITY EVENT [{event_type}]: {json.dumps(details)}"
            )
            
            # Also log to debug for detailed analysis
            self.debug_logger.warning(f"Security event: {json.dumps(security_event, indent=2)}")
    
    def log_performance(self, operation: str, duration: float, details: Dict[str, Any] = None):
        """Log performance metrics"""
        with self._lock:
            self.performance_data[operation].append({
                'timestamp': datetime.now(),
                'duration': duration,
                'details': details or {}
            })
            
            self.performance_logger.info(
                f"PERFORMANCE: {operation} took {duration:.3f}s "
                f"Details: {json.dumps(details or {})}"
            )
            
            # Log slow operations
            if duration > 0.5:  # More than 500ms
                self.performance_logger.warning(
                    f"SLOW OPERATION: {operation} took {duration:.3f}s"
                )
    
    def log_debug(self, message: str, data: Dict[str, Any] = None):
        """Log debug information"""
        if data:
            self.debug_logger.debug(f"{message} - Data: {json.dumps(data, indent=2)}")
        else:
            self.debug_logger.debug(message)
    
    def log_info(self, message: str, data: Dict[str, Any] = None):
        """Log general information"""
        if data:
            self.app_logger.info(f"{message} - Data: {json.dumps(data, indent=2)}")
        else:
            self.app_logger.info(message)
    
    def log_warning(self, message: str, data: Dict[str, Any] = None):
        """Log warnings"""
        if data:
            self.app_logger.warning(f"{message} - Data: {json.dumps(data, indent=2)}")
        else:
            self.app_logger.warning(message)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self._lock:
            stats = {}
            
            # Request statistics
            if self.request_times:
                durations = [req['duration'] for req in self.request_times]
                stats['requests'] = {
                    'total': len(self.request_times),
                    'avg_duration': sum(durations) / len(durations),
                    'max_duration': max(durations),
                    'min_duration': min(durations),
                    'slow_requests': len([d for d in durations if d > 1.0])
                }
            
            # Performance statistics by operation
            for operation, data in self.performance_data.items():
                if data:
                    durations = [item['duration'] for item in data]
                    stats[operation] = {
                        'count': len(data),
                        'avg_duration': sum(durations) / len(durations),
                        'max_duration': max(durations),
                        'min_duration': min(durations)
                    }
            
            # Error statistics
            stats['errors'] = dict(self.error_counts)
            
            return stats
    
    def get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent error information"""
        # This would need to be implemented with a more sophisticated approach
        # For now, return basic error counts
        return [
            {'error_type': error_type, 'count': count}
            for error_type, count in self.error_counts.items()
        ]
    
    def clear_old_logs(self, days: int = 30):
        """Clear old log files"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        for log_file in self.log_dir.glob('*.log.*'):
            try:
                file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_time < cutoff_date:
                    log_file.unlink()
                    self.app_logger.info(f"Deleted old log file: {log_file}")
            except Exception as e:
                self.app_logger.error(f"Error deleting old log file {log_file}: {e}")

# Global logger instance
enhanced_logger = EnhancedLogger()

def log_request_decorator(f):
    """Decorator to log request details"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = f(*args, **kwargs)
            duration = time.time() - start_time
            
            # Log successful request
            enhanced_logger.log_request({
                'method': 'GET',  # Would need to get from Flask request
                'path': f.__name__,
                'status': '200',
                'duration': duration,
                'ip': '127.0.0.1',  # Would need to get from Flask request
                'user_agent': 'Unknown'  # Would need to get from Flask request
            })
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Log failed request
            enhanced_logger.log_request({
                'method': 'GET',
                'path': f.__name__,
                'status': '500',
                'duration': duration,
                'ip': '127.0.0.1',
                'user_agent': 'Unknown'
            })
            
            # Log the error
            enhanced_logger.log_error(e, {
                'function': f.__name__,
                'args': str(args),
                'kwargs': str(kwargs)
            })
            
            raise
    
    return decorated_function

def performance_monitor(operation_name: str):
    """Decorator to monitor performance of operations"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = f(*args, **kwargs)
                duration = time.time() - start_time
                
                enhanced_logger.log_performance(operation_name, duration, {
                    'function': f.__name__,
                    'success': True
                })
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                enhanced_logger.log_performance(operation_name, duration, {
                    'function': f.__name__,
                    'success': False,
                    'error': str(e)
                })
                
                enhanced_logger.log_error(e, {
                    'operation': operation_name,
                    'function': f.__name__
                })
                
                raise
        
        return decorated_function
    return decorator 