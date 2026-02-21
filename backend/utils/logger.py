"""
ScamShield Logger
Logging configuration and utilities
"""
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime


def setup_logger(name: str = 'scamshield', log_file: str = None, 
                 level: str = 'INFO') -> logging.Logger:
    """
    Setup logger with file and console handlers
    
    Args:
        name: Logger name
        log_file: Log file path
        level: Log level
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    
    # Set level
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        # Create log directory if needed
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = 'scamshield') -> logging.Logger:
    """Get logger by name"""
    return logging.getLogger(name)


class StructuredLogger:
    """Structured logging helper"""
    
    def __init__(self, name: str = 'scamshield'):
        """Initialize structured logger"""
        self.logger = logging.getLogger(name)
    
    def log(self, level: str, event: str, **kwargs):
        """Log structured event"""
        message = f"{event}"
        if kwargs:
            message += f" | {kwargs}"
        
        log_func = getattr(self.logger, level.lower(), self.logger.info)
        log_func(message)
    
    def info(self, event: str, **kwargs):
        """Log info event"""
        self.log('info', event, **kwargs)
    
    def warning(self, event: str, **kwargs):
        """Log warning event"""
        self.log('warning', event, **kwargs)
    
    def error(self, event: str, **kwargs):
        """Log error event"""
        self.log('error', event, **kwargs)
    
    def debug(self, event: str, **kwargs):
        """Log debug event"""
        self.log('debug', event, **kwargs)


# Setup default loggers
logger = setup_logger('scamshield')
system_logger = setup_logger('scamshield.system', 'logs/system.log')
detection_logger = setup_logger('scamshield.detection', 'logs/detection.log')
alert_logger = setup_logger('scamshield.alerts', 'logs/alerts.log')
