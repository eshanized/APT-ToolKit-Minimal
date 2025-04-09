import logging
import os
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import json
import traceback

class APTLogger:
    """
    Advanced logging utility for the APT-Toolkit.
    Provides unified logging capabilities with multiple outputs,
    log rotation, structured logging, and more.
    """
    
    # Log levels dictionary for easy conversion between names and values
    LOG_LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    # ANSI color codes for terminal output
    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
        "RESET": "\033[0m"        # Reset
    }
    
    def __init__(self, 
                log_file=None, 
                log_level="INFO", 
                log_to_console=True,
                log_to_file=True,
                enable_json=False,
                max_file_size=10485760,  # 10MB
                backup_count=5,
                use_time_rotation=False,
                module_name=None):
        """
        Initialize the APT-Toolkit logger with configurable settings
        
        Args:
            log_file (str, optional): Path to log file. If None, uses apt-toolkit.log in logs directory.
            log_level (str, optional): Minimum log level to record. Defaults to "INFO".
            log_to_console (bool, optional): Enable console logging. Defaults to True.
            log_to_file (bool, optional): Enable file logging. Defaults to True.
            enable_json (bool, optional): Enable JSON formatting for log file. Defaults to False.
            max_file_size (int, optional): Maximum size of log file in bytes before rotation. Defaults to 10MB.
            backup_count (int, optional): Number of backup logs to keep. Defaults to 5.
            use_time_rotation (bool, optional): Use time-based rotation instead of size-based. Defaults to False.
            module_name (str, optional): Name of the module for specialized logging. Defaults to None.
        """
        self.log_to_console = log_to_console
        self.log_to_file = log_to_file
        self.enable_json = enable_json
        self.module_name = module_name
        
        # Configure base logger
        if module_name:
            self.logger = logging.getLogger(f"apt-toolkit.{module_name}")
        else:
            self.logger = logging.getLogger("apt-toolkit")
        
        # Set log level
        self.set_level(log_level)
        
        # Clear existing handlers to avoid duplication
        self.logger.handlers = []
        
        # Ensure logs directory exists if logging to file
        if log_to_file:
            if log_file is None:
                logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logs')
                os.makedirs(logs_dir, exist_ok=True)
                log_file = os.path.join(logs_dir, 'apt-toolkit.log')
            else:
                os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
                
            self.log_file = log_file
            self._setup_file_handler(max_file_size, backup_count, use_time_rotation)
            
        # Set up console handler if enabled
        if log_to_console:
            self._setup_console_handler()
            
        # Set propagate to False to avoid double logging if using child loggers
        self.logger.propagate = False
            
    def _setup_console_handler(self):
        """Set up a console handler with colored output"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
    def _setup_file_handler(self, max_file_size, backup_count, use_time_rotation):
        """Set up a file handler with rotation capabilities"""
        if use_time_rotation:
            # Use time-based rotation (daily)
            file_handler = TimedRotatingFileHandler(
                self.log_file,
                when='midnight',
                interval=1,
                backupCount=backup_count
            )
        else:
            # Use size-based rotation
            file_handler = RotatingFileHandler(
                self.log_file,
                maxBytes=max_file_size,
                backupCount=backup_count
            )
            
        if self.enable_json:
            file_handler.setFormatter(self.JsonFormatter())
        else:
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s')
            file_handler.setFormatter(file_formatter)
            
        self.logger.addHandler(file_handler)
    
    def set_level(self, level):
        """Set the logging level from string or integer"""
        if isinstance(level, str):
            if level.upper() in self.LOG_LEVELS:
                self.logger.setLevel(self.LOG_LEVELS[level.upper()])
            else:
                self.logger.setLevel(logging.INFO)
                self.logger.warning(f"Invalid log level: {level}, defaulting to INFO")
        else:
            # Assume it's already a proper log level integer
            self.logger.setLevel(level)
    
    def debug(self, message, *args, **kwargs):
        """Log a debug message"""
        self._log_with_color(logging.DEBUG, message, *args, **kwargs)
    
    def info(self, message, *args, **kwargs):
        """Log an info message"""
        self._log_with_color(logging.INFO, message, *args, **kwargs)
    
    def warning(self, message, *args, **kwargs):
        """Log a warning message"""
        self._log_with_color(logging.WARNING, message, *args, **kwargs)
    
    def error(self, message, *args, **kwargs):
        """Log an error message"""
        self._log_with_color(logging.ERROR, message, *args, **kwargs)
    
    def critical(self, message, *args, **kwargs):
        """Log a critical message"""
        self._log_with_color(logging.CRITICAL, message, *args, **kwargs)
        
    def exception(self, message, *args, exc_info=True, **kwargs):
        """Log an exception with traceback"""
        self._log_with_color(logging.ERROR, message, *args, exc_info=exc_info, **kwargs)
    
    def _log_with_color(self, level, message, *args, **kwargs):
        """Internal method to handle colored logging for console output"""
        level_name = logging.getLevelName(level)
        
        # Only colorize if logging to console
        if self.log_to_console and sys.stdout.isatty():
            color_code = self.COLORS.get(level_name, self.COLORS["RESET"])
            colored_message = f"{color_code}{message}{self.COLORS['RESET']}"
            self.logger.log(level, colored_message, *args, **kwargs)
        else:
            self.logger.log(level, message, *args, **kwargs)
            
    def log_dict(self, level, data_dict, message=None):
        """Log a dictionary at the specified level, optionally with a message"""
        if message:
            log_message = f"{message}: {json.dumps(data_dict, default=str)}"
        else:
            log_message = json.dumps(data_dict, default=str)
            
        self._log_with_color(self.LOG_LEVELS.get(level.upper(), logging.INFO), log_message)
            
    class JsonFormatter(logging.Formatter):
        """Custom formatter for JSON structured logging"""
        def format(self, record):
            log_entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno
            }
            
            # Add exception info if available
            if record.exc_info:
                log_entry["exception"] = {
                    "type": record.exc_info[0].__name__,
                    "value": str(record.exc_info[1]),
                    "traceback": traceback.format_exception(*record.exc_info)
                }
                
            return json.dumps(log_entry)
            
    def get_logger(self):
        """Get the underlying logger instance"""
        return self.logger
        
    def capture_warnings(self, capture=True):
        """Capture Python warnings in the logging system"""
        logging.captureWarnings(capture)


# Create a default logger instance for easy import and use
default_logger = APTLogger()

# Convenience functions using the default logger
def debug(message, *args, **kwargs):
    default_logger.debug(message, *args, **kwargs)

def info(message, *args, **kwargs):
    default_logger.info(message, *args, **kwargs)

def warning(message, *args, **kwargs):
    default_logger.warning(message, *args, **kwargs)

def error(message, *args, **kwargs):
    default_logger.error(message, *args, **kwargs)

def critical(message, *args, **kwargs):
    default_logger.critical(message, *args, **kwargs)

def exception(message, *args, **kwargs):
    default_logger.exception(message, *args, **kwargs)

def get_module_logger(module_name, **kwargs):
    """Create a new logger for a specific module with optional custom settings"""
    return APTLogger(module_name=module_name, **kwargs)


if __name__ == "__main__":
    # Example usage
    logger = APTLogger(log_level="DEBUG", enable_json=True)
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    try:
        1/0
    except Exception as e:
        logger.exception(f"Caught an exception: {e}")
        
    # Log structured data
    scan_results = {
        "target": "192.168.1.1",
        "ports": [22, 80, 443],
        "vulnerabilities": ["CVE-2023-12345", "CVE-2023-67890"]
    }
    logger.log_dict("INFO", scan_results, "Scan completed")