"""
Logger module for the APT toolkit.

This module provides logging functionality for the APT toolkit, including
configurable log levels, file and console output, and log rotation.
"""

import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional, Dict, Any

# Default log directory
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Default log file
DEFAULT_LOG_FILE = os.path.join(LOG_DIR, "apt_toolkit.log")

# Log format
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Log levels
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL
}

# Cache for loggers to avoid creating multiple instances
_loggers: Dict[str, logging.Logger] = {}


def get_logger(name: str, log_level: str = "info", log_file: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance with the specified name and configuration.

    Args:
        name: The name of the logger.
        log_level: The log level (debug, info, warning, error, critical).
        log_file: The log file path. If None, uses the default log file.

    Returns:
        A configured logger instance.
    """
    # Check if logger already exists in cache
    if name in _loggers:
        return _loggers[name]

    # Create logger
    logger = logging.getLogger(name)
    
    # Set log level
    level = LOG_LEVELS.get(log_level.lower(), logging.INFO)
    logger.setLevel(level)
    
    # Avoid adding handlers multiple times
    if not logger.handlers:
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # Create file handler
        log_path = log_file or DEFAULT_LOG_FILE
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Cache logger
    _loggers[name] = logger
    
    return logger


def get_module_logger(module_name: str, log_level: str = "info", log_file: Optional[str] = None) -> logging.Logger:
    """
    Get a logger specifically configured for a module.

    Args:
        module_name: The name of the module.
        log_level: The log level (debug, info, warning, error, critical).
        log_file: The log file path. If None, uses the default log file.

    Returns:
        A configured logger instance for the module.
    """
    # Use a consistent prefix for module loggers
    logger_name = f"module.{module_name}"
    
    # Get the logger using the standard get_logger function
    return get_logger(logger_name, log_level, log_file)


def set_log_level(logger_name: str, level: str) -> None:
    """
    Set the log level for a specific logger.

    Args:
        logger_name: The name of the logger.
        level: The log level (debug, info, warning, error, critical).
    """
    if logger_name in _loggers:
        log_level = LOG_LEVELS.get(level.lower(), logging.INFO)
        _loggers[logger_name].setLevel(log_level)
        for handler in _loggers[logger_name].handlers:
            handler.setLevel(log_level)


def clear_logs() -> None:
    """Clear all log files."""
    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".log"):
            try:
                os.remove(os.path.join(LOG_DIR, filename))
            except (OSError, PermissionError) as e:
                print(f"Error clearing log file {filename}: {e}")


def get_log_file_path(logger_name: str = None) -> str:
    """
    Get the path to the log file for a specific logger.

    Args:
        logger_name: The name of the logger. If None, returns the default log file path.

    Returns:
        The path to the log file.
    """
    if logger_name and logger_name in _loggers:
        for handler in _loggers[logger_name].handlers:
            if isinstance(handler, logging.FileHandler):
                return handler.baseFilename
    return DEFAULT_LOG_FILE


def configure_logger(config: Dict[str, Any]) -> None:
    """
    Configure the logger based on a configuration dictionary.

    Args:
        config: A dictionary containing logger configuration.
    """
    log_level = config.get("log_level", "info")
    log_file = config.get("log_file", DEFAULT_LOG_FILE)
    log_to_console = config.get("log_to_console", True)
    log_to_file = config.get("log_to_file", True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVELS.get(log_level.lower(), logging.INFO))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler if enabled
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(LOG_LEVELS.get(log_level.lower(), logging.INFO))
        console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # Add file handler if enabled
    if log_to_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(LOG_LEVELS.get(log_level.lower(), logging.INFO))
        file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Clear logger cache to force reconfiguration
    _loggers.clear()


if __name__ == "__main__":
    # Example usage
    logger = get_logger("LoggerTest")
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")