import logging
import os
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
import sys

try:
    from colorlog import ColoredFormatter
except ImportError:
    print("[!] colorlog not found. Run: pip install colorlog")
    sys.exit(1)

# Set default log directory and ensure it exists
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Environment-controlled log level (fallback to DEBUG)
LOG_LEVEL = os.getenv("APT_LOG_LEVEL", "DEBUG").upper()

# Log file path
LOG_FILE = LOG_DIR / "apt_toolkit.log"

# Log formatter
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
COLOR_FORMAT = "%(log_color)s%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"

color_formatter = ColoredFormatter(
    COLOR_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'bold_red',
    }
)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)

    if not logger.handlers:
        # Console handler with color
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(color_formatter)

        # File handler with daily rotation
        file_handler = TimedRotatingFileHandler(
            LOG_FILE, when="midnight", interval=1, backupCount=7, encoding='utf-8'
        )
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        logger.propagate = False  # Prevent log duplication

    return logger
