import json
import os
from pathlib import Path
from typing import Any, Dict
from utils.logger import get_logger

logger = get_logger("ConfigManager")

CONFIG_PATH = Path("config.json")


class ConfigManager:
    """
    Handles loading, modifying, and saving user config.
    """

    DEFAULT_CONFIG = {
        "proxy": None,
        "timeout": 10,
        "user_agent": "APT-Toolkit/1.0",
        "report_format": "html",
        "theme": "light",
        "log_level": "INFO"
    }

    def __init__(self, config_file: Path = CONFIG_PATH):
        self.config_file = config_file
        self.config: Dict[str, Any] = {}

        self._load()

    def _load(self):
        """
        Load the configuration from file or fallback to defaults.
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
                    logger.info(f"Loaded config from {self.config_file}")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to decode config file: {e}")
                self.config = self.DEFAULT_CONFIG.copy()
        else:
            logger.info("No config file found. Using defaults.")
            self.config = self.DEFAULT_CONFIG.copy()

    def save(self) -> None:
        """
        Persist the current configuration to file.
        """
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
                logger.info("Configuration saved.")
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a config value with an optional default.
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set and persist a config value.
        """
        self.config[key] = value
        self.save()

    def reset(self) -> None:
        """
        Reset to default configuration.
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self.save()

    def all(self) -> Dict[str, Any]:
        """
        Return the entire config dictionary.
        """
        return self.config


# Singleton-like instance (can be imported and reused)
config = ConfigManager()
