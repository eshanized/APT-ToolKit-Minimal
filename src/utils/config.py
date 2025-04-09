import os
import json
import yaml
import configparser
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple

from src.utils.logger import get_module_logger


class ConfigManager:
    """
    Configuration management for the APT-Toolkit.
    Handles loading, saving, and accessing configuration from multiple formats
    including JSON, YAML, INI, and environment variables.
    
    Supports:
    - Default configurations
    - User configurations
    - Module-specific configurations
    - Configuration validation
    - Environment variable overrides
    """
    
    # Default config paths
    DEFAULT_CONFIG_FILENAME = "config.yaml"
    USER_CONFIG_FILENAME = "user_config.yaml"
    
    # Config file search paths
    CONFIG_SEARCH_PATHS = [
        # Current directory
        os.path.dirname(os.path.abspath(__file__)),
        # Project root
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        # User home directory for portable configurations
        os.path.expanduser("~/.apt-toolkit/")
    ]
    
    # Environment variable prefix for overrides
    ENV_PREFIX = "APT_TOOLKIT_"
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 create_if_missing: bool = True,
                 load_env_vars: bool = True,
                 validate_config: bool = True):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Optional path to the configuration file. If None, searches in default locations.
            create_if_missing: Create a default configuration file if none exists.
            load_env_vars: Load environment variables that match the prefix.
            validate_config: Validate the configuration after loading.
        """
        self.logger = get_module_logger("config")
        self.config_data = {}
        self.config_path = None
        self.user_config_path = None
        self.create_if_missing = create_if_missing
        self.load_env_vars = load_env_vars
        self.validate_config = validate_config
        
        # Try to load the configuration file
        if config_path:
            # Use the specified config path
            self.config_path = config_path
            if not os.path.exists(config_path) and create_if_missing:
                self._create_default_config(config_path)
            self._load_config(config_path)
        else:
            # Search for config in standard locations
            self._find_and_load_config()
            
        # Load environment variables if enabled
        if load_env_vars:
            self._load_environment_variables()
            
        # Validate the configuration if enabled
        if validate_config:
            self._validate_config()
            
        self.logger.info(f"Configuration loaded from {self.config_path}")
        
    def _find_and_load_config(self) -> None:
        """
        Search for configuration files in standard locations and load them.
        Creates default configuration if not found and creation is enabled.
        """
        # First look for the default config
        for search_path in self.CONFIG_SEARCH_PATHS:
            default_path = os.path.join(search_path, self.DEFAULT_CONFIG_FILENAME)
            if os.path.exists(default_path):
                self.config_path = default_path
                self._load_config(default_path)
                break
                
        # If no config found and creation is enabled
        if not self.config_path and self.create_if_missing:
            # Create default config in the first search path
            default_dir = self.CONFIG_SEARCH_PATHS[0]
            os.makedirs(default_dir, exist_ok=True)
            default_path = os.path.join(default_dir, self.DEFAULT_CONFIG_FILENAME)
            self._create_default_config(default_path)
            self.config_path = default_path
            self._load_config(default_path)
            
        # Look for user config that overrides defaults
        for search_path in self.CONFIG_SEARCH_PATHS:
            user_path = os.path.join(search_path, self.USER_CONFIG_FILENAME)
            if os.path.exists(user_path):
                self.user_config_path = user_path
                self._load_config(user_path, merge=True)
                break
    
    def _create_default_config(self, config_path: str) -> None:
        """
        Create a default configuration file at the specified path.
        
        Args:
            config_path: The path where the default config should be created.
        """
        # Ensure the directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        # Default configuration structure
        default_config = {
            "general": {
                "debug": False,
                "log_level": "INFO",
                "max_threads": 10,
                "timeout": 30,
                "user_agent": "APT-Toolkit Scanner"
            },
            "network": {
                "default_timeout": 5,
                "max_retries": 3,
                "use_proxy": False,
                "proxy": {
                    "http": "",
                    "https": ""
                }
            },
            "modules": {
                "recon": {
                    "enabled": True,
                    "max_depth": 2,
                    "dns_servers": ["8.8.8.8", "8.8.4.4"]
                },
                "vuln_scanner": {
                    "enabled": True,
                    "scan_level": "medium",
                    "cve_check": True
                },
                "brute_force": {
                    "enabled": True,
                    "max_attempts": 1000,
                    "delay": 0.5
                },
                "payload_gen": {
                    "enabled": True,
                    "obfuscate": False,
                    "template_dir": "templates"
                }
            },
            "ui": {
                "theme": "dark",
                "auto_save": True,
                "confirm_actions": True,
                "terminal_history": 1000
            },
            "reporting": {
                "format": "html",
                "include_evidence": True,
                "include_remediation": True,
                "risk_classification": True
            },
            "paths": {
                "wordlists": "src/wordlists",
                "reports": "reports",
                "logs": "logs"
            }
        }
        
        # Write the default configuration
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
            
        self.logger.info(f"Created default configuration at {config_path}")
    
    def _load_config(self, config_path: str, merge: bool = False) -> None:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to the configuration file.
            merge: If True, merge with existing config. If False, replace existing config.
        """
        if not os.path.exists(config_path):
            self.logger.error(f"Configuration file not found: {config_path}")
            return
            
        file_ext = os.path.splitext(config_path)[1].lower()
        
        try:
            if file_ext == '.json':
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
            elif file_ext in ('.yml', '.yaml'):
                with open(config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
            elif file_ext in ('.ini', '.cfg'):
                config_parser = configparser.ConfigParser()
                config_parser.read(config_path)
                loaded_config = {s: dict(config_parser.items(s)) for s in config_parser.sections()}
            else:
                self.logger.error(f"Unsupported configuration file format: {file_ext}")
                return
                
            if merge:
                # Recursively merge the loaded config with existing config
                self._merge_configs(self.config_data, loaded_config)
                self.logger.debug(f"Merged configuration from {config_path}")
            else:
                # Replace the existing config
                self.config_data = loaded_config
                self.logger.debug(f"Loaded configuration from {config_path}")
                
        except Exception as e:
            self.logger.error(f"Error loading configuration from {config_path}: {str(e)}")
    
    def _merge_configs(self, base_config: Dict[str, Any], new_config: Dict[str, Any]) -> None:
        """
        Recursively merge configuration dictionaries.
        
        Args:
            base_config: The base configuration to merge into.
            new_config: The new configuration to merge from.
        """
        for key, value in new_config.items():
            if isinstance(value, dict) and key in base_config and isinstance(base_config[key], dict):
                # If both values are dicts, recurse
                self._merge_configs(base_config[key], value)
            else:
                # Otherwise overwrite the value
                base_config[key] = value
    
    def _load_environment_variables(self) -> None:
        """
        Load configuration values from environment variables with the defined prefix.
        Environment variables should be in the format PREFIX_SECTION_KEY=value.
        """
        for env_var, value in os.environ.items():
            if env_var.startswith(self.ENV_PREFIX):
                # Remove prefix and split into parts
                config_path = env_var[len(self.ENV_PREFIX):].lower().split('_')
                
                if len(config_path) < 2:
                    continue
                    
                # Navigate to the correct position in the config
                current = self.config_data
                for part in config_path[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                
                # Set the value, trying to convert to appropriate type
                key = config_path[-1]
                try:
                    # Try to parse as JSON for complex types
                    current[key] = json.loads(value)
                except json.JSONDecodeError:
                    # Handle basic types
                    if value.lower() == 'true':
                        current[key] = True
                    elif value.lower() == 'false':
                        current[key] = False
                    elif value.isdigit():
                        current[key] = int(value)
                    elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                        current[key] = float(value)
                    else:
                        current[key] = value
                        
                self.logger.debug(f"Loaded environment variable {env_var}")
    
    def _validate_config(self) -> bool:
        """
        Validate the loaded configuration.
        
        Returns:
            bool: True if the configuration is valid, False otherwise.
        """
        # Basic validation rules
        validation_rules = {
            "general.log_level": lambda x: x in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            "general.max_threads": lambda x: isinstance(x, int) and x > 0,
            "general.timeout": lambda x: isinstance(x, (int, float)) and x > 0,
            "network.default_timeout": lambda x: isinstance(x, (int, float)) and x > 0,
            "network.max_retries": lambda x: isinstance(x, int) and x >= 0,
            "modules.brute_force.max_attempts": lambda x: isinstance(x, int) and x > 0
        }
        
        # Check required keys
        required_keys = [
            "general", "network", "modules", "ui", "reporting", "paths"
        ]
        
        for key in required_keys:
            if key not in self.config_data:
                self.logger.warning(f"Missing required configuration section: {key}")
                if self.create_if_missing:
                    self.config_data[key] = {}
        
        # Validate values
        for path, validate_func in validation_rules.items():
            value = self.get(path)
            if value is not None:
                if not validate_func(value):
                    self.logger.warning(f"Invalid configuration value for {path}: {value}")
                    
        return True
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value by its dot-notation path.
        
        Args:
            key_path: Dot-notation path to the configuration value (e.g., "network.proxy.http").
            default: Default value to return if the key doesn't exist.
            
        Returns:
            The configuration value or default if not found.
        """
        keys = key_path.split('.')
        value = self.config_data
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any, save: bool = False) -> None:
        """
        Set a configuration value by its dot-notation path.
        
        Args:
            key_path: Dot-notation path to the configuration value.
            value: Value to set.
            save: If True, save the configuration to file after setting.
        """
        keys = key_path.split('.')
        
        # Navigate to the correct position
        current = self.config_data
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
            
        # Set the value
        current[keys[-1]] = value
        
        # Save if requested
        if save:
            self.save()
            
        self.logger.debug(f"Set configuration value for {key_path}: {value}")
    
    def save(self, config_path: Optional[str] = None) -> None:
        """
        Save the current configuration to a file.
        
        Args:
            config_path: Path to save the configuration to. If None, uses the current config_path.
        """
        # Use provided path or current path or default
        save_path = config_path or self.config_path
        
        if not save_path:
            # If no path was provided or set, use the default
            save_path = os.path.join(self.CONFIG_SEARCH_PATHS[0], self.USER_CONFIG_FILENAME)
            
        # Ensure the directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        file_ext = os.path.splitext(save_path)[1].lower()
        
        try:
            if file_ext == '.json':
                with open(save_path, 'w') as f:
                    json.dump(self.config_data, f, indent=4)
            elif file_ext in ('.yml', '.yaml'):
                with open(save_path, 'w') as f:
                    yaml.dump(self.config_data, f, default_flow_style=False)
            elif file_ext in ('.ini', '.cfg'):
                config = configparser.ConfigParser()
                for section, options in self.config_data.items():
                    if not isinstance(options, dict):
                        continue
                    config[section] = {}
                    for option, value in options.items():
                        if isinstance(value, (dict, list)):
                            config[section][option] = json.dumps(value)
                        else:
                            config[section][option] = str(value)
                            
                with open(save_path, 'w') as f:
                    config.write(f)
            else:
                self.logger.error(f"Unsupported configuration file format: {file_ext}")
                return
                
            self.logger.info(f"Saved configuration to {save_path}")
        except Exception as e:
            self.logger.error(f"Error saving configuration to {save_path}: {str(e)}")
    
    def reset_to_default(self, save: bool = True) -> None:
        """
        Reset the configuration to default values.
        
        Args:
            save: If True, save the default configuration to file.
        """
        # Create a temporary path for the default config
        temp_file = tempfile.NamedTemporaryFile(suffix='.yaml', delete=False)
        temp_file.close()
        
        # Create and load default config
        self._create_default_config(temp_file.name)
        self._load_config(temp_file.name, merge=False)
        
        # Remove the temporary file
        try:
            os.unlink(temp_file.name)
        except OSError:
            pass
            
        if save:
            self.save()
            
        self.logger.info("Reset configuration to default values")
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.
        
        Args:
            section: The section name to retrieve.
            
        Returns:
            The configuration section as a dictionary.
        """
        return self.config_data.get(section, {})
    
    def get_available_modules(self) -> List[str]:
        """
        Get a list of available modules from the configuration.
        
        Returns:
            List of module names that are defined in the configuration.
        """
        modules = self.get("modules", {})
        return [name for name, config in modules.items() if isinstance(config, dict)]
    
    def get_enabled_modules(self) -> List[str]:
        """
        Get a list of enabled modules from the configuration.
        
        Returns:
            List of module names that are enabled in the configuration.
        """
        modules = self.get("modules", {})
        return [name for name, config in modules.items() 
                if isinstance(config, dict) and config.get("enabled", False)]
    
    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """
        Get the configuration for a specific module.
        
        Args:
            module_name: The name of the module.
            
        Returns:
            The module's configuration as a dictionary.
        """
        return self.get(f"modules.{module_name}", {})
    
    def set_module_config(self, module_name: str, config: Dict[str, Any], save: bool = False) -> None:
        """
        Set the configuration for a specific module.
        
        Args:
            module_name: The name of the module.
            config: The module's configuration.
            save: If True, save the configuration to file after setting.
        """
        modules = self.get("modules", {})
        modules[module_name] = config
        self.set("modules", modules, save=save)
    
    def get_path(self, path_type: str) -> Optional[str]:
        """
        Get a configured path.
        
        Args:
            path_type: The type of path to retrieve (e.g., "wordlists", "reports").
            
        Returns:
            The path as a string or None if not found.
        """
        path = self.get(f"paths.{path_type}")
        
        if not path:
            return None
            
        # If not absolute, convert to absolute path relative to the config file location
        if not os.path.isabs(path) and self.config_path:
            base_dir = os.path.dirname(os.path.abspath(self.config_path))
            path = os.path.join(base_dir, path)
            
        return path
    
    def ensure_path_exists(self, path_type: str) -> str:
        """
        Ensure that a configured path exists, creating it if necessary.
        
        Args:
            path_type: The type of path to retrieve and ensure exists.
            
        Returns:
            The absolute path as a string.
        """
        path = self.get_path(path_type)
        
        if not path:
            # Use a default path relative to the project root
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            path = os.path.join(project_root, path_type)
            
        # Ensure the directory exists
        os.makedirs(path, exist_ok=True)
        
        return path


# Create a default config instance for easy import and use
config_manager = ConfigManager()

def get_config() -> ConfigManager:
    """
    Get the global configuration manager instance.
    
    Returns:
        The global ConfigManager instance.
    """
    return config_manager


if __name__ == "__main__":
    # Example usage
    config = ConfigManager()
    
    # Get values
    debug_mode = config.get("general.debug", False)
    proxy_settings = config.get("network.proxy", {})
    
    # Set values
    config.set("general.debug", True)
    config.set("network.proxy.http", "http://proxy.example.com:8080")
    
    # Save configuration
    config.save()
    
    # List modules
    enabled_modules = config.get_enabled_modules()
    print(f"Enabled modules: {enabled_modules}")
    
    # Get module config
    recon_config = config.get_module_config("recon")
    print(f"Recon module config: {recon_config}")