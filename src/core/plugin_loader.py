"""
Plugin Loader for the apt toolkit.

This module provides functionality to discover, load, and manage plugins
that extend the apt toolkit's capabilities.
"""

import os
import sys
import importlib
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Type, Union, Set, Tuple
import traceback
import json
import yaml

# Define plugin interface / base class
class AptPlugin:
    """Base class for all apt toolkit plugins."""
    
    # Class attributes that define plugin metadata
    PLUGIN_NAME = "base_plugin"
    PLUGIN_VERSION = "0.1.0"
    PLUGIN_DESCRIPTION = "Base plugin class"
    PLUGIN_AUTHOR = "Unknown"
    PLUGIN_DEPENDENCIES = []  # List of other plugin names this plugin depends on
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the plugin.
        
        Args:
            config: Configuration dictionary for the plugin
        """
        self.config = config or {}
        self.logger = logging.getLogger(f"apt.plugins.{self.PLUGIN_NAME}")
    
    def initialize(self) -> bool:
        """
        Initialize the plugin. Called when the plugin is loaded.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        return True
    
    def shutdown(self) -> None:
        """Clean up resources. Called when the plugin is unloaded."""
        pass
    
    def get_handlers(self) -> Dict[str, Callable]:
        """
        Get command handlers provided by this plugin.
        
        Returns:
            Dictionary mapping command names to handler functions
        """
        return {}
    
    def get_hooks(self) -> Dict[str, List[Callable]]:
        """
        Get hooks provided by this plugin.
        
        Returns:
            Dictionary mapping hook points to hook functions
        """
        return {}
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """
        Get plugin metadata.
        
        Returns:
            Dictionary containing plugin metadata
        """
        return {
            "name": cls.PLUGIN_NAME,
            "version": cls.PLUGIN_VERSION,
            "description": cls.PLUGIN_DESCRIPTION,
            "author": cls.PLUGIN_AUTHOR,
            "dependencies": cls.PLUGIN_DEPENDENCIES
        }


class PluginMetadata:
    """Class to store and validate plugin metadata."""
    
    def __init__(self, 
                name: str, 
                version: str, 
                description: str, 
                author: str,
                dependencies: List[str] = None,
                module_path: str = None,
                enabled: bool = True):
        """
        Initialize plugin metadata.
        
        Args:
            name: Plugin name
            version: Plugin version
            description: Plugin description
            author: Plugin author
            dependencies: List of plugin dependencies
            module_path: Path to the plugin module
            enabled: Whether the plugin is enabled
        """
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.dependencies = dependencies or []
        self.module_path = module_path
        self.enabled = enabled
    
    @classmethod
    def from_plugin_class(cls, plugin_class: Type[AptPlugin], 
                         module_path: str = None) -> 'PluginMetadata':
        """
        Create metadata from plugin class.
        
        Args:
            plugin_class: Plugin class
            module_path: Path to the plugin module
            
        Returns:
            PluginMetadata instance
        """
        return cls(
            name=plugin_class.PLUGIN_NAME,
            version=plugin_class.PLUGIN_VERSION,
            description=plugin_class.PLUGIN_DESCRIPTION,
            author=plugin_class.PLUGIN_AUTHOR,
            dependencies=plugin_class.PLUGIN_DEPENDENCIES,
            module_path=module_path,
            enabled=True
        )
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PluginMetadata':
        """
        Create metadata from dictionary.
        
        Args:
            data: Dictionary containing metadata
            
        Returns:
            PluginMetadata instance
        """
        return cls(
            name=data.get("name", "unknown"),
            version=data.get("version", "0.0.0"),
            description=data.get("description", ""),
            author=data.get("author", "unknown"),
            dependencies=data.get("dependencies", []),
            module_path=data.get("module_path"),
            enabled=data.get("enabled", True)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert metadata to dictionary.
        
        Returns:
            Dictionary representation of metadata
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "dependencies": self.dependencies,
            "module_path": self.module_path,
            "enabled": self.enabled
        }


class PluginRegistry:
    """Registry for tracking loaded plugins and their metadata."""
    
    def __init__(self):
        """Initialize the plugin registry."""
        self.plugins: Dict[str, AptPlugin] = {}
        self.metadata: Dict[str, PluginMetadata] = {}
        self.handlers: Dict[str, Tuple[str, Callable]] = {}  # command_name -> (plugin_name, handler)
        self.hooks: Dict[str, Dict[str, Callable]] = {}  # hook_point -> {plugin_name: hook_function}
    
    def register_plugin(self, plugin: AptPlugin, metadata: PluginMetadata) -> None:
        """
        Register a plugin in the registry.
        
        Args:
            plugin: Plugin instance
            metadata: Plugin metadata
        """
        name = metadata.name
        self.plugins[name] = plugin
        self.metadata[name] = metadata
        
        # Register handlers
        for cmd_name, handler in plugin.get_handlers().items():
            self.handlers[cmd_name] = (name, handler)
        
        # Register hooks
        for hook_point, hook_funcs in plugin.get_hooks().items():
            if hook_point not in self.hooks:
                self.hooks[hook_point] = {}
            
            for hook_func in hook_funcs:
                self.hooks[hook_point][name] = hook_func
    
    def unregister_plugin(self, name: str) -> None:
        """
        Unregister a plugin from the registry.
        
        Args:
            name: Plugin name
        """
        if name not in self.plugins:
            return
        
        # Unregister handlers
        to_remove = []
        for cmd_name, (plugin_name, _) in self.handlers.items():
            if plugin_name == name:
                to_remove.append(cmd_name)
        
        for cmd_name in to_remove:
            del self.handlers[cmd_name]
        
        # Unregister hooks
        for hook_point in self.hooks:
            if name in self.hooks[hook_point]:
                del self.hooks[hook_point][name]
        
        # Remove plugin and metadata
        del self.plugins[name]
        del self.metadata[name]
    
    def get_plugin(self, name: str) -> Optional[AptPlugin]:
        """
        Get a plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin instance or None if not found
        """
        return self.plugins.get(name)
    
    def get_metadata(self, name: str) -> Optional[PluginMetadata]:
        """
        Get plugin metadata by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin metadata or None if not found
        """
        return self.metadata.get(name)
    
    def get_all_plugins(self) -> Dict[str, AptPlugin]:
        """
        Get all plugins.
        
        Returns:
            Dictionary mapping plugin names to plugin instances
        """
        return self.plugins.copy()
    
    def get_all_metadata(self) -> Dict[str, PluginMetadata]:
        """
        Get metadata for all plugins.
        
        Returns:
            Dictionary mapping plugin names to metadata
        """
        return self.metadata.copy()
    
    def get_handler(self, command_name: str) -> Optional[Tuple[str, Callable]]:
        """
        Get command handler.
        
        Args:
            command_name: Command name
            
        Returns:
            Tuple (plugin_name, handler_function) or None if not found
        """
        return self.handlers.get(command_name)
    
    def get_all_handlers(self) -> Dict[str, Tuple[str, Callable]]:
        """
        Get all command handlers.
        
        Returns:
            Dictionary mapping command names to (plugin_name, handler) tuples
        """
        return self.handlers.copy()
    
    def get_hooks(self, hook_point: str) -> Dict[str, Callable]:
        """
        Get hook functions for a specific hook point.
        
        Args:
            hook_point: Hook point name
            
        Returns:
            Dictionary mapping plugin names to hook functions
        """
        return self.hooks.get(hook_point, {}).copy()
    
    def get_all_hooks(self) -> Dict[str, Dict[str, Callable]]:
        """
        Get all hooks.
        
        Returns:
            Dictionary mapping hook points to dictionaries of plugin names and hook functions
        """
        return {point: hooks.copy() for point, hooks in self.hooks.items()}


class PluginLoader:
    """
    Responsible for discovering, loading, and managing plugins.
    """
    
    def __init__(self, plugin_dirs: List[str] = None):
        """
        Initialize the plugin loader.
        
        Args:
            plugin_dirs: List of directories to search for plugins
        """
        self.plugin_dirs = plugin_dirs or ["plugins"]
        self.registry = PluginRegistry()
        self.logger = logging.getLogger("apt.plugin_loader")
        
        # Track import paths that were added to sys.path
        self.added_paths = set()
    
    def _discover_plugins_in_directory(self, directory: str) -> Dict[str, PluginMetadata]:
        """
        Discover plugins in a directory.
        
        Args:
            directory: Directory to search for plugins
            
        Returns:
            Dictionary mapping plugin names to metadata
        """
        discovered = {}
        directory_path = Path(directory)
        
        if not directory_path.exists() or not directory_path.is_dir():
            self.logger.warning(f"Plugin directory does not exist: {directory}")
            return discovered
        
        # Try to load plugin manifest file if it exists
        manifest_path = directory_path / "plugins.json"
        yaml_manifest_path = directory_path / "plugins.yaml"
        
        if manifest_path.exists():
            try:
                with open(manifest_path, 'r') as f:
                    manifest_data = json.load(f)
                
                for plugin_data in manifest_data.get("plugins", []):
                    metadata = PluginMetadata.from_dict(plugin_data)
                    discovered[metadata.name] = metadata
                    
                self.logger.info(f"Loaded plugin manifest from {manifest_path}")
                return discovered
                
            except Exception as e:
                self.logger.error(f"Error loading plugin manifest: {str(e)}")
        
        if yaml_manifest_path.exists():
            try:
                with open(yaml_manifest_path, 'r') as f:
                    manifest_data = yaml.safe_load(f)
                
                for plugin_data in manifest_data.get("plugins", []):
                    metadata = PluginMetadata.from_dict(plugin_data)
                    discovered[metadata.name] = metadata
                    
                self.logger.info(f"Loaded plugin manifest from {yaml_manifest_path}")
                return discovered
                
            except Exception as e:
                self.logger.error(f"Error loading plugin manifest: {str(e)}")
        
        # If no manifest file exists, search for Python modules
        # Add the parent directory to sys.path if not already there
        parent_dir = str(directory_path.parent.absolute())
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
            self.added_paths.add(parent_dir)
        
        # Search for Python modules in the directory
        package_name = directory_path.name
        
        for _, name, is_pkg in pkgutil.iter_modules([str(directory_path)]):
            if is_pkg:  # Only consider packages (directories with __init__.py)
                try:
                    # Import the package
                    module_path = f"{package_name}.{name}"
                    module = importlib.import_module(module_path)
                    
                    # Look for plugin classes
                    for _, obj in inspect.getmembers(module, inspect.isclass):
                        if (issubclass(obj, AptPlugin) and 
                            obj is not AptPlugin and 
                            obj.__module__ == module_path):
                            
                            metadata = PluginMetadata.from_plugin_class(
                                obj, module_path=module_path
                            )
                            discovered[metadata.name] = metadata
                            
                            self.logger.debug(f"Discovered plugin: {metadata.name} ({module_path})")
                            
                except Exception as e:
                    self.logger.error(f"Error discovering plugin {name}: {str(e)}")
                    self.logger.debug(traceback.format_exc())
        
        return discovered
    
    def discover_plugins(self) -> Dict[str, PluginMetadata]:
        """
        Discover plugins in all plugin directories.
        
        Returns:
            Dictionary mapping plugin names to metadata
        """
        discovered = {}
        
        for directory in self.plugin_dirs:
            plugins = self._discover_plugins_in_directory(directory)
            discovered.update(plugins)
        
        self.logger.info(f"Discovered {len(discovered)} plugins")
        return discovered
    
    def _load_plugin(self, metadata: PluginMetadata, 
                   config: Dict[str, Any] = None) -> Optional[AptPlugin]:
        """
        Load a single plugin.
        
        Args:
            metadata: Plugin metadata
            config: Plugin configuration
            
        Returns:
            Plugin instance or None if loading failed
        """
        if not metadata.enabled:
            self.logger.info(f"Plugin {metadata.name} is disabled, skipping")
            return None
        
        try:
            # Import the module
            module_path = metadata.module_path
            if not module_path:
                self.logger.error(f"No module path specified for plugin {metadata.name}")
                return None
            
            module = importlib.import_module(module_path)
            
            # Find the plugin class
            plugin_class = None
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, AptPlugin) and 
                    obj is not AptPlugin and 
                    obj.PLUGIN_NAME == metadata.name):
                    plugin_class = obj
                    break
            
            if not plugin_class:
                self.logger.error(f"Could not find plugin class for {metadata.name}")
                return None
            
            # Instantiate the plugin
            plugin = plugin_class(config=config)
            
            # Initialize the plugin
            if not plugin.initialize():
                self.logger.error(f"Plugin {metadata.name} failed to initialize")
                return None
            
            self.logger.info(f"Loaded plugin: {metadata.name} v{metadata.version}")
            return plugin
            
        except Exception as e:
            self.logger.error(f"Error loading plugin {metadata.name}: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return None
    
    def _resolve_dependencies(self, 
                            plugins: Dict[str, PluginMetadata]) -> List[str]:
        """
        Resolve plugin dependencies and determine load order.
        
        Args:
            plugins: Dictionary mapping plugin names to metadata
            
        Returns:
            List of plugin names in the order they should be loaded
        """
        # Build dependency graph
        graph = {name: set(meta.dependencies) for name, meta in plugins.items()}
        
        # Check for missing dependencies
        all_plugins = set(plugins.keys())
        for name, deps in graph.items():
            missing = deps - all_plugins
            if missing:
                self.logger.warning(
                    f"Plugin {name} has missing dependencies: {', '.join(missing)}"
                )
                # Remove missing dependencies
                graph[name] = deps - missing
        
        # Topological sort (Kahn's algorithm)
        result = []
        no_deps = [name for name, deps in graph.items() if not deps]
        
        while no_deps:
            name = no_deps.pop(0)
            result.append(name)
            
            # Remove this plugin from all dependency lists
            for deps in graph.values():
                if name in deps:
                    deps.remove(name)
            
            # Find new nodes with no dependencies
            for plugin_name, deps in graph.items():
                if plugin_name not in result and not deps:
                    no_deps.append(plugin_name)
        
        # Check for circular dependencies
        if len(result) < len(plugins):
            remaining = set(plugins.keys()) - set(result)
            self.logger.error(
                f"Circular dependencies detected among plugins: {', '.join(remaining)}"
            )
        
        return result
    
    def load_plugins(self, 
                   config: Dict[str, Dict[str, Any]] = None) -> List[str]:
        """
        Discover and load plugins.
        
        Args:
            config: Configuration dictionary mapping plugin names to configurations
            
        Returns:
            List of names of successfully loaded plugins
        """
        config = config or {}
        
        # Discover plugins
        discovered = self.discover_plugins()
        
        # Resolve dependencies
        load_order = self._resolve_dependencies(discovered)
        
        # Load plugins in dependency order
        loaded = []
        
        for name in load_order:
            metadata = discovered[name]
            plugin_config = config.get(name, {})
            
            plugin = self._load_plugin(metadata, plugin_config)
            if plugin:
                self.registry.register_plugin(plugin, metadata)
                loaded.append(name)
        
        self.logger.info(f"Loaded {len(loaded)} plugins successfully")
        return loaded
    
    def unload_plugin(self, name: str) -> bool:
        """
        Unload a plugin.
        
        Args:
            name: Plugin name
            
        Returns:
            True if plugin was unloaded, False if not found or unload failed
        """
        plugin = self.registry.get_plugin(name)
        if not plugin:
            return False
        
        try:
            # Call plugin's shutdown method
            plugin.shutdown()
            
            # Unregister from registry
            self.registry.unregister_plugin(name)
            
            self.logger.info(f"Unloaded plugin: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error unloading plugin {name}: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return False
    
    def unload_all_plugins(self) -> None:
        """Unload all plugins."""
        for name in list(self.registry.get_all_plugins().keys()):
            self.unload_plugin(name)
    
    def reload_plugin(self, name: str, 
                    config: Dict[str, Any] = None) -> bool:
        """
        Reload a plugin.
        
        Args:
            name: Plugin name
            config: Plugin configuration
            
        Returns:
            True if plugin was reloaded, False if reload failed
        """
        metadata = self.registry.get_metadata(name)
        if not metadata:
            return False
        
        # Unload the plugin
        if not self.unload_plugin(name):
            return False
        
        # Reload the module
        try:
            module_path = metadata.module_path
            if module_path:
                module = importlib.import_module(module_path)
                importlib.reload(module)
        except Exception as e:
            self.logger.error(f"Error reloading module for plugin {name}: {str(e)}")
            return False
        
        # Load the plugin again
        plugin = self._load_plugin(metadata, config)
        if plugin:
            self.registry.register_plugin(plugin, metadata)
            self.logger.info(f"Reloaded plugin: {name}")
            return True
        
        return False
    
    def get_plugin_registry(self) -> PluginRegistry:
        """
        Get the plugin registry.
        
        Returns:
            PluginRegistry instance
        """
        return self.registry
    
    def execute_hook(self, hook_point: str, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute all hooks registered for a hook point.
        
        Args:
            hook_point: Hook point name
            *args: Positional arguments to pass to hook functions
            **kwargs: Keyword arguments to pass to hook functions
            
        Returns:
            Dictionary mapping plugin names to hook results
        """
        hooks = self.registry.get_hooks(hook_point)
        results = {}
        
        for plugin_name, hook_func in hooks.items():
            try:
                results[plugin_name] = hook_func(*args, **kwargs)
            except Exception as e:
                self.logger.error(
                    f"Error executing hook {hook_point} in plugin {plugin_name}: {str(e)}"
                )
                self.logger.debug(traceback.format_exc())
                results[plugin_name] = None
        
        return results
    
    def cleanup(self) -> None:
        """Clean up resources and unload all plugins."""
        self.unload_all_plugins()
        
        # Remove added paths from sys.path
        for path in self.added_paths:
            if path in sys.path:
                sys.path.remove(path)
        
        self.added_paths.clear()