"""
Command Dispatcher for the apt toolkit.

This module provides a dispatcher that routes commands to the appropriate handlers
and orchestrates the execution of apt-related operations.
"""

import logging
import importlib
import inspect
from typing import Dict, Any, Callable, List, Optional, Tuple, Union
from pathlib import Path
import os
import sys
import traceback

# Local imports
from src.core.thread_pool import ThreadPool


class CommandDispatcher:
    """
    Dispatcher for routing commands to the appropriate handlers.
    
    This class is responsible for:
    1. Registering command handlers
    2. Dispatching commands to the appropriate handler
    3. Managing command execution and error handling
    4. Supporting synchronous and asynchronous execution
    """
    
    def __init__(self, max_workers: int = 4, enable_logging: bool = True):
        """
        Initialize the command dispatcher.
        
        Args:
            max_workers: Maximum number of worker threads for async execution
            enable_logging: Whether to enable logging
        """
        self.handlers: Dict[str, Callable] = {}
        self.thread_pool = ThreadPool(num_workers=max_workers)
        self.logger = logging.getLogger(__name__)
        
        if enable_logging and not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def register_handler(self, command_name: str, handler_func: Callable) -> None:
        """
        Register a handler function for a specific command.
        
        Args:
            command_name: Name of the command
            handler_func: Function to handle the command
        """
        if command_name in self.handlers:
            self.logger.warning(f"Overwriting existing handler for command '{command_name}'")
        
        self.handlers[command_name] = handler_func
        self.logger.debug(f"Registered handler for command '{command_name}'")
    
    def register_module(self, module_name: str, prefix: str = "") -> List[str]:
        """
        Register all handler functions from a module.
        
        This method imports the specified module and registers all functions
        that have a name starting with 'handle_' as command handlers.
        
        Args:
            module_name: Name of the module to import
            prefix: Optional prefix to add to command names
            
        Returns:
            List of registered command names
        """
        try:
            module = importlib.import_module(module_name)
            registered_commands = []
            
            for name, func in inspect.getmembers(module, inspect.isfunction):
                if name.startswith("handle_"):
                    # Extract command name from handler function name
                    # e.g., handle_install -> install
                    command_name = name[7:]  # Remove 'handle_' prefix
                    if prefix:
                        command_name = f"{prefix}:{command_name}"
                    
                    self.register_handler(command_name, func)
                    registered_commands.append(command_name)
            
            self.logger.info(f"Registered {len(registered_commands)} commands from module '{module_name}'")
            return registered_commands
            
        except ImportError as e:
            self.logger.error(f"Failed to import module '{module_name}': {str(e)}")
            return []
    
    def discover_and_register_handlers(self, package_dir: str = "src/handlers") -> int:
        """
        Discover and register handlers from all modules in a package directory.
        
        Args:
            package_dir: Directory containing handler modules
            
        Returns:
            Number of commands registered
        """
        package_path = Path(package_dir)
        if not package_path.exists() or not package_path.is_dir():
            self.logger.error(f"Handler directory '{package_dir}' does not exist or is not a directory")
            return 0
        
        # Add the parent directory to sys.path if not already there
        parent_dir = str(package_path.parent.absolute())
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        
        command_count = 0
        package_name = package_path.name
        
        # Find all Python files in the package directory
        for module_file in package_path.glob("*.py"):
            if module_file.name.startswith("__"):
                continue
            
            module_name = f"{package_name}.{module_file.stem}"
            registered = self.register_module(module_name)
            command_count += len(registered)
        
        self.logger.info(f"Discovered and registered a total of {command_count} commands")
        return command_count
    
    def has_handler(self, command_name: str) -> bool:
        """
        Check if a handler exists for the specified command.
        
        Args:
            command_name: Name of the command to check
            
        Returns:
            True if a handler exists, False otherwise
        """
        return command_name in self.handlers
    
    def get_available_commands(self) -> List[str]:
        """
        Get a list of all available commands.
        
        Returns:
            List of command names
        """
        return sorted(list(self.handlers.keys()))
    
    def execute(self, command_name: str, **kwargs) -> Any:
        """
        Execute a command synchronously.
        
        Args:
            command_name: Name of the command to execute
            **kwargs: Arguments to pass to the command handler
            
        Returns:
            Result of the command handler
            
        Raises:
            ValueError: If the command does not exist
            Exception: Any exception raised by the command handler
        """
        if not self.has_handler(command_name):
            raise ValueError(f"No handler registered for command '{command_name}'")
        
        handler = self.handlers[command_name]
        self.logger.debug(f"Executing command '{command_name}'")
        
        try:
            result = handler(**kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Error executing command '{command_name}': {str(e)}")
            self.logger.debug(traceback.format_exc())
            raise
    
    def execute_async(self, command_name: str, **kwargs) -> int:
        """
        Execute a command asynchronously.
        
        Args:
            command_name: Name of the command to execute
            **kwargs: Arguments to pass to the command handler
            
        Returns:
            Task ID that can be used to retrieve the result later
            
        Raises:
            ValueError: If the command does not exist
        """
        if not self.has_handler(command_name):
            raise ValueError(f"No handler registered for command '{command_name}'")
        
        handler = self.handlers[command_name]
        
        # Start the thread pool if it's not already running
        if not self.thread_pool.running:
            self.thread_pool.start()
        
        self.logger.debug(f"Executing command '{command_name}' asynchronously")
        return self.thread_pool.submit(handler, **kwargs)
    
    def execute_multiple(self, commands: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Execute multiple commands synchronously.
        
        Args:
            commands: List of (command_name, kwargs) tuples
            
        Returns:
            Dict mapping command names to their results
        """
        results = {}
        for command_name, kwargs in commands:
            try:
                results[command_name] = self.execute(command_name, **kwargs)
            except Exception as e:
                results[command_name] = {"error": str(e)}
        
        return results
    
    def execute_multiple_async(self, commands: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, int]:
        """
        Execute multiple commands asynchronously.
        
        Args:
            commands: List of (command_name, kwargs) tuples
            
        Returns:
            Dict mapping command names to their task IDs
        """
        task_ids = {}
        for command_name, kwargs in commands:
            try:
                task_id = self.execute_async(command_name, **kwargs)
                task_ids[command_name] = task_id
            except ValueError as e:
                self.logger.error(f"Error queuing command '{command_name}': {str(e)}")
        
        return task_ids
    
    def wait_for_results(self, task_ids: List[int], timeout: Optional[float] = None) -> Dict[int, Any]:
        """
        Wait for the results of multiple asynchronous tasks.
        
        Args:
            task_ids: List of task IDs to wait for
            timeout: Maximum time to wait in seconds (None means wait forever)
            
        Returns:
            Dict mapping task IDs to their results
        """
        results = {}
        for task_id in task_ids:
            self.thread_pool.wait_for_task(task_id, timeout=timeout)
            results[task_id] = self.thread_pool.get_result(task_id)
        
        return results
    
    def get_task_result(self, task_id: int) -> Any:
        """
        Get the result of an asynchronous task.
        
        Args:
            task_id: Task ID to get the result for
            
        Returns:
            Result of the task
        """
        return self.thread_pool.get_result(task_id)
    
    def shutdown(self) -> None:
        """Shut down the command dispatcher and its thread pool."""
        if self.thread_pool.running:
            self.thread_pool.shutdown(wait=True)
        self.logger.info("Command dispatcher shut down")
    
    def __enter__(self) -> 'CommandDispatcher':
        """Support for context manager protocol."""
        self.thread_pool.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Support for context manager protocol."""
        self.shutdown()


class AptDispatcher(CommandDispatcher):
    """
    Specialized dispatcher for apt-related commands.
    
    This class extends the CommandDispatcher with apt-specific functionality.
    """
    
    def __init__(self, max_workers: int = 4, 
                enable_logging: bool = True,
                auto_discover: bool = True):
        """
        Initialize the apt dispatcher.
        
        Args:
            max_workers: Maximum number of worker threads for async execution
            enable_logging: Whether to enable logging
            auto_discover: Whether to automatically discover and register handlers
        """
        super().__init__(max_workers=max_workers, enable_logging=enable_logging)
        
        # Register built-in handlers
        self.register_handler("help", self._handle_help)
        self.register_handler("list_commands", self._handle_list_commands)
        
        if auto_discover:
            self.discover_and_register_handlers()
    
    def _handle_help(self, command_name: Optional[str] = None) -> str:
        """
        Handle the 'help' command.
        
        Args:
            command_name: Optional name of command to get help for
            
        Returns:
            Help text
        """
        if command_name is None or command_name == "help":
            return (
                "Available commands:\n" +
                "\n".join(f"  - {cmd}" for cmd in self.get_available_commands())
            )
        
        if not self.has_handler(command_name):
            return f"No help available for unknown command '{command_name}'"
        
        handler = self.handlers[command_name]
        doc = inspect.getdoc(handler) or "No documentation available."
        
        # Parse command signature
        sig = inspect.signature(handler)
        params = []
        for name, param in sig.parameters.items():
            if param.default is inspect.Parameter.empty:
                params.append(f"{name}")
            else:
                default = param.default
                if isinstance(default, str):
                    default = f"'{default}'"
                params.append(f"{name}={default}")
        
        usage = f"{command_name}({', '.join(params)})"
        
        return f"Usage: {usage}\n\n{doc}"
    
    def _handle_list_commands(self) -> List[str]:
        """
        Handle the 'list_commands' command.
        
        Returns:
            List of available command names
        """
        return self.get_available_commands()
    
    def execute_apt_command(self, command_name: str, 
                           options: Optional[Dict[str, Any]] = None, 
                           async_execution: bool = False) -> Union[Any, int]:
        """
        Execute an apt-related command.
        
        Args:
            command_name: Name of the command to execute
            options: Optional dictionary of command options
            async_execution: Whether to execute the command asynchronously
            
        Returns:
            Result of the command or task ID if async_execution is True
        """
        if options is None:
            options = {}
        
        if async_execution:
            return self.execute_async(command_name, **options)
        else:
            return self.execute(command_name, **options)