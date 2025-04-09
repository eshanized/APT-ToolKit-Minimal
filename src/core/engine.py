"""
Core Engine for the APT toolkit.

This module provides the central engine that integrates and coordinates the various
components of the APT toolkit, including thread pool, command dispatcher, task scheduler,
plugin loader, and the various modules.
"""

import os
import sys
import logging
import time
import threading
import json
import yaml
from typing import Dict, List, Any, Optional, Union, Callable, Set, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import importlib
import traceback

# Core components
from src.core.thread_pool import ThreadPool
from src.core.dispatcher import CommandDispatcher, AptDispatcher
from src.core.scheduler import TaskScheduler, TaskPriority, TaskStatus
from src.core.plugin_loader import PluginLoader, AptPlugin

# Utilities
from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager

# Modules
from src.modules.recon import ReconModule
from src.modules.network_mapper import NetworkMapper
from src.modules.service_enum import ServiceEnumModule
from src.modules.scan_engine import ScanEngine
from src.modules.web_scanner import WebScanner
from src.modules.vuln_scanner import VulnScannerModule
from src.modules.brute_force import BruteForceModule
from src.modules.auth_bypass import AuthBypassModule
from src.modules.payload_gen import PayloadGenModule
from src.modules.exploit_exec import ExploitExecModule
from src.modules.report_gen import ReportGenerator


class EngineStatus:
    """Status of the APT toolkit engine."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class AptEngine:
    """
    Core engine for the APT toolkit.
    
    This class integrates and coordinates the various components of the APT toolkit,
    including thread pool, command dispatcher, task scheduler, plugin loader, and
    the various modules.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the APT toolkit engine.
        
        Args:
            config_path: Path to configuration file (JSON or YAML)
        """
        self.logger = get_module_logger("engine")
        self.status = EngineStatus.STOPPED
        self.config = ConfigManager()
        
        # Load configuration if provided
        if config_path:
            self._load_config(config_path)
        
        # Initialize core components
        self._init_core_components()
        
        # Initialize modules
        self._init_modules()
        
        # Track registered command handlers
        self.command_handlers = {}
        
        # Track engine start time
        self.start_time = None
        
        # Engine lock for thread safety
        self.engine_lock = threading.RLock()
    
    def _load_config(self, config_path: str) -> None:
        """
        Load configuration from file.
        
        Args:
            config_path: Path to configuration file (JSON or YAML)
        """
        try:
            path = Path(config_path)
            if not path.exists():
                self.logger.warning(f"Configuration file not found: {config_path}")
                return
            
            if path.suffix.lower() in ['.json']:
                with open(path, 'r') as f:
                    config_data = json.load(f)
            elif path.suffix.lower() in ['.yaml', '.yml']:
                with open(path, 'r') as f:
                    config_data = yaml.safe_load(f)
            else:
                self.logger.warning(f"Unsupported configuration file format: {path.suffix}")
                return
            
            # Load configuration into ConfigManager
            self.config.load_from_dict(config_data)
            self.logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self.logger.debug(traceback.format_exc())
    
    def _init_core_components(self) -> None:
        """Initialize core components of the engine."""
        # Get configuration values
        thread_pool_size = self.config.get("core.thread_pool.size", 8)
        scheduler_workers = self.config.get("core.scheduler.workers", 4)
        plugin_dirs = self.config.get("core.plugins.directories", ["plugins"])
        
        # Initialize thread pool
        self.thread_pool = ThreadPool(
            num_workers=thread_pool_size,
            worker_name_prefix="apt-worker"
        )
        
        # Initialize command dispatcher
        self.dispatcher = AptDispatcher(
            max_workers=thread_pool_size,
            enable_logging=True,
            auto_discover=False  # We'll manually register handlers
        )
        
        # Initialize task scheduler
        self.scheduler = TaskScheduler(
            max_workers=scheduler_workers
        )
        
        # Initialize plugin loader
        self.plugin_loader = PluginLoader(
            plugin_dirs=plugin_dirs
        )
        
        self.logger.debug("Core components initialized")
    
    def _init_modules(self) -> None:
        """Initialize APT toolkit modules."""
        # Initialize modules with configuration
        self.recon = ReconModule(config=self.config)
        self.network_mapper = NetworkMapper(config=self.config)
        self.service_enum = ServiceEnumModule(config=self.config)
        self.scan_engine = ScanEngine(config=self.config)
        self.web_scanner = WebScanner(config=self.config)
        self.vuln_scanner = VulnScannerModule(config=self.config)
        self.brute_force = BruteForceModule(config=self.config)
        self.auth_bypass = AuthBypassModule(config=self.config)
        self.payload_gen = PayloadGenModule(config=self.config)
        self.exploit_exec = ExploitExecModule(config=self.config)
        self.report_gen = ReportGenerator(config=self.config)
        
        # Store modules in a dictionary for easy access
        self.modules = {
            "recon": self.recon,
            "network_mapper": self.network_mapper,
            "service_enum": self.service_enum,
            "scan_engine": self.scan_engine,
            "web_scanner": self.web_scanner,
            "vuln_scanner": self.vuln_scanner,
            "brute_force": self.brute_force,
            "auth_bypass": self.auth_bypass,
            "payload_gen": self.payload_gen,
            "exploit_exec": self.exploit_exec,
            "report_gen": self.report_gen
        }
        
        self.logger.debug("Modules initialized")
    
    def _register_command_handlers(self) -> None:
        """Register command handlers for all modules."""
        # Register recon module handlers
        self.dispatcher.register_handler("recon:scan", self.recon.scan)
        # The following methods don't exist directly, use network utils methods instead
        self.dispatcher.register_handler("recon:dns_lookup", self.network.resolve_hostname if hasattr(self.network, 'resolve_hostname') else self.recon.network.resolve_hostname)
        self.dispatcher.register_handler("recon:whois_lookup", self.network.whois_lookup if hasattr(self.network, 'whois_lookup') else self.recon.network.whois_lookup)
        self.dispatcher.register_handler("recon:port_scan", self.network.port_scan if hasattr(self.network, 'port_scan') else self.recon.network.port_scan)
        
        # Register network mapper handlers
        self.dispatcher.register_handler("network:map", self.network_mapper.map_network)
        self.dispatcher.register_handler("network:discover", self.network_mapper.discover_hosts)
        self.dispatcher.register_handler("network:trace", self.network_mapper.trace_route)
        
        # Register service enumeration handlers
        self.dispatcher.register_handler("service:enum", self.service_enum.enumerate_services)
        self.dispatcher.register_handler("service:fingerprint", self.service_enum.fingerprint_service)
        
        # Register scan engine handlers
        self.dispatcher.register_handler("scan:create", self.scan_engine.create_scan)
        self.dispatcher.register_handler("scan:start", self.scan_engine.start_scan)
        self.dispatcher.register_handler("scan:stop", self.scan_engine.stop_scan)
        self.dispatcher.register_handler("scan:status", self.scan_engine.get_scan_status)
        self.dispatcher.register_handler("scan:results", self.scan_engine.get_scan_results)
        
        # Register web scanner handlers
        self.dispatcher.register_handler("web:scan", self.web_scanner.scan_target)
        self.dispatcher.register_handler("web:crawl", self.web_scanner.crawl_website)
        self.dispatcher.register_handler("web:identify", self.web_scanner.identify_technologies)
        
        # Register vulnerability scanner handlers
        self.dispatcher.register_handler("vuln_scanner:scan", self.vuln_scanner.scan_target)
        self.dispatcher.register_handler("vuln_scanner:check", self.vuln_scanner.check_vulnerability)
        
        # Register brute force handlers
        self.dispatcher.register_handler("brute_force:attack", self.brute_force.attack)
        self.dispatcher.register_handler("brute_force:wordlist", self.brute_force.generate_wordlist)
        
        # Register auth bypass handlers
        self.dispatcher.register_handler("auth_bypass:test", self.auth_bypass.test_target)
        self.dispatcher.register_handler("auth_bypass:techniques", self.auth_bypass.get_techniques)
        
        # Register payload generation handlers
        self.dispatcher.register_handler("payload_gen:generate", self.payload_gen.create_payload)
        self.dispatcher.register_handler("payload_gen:list", self.payload_gen.list_payloads)
        
        # Register exploit execution handlers
        self.dispatcher.register_handler("exploit_exec:execute", self.exploit_exec.execute_exploit)
        self.dispatcher.register_handler("exploit_exec:list", self.exploit_exec.get_available_exploits)
        
        # Register report generation handlers
        self.dispatcher.register_handler("report_gen:generate", self.report_gen.generate_report)
        self.dispatcher.register_handler("report_gen:list", self.report_gen.list_reports)
        
        # Register engine handlers
        self.dispatcher.register_handler("engine:status", self.get_status)
        self.dispatcher.register_handler("engine:modules", self.get_modules)
        self.dispatcher.register_handler("engine:commands", self.get_commands)
        
        self.logger.debug("Command handlers registered")
    
    def _load_plugins(self) -> None:
        """Load plugins using the plugin loader."""
        # Get plugin configuration
        plugin_config = self.config.get("plugins", {})
        
        # Load plugins
        loaded_plugins = self.plugin_loader.load_plugins(plugin_config)
        
        if loaded_plugins:
            self.logger.info(f"Loaded {len(loaded_plugins)} plugins: {', '.join(loaded_plugins)}")
            
            # Register plugin command handlers
            registry = self.plugin_loader.get_plugin_registry()
            for cmd_name, (plugin_name, handler) in registry.get_all_handlers().items():
                self.dispatcher.register_handler(f"plugin:{cmd_name}", handler)
                self.logger.debug(f"Registered plugin handler: plugin:{cmd_name} from {plugin_name}")
    
    def start(self) -> bool:
        """
        Start the APT toolkit engine.
        
        Returns:
            True if engine started successfully, False otherwise
        """
        with self.engine_lock:
            if self.status != EngineStatus.STOPPED:
                self.logger.warning(f"Cannot start engine: current status is {self.status}")
                return False
            
            self.logger.info("Starting APT toolkit engine")
            self.status = EngineStatus.STARTING
            
            try:
                # Start core components
                self.thread_pool.start()
                self.scheduler.start()
                
                # Register command handlers
                self._register_command_handlers()
                
                # Load plugins
                self._load_plugins()
                
                # Set engine status
                self.status = EngineStatus.RUNNING
                self.start_time = datetime.now()
                
                self.logger.info("APT toolkit engine started successfully")
                return True
                
            except Exception as e:
                self.logger.error(f"Error starting engine: {str(e)}")
                self.logger.debug(traceback.format_exc())
                self.status = EngineStatus.ERROR
                return False
    
    def stop(self) -> bool:
        """
        Stop the APT toolkit engine.
        
        Returns:
            True if engine stopped successfully, False otherwise
        """
        with self.engine_lock:
            if self.status not in [EngineStatus.RUNNING, EngineStatus.ERROR]:
                self.logger.warning(f"Cannot stop engine: current status is {self.status}")
                return False
            
            self.logger.info("Stopping APT toolkit engine")
            self.status = EngineStatus.STOPPING
            
            try:
                # Unload plugins
                self.plugin_loader.cleanup()
                
                # Stop core components
                self.scheduler.stop(wait=True)
                self.thread_pool.shutdown(wait=True)
                
                # Set engine status
                self.status = EngineStatus.STOPPED
                
                self.logger.info("APT toolkit engine stopped successfully")
                return True
                
            except Exception as e:
                self.logger.error(f"Error stopping engine: {str(e)}")
                self.logger.debug(traceback.format_exc())
                self.status = EngineStatus.ERROR
                return False
    
    def restart(self) -> bool:
        """
        Restart the APT toolkit engine.
        
        Returns:
            True if engine restarted successfully, False otherwise
        """
        if self.stop():
            return self.start()
        return False
    
    def execute_command(self, command: str, 
                       args: Dict[str, Any] = None, 
                       async_execution: bool = False) -> Any:
        """
        Execute a command.
        
        Args:
            command: Command to execute
            args: Command arguments
            async_execution: Whether to execute the command asynchronously
            
        Returns:
            Command result or task ID if async_execution is True
        """
        if self.status != EngineStatus.RUNNING:
            raise RuntimeError(f"Cannot execute command: engine is not running (status: {self.status})")
        
        args = args or {}
        
        self.logger.debug(f"Executing command: {command}")
        
        if async_execution:
            return self.dispatcher.execute_async(command, **args)
        else:
            return self.dispatcher.execute(command, **args)
    
    def schedule_task(self, name: str, command: str, 
                     args: Dict[str, Any] = None,
                     schedule_time: Optional[datetime] = None,
                     priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """
        Schedule a task for execution.
        
        Args:
            name: Task name
            command: Command to execute
            args: Command arguments
            schedule_time: When to execute the task (None means immediate)
            priority: Task priority
            
        Returns:
            Task ID
        """
        if self.status != EngineStatus.RUNNING:
            raise RuntimeError(f"Cannot schedule task: engine is not running (status: {self.status})")
        
        args = args or {}
        
        # Create a function that will execute the command
        def execute_command_task():
            return self.execute_command(command, args)
        
        # Schedule the task
        task_id = self.scheduler.schedule_task(
            name=name,
            func=execute_command_task,
            schedule_time=schedule_time,
            priority=priority
        )
        
        self.logger.debug(f"Scheduled task {task_id} ({name}) for command: {command}")
        return task_id
    
    def schedule_recurring_task(self, name: str, command: str,
                              args: Dict[str, Any] = None,
                              interval: timedelta = timedelta(hours=1),
                              start_time: Optional[datetime] = None,
                              priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """
        Schedule a recurring task.
        
        Args:
            name: Task name
            command: Command to execute
            args: Command arguments
            interval: Time interval between executions
            start_time: When to start the recurring task (None means immediate)
            priority: Task priority
            
        Returns:
            Recurring task ID
        """
        if self.status != EngineStatus.RUNNING:
            raise RuntimeError(f"Cannot schedule recurring task: engine is not running (status: {self.status})")
        
        args = args or {}
        
        # Create a function that will execute the command
        def execute_command_task():
            return self.execute_command(command, args)
        
        # Schedule the recurring task
        recurring_id = self.scheduler.schedule_recurring_task(
            name=name,
            func=execute_command_task,
            interval=interval,
            start_time=start_time,
            priority=priority
        )
        
        self.logger.debug(f"Scheduled recurring task {recurring_id} ({name}) for command: {command}")
        return recurring_id
    
    def get_module(self, module_name: str) -> Any:
        """
        Get a module by name.
        
        Args:
            module_name: Module name
            
        Returns:
            Module instance
            
        Raises:
            ValueError: If module not found
        """
        if module_name not in self.modules:
            raise ValueError(f"Module not found: {module_name}")
        
        return self.modules[module_name]
    
    def get_modules(self) -> Dict[str, Any]:
        """
        Get all modules.
        
        Returns:
            Dictionary mapping module names to module instances
        """
        return self.modules.copy()
    
    def get_commands(self) -> List[str]:
        """
        Get all available commands.
        
        Returns:
            List of command names
        """
        return self.dispatcher.get_available_commands()
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get engine status.
        
        Returns:
            Dictionary with engine status information
        """
        with self.engine_lock:
            status_info = {
                "status": self.status,
                "uptime": str(datetime.now() - self.start_time) if self.start_time else None,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "thread_pool": self.thread_pool.get_stats(),
                "modules": list(self.modules.keys()),
                "plugins": list(self.plugin_loader.get_plugin_registry().get_all_plugins().keys())
            }
            
            return status_info
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get task status.
        
        Args:
            task_id: Task ID
            
        Returns:
            Dictionary with task status information or None if task not found
        """
        return self.scheduler.get_task_info(task_id)
    
    def get_task_result(self, task_id: str) -> Any:
        """
        Get task result.
        
        Args:
            task_id: Task ID
            
        Returns:
            Task result or None if task not found or not completed
        """
        return self.scheduler.get_task_result(task_id)
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.
        
        Args:
            task_id: Task ID
            
        Returns:
            True if task was canceled, False otherwise
        """
        return self.scheduler.cancel_task(task_id)
    
    def __enter__(self):
        """Support for context manager protocol."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support for context manager protocol."""
        self.stop()


# Singleton instance
_engine_instance = None


def get_engine(config_path: Optional[str] = None) -> AptEngine:
    """
    Get the singleton engine instance.
    
    Args:
        config_path: Path to configuration file (only used if engine not already initialized)
        
    Returns:
        AptEngine instance
    """
    global _engine_instance
    
    if _engine_instance is None:
        _engine_instance = AptEngine(config_path=config_path)
        
    return _engine_instance