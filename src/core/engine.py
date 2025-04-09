import importlib
import traceback
from typing import Any, Dict, Optional

from utils.logger import get_logger

logger = get_logger("Engine")

class ModuleExecutionError(Exception):
    """Custom exception for module execution failures."""
    pass

class Engine:
    """
    Core Engine responsible for managing and executing pentest modules.
    """

    def __init__(self):
        self.available_modules = {
            "recon": "modules.recon",
            "vuln_scanner": "modules.vuln_scanner",
            "brute_force": "modules.brute_force",
            "payload_gen": "modules.payload_gen",
            "exploit_exec": "modules.exploit_exec",
            "report_gen": "modules.report_gen",
            "auth_bypass": "modules.auth_bypass",
            "web_scanner": "modules.web_scanner",
            "network_mapper": "modules.network_mapper",
            "service_enum": "modules.service_enum",
            "scan_engine": "modules.scan_engine"
        }

    def list_modules(self) -> Dict[str, str]:
        """Return a dictionary of available modules."""
        return self.available_modules

    def execute_module(self, module_name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Load and execute a module by name with optional arguments.

        Args:
            module_name (str): The name of the module to run.
            args (dict): Arguments to pass to the module.

        Returns:
            dict: A dictionary with the execution result.
        """
        logger.info(f"Requested execution of module: {module_name}")
        args = args or {}

        if module_name not in self.available_modules:
            msg = f"Module '{module_name}' not found."
            logger.error(msg)
            raise ModuleExecutionError(msg)

        try:
            module_path = self.available_modules[module_name]
            module = importlib.import_module(module_path)

            if not hasattr(module, "run"):
                msg = f"Module '{module_name}' has no 'run(args)' method."
                logger.error(msg)
                raise ModuleExecutionError(msg)

            logger.debug(f"Executing {module_name} with args: {args}")
            result = module.run(args)
            logger.info(f"Execution of '{module_name}' complete.")
            return {
                "success": True,
                "module": module_name,
                "result": result
            }

        except Exception as e:
            error_trace = traceback.format_exc()
            logger.error(f"Error executing module '{module_name}': {e}")
            logger.debug(error_trace)
            return {
                "success": False,
                "module": module_name,
                "error": str(e),
                "traceback": error_trace
            }
