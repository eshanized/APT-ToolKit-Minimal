import importlib.util
import os
import traceback
from typing import Callable, Dict, List, Optional
from pathlib import Path
from utils.logger import get_logger

logger = get_logger("PluginLoader")


class Plugin:
    """
    Represents a loaded plugin/module.
    """
    def __init__(self, name: str, path: Path, run_func: Optional[Callable] = None):
        self.name = name
        self.path = path
        self.run = run_func


class PluginLoader:
    """
    Loads Python modules dynamically from the 'modules/' directory.
    """

    def __init__(self, modules_dir: str = "src/modules"):
        self.modules_dir = Path(modules_dir)
        self.plugins: Dict[str, Plugin] = {}

    def load_plugins(self) -> Dict[str, Plugin]:
        """
        Scan the directory and load all plugins.
        """
        if not self.modules_dir.exists():
            logger.warning(f"Modules directory '{self.modules_dir}' not found.")
            return {}

        for file in os.listdir(self.modules_dir):
            if file.endswith(".py") and not file.startswith("__"):
                module_name = file[:-3]
                full_path = self.modules_dir / file
                plugin = self._load_plugin(module_name, full_path)
                if plugin:
                    self.plugins[module_name] = plugin

        logger.info(f"Loaded {len(self.plugins)} plugins.")
        return self.plugins

    def _load_plugin(self, name: str, path: Path) -> Optional[Plugin]:
        """
        Load a single plugin from a file.
        """
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                run_func = getattr(module, "run", None)
                if callable(run_func):
                    logger.debug(f"Plugin '{name}' loaded successfully.")
                    return Plugin(name=name, path=path, run_func=run_func)
                else:
                    logger.warning(f"Plugin '{name}' has no 'run()' function.")
        except Exception as e:
            logger.error(f"Error loading plugin '{name}': {e}")
            logger.debug(traceback.format_exc())

        return None

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """
        Retrieve a plugin by name.
        """
        return self.plugins.get(name)

    def list_plugins(self) -> List[str]:
        """
        List all available plugin names.
        """
        return list(self.plugins.keys())
