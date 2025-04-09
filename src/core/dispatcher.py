from PyQt6.QtCore import QObject, pyqtSignal, QThreadPool, QRunnable, pyqtSlot
from core.engine import Engine
from utils.logger import get_logger

logger = get_logger("Dispatcher")


class ModuleExecutionTask(QRunnable):
    """
    Worker for running modules in background threads.
    """
    def __init__(self, engine: Engine, module_name: str, args: dict, callback):
        super().__init__()
        self.engine = engine
        self.module_name = module_name
        self.args = args
        self.callback = callback

    @pyqtSlot()
    def run(self):
        logger.debug(f"Running module '{self.module_name}' in thread.")
        result = self.engine.execute_module(self.module_name, self.args)
        if self.callback:
            self.callback(result)


class Dispatcher(QObject):
    """
    Dispatcher connects the UI to the engine and handles async execution.
    """

    # Signals (optional if you want to connect to Qt UI)
    module_started = pyqtSignal(str)
    module_finished = pyqtSignal(str, dict)

    def __init__(self):
        super().__init__()
        self.engine = Engine()
        self.thread_pool = QThreadPool.globalInstance()

    def get_available_modules(self) -> dict:
        """
        Return a list of all available modules.
        """
        return self.engine.list_modules()

    def execute_module(self, module_name: str, args: dict = None, callback=None):
        """
        Run a module in a background thread.

        Args:
            module_name (str): Module to execute
            args (dict): Arguments to pass
            callback (func): Function to call with result
        """
        args = args or {}
        logger.info(f"Dispatching module: {module_name} with args: {args}")
        self.module_started.emit(module_name)

        task = ModuleExecutionTask(
            engine=self.engine,
            module_name=module_name,
            args=args,
            callback=lambda result: self._on_module_finished(module_name, result, callback)
        )
        self.thread_pool.start(task)

    def _on_module_finished(self, module_name: str, result: dict, callback=None):
        """
        Internal handler for when a module finishes.
        """
        logger.info(f"Module '{module_name}' finished.")
        self.module_finished.emit(module_name, result)
        if callback:
            callback(result)
