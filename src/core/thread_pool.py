"""
Thread Pool implementation for the apt toolkit.

This module provides a thread pool implementation for managing concurrent operations
in the apt toolkit, allowing controlled parallel execution of tasks.
"""

import threading
import queue
import time
import logging
import traceback
from typing import Callable, List, Dict, Any, Optional, Union, Tuple


class Worker(threading.Thread):
    """Worker thread that executes tasks from a queue."""
    
    def __init__(self, task_queue: queue.Queue, results: Dict[int, Any], 
                 name: Optional[str] = None):
        """
        Initialize a worker thread.
        
        Args:
            task_queue: Queue to pull tasks from
            results: Shared dictionary to store task results
            name: Optional name for the worker thread
        """
        super().__init__(name=name, daemon=True)
        self.task_queue = task_queue
        self.results = results
        self.shutdown_flag = threading.Event()
        self.logger = logging.getLogger(__name__)
        
    def run(self) -> None:
        """Main worker loop to process tasks from the queue."""
        while not self.shutdown_flag.is_set():
            try:
                # Get task with timeout to allow checking shutdown flag periodically
                task_id, func, args, kwargs = self.task_queue.get(timeout=0.1)
                
                try:
                    result = func(*args, **kwargs)
                    self.results[task_id] = {"status": "completed", "result": result}
                except Exception as e:
                    self.logger.error(f"Task {task_id} failed: {str(e)}")
                    self.logger.debug(traceback.format_exc())
                    self.results[task_id] = {
                        "status": "failed", 
                        "error": str(e), 
                        "traceback": traceback.format_exc()
                    }
                finally:
                    # Mark task as done regardless of success/failure
                    self.task_queue.task_done()
                    
            except queue.Empty:
                # No tasks available, continue checking shutdown flag
                continue
            except Exception as e:
                # Catch any other exceptions to keep worker alive
                self.logger.error(f"Worker error: {str(e)}")
                self.logger.debug(traceback.format_exc())
                
    def shutdown(self) -> None:
        """Signal the worker to shut down after finishing current task."""
        self.shutdown_flag.set()


class ThreadPool:
    """
    Thread pool for executing tasks concurrently with controlled parallelism.
    """
    
    def __init__(self, num_workers: int = 4, queue_size: int = 0, 
                worker_name_prefix: str = "worker"):
        """
        Initialize thread pool with the specified number of worker threads.
        
        Args:
            num_workers: Number of worker threads to create
            queue_size: Maximum size of task queue (0 means unlimited)
            worker_name_prefix: Prefix for worker thread names
        """
        self.num_workers = max(1, num_workers)  # Ensure at least one worker
        self.task_queue = queue.Queue(maxsize=queue_size)
        self.results = {}
        self.workers = []
        self.task_counter = 0
        self.task_counter_lock = threading.Lock()
        self.worker_name_prefix = worker_name_prefix
        self.logger = logging.getLogger(__name__)
        self.running = False
        
    def start(self) -> None:
        """Start the thread pool workers."""
        if self.running:
            return
            
        self.running = True
        self.workers = []
        
        for i in range(self.num_workers):
            worker = Worker(
                self.task_queue, 
                self.results, 
                name=f"{self.worker_name_prefix}-{i+1}"
            )
            self.workers.append(worker)
            worker.start()
            
        self.logger.info(f"Thread pool started with {self.num_workers} workers")
        
    def submit(self, func: Callable, *args, **kwargs) -> int:
        """
        Submit a task to be executed by the thread pool.
        
        Args:
            func: The function to execute
            *args: Positional arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function
            
        Returns:
            int: Task ID that can be used to retrieve the result later
            
        Raises:
            RuntimeError: If the thread pool is not running
        """
        if not self.running:
            raise RuntimeError("Thread pool is not running")
            
        with self.task_counter_lock:
            task_id = self.task_counter
            self.task_counter += 1
            
        self.results[task_id] = {"status": "pending"}
        self.task_queue.put((task_id, func, args, kwargs))
        return task_id
        
    def submit_batch(self, tasks: List[Tuple[Callable, List, Dict]]) -> List[int]:
        """
        Submit multiple tasks to the thread pool.
        
        Args:
            tasks: List of tuples (func, args, kwargs)
            
        Returns:
            List[int]: List of task IDs
        """
        return [self.submit(func, *args, **kwargs) 
                for func, args, kwargs in tasks]
                
    def wait_for_task(self, task_id: int, timeout: Optional[float] = None) -> bool:
        """
        Wait for a specific task to complete.
        
        Args:
            task_id: The task ID to wait for
            timeout: Maximum time to wait in seconds (None means wait forever)
            
        Returns:
            bool: True if task completed, False if timeout occurred
        """
        if task_id not in self.results:
            raise ValueError(f"Invalid task ID: {task_id}")
            
        start_time = time.time()
        while self.results[task_id]["status"] == "pending":
            if timeout is not None and time.time() - start_time > timeout:
                return False
            time.sleep(0.01)
            
        return True
        
    def wait_all(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all submitted tasks to complete.
        
        Args:
            timeout: Maximum time to wait in seconds (None means wait forever)
            
        Returns:
            bool: True if all tasks completed, False if timeout occurred
        """
        try:
            self.task_queue.join(timeout=timeout)
            return True
        except queue.Empty:
            return False
            
    def get_result(self, task_id: int, 
                  default: Any = None, 
                  raise_exception: bool = False) -> Any:
        """
        Get the result of a specific task.
        
        Args:
            task_id: The task ID to get the result for
            default: Value to return if task failed (when raise_exception is False)
            raise_exception: If True, raise an exception if the task failed
            
        Returns:
            The result of the task, or default value if task failed
            
        Raises:
            KeyError: If the task ID is invalid
            RuntimeError: If raise_exception is True and the task failed
        """
        if task_id not in self.results:
            raise KeyError(f"Invalid task ID: {task_id}")
            
        task_result = self.results[task_id]
        
        if task_result["status"] == "pending":
            return None
        elif task_result["status"] == "completed":
            return task_result["result"]
        elif task_result["status"] == "failed":
            if raise_exception:
                raise RuntimeError(f"Task failed: {task_result['error']}")
            return default
            
    def get_all_results(self, raise_exceptions: bool = False) -> Dict[int, Any]:
        """
        Get all task results.
        
        Args:
            raise_exceptions: If True, raise an exception for the first failed task
            
        Returns:
            Dict mapping task IDs to their results
            
        Raises:
            RuntimeError: If raise_exceptions is True and any task failed
        """
        completed_results = {}
        
        for task_id, task_result in self.results.items():
            if task_result["status"] == "completed":
                completed_results[task_id] = task_result["result"]
            elif task_result["status"] == "failed" and raise_exceptions:
                raise RuntimeError(f"Task {task_id} failed: {task_result['error']}")
                
        return completed_results
        
    def shutdown(self, wait: bool = True, cancel_pending: bool = False) -> None:
        """
        Shut down the thread pool.
        
        Args:
            wait: If True, wait for all tasks to complete before shutting down
            cancel_pending: If True, clear the task queue before shutting down
        """
        if not self.running:
            return
            
        if cancel_pending:
            # Clear the queue
            while not self.task_queue.empty():
                try:
                    task_id, _, _, _ = self.task_queue.get_nowait()
                    self.results[task_id] = {"status": "cancelled"}
                    self.task_queue.task_done()
                except queue.Empty:
                    break
                    
        if wait:
            # Wait for all tasks to complete
            self.task_queue.join()
            
        # Signal all workers to shut down
        for worker in self.workers:
            worker.shutdown()
            
        # Wait for all workers to terminate
        for worker in self.workers:
            worker.join(timeout=1.0)
            
        self.running = False
        self.logger.info("Thread pool shut down")
        
    def __enter__(self):
        """Support for context manager protocol."""
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support for context manager protocol."""
        self.shutdown(wait=True)
        
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the thread pool.
        
        Returns:
            Dict containing thread pool statistics
        """
        pending_count = sum(1 for r in self.results.values() 
                          if r["status"] == "pending")
        completed_count = sum(1 for r in self.results.values() 
                            if r["status"] == "completed")
        failed_count = sum(1 for r in self.results.values() 
                         if r["status"] == "failed")
        cancelled_count = sum(1 for r in self.results.values() 
                            if r["status"] == "cancelled")
                            
        return {
            "num_workers": self.num_workers,
            "queue_size": self.task_queue.qsize(),
            "running": self.running,
            "task_count": len(self.results),
            "pending_tasks": pending_count,
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "cancelled_tasks": cancelled_count
        }