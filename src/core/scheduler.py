"""
Task Scheduler for the apt toolkit.

This module provides a scheduler for planning and executing apt operations 
with timing controls, dependencies, and execution policies.
"""

import logging
import time
import threading
import heapq
import uuid
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Callable, Any, Optional, Union, Tuple, Set
import traceback

# Local imports
from src.core.thread_pool import ThreadPool


class TaskPriority(Enum):
    """Priority levels for scheduled tasks."""
    LOW = auto()
    NORMAL = auto()
    HIGH = auto()
    CRITICAL = auto()
    
    def __lt__(self, other):
        """Enable comparison for priority queue."""
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class TaskStatus(Enum):
    """Status of a scheduled task."""
    PENDING = auto()    # Not yet due to run
    READY = auto()      # Ready to run but not yet started
    RUNNING = auto()    # Currently running
    COMPLETED = auto()  # Completed successfully
    FAILED = auto()     # Failed with an error
    CANCELED = auto()   # Canceled before execution
    BLOCKED = auto()    # Blocked by dependencies
    SKIPPED = auto()    # Skipped due to policy


class Task:
    """Represents a scheduled task in the system."""
    
    def __init__(self, 
                task_id: str,
                name: str, 
                func: Callable, 
                args: tuple = (), 
                kwargs: dict = None,
                schedule_time: Optional[datetime] = None,
                priority: TaskPriority = TaskPriority.NORMAL,
                dependencies: List[str] = None,
                timeout: Optional[float] = None,
                retry_count: int = 0,
                retry_delay: float = 60.0,
                retry_backoff: float = 2.0,
                metadata: Dict[str, Any] = None):
        """
        Initialize a task.
        
        Args:
            task_id: Unique identifier for the task
            name: Human-readable name of the task
            func: Function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            schedule_time: When to execute the task (None means immediate)
            priority: Task priority
            dependencies: List of task IDs that must complete before this task
            timeout: Maximum execution time in seconds (None means no limit)
            retry_count: Number of times to retry on failure
            retry_delay: Initial delay between retries in seconds
            retry_backoff: Multiplier for retry delay after each attempt
            metadata: Additional task metadata
        """
        self.task_id = task_id
        self.name = name
        self.func = func
        self.args = args
        self.kwargs = kwargs or {}
        self.schedule_time = schedule_time or datetime.now()
        self.priority = priority
        self.dependencies = dependencies or []
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.retry_backoff = retry_backoff
        self.metadata = metadata or {}
        
        # Execution tracking
        self.status = TaskStatus.PENDING
        self.result = None
        self.error = None
        self.start_time = None
        self.end_time = None
        self.attempts = 0
        self.next_retry_time = None
        
    def __lt__(self, other):
        """Enable comparison for priority queue."""
        if not isinstance(other, Task):
            return NotImplemented
            
        # First compare by schedule time
        if self.schedule_time != other.schedule_time:
            return self.schedule_time < other.schedule_time
            
        # Then by priority (higher priority comes first)
        return self.priority.value > other.priority.value
        
    def is_due(self, current_time: datetime = None) -> bool:
        """Check if the task is due to run."""
        current_time = current_time or datetime.now()
        return current_time >= self.schedule_time
        
    def are_dependencies_met(self, completed_tasks: Set[str]) -> bool:
        """Check if all dependencies are met."""
        return all(dep in completed_tasks for dep in self.dependencies)
        
    def mark_as_running(self) -> None:
        """Mark the task as running."""
        self.status = TaskStatus.RUNNING
        self.start_time = datetime.now()
        self.attempts += 1
        
    def mark_as_completed(self, result: Any) -> None:
        """Mark the task as completed."""
        self.status = TaskStatus.COMPLETED
        self.result = result
        self.end_time = datetime.now()
        
    def mark_as_failed(self, error: Exception) -> None:
        """Mark the task as failed."""
        self.status = TaskStatus.FAILED
        self.error = str(error)
        self.end_time = datetime.now()
        
        # Calculate next retry time if retries are available
        if self.attempts <= self.retry_count:
            delay = self.retry_delay * (self.retry_backoff ** (self.attempts - 1))
            self.next_retry_time = datetime.now() + timedelta(seconds=delay)
            self.status = TaskStatus.PENDING
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "name": self.name,
            "schedule_time": self.schedule_time.isoformat(),
            "priority": self.priority.name,
            "dependencies": self.dependencies,
            "status": self.status.name,
            "attempts": self.attempts,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "result": str(self.result) if self.result else None,
            "error": self.error,
            "metadata": self.metadata
        }


class SchedulingPolicy(Enum):
    """Policies for scheduling tasks."""
    DEFAULT = auto()         # Execute in order of schedule time and priority
    DEPENDENCIES_FIRST = auto()  # Execute dependencies before dependents
    SKIP_FAILED_DEPS = auto()    # Skip tasks with failed dependencies
    RETRY_FAILED = auto()        # Retry failed tasks automatically
    CANCEL_ON_FAILURE = auto()   # Cancel all tasks if any task fails


class TaskScheduler:
    """
    Scheduler for planning and executing apt operations.
    """
    
    def __init__(self, max_workers: int = 4, policies: List[SchedulingPolicy] = None):
        """
        Initialize the task scheduler.
        
        Args:
            max_workers: Maximum number of concurrent tasks
            policies: List of scheduling policies to apply
        """
        self.thread_pool = ThreadPool(num_workers=max_workers)
        self.policies = set(policies or [SchedulingPolicy.DEFAULT])
        self.tasks: Dict[str, Task] = {}
        self.task_queue = []  # Priority queue of tasks
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        self.scheduler_lock = threading.Lock()
        self.running = False
        self.scheduler_thread = None
        self.logger = logging.getLogger(__name__)
        
    def schedule_task(self, 
                    name: str, 
                    func: Callable, 
                    args: tuple = (), 
                    kwargs: dict = None,
                    schedule_time: Optional[datetime] = None,
                    priority: TaskPriority = TaskPriority.NORMAL,
                    dependencies: List[str] = None,
                    timeout: Optional[float] = None,
                    retry_count: int = 0,
                    retry_delay: float = 60.0,
                    retry_backoff: float = 2.0,
                    metadata: Dict[str, Any] = None) -> str:
        """
        Schedule a task for execution.
        
        Args:
            name: Human-readable name of the task
            func: Function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            schedule_time: When to execute the task (None means immediate)
            priority: Task priority
            dependencies: List of task IDs that must complete before this task
            timeout: Maximum execution time in seconds (None means no limit)
            retry_count: Number of times to retry on failure
            retry_delay: Initial delay between retries in seconds
            retry_backoff: Multiplier for retry delay after each attempt
            metadata: Additional task metadata
            
        Returns:
            Task ID that can be used to track the task
        """
        task_id = str(uuid.uuid4())
        
        task = Task(
            task_id=task_id,
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            schedule_time=schedule_time,
            priority=priority,
            dependencies=dependencies,
            timeout=timeout,
            retry_count=retry_count,
            retry_delay=retry_delay,
            retry_backoff=retry_backoff,
            metadata=metadata
        )
        
        with self.scheduler_lock:
            # Add task to dictionary and priority queue
            self.tasks[task_id] = task
            
            # Check if dependencies are valid
            if dependencies:
                for dep_id in dependencies:
                    if dep_id not in self.tasks and dep_id not in self.completed_tasks:
                        self.logger.warning(
                            f"Task {task_id} depends on unknown task {dep_id}"
                        )
            
            # If dependencies are not met, mark as blocked
            if dependencies and not task.are_dependencies_met(self.completed_tasks):
                task.status = TaskStatus.BLOCKED
            
            # Add to priority queue
            heapq.heappush(self.task_queue, task)
            
            self.logger.debug(
                f"Scheduled task {task_id} ({name}) for execution at {schedule_time}"
            )
        
        return task_id
        
    def schedule_recurring_task(self,
                              name: str,
                              func: Callable,
                              interval: timedelta,
                              args: tuple = (),
                              kwargs: dict = None,
                              start_time: Optional[datetime] = None,
                              priority: TaskPriority = TaskPriority.NORMAL,
                              timeout: Optional[float] = None,
                              metadata: Dict[str, Any] = None) -> str:
        """
        Schedule a recurring task.
        
        Args:
            name: Human-readable name of the task
            func: Function to execute
            interval: Time interval between executions
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            start_time: When to start the recurring task (None means immediate)
            priority: Task priority
            timeout: Maximum execution time in seconds (None means no limit)
            metadata: Additional task metadata
            
        Returns:
            Task ID for the recurring task definition
        """
        if metadata is None:
            metadata = {}
            
        # Add recurring task metadata
        metadata["recurring"] = True
        metadata["interval"] = interval.total_seconds()
        
        # Create recurring task definition
        recurring_id = str(uuid.uuid4())
        metadata["recurring_id"] = recurring_id
        
        # Schedule the first instance
        start_time = start_time or datetime.now()
        
        task_id = self.schedule_task(
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            schedule_time=start_time,
            priority=priority,
            timeout=timeout,
            metadata=metadata
        )
        
        self.logger.info(
            f"Scheduled recurring task {recurring_id} ({name}) "
            f"with interval {interval}"
        )
        
        return recurring_id
        
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a scheduled task.
        
        Args:
            task_id: ID of the task to cancel
            
        Returns:
            True if task was canceled, False if task was not found or already running
        """
        with self.scheduler_lock:
            if task_id not in self.tasks:
                return False
                
            task = self.tasks[task_id]
            
            if task.status == TaskStatus.RUNNING:
                # Cannot cancel running tasks
                return False
                
            task.status = TaskStatus.CANCELED
            
            # Remove from queue (will be filtered out in _process_task_queue)
            
            self.logger.info(f"Canceled task {task_id} ({task.name})")
            return True
            
    def cancel_recurring_task(self, recurring_id: str) -> int:
        """
        Cancel a recurring task and all its future instances.
        
        Args:
            recurring_id: ID of the recurring task to cancel
            
        Returns:
            Number of tasks canceled
        """
        canceled_count = 0
        
        with self.scheduler_lock:
            # Find and cancel all tasks with this recurring ID
            for task_id, task in self.tasks.items():
                if (task.metadata.get("recurring") and 
                    task.metadata.get("recurring_id") == recurring_id and
                    task.status not in (TaskStatus.RUNNING, TaskStatus.COMPLETED, 
                                     TaskStatus.FAILED)):
                    task.status = TaskStatus.CANCELED
                    canceled_count += 1
                    
            if canceled_count > 0:
                self.logger.info(
                    f"Canceled recurring task {recurring_id} ({canceled_count} instances)"
                )
                
        return canceled_count
        
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """
        Get the status of a task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            Task status or None if task was not found
        """
        with self.scheduler_lock:
            if task_id not in self.tasks:
                return None
                
            return self.tasks[task_id].status
            
    def get_task_result(self, task_id: str) -> Optional[Any]:
        """
        Get the result of a completed task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            Task result or None if task was not found or not completed
        """
        with self.scheduler_lock:
            if task_id not in self.tasks:
                return None
                
            task = self.tasks[task_id]
            
            if task.status != TaskStatus.COMPLETED:
                return None
                
            return task.result
            
    def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            Dictionary with task information or None if task was not found
        """
        with self.scheduler_lock:
            if task_id not in self.tasks:
                return None
                
            return self.tasks[task_id].to_dict()
            
    def get_all_tasks(self) -> List[Dict[str, Any]]:
        """
        Get information about all tasks.
        
        Returns:
            List of dictionaries with task information
        """
        with self.scheduler_lock:
            return [task.to_dict() for task in self.tasks.values()]
            
    def start(self) -> None:
        """Start the scheduler."""
        if self.running:
            return
            
        self.running = True
        self.thread_pool.start()
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler,
            name="scheduler-thread",
            daemon=True
        )
        self.scheduler_thread.start()
        
        self.logger.info("Task scheduler started")
        
    def stop(self, wait: bool = True) -> None:
        """
        Stop the scheduler.
        
        Args:
            wait: If True, wait for all running tasks to complete
        """
        if not self.running:
            return
            
        self.running = False
        
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=1.0)
            
        self.thread_pool.shutdown(wait=wait)
        
        self.logger.info("Task scheduler stopped")
        
    def _run_scheduler(self) -> None:
        """Main scheduler loop."""
        while self.running:
            try:
                self._process_task_queue()
                time.sleep(0.1)  # Avoid consuming CPU with tight loop
            except Exception as e:
                self.logger.error(f"Scheduler error: {str(e)}")
                self.logger.debug(traceback.format_exc())
                
    def _process_task_queue(self) -> None:
        """Process the task queue, executing due tasks."""
        current_time = datetime.now()
        tasks_to_execute = []
        
        with self.scheduler_lock:
            # Find due tasks and prepare for execution
            while self.task_queue:
                # Peek at the next task
                task = self.task_queue[0]
                
                # Skip tasks that are not pending or ready
                if task.status not in (TaskStatus.PENDING, TaskStatus.READY, TaskStatus.BLOCKED):
                    heapq.heappop(self.task_queue)  # Remove from queue
                    continue
                    
                # Stop if the next task is not due yet
                if not task.is_due(current_time):
                    break
                    
                # Pop the task from the queue
                task = heapq.heappop(self.task_queue)
                
                # Skip canceled tasks
                if task.status == TaskStatus.CANCELED:
                    continue
                    
                # Check dependencies
                if task.dependencies:
                    # Apply policy for failed dependencies
                    if (SchedulingPolicy.SKIP_FAILED_DEPS in self.policies and
                        any(dep in self.failed_tasks for dep in task.dependencies)):
                        task.status = TaskStatus.SKIPPED
                        self.logger.info(
                            f"Skipping task {task.task_id} ({task.name}) due to failed dependencies"
                        )
                        continue
                        
                    # Check if all dependencies are completed
                    if not task.are_dependencies_met(self.completed_tasks):
                        task.status = TaskStatus.BLOCKED
                        # Put back in queue for later
                        heapq.heappush(self.task_queue, task)
                        continue
                        
                # Task is ready to execute
                task.status = TaskStatus.READY
                tasks_to_execute.append(task)
                
            # Submit tasks for execution
            for task in tasks_to_execute:
                self._execute_task(task)
                
                # Schedule next instance for recurring tasks
                if task.metadata.get("recurring"):
                    self._schedule_next_recurring_instance(task)
                    
    def _execute_task(self, task: Task) -> None:
        """Execute a single task."""
        task.mark_as_running()
        
        self.logger.debug(f"Executing task {task.task_id} ({task.name})")
        
        # Define a wrapper function to handle task completion and errors
        def task_wrapper():
            try:
                # Execute the task with timeout if specified
                if task.timeout is not None:
                    # TODO: Implement timeout handling
                    result = task.func(*task.args, **task.kwargs)
                else:
                    result = task.func(*task.args, **task.kwargs)
                    
                with self.scheduler_lock:
                    task.mark_as_completed(result)
                    self.completed_tasks.add(task.task_id)
                    
                    self.logger.debug(
                        f"Task {task.task_id} ({task.name}) completed successfully"
                    )
                    
                    # Check if we need to cancel all tasks on failure
                    if (SchedulingPolicy.CANCEL_ON_FAILURE in self.policies and
                        task.status == TaskStatus.FAILED):
                        self._cancel_all_pending_tasks()
                        
            except Exception as e:
                with self.scheduler_lock:
                    task.mark_as_failed(e)
                    
                    if task.next_retry_time is None:
                        # No more retries available
                        self.failed_tasks.add(task.task_id)
                        self.logger.error(
                            f"Task {task.task_id} ({task.name}) failed: {str(e)}"
                        )
                    else:
                        # Schedule for retry
                        self.logger.info(
                            f"Task {task.task_id} ({task.name}) failed, "
                            f"retry scheduled at {task.next_retry_time}"
                        )
                        heapq.heappush(self.task_queue, task)
                        
        # Submit task to thread pool
        self.thread_pool.submit(task_wrapper)
        
    def _schedule_next_recurring_instance(self, task: Task) -> None:
        """Schedule the next instance of a recurring task."""
        if not task.metadata.get("recurring"):
            return
            
        interval_seconds = task.metadata.get("interval")
        if not interval_seconds:
            return
            
        interval = timedelta(seconds=interval_seconds)
        next_time = task.schedule_time + interval
        
        # Schedule next instance
        self.schedule_task(
            name=task.name,
            func=task.func,
            args=task.args,
            kwargs=task.kwargs,
            schedule_time=next_time,
            priority=task.priority,
            timeout=task.timeout,
            metadata=task.metadata  # Pass the same metadata (including recurring info)
        )
        
    def _cancel_all_pending_tasks(self) -> None:
        """Cancel all pending tasks."""
        with self.scheduler_lock:
            for task_id, task in self.tasks.items():
                if task.status in (TaskStatus.PENDING, TaskStatus.READY, TaskStatus.BLOCKED):
                    task.status = TaskStatus.CANCELED
                    
            # Clear the task queue
            self.task_queue = []
            
            self.logger.warning("Canceled all pending tasks due to failure")
            
    def __enter__(self):
        """Support for context manager protocol."""
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support for context manager protocol."""
        self.stop(wait=True)