"""
Scan Engine module for the APT toolkit.

This module provides a unified scanning engine that integrates various
scanning modules and provides a consistent interface for scan operations.
"""

import os
import time
import json
import uuid
import ipaddress
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from datetime import datetime

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils
from src.modules.recon import ReconModule, ReconResult
from src.modules.network_mapper import NetworkMapper, NetworkMapResult
from src.modules.service_enum import ServiceEnumModule, ServiceEnumResult

logger = get_module_logger("scan_engine")

class ScanStatus(Enum):
    """Enumeration of scan statuses"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()

class ScanType(Enum):
    """Enumeration of scan types"""
    RECON = auto()
    NETWORK_MAP = auto()
    SERVICE_ENUM = auto()
    VULNERABILITY = auto()
    COMPREHENSIVE = auto()
    CUSTOM = auto()

@dataclass
class ScanTarget:
    """Data class for scan target information"""
    target: str  # IP, domain, CIDR, etc.
    target_type: str = ""  # IP, DOMAIN, CIDR, etc.
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Automatically determine target type if not specified"""
        if not self.target_type:
            if self._is_valid_ip(self.target):
                self.target_type = "IP"
            elif self._is_valid_cidr(self.target):
                self.target_type = "CIDR"
            elif self._is_valid_domain(self.target):
                self.target_type = "DOMAIN"
            else:
                self.target_type = "UNKNOWN"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_valid_cidr(self, cidr: str) -> bool:
        """Check if string is a valid CIDR notation"""
        try:
            if '/' in cidr:
                ipaddress.ip_network(cidr, strict=False)
                return True
            return False
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Simple check if string looks like a domain name"""
        if '.' in domain and not self._is_valid_ip(domain) and not self._is_valid_cidr(domain):
            return True
        return False

@dataclass
class ScanConfig:
    """Data class for scan configuration"""
    scan_types: List[ScanType] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    timeout: float = 5.0
    max_threads: int = 20
    aggressive: bool = False
    check_vulns: bool = True
    check_default_creds: bool = False
    max_hosts: int = 100
    max_depth: int = 2
    output_format: str = "json"
    output_dir: str = ""
    custom_options: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanVulnerability:
    """Data class for aggregated vulnerability information"""
    target: str
    port: int
    service: str
    vulnerability_id: str
    severity: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_info: Dict[str, Any] = field(default_factory=dict)
    scan_module: str = ""  # Which module detected this vulnerability

@dataclass
class ScanResult:
    """Data class for comprehensive scan results"""
    scan_id: str
    target: str
    scan_types: List[str]
    start_time: float
    end_time: float = 0.0
    status: ScanStatus = ScanStatus.PENDING
    recon_results: Optional[ReconResult] = None
    network_map_results: Optional[NetworkMapResult] = None
    service_enum_results: Optional[ServiceEnumResult] = None
    vulnerabilities: List[ScanVulnerability] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        result = {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_types": [st for st in self.scan_types],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status.name,
            "notes": self.notes,
            "errors": self.errors,
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities]
        }
        
        # Add module-specific results if available
        if self.recon_results:
            result["recon_results"] = self.recon_results.to_dict()
        
        if self.network_map_results:
            result["network_map_results"] = self.network_map_results.to_dict()
        
        if self.service_enum_results:
            result["service_enum_results"] = self.service_enum_results.to_dict()
        
        return result
    
    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string"""
        if pretty:
            return json.dumps(self.to_dict(), indent=4)
        return json.dumps(self.to_dict())
    
    def save_to_file(self, filename: str) -> bool:
        """Save results to a JSON file"""
        try:
            with open(filename, 'w') as f:
                f.write(self.to_json())
            logger.info(f"Saved scan results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results to {filename}: {e}")
            return False
    
    def get_duration(self) -> float:
        """Get scan duration in seconds"""
        if self.end_time > 0:
            return self.end_time - self.start_time
        elif self.status == ScanStatus.RUNNING:
            return time.time() - self.start_time
        return 0.0


class ScanEngine:
    """
    Unified scanning engine that integrates various scanning modules
    and provides a consistent interface for scan operations.
    """
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the scan engine.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Initialize network utilities
        if config:
            self.network = NetworkUtils(config)
        else:
            self.network = network_utils
        
        # Initialize scanning modules
        self.recon_module = ReconModule(config)
        self.network_mapper = NetworkMapper(config)
        self.service_enum = ServiceEnumModule(config)
        
        # Load configuration settings
        self.output_dir = "results"
        self.default_scan_types = [ScanType.RECON]
        self.default_ports = self.recon_module.DEFAULT_PORTS
        self.max_threads = 20
        self.timeout = 5.0
        
        if config:
            self.output_dir = config.get("modules.scan_engine.output_dir", "results")
            self.max_threads = config.get("modules.scan_engine.max_threads", 20)
            self.timeout = config.get("modules.scan_engine.timeout", 5.0)
            
            # Create output directory if it doesn't exist
            if self.output_dir and not os.path.exists(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                    logger.info(f"Created output directory: {self.output_dir}")
                except Exception as e:
                    logger.error(f"Failed to create output directory {self.output_dir}: {e}")
        
        # Track active scans
        self.active_scans = {}
        self.completed_scans = {}
    
    def create_scan(self, target: str, scan_config: Optional[ScanConfig] = None) -> str:
        """
        Create a new scan for the specified target with the given configuration.
        
        Args:
            target: Target to scan (IP, hostname, domain, CIDR)
            scan_config: Optional scan configuration
            
        Returns:
            str: Scan ID for tracking the scan
        """
        # Generate a unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan target
        scan_target = ScanTarget(target=target)
        
        # Use default config if none provided
        if not scan_config:
            scan_config = ScanConfig(
                scan_types=[ScanType.RECON],
                ports=self.default_ports,
                timeout=self.timeout,
                max_threads=self.max_threads
            )
        
        # Create scan result object
        scan_result = ScanResult(
            scan_id=scan_id,
            target=target,
            scan_types=[st.name for st in scan_config.scan_types],
            start_time=time.time(),
            status=ScanStatus.PENDING
        )
        
        # Store in active scans
        self.active_scans[scan_id] = {
            "target": scan_target,
            "config": scan_config,
            "result": scan_result
        }
        
        logger.info(f"Created scan {scan_id} for target {target}")
        return scan_id
    
    def start_scan(self, scan_id: str) -> bool:
        """
        Start a previously created scan.
        
        Args:
            scan_id: Scan ID to start
            
        Returns:
            bool: True if scan started successfully, False otherwise
        """
        if scan_id not in self.active_scans:
            logger.error(f"Scan ID {scan_id} not found")
            return False
        
        scan_data = self.active_scans[scan_id]
        scan_result = scan_data["result"]
        
        # Update scan status
        scan_result.status = ScanStatus.RUNNING
        scan_result.start_time = time.time()
        
        try:
            # Execute the scan based on configured scan types
            self._execute_scan(scan_id)
            return True
        except Exception as e:
            logger.error(f"Failed to start scan {scan_id}: {e}")
            scan_result.status = ScanStatus.FAILED
            scan_result.errors.append(f"Failed to start scan: {str(e)}")
            return False
    
    def _execute_scan(self, scan_id: str) -> None:
        """
        Execute a scan with the specified configuration.
        
        Args:
            scan_id: Scan ID to execute
        """
        scan_data = self.active_scans[scan_id]
        scan_target = scan_data["target"]
        scan_config = scan_data["config"]
        scan_result = scan_data["result"]
        
        target = scan_target.target
        
        try:
            # Prepare common scan parameters
            scan_params = {
                "timeout": scan_config.timeout,
                "max_threads": scan_config.max_threads,
                "aggressive": scan_config.aggressive
            }
            
            if scan_config.ports:
                scan_params["ports"] = scan_config.ports
            
            # Execute each configured scan type
            for scan_type in scan_config.scan_types:
                try:
                    if scan_type == ScanType.RECON:
                        logger.info(f"Starting reconnaissance scan for {target}")
                        recon_result = self.recon_module.scan(target, **scan_params)
                        scan_result.recon_results = recon_result
                        scan_result.notes.append(f"Completed reconnaissance scan with {len(recon_result.hosts)} hosts discovered")
                    
                    elif scan_type == ScanType.NETWORK_MAP:
                        logger.info(f"Starting network mapping for {target}")
                        network_map_result = self.network_mapper.map_network(target, **scan_params)
                        scan_result.network_map_results = network_map_result
                        scan_result.notes.append(f"Completed network mapping with {len(network_map_result.nodes)} nodes discovered")
                    
                    elif scan_type == ScanType.SERVICE_ENUM:
                        logger.info(f"Starting service enumeration for {target}")
                        # Add service enum specific parameters
                        service_params = scan_params.copy()
                        service_params["check_vulns"] = scan_config.check_vulns
                        service_params["check_default_creds"] = scan_config.check_default_creds
                        
                        service_enum_result = self.service_enum.enumerate_services(target, **service_params)
                        scan_result.service_enum_results = service_enum_result
                        scan_result.notes.append(f"Completed service enumeration with {len(service_enum_result.services)} services discovered")
                        
                        # Aggregate vulnerabilities
                        if service_enum_result.vulnerabilities:
                            for vuln in service_enum_result.vulnerabilities:
                                scan_vuln = ScanVulnerability(
                                    target=target,
                                    port=vuln.service_port,
                                    service=vuln.service_name,
                                    vulnerability_id=vuln.vulnerability_id,
                                    severity=vuln.severity,
                                    description=vuln.description,
                                    references=vuln.references,
                                    exploit_available=vuln.exploit_available,
                                    exploit_info=vuln.exploit_info,
                                    scan_module="service_enum"
                                )
                                scan_result.vulnerabilities.append(scan_vuln)
                    
                    elif scan_type == ScanType.COMPREHENSIVE:
                        # Comprehensive scan includes all scan types
                        logger.info(f"Starting comprehensive scan for {target}")
                        
                        # First do reconnaissance
                        recon_result = self.recon_module.scan(target, **scan_params)
                        scan_result.recon_results = recon_result
                        scan_result.notes.append(f"Completed reconnaissance scan with {len(recon_result.hosts)} hosts discovered")
                        
                        # Then do network mapping
                        network_map_result = self.network_mapper.map_network(target, **scan_params)
                        scan_result.network_map_results = network_map_result
                        scan_result.notes.append(f"Completed network mapping with {len(network_map_result.nodes)} nodes discovered")
                        
                        # Finally do service enumeration
                        service_params = scan_params.copy()
                        service_params["check_vulns"] = scan_config.check_vulns
                        service_params["check_default_creds"] = scan_config.check_default_creds
                        
                        service_enum_result = self.service_enum.enumerate_services(target, **service_params)
                        scan_result.service_enum_results = service_enum_result
                        scan_result.notes.append(f"Completed service enumeration with {len(service_enum_result.services)} services discovered")
                        
                        # Aggregate vulnerabilities
                        if service_enum_result.vulnerabilities:
                            for vuln in service_enum_result.vulnerabilities:
                                scan_vuln = ScanVulnerability(
                                    target=target,
                                    port=vuln.service_port,
                                    service=vuln.service_name,
                                    vulnerability_id=vuln.vulnerability_id,
                                    severity=vuln.severity,
                                    description=vuln.description,
                                    references=vuln.references,
                                    exploit_available=vuln.exploit_available,
                                    exploit_info=vuln.exploit_info,
                                    scan_module="service_enum"
                                )
                                scan_result.vulnerabilities.append(scan_vuln)
                
                except Exception as e:
                    error_msg = f"Error during {scan_type.name} scan: {str(e)}"
                    logger.error(error_msg)
                    scan_result.errors.append(error_msg)
            
            # Mark scan as completed
            scan_result.status = ScanStatus.COMPLETED
            scan_result.end_time = time.time()
            
            # Save results if output directory is configured
            if self.output_dir:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(self.output_dir, f"scan_{scan_id}_{timestamp}.json")
                scan_result.save_to_file(filename)
            
            # Move from active to completed scans
            self.completed_scans[scan_id] = self.active_scans.pop(scan_id)
            
            logger.info(f"Scan {scan_id} completed in {scan_result.get_duration():.2f} seconds")
            
        except Exception as e:
            error_msg = f"Scan execution failed: {str(e)}"
            logger.error(error_msg)
            scan_result.errors.append(error_msg)
            scan_result.status = ScanStatus.FAILED
            scan_result.end_time = time.time()
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a scan.
        
        Args:
            scan_id: Scan ID to check
            
        Returns:
            Dict: Scan status information or None if scan not found
        """
        # Check active scans
        if scan_id in self.active_scans:
            scan_result = self.active_scans[scan_id]["result"]
            return {
                "scan_id": scan_id,
                "target": scan_result.target,
                "status": scan_result.status.name,
                "start_time": scan_result.start_time,
                "duration": scan_result.get_duration(),
                "progress": self._estimate_scan_progress(scan_id)
            }
        
        # Check completed scans
        if scan_id in self.completed_scans:
            scan_result = self.completed_scans[scan_id]["result"]
            return {
                "scan_id": scan_id,
                "target": scan_result.target,
                "status": scan_result.status.name,
                "start_time": scan_result.start_time,
                "end_time": scan_result.end_time,
                "duration": scan_result.get_duration(),
                "progress": 100.0
            }
        
        return None
    
    def _estimate_scan_progress(self, scan_id: str) -> float:
        """
        Estimate the progress of a scan as a percentage.
        
        Args:
            scan_id: Scan ID to estimate progress for
            
        Returns:
            float: Estimated progress percentage (0-100)
        """
        if scan_id not in self.active_scans:
            return 0.0
        
        scan_data = self.active_scans[scan_id]
        scan_result = scan_data["result"]
        
        if scan_result.status == ScanStatus.PENDING:
            return 0.0
        elif scan_result.status == ScanStatus.COMPLETED:
            return 100.0
        elif scan_result.status == ScanStatus.FAILED or scan_result.status == ScanStatus.CANCELLED:
            # For failed/cancelled scans, estimate progress based on completed scan types
            return self._calculate_completed_scan_types_percentage(scan_data)
        
        # For running scans, estimate based on time and completed scan types
        time_based = self._estimate_time_based_progress(scan_data)
        type_based = self._calculate_completed_scan_types_percentage(scan_data)
        
        # Use the maximum of the two estimates
        return max(time_based, type_based)
    
    def _estimate_time_based_progress(self, scan_data: Dict[str, Any]) -> float:
        """
        Estimate scan progress based on elapsed time.
        
        Args:
            scan_data: Scan data dictionary
            
        Returns:
            float: Estimated progress percentage (0-100)
        """
        scan_result = scan_data["result"]
        scan_config = scan_data["config"]
        
        # Estimate total scan time based on target and scan types
        estimated_total_time = self._estimate_total_scan_time(scan_data)
        
        # Calculate elapsed time
        elapsed_time = time.time() - scan_result.start_time
        
        # Calculate progress percentage
        progress = (elapsed_time / estimated_total_time) * 100.0
        
        # Cap at 99% (reserve 100% for actual completion)
        return min(99.0, progress)
    
    def _estimate_total_scan_time(self, scan_data: Dict[str, Any]) -> float:
        """
        Estimate the total time a scan will take based on target and scan types.
        
        Args:
            scan_data: Scan data dictionary
            
        Returns:
            float: Estimated total scan time in seconds
        """
        scan_target = scan_data["target"]
        scan_config = scan_data["config"]
        
        # Base time depends on target type
        if scan_target.target_type == "IP":
            base_time = 30.0  # 30 seconds for a single IP
        elif scan_target.target_type == "DOMAIN":
            base_time = 60.0  # 60 seconds for a domain
        elif scan_target.target_type == "CIDR":
            # Estimate based on network size
            try:
                network = ipaddress.ip_network(scan_target.target, strict=False)
                host_count = min(scan_config.max_hosts, network.num_addresses)
                base_time = 5.0 * host_count  # 5 seconds per host
            except:
                base_time = 300.0  # Default to 5 minutes for unknown network size
        else:
            base_time = 120.0  # Default for unknown target types
        
        # Multiply by scan type complexity
        total_time = base_time
        for scan_type in scan_config.scan_types:
            if scan_type == ScanType.RECON:
                total_time += base_time * 1.0
            elif scan_type == ScanType.NETWORK_MAP:
                total_time += base_time * 1.5
            elif scan_type == ScanType.SERVICE_ENUM:
                total_time += base_time * 2.0
            elif scan_type == ScanType.VULNERABILITY:
                total_time += base_time * 3.0
            elif scan_type == ScanType.COMPREHENSIVE:
                total_time += base_time * 5.0
        
        # Adjust for aggressive scanning
        if scan_config.aggressive:
            total_time *= 1.5
        
        return total_time
    
    def _calculate_completed_scan_types_percentage(self, scan_data: Dict[str, Any]) -> float:
        """
        Calculate the percentage of scan types that have been completed.
        
        Args:
            scan_data: Scan data dictionary
            
        Returns:
            float: Percentage of completed scan types (0-100)
        """
        scan_result = scan_data["result"]
        scan_config = scan_data["config"]
        
        total_types = len(scan_config.scan_types)
        if total_types == 0:
            return 0.0
        
        completed_types = 0
        
        # Check which scan types have completed
        if scan_result.recon_results:
            completed_types += 1
        
        if scan_result.network_map_results:
            completed_types += 1
        
        if scan_result.service_enum_results:
            completed_types += 1
        
        # For comprehensive scans, count each component separately
        if ScanType.COMPREHENSIVE in scan_config.scan_types:
            # Comprehensive counts as 3 scan types (recon, network map, service enum)
            total_types += 2
        
        return (completed_types / total_types) * 100.0
    
    def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: Scan ID to cancel
            
        Returns:
            bool: True if scan was cancelled, False otherwise
        """
        if scan_id not in self.active_scans:
            logger.error(f"Scan ID {scan_id} not found or already completed")
            return False
        
        scan_result = self.active_scans[scan_id]["result"]
        
        if scan_result.status != ScanStatus.RUNNING:
            logger.error(f"Scan {scan_id} is not running (status: {scan_result.status.name})")
            return False
        
        # Mark as cancelled
        scan_result.status = ScanStatus.CANCELLED
        scan_result.end_time = time.time()
        scan_result.notes.append("Scan cancelled by user")
        
        # Move from active to completed scans
        self.completed_scans[scan_id] = self.active_scans.pop(scan_id)
        
        logger.info(f"Scan {scan_id} cancelled after {scan_result.get_duration():.2f} seconds")
        return True
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """
        Get the result of a scan.
        
        Args:
            scan_id: Scan ID to get results for
            
        Returns:
            ScanResult: Scan result or None if scan not found
        """
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]["result"]
        
        if scan_id in self.completed_scans:
            return self.completed_scans[scan_id]["result"]
        
        return None
    
    def get_active_scans(self) -> List[Dict[str, Any]]:
        """
        Get a list of all active scans.
        
        Returns:
            List[Dict]: List of active scan information
        """
        return [
            {
                "scan_id": scan_id,
                "target": scan_data["target"].target,
                "status": scan_data["result"].status.name,
                "start_time": scan_data["result"].start_time,
                "duration": scan_data["result"].get_duration(),
                "progress": self._estimate_scan_progress(scan_id)
            }
            for scan_id, scan_data in self.active_scans.items()
        ]
    
    def get_completed_scans(self) -> List[Dict[str, Any]]:
        """
        Get a list of all completed scans.
        
        Returns:
            List[Dict]: List of completed scan information
        """
        return [
            {
                "scan_id": scan_id,
                "target": scan_data["target"].target,
                "status": scan_data["result"].status.name,
                "start_time": scan_data["result"].start_time,
                "end_time": scan_data["result"].end_time,
                "duration": scan_data["result"].get_duration()
            }
            for scan_id, scan_data in self.completed_scans.items()
        ]
    
    def clear_completed_scans(self) -> int:
        """
        Clear the list of completed scans.
        
        Returns:
            int: Number of scans cleared
        """
        count = len(self.completed_scans)
        self.completed_scans.clear()
        logger.info(f"Cleared {count} completed scans")
        return count
    
    def run_scan(self, target: str, scan_config: Optional[ScanConfig] = None) -> ScanResult:
        """
        Create and run a scan in one operation, waiting for completion.
        
        Args:
            target: Target to scan
            scan_config: Optional scan configuration
            
        Returns:
            ScanResult: Scan result
        """
        # Create the scan
        scan_id = self.create_scan(target, scan_config)
        
        # Execute the scan directly (not asynchronously)
        scan_data = self.active_scans[scan_id]
        scan_result = scan_data["result"]
        
        try:
            # Update scan status
            scan_result.status = ScanStatus.RUNNING
            scan_result.start_time = time.time()
            
            # Execute the scan
            self._execute_scan(scan_id)
            
            # Return the result
            return self.get_scan_result(scan_id)
            
        except Exception as e:
            error_msg = f"Scan execution failed: {str(e)}"
            logger.error(error_msg)
            scan_result.errors.append(error_msg)
            scan_result.status = ScanStatus.FAILED
            scan_result.end_time = time.time()
            return scan_result