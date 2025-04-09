"""
Vulnerability Scanner module for the APT toolkit.

This module provides comprehensive vulnerability scanning capabilities,
integrating with other modules to identify, assess, and report vulnerabilities
across different types of systems and services.
"""

import os
import re
import time
import json
import uuid
import hashlib
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from urllib.parse import urlparse
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from datetime import datetime

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils
from src.modules.recon import ReconModule, HostInfo
from src.modules.service_enum import ServiceEnumModule, ServiceInfo
from src.modules.web_scanner import WebScanner, WebVulnerability, VulnerabilitySeverity as WebVulnerabilitySeverity

logger = get_module_logger("vuln_scanner")

class VulnerabilitySeverity(Enum):
    """Enumeration of vulnerability severity levels"""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()
    
    @classmethod
    def from_web_severity(cls, web_severity: WebVulnerabilitySeverity) -> 'VulnerabilitySeverity':
        """Convert WebVulnerabilitySeverity to VulnerabilitySeverity"""
        mapping = {
            WebVulnerabilitySeverity.CRITICAL: cls.CRITICAL,
            WebVulnerabilitySeverity.HIGH: cls.HIGH,
            WebVulnerabilitySeverity.MEDIUM: cls.MEDIUM,
            WebVulnerabilitySeverity.LOW: cls.LOW,
            WebVulnerabilitySeverity.INFO: cls.INFO
        }
        return mapping.get(web_severity, cls.MEDIUM)
    
    @classmethod
    def from_cvss(cls, cvss_score: float) -> 'VulnerabilitySeverity':
        """Convert CVSS score to VulnerabilitySeverity"""
        if cvss_score >= 9.0:
            return cls.CRITICAL
        elif cvss_score >= 7.0:
            return cls.HIGH
        elif cvss_score >= 4.0:
            return cls.MEDIUM
        elif cvss_score >= 0.1:
            return cls.LOW
        else:
            return cls.INFO

class VulnerabilityCategory(Enum):
    """Enumeration of vulnerability categories"""
    NETWORK = auto()
    WEB = auto()
    SYSTEM = auto()
    APPLICATION = auto()
    DATABASE = auto()
    AUTHENTICATION = auto()
    ENCRYPTION = auto()
    CONFIGURATION = auto()
    MISCONFIGURATION = auto()
    INFORMATION_DISCLOSURE = auto()
    INJECTION = auto()
    XSS = auto()
    CSRF = auto()
    FILE_INCLUSION = auto()
    COMMAND_INJECTION = auto()
    PRIVILEGE_ESCALATION = auto()
    DEFAULT_CREDENTIALS = auto()
    OUTDATED_SOFTWARE = auto()
    MISSING_PATCH = auto()
    OTHER = auto()

class VulnerabilityStatus(Enum):
    """Enumeration of vulnerability status"""
    OPEN = auto()
    CONFIRMED = auto()
    FALSE_POSITIVE = auto()
    RISK_ACCEPTED = auto()
    MITIGATED = auto()
    REMEDIATED = auto()
    CLOSED = auto()

@dataclass
class VulnerabilityReference:
    """Data class for vulnerability reference information"""
    source: str  # CVE, CWE, OWASP, etc.
    id: str  # Reference ID
    url: str = ""  # URL to reference
    description: str = ""  # Description of the reference

@dataclass
class VulnerabilityDetail:
    """Data class for detailed vulnerability information"""
    name: str
    description: str
    severity: VulnerabilitySeverity
    category: VulnerabilityCategory
    references: List[VulnerabilityReference] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve_id: str = ""
    cwe_id: str = ""
    exploit_available: bool = False
    exploit_details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    affected_software: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    detection_method: str = ""

@dataclass
class Vulnerability:
    """Data class for vulnerability instance information"""
    id: str  # Unique identifier for this vulnerability instance
    detail_id: str  # Reference to VulnerabilityDetail
    target: str  # IP, hostname, URL, etc.
    target_type: str = ""  # IP, hostname, URL, etc.
    port: int = 0
    protocol: str = ""
    service: str = ""
    path: str = ""  # For web vulnerabilities
    parameter: str = ""  # For web vulnerabilities
    evidence: str = ""  # Evidence of the vulnerability
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    confidence: float = 0.0  # 0.0 to 1.0
    first_detected: float = field(default_factory=time.time)
    last_detected: float = field(default_factory=time.time)
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VulnerabilityScanResult:
    """Data class for vulnerability scan results"""
    scan_id: str
    target: str
    scan_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    vulnerability_details: Dict[str, VulnerabilityDetail] = field(default_factory=dict)
    scan_coverage: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
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
            logger.info(f"Saved vulnerability scan results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results to {filename}: {e}")
            return False
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get counts of vulnerabilities by severity"""
        counts = {severity.name: 0 for severity in VulnerabilitySeverity}
        
        for vuln_id in self.vulnerabilities:
            vuln_detail = self.vulnerability_details.get(vuln_id.detail_id)
            if vuln_detail:
                counts[vuln_detail.severity.name] += 1
        
        return counts
    
    def get_category_counts(self) -> Dict[str, int]:
        """Get counts of vulnerabilities by category"""
        counts = {category.name: 0 for category in VulnerabilityCategory}
        
        for vuln_id in self.vulnerabilities:
            vuln_detail = self.vulnerability_details.get(vuln_id.detail_id)
            if vuln_detail:
                counts[vuln_detail.category.name] += 1
        
        return counts


class VulnScannerModule:
    """
    Vulnerability scanner module for identifying, assessing, and reporting
    vulnerabilities across different types of systems and services.
    """
    
    # Vulnerability database (simplified for demonstration)
    # In a real implementation, this would be loaded from a database or file
    VULNERABILITY_DATABASE = {
        # Network vulnerabilities
        "open_ports": {
            "name": "Open Sensitive Ports",
            "description": "Sensitive ports are exposed to the network, potentially allowing unauthorized access.",
            "severity": VulnerabilitySeverity.MEDIUM,
            "category": VulnerabilityCategory.NETWORK,
            "references": [
                {"source": "CWE", "id": "CWE-200", "url": "https://cwe.mitre.org/data/definitions/200.html"}
            ],
            "remediation": "Close unnecessary ports or restrict access using firewall rules.",
            "detection_method": "port_scan"
        },
        "weak_ssh": {
            "name": "Weak SSH Configuration",
            "description": "SSH server is configured with weak algorithms or settings.",
            "severity": VulnerabilitySeverity.HIGH,
            "category": VulnerabilityCategory.CONFIGURATION,
            "references": [
                {"source": "CWE", "id": "CWE-326", "url": "https://cwe.mitre.org/data/definitions/326.html"}
            ],
            "remediation": "Configure SSH to use strong algorithms and disable weak settings.",
            "detection_method": "service_enum"
        },
        
        # Web vulnerabilities
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "description": "Application is vulnerable to Cross-Site Scripting attacks.",
            "severity": VulnerabilitySeverity.HIGH,
            "category": VulnerabilityCategory.XSS,
            "references": [
                {"source": "CWE", "id": "CWE-79", "url": "https://cwe.mitre.org/data/definitions/79.html"},
                {"source": "OWASP", "id": "A7:2017", "url": "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)"}
            ],
            "remediation": "Implement proper input validation and output encoding.",
            "detection_method": "web_scan"
        },
        "sqli": {
            "name": "SQL Injection",
            "description": "Application is vulnerable to SQL Injection attacks.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "category": VulnerabilityCategory.INJECTION,
            "references": [
                {"source": "CWE", "id": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html"},
                {"source": "OWASP", "id": "A1:2017", "url": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"}
            ],
            "remediation": "Use parameterized queries or prepared statements.",
            "detection_method": "web_scan"
        },
        
        # Service vulnerabilities
        "default_credentials": {
            "name": "Default Credentials",
            "description": "Service is using default or easily guessable credentials.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "category": VulnerabilityCategory.DEFAULT_CREDENTIALS,
            "references": [
                {"source": "CWE", "id": "CWE-798", "url": "https://cwe.mitre.org/data/definitions/798.html"}
            ],
            "remediation": "Change default credentials and implement strong password policies.",
            "detection_method": "service_enum"
        },
        "outdated_software": {
            "name": "Outdated Software",
            "description": "Service is running an outdated version with known vulnerabilities.",
            "severity": VulnerabilitySeverity.HIGH,
            "category": VulnerabilityCategory.OUTDATED_SOFTWARE,
            "references": [
                {"source": "CWE", "id": "CWE-1104", "url": "https://cwe.mitre.org/data/definitions/1104.html"}
            ],
            "remediation": "Update to the latest stable version of the software.",
            "detection_method": "version_check"
        }
    }
    
    # Sensitive ports and their associated risks
    SENSITIVE_PORTS = {
        21: {"service": "FTP", "risk": "Unencrypted file transfer"},
        22: {"service": "SSH", "risk": "Remote access"},
        23: {"service": "Telnet", "risk": "Unencrypted remote access"},
        25: {"service": "SMTP", "risk": "Mail server"},
        53: {"service": "DNS", "risk": "Domain name resolution"},
        80: {"service": "HTTP", "risk": "Unencrypted web server"},
        110: {"service": "POP3", "risk": "Unencrypted mail retrieval"},
        111: {"service": "RPC", "risk": "Remote procedure call"},
        135: {"service": "MSRPC", "risk": "Windows RPC"},
        139: {"service": "NetBIOS", "risk": "Windows file sharing"},
        389: {"service": "LDAP", "risk": "Directory services"},
        445: {"service": "SMB", "risk": "Windows file sharing"},
        1433: {"service": "MSSQL", "risk": "Database server"},
        1521: {"service": "Oracle", "risk": "Database server"},
        3306: {"service": "MySQL", "risk": "Database server"},
        3389: {"service": "RDP", "risk": "Remote desktop"},
        5432: {"service": "PostgreSQL", "risk": "Database server"},
        5900: {"service": "VNC", "risk": "Remote desktop"},
        8080: {"service": "HTTP-ALT", "risk": "Alternative web server"}
    }
    
    # Software versions with known vulnerabilities (simplified for demonstration)
    VULNERABLE_VERSIONS = {
        "apache": [
            {"version": "2.4.49", "cve": "CVE-2021-41773", "severity": VulnerabilitySeverity.CRITICAL},
            {"version": "2.4.50", "cve": "CVE-2021-42013", "severity": VulnerabilitySeverity.CRITICAL}
        ],
        "nginx": [
            {"version": "1.20.0", "cve": "CVE-2021-23017", "severity": VulnerabilitySeverity.HIGH}
        ],
        "openssh": [
            {"version": "7.2", "cve": "CVE-2016-8858", "severity": VulnerabilitySeverity.HIGH},
            {"version": "7.2p2", "cve": "CVE-2016-6210", "severity": VulnerabilitySeverity.MEDIUM}
        ],
        "php": [
            {"version": "5.6", "cve": "CVE-2019-11043", "severity": VulnerabilitySeverity.CRITICAL},
            {"version": "7.2", "cve": "CVE-2019-11043", "severity": VulnerabilitySeverity.CRITICAL}
        ]
    }
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the vulnerability scanner module.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Initialize network utilities
        if config:
            self.network = NetworkUtils(config)
        else:
            self.network = network_utils
            
        # Initialize other modules
        self.recon_module = ReconModule(config)
        self.service_enum = ServiceEnumModule(config)
        self.web_scanner = WebScanner(config)
        
        # Load configuration settings
        self.timeout = 10
        self.max_threads = 10
        self.output_dir = "results/vulnerabilities"
        self.check_network_vulns = True
        self.check_service_vulns = True
        self.check_web_vulns = True
        self.check_system_vulns = True
        self.min_severity = VulnerabilitySeverity.LOW
        self.vuln_database_path = ""
        
        if config:
            self.timeout = config.get("modules.vuln_scanner.timeout", 10)
            self.max_threads = config.get("modules.vuln_scanner.max_threads", 10)
            self.output_dir = config.get("modules.vuln_scanner.output_dir", "results/vulnerabilities")
            self.check_network_vulns = config.get("modules.vuln_scanner.check_network_vulns", True)
            self.check_service_vulns = config.get("modules.vuln_scanner.check_service_vulns", True)
            self.check_web_vulns = config.get("modules.vuln_scanner.check_web_vulns", True)
            self.check_system_vulns = config.get("modules.vuln_scanner.check_system_vulns", True)
            
            severity_str = config.get("modules.vuln_scanner.min_severity", "LOW")
            try:
                self.min_severity = VulnerabilitySeverity[severity_str]
            except KeyError:
                logger.warning(f"Invalid minimum severity '{severity_str}', using LOW")
                self.min_severity = VulnerabilitySeverity.LOW
            
            self.vuln_database_path = config.get("modules.vuln_scanner.vuln_database_path", "")
            
            # Create output directory if it doesn't exist
            if self.output_dir and not os.path.exists(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                    logger.info(f"Created output directory: {self.output_dir}")
                except Exception as e:
                    logger.error(f"Failed to create output directory {self.output_dir}: {e}")
        
        # Load vulnerability database if specified
        if self.vuln_database_path and os.path.exists(self.vuln_database_path):
            self._load_vulnerability_database()
    
    def _load_vulnerability_database(self) -> None:
        """Load vulnerability database from file"""
        try:
            with open(self.vuln_database_path, 'r') as f:
                data = json.load(f)
                
                # Process and validate the data
                if isinstance(data, dict):
                    # Merge with existing database
                    for vuln_id, vuln_data in data.items():
                        # Validate required fields
                        if all(k in vuln_data for k in ["name", "description", "severity", "category"]):
                            # Convert string severity to enum
                            if isinstance(vuln_data["severity"], str):
                                try:
                                    vuln_data["severity"] = VulnerabilitySeverity[vuln_data["severity"]]
                                except KeyError:
                                    logger.warning(f"Invalid severity '{vuln_data['severity']}' for {vuln_id}")
                                    continue
                            
                            # Convert string category to enum
                            if isinstance(vuln_data["category"], str):
                                try:
                                    vuln_data["category"] = VulnerabilityCategory[vuln_data["category"]]
                                except KeyError:
                                    logger.warning(f"Invalid category '{vuln_data['category']}' for {vuln_id}")
                                    continue
                            
                            # Add to database
                            self.VULNERABILITY_DATABASE[vuln_id] = vuln_data
                
                logger.info(f"Loaded {len(data)} vulnerabilities from {self.vuln_database_path}")
                
        except Exception as e:
            logger.error(f"Failed to load vulnerability database from {self.vuln_database_path}: {e}")
    
    def scan(self, target: str, **kwargs) -> VulnerabilityScanResult:
        """
        Scan a target for vulnerabilities.
        
        Args:
            target: Target to scan (IP, hostname, domain, URL, CIDR)
            **kwargs: Optional scan parameters:
                - timeout: Scan timeout in seconds
                - max_threads: Maximum number of concurrent threads
                - check_network_vulns: Whether to check for network vulnerabilities
                - check_service_vulns: Whether to check for service vulnerabilities
                - check_web_vulns: Whether to check for web vulnerabilities
                - check_system_vulns: Whether to check for system vulnerabilities
                - min_severity: Minimum severity level to report
                - ports: List of ports to scan
                
        Returns:
            VulnerabilityScanResult: Vulnerability scan results
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())
        
        # Parse scan parameters
        timeout = kwargs.get("timeout", self.timeout)
        max_threads = kwargs.get("max_threads", self.max_threads)
        check_network_vulns = kwargs.get("check_network_vulns", self.check_network_vulns)
        check_service_vulns = kwargs.get("check_service_vulns", self.check_service_vulns)
        check_web_vulns = kwargs.get("check_web_vulns", self.check_web_vulns)
        check_system_vulns = kwargs.get("check_system_vulns", self.check_system_vulns)
        min_severity = kwargs.get("min_severity", self.min_severity)
        ports = kwargs.get("ports", None)  # None means use default ports
        
        # Initialize result object
        result = VulnerabilityScanResult(
            scan_id=scan_id,
            target=target
        )
        
        # Initialize vulnerability details dictionary
        vuln_details = {}
        for vuln_id, vuln_data in self.VULNERABILITY_DATABASE.items():
            # Convert dictionary to VulnerabilityDetail object
            references = []
            if "references" in vuln_data:
                for ref in vuln_data["references"]:
                    references.append(VulnerabilityReference(**ref))
            
            detail = VulnerabilityDetail(
                name=vuln_data["name"],
                description=vuln_data["description"],
                severity=vuln_data["severity"],
                category=vuln_data["category"],
                references=references,
                remediation=vuln_data.get("remediation", ""),
                detection_method=vuln_data.get("detection_method", "")
            )
            vuln_details[vuln_id] = detail
        
        result.vulnerability_details = vuln_details
        
        logger.info(f"Starting vulnerability scan of {target}")
        
        try:
            # Phase 1: Reconnaissance scan to discover hosts and services
            logger.info(f"Performing reconnaissance scan of {target}")
            recon_result = self.recon_module.scan(
                target,
                ports=ports,
                timeout=timeout,
                max_threads=max_threads
            )
            
            # Track scan coverage
            result.scan_coverage["hosts_discovered"] = len(recon_result.hosts)
            result.scan_coverage["domains_discovered"] = len(recon_result.domains)
            
            # Phase 2: Check for network vulnerabilities
            if check_network_vulns:
                logger.info("Checking for network vulnerabilities")
                network_vulns = self._check_network_vulnerabilities(recon_result, min_severity)
                result.vulnerabilities.extend(network_vulns)
                result.notes.append(f"Discovered {len(network_vulns)} network vulnerabilities")
            
            # Phase 3: Check for service vulnerabilities
            if check_service_vulns:
                logger.info("Checking for service vulnerabilities")
                
                # Perform service enumeration
                service_enum_result = self.service_enum.enumerate_services(
                    target,
                    ports=ports,
                    timeout=timeout,
                    max_threads=max_threads,
                    check_vulns=True,
                    check_default_creds=True
                )
                
                # Track scan coverage
                result.scan_coverage["services_discovered"] = len(service_enum_result.services)
                
                # Check for vulnerabilities
                service_vulns = self._check_service_vulnerabilities(
                    service_enum_result, 
                    min_severity
                )
                result.vulnerabilities.extend(service_vulns)
                result.notes.append(f"Discovered {len(service_vulns)} service vulnerabilities")
            
            # Phase 4: Check for web vulnerabilities
            if check_web_vulns:
                logger.info("Checking for web vulnerabilities")
                
                # Identify web servers from reconnaissance results
                web_targets = self._identify_web_targets(recon_result)
                result.scan_coverage["web_targets_discovered"] = len(web_targets)
                
                web_vulns = []
                for web_target in web_targets:
                    logger.info(f"Scanning web target: {web_target}")
                    
                    # Perform web scan
                    web_scan_result = self.web_scanner.scan(
                        web_target,
                        timeout=timeout,
                        max_threads=max_threads,
                        test_xss=True,
                        test_sqli=True,
                        test_open_redirect=True
                    )
                    
                    # Convert web vulnerabilities to general vulnerabilities
                    target_web_vulns = self._convert_web_vulnerabilities(
                        web_scan_result.vulnerabilities,
                        min_severity
                    )
                    web_vulns.extend(target_web_vulns)
                
                result.vulnerabilities.extend(web_vulns)
                result.notes.append(f"Discovered {len(web_vulns)} web vulnerabilities")
            
            # Phase 5: Check for system vulnerabilities
            if check_system_vulns:
                logger.info("Checking for system vulnerabilities")
                # This would typically involve more advanced techniques like
                # authenticated scanning, OS fingerprinting, etc.
                # For demonstration, we'll skip this phase
                result.notes.append("System vulnerability scanning not implemented in this version")
            
            # Calculate scan duration
            end_time = time.time()
            result.end_time = end_time
            scan_duration = end_time - start_time
            result.notes.append(f"Vulnerability scan completed in {scan_duration:.2f} seconds")
            logger.info(f"Vulnerability scan of {target} completed in {scan_duration:.2f} seconds")
            
            # Save results if output directory is configured
            if self.output_dir:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(self.output_dir, f"vuln_scan_{scan_id}_{timestamp}.json")
                result.save_to_file(filename)
            
        except Exception as e:
            error_msg = f"Error during vulnerability scan: {str(e)}"
            logger.error(error_msg)
            result.errors.append(error_msg)
        
        return result
    
    def _check_network_vulnerabilities(self, recon_result, min_severity: VulnerabilitySeverity) -> List[Vulnerability]:
        """
        Check for network vulnerabilities based on reconnaissance results.
        
        Args:
            recon_result: Reconnaissance results
            min_severity: Minimum severity level to report
            
        Returns:
            List[Vulnerability]: List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # Check for open sensitive ports
        for host in recon_result.hosts:
            if host.status != "up" or not host.open_ports:
                continue
            
            sensitive_ports = []
            for port_info in host.open_ports:
                if port_info.port in self.SENSITIVE_PORTS:
                    sensitive_ports.append(port_info)
            
            if sensitive_ports:
                # Create vulnerability for open sensitive ports
                vuln_detail_id = "open_ports"
                vuln_detail = self.VULNERABILITY_DATABASE[vuln_detail_id]
                
                # Skip if below minimum severity
                if vuln_detail["severity"].value < min_severity.value:
                    continue
                
                # Create evidence string
                evidence = "Open sensitive ports: " + ", ".join([
                    f"{port_info.port}/{port_info.protocol} ({port_info.service})"
                    for port_info in sensitive_ports
                ])
                
                # Create vulnerability instance
                vuln_id = hashlib.md5(f"{host.ip_address}:{vuln_detail_id}".encode()).hexdigest()
                vulnerability = Vulnerability(
                    id=vuln_id,
                    detail_id=vuln_detail_id,
                    target=host.ip_address,
                    target_type="IP",
                    evidence=evidence,
                    confidence=0.8,
                    notes=[f"Found {len(sensitive_ports)} sensitive open ports"]
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_service_vulnerabilities(self, service_enum_result, min_severity: VulnerabilitySeverity) -> List[Vulnerability]:
        """
        Check for service vulnerabilities based on service enumeration results.
        
        Args:
            service_enum_result: Service enumeration results
            min_severity: Minimum severity level to report
            
        Returns:
            List[Vulnerability]: List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # Process service enumeration vulnerabilities
        for service_vuln in service_enum_result.vulnerabilities:
            # Map service vulnerability to our vulnerability database
            if service_vuln.vulnerability_id in self.VULNERABILITY_DATABASE:
                vuln_detail_id = service_vuln.vulnerability_id
            else:
                # Try to map based on name or description
                vuln_detail_id = None
                for vid, vdata in self.VULNERABILITY_DATABASE.items():
                    if (service_vuln.service_name.lower() in vdata["name"].lower() or
                        service_vuln.description.lower() in vdata["description"].lower()):
                        vuln_detail_id = vid
                        break
                
                if not vuln_detail_id:
                    # Use default_credentials or outdated_software as fallback
                    if "default" in service_vuln.description.lower() or "credential" in service_vuln.description.lower():
                        vuln_detail_id = "default_credentials"
                    else:
                        vuln_detail_id = "outdated_software"
            
            vuln_detail = self.VULNERABILITY_DATABASE[vuln_detail_id]
            
            # Skip if below minimum severity
            if vuln_detail["severity"].value < min_severity.value:
                continue
            
            # Create vulnerability instance
            vuln_id = hashlib.md5(f"{service_vuln.service_name}:{service_vuln.service_port}:{vuln_detail_id}".encode()).hexdigest()
            vulnerability = Vulnerability(
                id=vuln_id,
                detail_id=vuln_detail_id,
                target=service_vuln.service_name,
                port=service_vuln.service_port,
                service=service_vuln.service_name,
                evidence=service_vuln.description,
                confidence=0.7
            )
            vulnerabilities.append(vulnerability)
        
        # Check for outdated software versions
        for service in service_enum_result.services:
            if service.product and service.version:
                product = service.product.lower()
                if product in self.VULNERABLE_VERSIONS:
                    for vuln_version in self.VULNERABLE_VERSIONS[product]:
                        if service.version.startswith(vuln_version["version"]):
                            # Skip if below minimum severity
                            if vuln_version["severity"].value < min_severity.value:
                                continue
                            
                            # Create vulnerability instance
                            vuln_detail_id = "outdated_software"
                            vuln_id = hashlib.md5(f"{service.service}:{service.port}:{vuln_version['cve']}".encode()).hexdigest()
                            
                            vulnerability = Vulnerability(
                                id=vuln_id,
                                detail_id=vuln_detail_id,
                                target=service.service,
                                port=service.port,
                                service=service.service,
                                protocol=service.protocol,
                                evidence=f"Vulnerable version {service.version} of {service.product} (CVE: {vuln_version['cve']})",
                                confidence=0.9,
                                metadata={
                                    "cve": vuln_version["cve"],
                                    "product": service.product,
                                    "version": service.version
                                }
                            )
                            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _identify_web_targets(self, recon_result) -> List[str]:
        """
        Identify web targets from reconnaissance results.
        
        Args:
            recon_result: Reconnaissance results
            
        Returns:
            List[str]: List of web targets (URLs)
        """
        web_targets = []
        
        for host in recon_result.hosts:
            if host.status != "up" or not host.open_ports:
                continue
            
            # Check for web ports
            web_ports = []
            for port_info in host.open_ports:
                if port_info.service in ["http", "https"] or port_info.port in [80, 443, 8080, 8443]:
                    web_ports.append(port_info)
            
            # Create web targets
            for port_info in web_ports:
                protocol = "https" if port_info.service == "https" or port_info.port in [443, 8443] else "http"
                if host.hostname:
                    web_targets.append(f"{protocol}://{host.hostname}:{port_info.port}")
                web_targets.append(f"{protocol}://{host.ip_address}:{port_info.port}")
        
        return web_targets
    
    def _convert_web_vulnerabilities(self, web_vulns: List[WebVulnerability], 
                                    min_severity: VulnerabilitySeverity) -> List[Vulnerability]:
        """
        Convert web vulnerabilities to general vulnerabilities.
        
        Args:
            web_vulns: List of web vulnerabilities
            min_severity: Minimum severity level to report
            
        Returns:
            List[Vulnerability]: List of converted vulnerabilities
        """
        vulnerabilities = []
        
        for web_vuln in web_vulns:
            # Map web vulnerability to our vulnerability database
            if web_vuln.name.lower() == "cross-site scripting (xss)":
                vuln_detail_id = "xss"
            elif web_vuln.name.lower() == "sql injection":
                vuln_detail_id = "sqli"
            else:
                # Try to map based on name or description
                vuln_detail_id = None
                for vid, vdata in self.VULNERABILITY_DATABASE.items():
                    if (web_vuln.name.lower() in vdata["name"].lower() or
                        web_vuln.description.lower() in vdata["description"].lower()):
                        vuln_detail_id = vid
                        break
                
                if not vuln_detail_id:
                    # Skip this vulnerability
                    continue
            
            vuln_detail = self.VULNERABILITY_DATABASE[vuln_detail_id]
            
            # Convert severity
            severity = VulnerabilitySeverity.from_web_severity(web_vuln.severity)
            
            # Skip if below minimum severity
            if severity.value < min_severity.value:
                continue
            
            # Parse URL to extract components
            parsed_url = urlparse(web_vuln.url)
            path = parsed_url.path
            parameter = ""
            if "parameter" in web_vuln.details:
                parameter = web_vuln.details["parameter"]
            
            # Create vulnerability instance
            vuln_id = hashlib.md5(f"{web_vuln.url}:{vuln_detail_id}:{parameter}".encode()).hexdigest()
            
            vulnerability = Vulnerability(
                id=vuln_id,
                detail_id=vuln_detail_id,
                target=web_vuln.url,
                target_type="URL",
                path=path,
                parameter=parameter,
                evidence=web_vuln.evidence,
                confidence=web_vuln.confidence,
                metadata=web_vuln.details
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def get_vulnerability_details(self, vuln_id: str) -> Optional[VulnerabilityDetail]:
        """
        Get detailed information about a vulnerability.
        
        Args:
            vuln_id: Vulnerability ID
            
        Returns:
            VulnerabilityDetail: Vulnerability details or None if not found
        """
        if vuln_id in self.VULNERABILITY_DATABASE:
            vuln_data = self.VULNERABILITY_DATABASE[vuln_id]
            
            # Convert dictionary to VulnerabilityDetail object
            references = []
            if "references" in vuln_data:
                for ref in vuln_data["references"]:
                    references.append(VulnerabilityReference(**ref))
            
            return VulnerabilityDetail(
                name=vuln_data["name"],
                description=vuln_data["description"],
                severity=vuln_data["severity"],
                category=vuln_data["category"],
                references=references,
                remediation=vuln_data.get("remediation", ""),
                detection_method=vuln_data.get("detection_method", "")
            )
        
        return None
    
    def get_remediation_advice(self, vulnerability: Vulnerability, 
                              vuln_detail: Optional[VulnerabilityDetail] = None) -> str:
        """
        Get remediation advice for a vulnerability.
        
        Args:
            vulnerability: Vulnerability instance
            vuln_detail: Optional vulnerability details
            
        Returns:
            str: Remediation advice
        """
        if not vuln_detail:
            vuln_detail = self.get_vulnerability_details(vulnerability.detail_id)
        
        if not vuln_detail:
            return "No remediation advice available."
        
        # Start with the general remediation advice
        advice = vuln_detail.remediation if vuln_detail.remediation else "No specific remediation advice available."
        
        # Add specific advice based on vulnerability type
        if vuln_detail.category == VulnerabilityCategory.NETWORK:
            advice += "\n\nFor network vulnerabilities, consider implementing network segmentation and firewall rules."
        
        elif vuln_detail.category == VulnerabilityCategory.WEB:
            advice += "\n\nFor web vulnerabilities, ensure input validation, output encoding, and consider using a Web Application Firewall (WAF)."
        
        elif vuln_detail.category == VulnerabilityCategory.OUTDATED_SOFTWARE:
            advice += "\n\nEnsure you have a regular patching schedule and vulnerability management process."
        
        # Add references if available
        if vuln_detail.references:
            advice += "\n\nReferences:"
            for ref in vuln_detail.references:
                if ref.url:
                    advice += f"\n- {ref.source} {ref.id}: {ref.url}"
                else:
                    advice += f"\n- {ref.source} {ref.id}"
        
        return advice