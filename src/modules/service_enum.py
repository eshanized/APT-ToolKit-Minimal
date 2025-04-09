"""
Service Enumeration module for the APT toolkit.

This module provides functionality for detailed service enumeration,
fingerprinting, and vulnerability identification.
"""

import os
import re
import time
import json
import socket
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass, field, asdict

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils
from src.modules.recon import ReconModule, PortInfo, HostInfo, ReconResult

logger = get_module_logger("service_enum")

@dataclass
class ServiceInfo:
    """Data class for detailed service information"""
    port: int
    service: str
    version: str = ""
    product: str = ""
    protocol: str = "tcp"
    banner: str = ""
    cpe: str = ""  # Common Platform Enumeration identifier
    extra_info: Dict[str, Any] = field(default_factory=dict)
    is_default_config: bool = False
    is_authenticated: bool = False
    auth_type: str = ""  # none, basic, digest, ntlm, kerberos, etc.

@dataclass
class ServiceVulnerability:
    """Data class for service vulnerability information"""
    service_port: int
    service_name: str
    vulnerability_id: str  # CVE, etc.
    severity: str = "unknown"  # critical, high, medium, low, info
    description: str = ""
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ServiceEnumResult:
    """Data class for service enumeration results"""
    target: str
    scan_time: float = field(default_factory=time.time)
    services: List[ServiceInfo] = field(default_factory=list)
    vulnerabilities: List[ServiceVulnerability] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

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
            logger.info(f"Saved service enumeration results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results to {filename}: {e}")
            return False


class ServiceEnumModule:
    """
    Service enumeration module for detailed service identification,
    fingerprinting, and vulnerability detection.
    """
    
    # Common service fingerprints (simplified for demonstration)
    SERVICE_FINGERPRINTS = {
        "http": {
            "headers": ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"],
            "patterns": {
                "apache": r"Apache/([\d\.]+)",
                "nginx": r"nginx/([\d\.]+)",
                "iis": r"Microsoft-IIS/([\d\.]+)",
                "tomcat": r"Apache Tomcat/([\d\.]+)",
                "nodejs": r"Node\.js",
                "php": r"PHP/([\d\.]+)",
                "wordpress": r"WordPress"
            }
        },
        "ssh": {
            "patterns": {
                "openssh": r"OpenSSH_([\d\.]+)",
                "dropbear": r"dropbear_([\d\.]+)",
                "cisco": r"Cisco-\d+"
            }
        },
        "ftp": {
            "patterns": {
                "vsftpd": r"vsftpd ([\d\.]+)",
                "proftpd": r"ProFTPD ([\d\.]+)",
                "filezilla": r"FileZilla Server",
                "microsoft": r"Microsoft FTP Service"
            }
        },
        "smtp": {
            "patterns": {
                "postfix": r"Postfix",
                "exim": r"Exim ([\d\.]+)",
                "sendmail": r"Sendmail",
                "microsoft": r"Microsoft ESMTP"
            }
        },
        "database": {
            "patterns": {
                "mysql": r"MySQL",
                "postgresql": r"PostgreSQL",
                "oracle": r"Oracle",
                "mssql": r"Microsoft SQL Server"
            }
        }
    }
    
    # Common default credentials to check (for demonstration purposes)
    DEFAULT_CREDENTIALS = {
        "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
        "ssh": [("root", "root"), ("admin", "admin"), ("user", "password")],
        "telnet": [("admin", "admin"), ("root", "root"), ("user", "password")],
        "http-basic": [("admin", "admin"), ("root", "root"), ("user", "password")]
    }
    
    # Common vulnerability patterns (simplified for demonstration)
    VULNERABILITY_PATTERNS = {
        "http": {
            "CVE-2021-44228": {  # Log4j
                "pattern": r"Apache.*Log4j",
                "severity": "critical",
                "description": "Log4Shell vulnerability in Log4j"
            },
            "CVE-2021-26084": {  # Confluence
                "pattern": r"Atlassian Confluence",
                "severity": "critical",
                "description": "Confluence Server OGNL injection"
            }
        },
        "ssh": {
            "CVE-2016-0777": {
                "pattern": r"OpenSSH_7\.1",
                "severity": "high",
                "description": "OpenSSH information leak"
            }
        }
    }
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the service enumeration module.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Initialize the network utilities
        if config:
            self.network = NetworkUtils(config)
        else:
            self.network = network_utils
            
        # Initialize the recon module for basic port scanning
        self.recon = ReconModule(config)
        
        # Load configuration settings
        self.timeout = 5
        self.max_threads = 20
        self.aggressive_scan = False
        self.check_vulns = True
        self.check_default_creds = False
        
        if config:
            self.timeout = config.get("modules.service_enum.timeout", 5)
            self.max_threads = config.get("modules.service_enum.max_threads", 20)
            self.aggressive_scan = config.get("modules.service_enum.aggressive", False)
            self.check_vulns = config.get("modules.service_enum.check_vulns", True)
            self.check_default_creds = config.get("modules.service_enum.check_default_creds", False)
    
    def enumerate_services(self, target: str, **kwargs) -> ServiceEnumResult:
        """
        Perform detailed service enumeration on a target.
        
        Args:
            target: Target to scan (IP, hostname, or domain)
            **kwargs: Optional scan parameters:
                - ports: List of ports or port ranges to scan
                - timeout: Scan timeout in seconds
                - max_threads: Maximum number of concurrent threads
                - aggressive: Whether to use aggressive scanning techniques
                - check_vulns: Whether to check for vulnerabilities
                - check_default_creds: Whether to check for default credentials
                
        Returns:
            ServiceEnumResult: Service enumeration results
        """
        start_time = time.time()
        
        # Parse scan parameters
        ports = kwargs.get("ports", None)  # None means use ReconModule's default ports
        timeout = kwargs.get("timeout", self.timeout)
        max_threads = kwargs.get("max_threads", self.max_threads)
        aggressive = kwargs.get("aggressive", self.aggressive_scan)
        check_vulns = kwargs.get("check_vulns", self.check_vulns)
        check_default_creds = kwargs.get("check_default_creds", self.check_default_creds)
        
        # Initialize result object
        result = ServiceEnumResult(target=target)
        
        # First, use the ReconModule to discover hosts and open ports
        logger.info(f"Starting service enumeration for {target}")
        recon_result = self.recon.scan(
            target,
            ports=ports,
            timeout=timeout,
            max_threads=max_threads,
            aggressive=aggressive,
            # Disable unnecessary recon features for service enumeration
            whois=False,
            dns_enum=False,
            subdomain_enum=False,
            traceroute=False
        )
        
        # Process each host from the recon results
        for host in recon_result.hosts:
            if host.status != "up" or not host.open_ports:
                continue
                
            logger.info(f"Enumerating services on {host.ip_address} ({len(host.open_ports)} open ports)")
            
            # Use thread pool for concurrent service enumeration
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit service enumeration tasks
                future_to_port = {}
                
                for port_info in host.open_ports:
                    future = executor.submit(
                        self._enumerate_service,
                        host.ip_address,
                        port_info,
                        timeout,
                        aggressive
                    )
                    future_to_port[future] = port_info.port
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        service_info = future.result()
                        if service_info:
                            result.services.append(service_info)
                            
                            # Check for vulnerabilities if enabled
                            if check_vulns:
                                vulns = self._check_vulnerabilities(service_info)
                                result.vulnerabilities.extend(vulns)
                            
                            # Check for default credentials if enabled
                            if check_default_creds and service_info.service in self.DEFAULT_CREDENTIALS:
                                self._check_default_credentials(host.ip_address, service_info, result)
                                
                    except Exception as e:
                        logger.error(f"Error enumerating service on port {port}: {e}")
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        result.notes.append(f"Service enumeration completed in {scan_duration:.2f} seconds")
        logger.info(f"Service enumeration of {target} completed in {scan_duration:.2f} seconds")
        
        return result
    
    def _enumerate_service(self, ip_address: str, port_info: PortInfo, 
                          timeout: float, aggressive: bool) -> Optional[ServiceInfo]:
        """
        Enumerate a specific service on a host.
        
        Args:
            ip_address: IP address of the host
            port_info: Port information from recon
            timeout: Timeout for service probes
            aggressive: Whether to use aggressive scanning techniques
            
        Returns:
            ServiceInfo: Detailed service information or None if enumeration failed
        """
        try:
            # Initialize service info from port info
            service_info = ServiceInfo(
                port=port_info.port,
                service=port_info.service,
                version=port_info.version,
                protocol=port_info.protocol,
                banner=port_info.banner
            )
            
            # Get or enhance the service banner if needed
            if not service_info.banner or aggressive:
                banner = self._get_service_banner(ip_address, port_info.port, port_info.service, timeout)
                if banner and (not service_info.banner or len(banner) > len(service_info.banner)):
                    service_info.banner = banner
            
            # Fingerprint the service based on banner and other information
            self._fingerprint_service(service_info)
            
            # Perform service-specific enumeration
            if service_info.service == "http" or service_info.service == "https":
                self._enumerate_http_service(ip_address, service_info, timeout, aggressive)
            elif service_info.service == "ssh":
                self._enumerate_ssh_service(ip_address, service_info, timeout, aggressive)
            elif service_info.service == "ftp":
                self._enumerate_ftp_service(ip_address, service_info, timeout, aggressive)
            elif service_info.service == "smtp":
                self._enumerate_smtp_service(ip_address, service_info, timeout, aggressive)
            elif service_info.service in ("mysql", "postgresql", "oracle", "ms-sql-s"):
                self._enumerate_database_service(ip_address, service_info, timeout, aggressive)
            
            return service_info
            
        except Exception as e:
            logger.debug(f"Error enumerating service on {ip_address}:{port_info.port}: {e}")
            return None
    
    def _get_service_banner(self, ip: str, port: int, service: str, timeout: float) -> str:
        """
        Get a service banner using appropriate techniques for the service type.
        
        Args:
            ip: IP address
            port: Port number
            service: Service name
            timeout: Timeout in seconds
            
        Returns:
            str: Service banner or empty string
        """
        # Reuse the banner grabbing functionality from ReconModule
        return self.recon._get_service_banner(ip, port, service, timeout)
    
    def _fingerprint_service(self, service_info: ServiceInfo) -> None:
        """
        Fingerprint a service based on its banner and other information.
        
        Args:
            service_info: Service information to update with fingerprinting results
        """
        if not service_info.banner:
            return
            
        # Check if we have fingerprints for this service type
        if service_info.service in self.SERVICE_FINGERPRINTS:
            fingerprints = self.SERVICE_FINGERPRINTS[service_info.service]
            
            # Check for patterns in the banner
            if "patterns" in fingerprints:
                for product, pattern in fingerprints["patterns"].items():
                    match = re.search(pattern, service_info.banner)
                    if match:
                        service_info.product = product
                        # If the pattern has a capture group for version, extract it
                        if match.groups():
                            service_info.version = match.group(1)
                        break
            
            # For HTTP services, check for specific headers
            if service_info.service == "http" and "headers" in fingerprints:
                if "extra_info" in service_info.extra_info and "headers" in service_info.extra_info:
                    headers = service_info.extra_info["headers"]
                    for header in fingerprints["headers"]:
                        if header in headers:
                            service_info.extra_info["server_headers"] = {
                                header: headers[header]
                            }
        
        # Generate CPE identifier if possible
        if service_info.product and service_info.version:
            # Format: cpe:/a:{vendor}:{product}:{version}
            vendor = service_info.product  # Simplification, in reality would map product to vendor
            service_info.cpe = f"cpe:/a:{vendor}:{service_info.product}:{service_info.version}"
    
    def _enumerate_http_service(self, ip: str, service_info: ServiceInfo, 
                               timeout: float, aggressive: bool) -> None:
        """
        Perform detailed enumeration of an HTTP/HTTPS service.
        
        Args:
            ip: IP address
            service_info: Service information to update
            timeout: Timeout in seconds
            aggressive: Whether to use aggressive scanning techniques
        """
        protocol = "https" if service_info.service == "https" else "http"
        url = f"{protocol}://{ip}:{service_info.port}"
        
        try:
            # Get HTTP headers
            status, headers, body = self.network.get_http_request(
                url,
                timeout=timeout,
                verify_ssl=False,
                headers={"User-Agent": self.network.get_random_user_agent()}
            )
            
            if status > 0:
                service_info.extra_info["http_status"] = status
                service_info.extra_info["headers"] = dict(headers)
                
                # Extract server information
                if "Server" in headers:
                    server = headers["Server"]
                    service_info.product = server.split("/")[0] if "/" in server else server
                    version_match = re.search(r"[\d\.]+", server)
                    if version_match:
                        service_info.version = version_match.group(0)
                
                # Check for authentication
                if "WWW-Authenticate" in headers:
                    service_info.is_authenticated = True
                    auth_header = headers["WWW-Authenticate"].lower()
                    if "basic" in auth_header:
                        service_info.auth_type = "basic"
                    elif "digest" in auth_header:
                        service_info.auth_type = "digest"
                    elif "ntlm" in auth_header:
                        service_info.auth_type = "ntlm"
                    elif "negotiate" in auth_header:
                        service_info.auth_type = "negotiate"
                
                # Check for common web technologies
                if aggressive:
                    # In a real implementation, would check for common paths, robots.txt, etc.
                    # For demonstration, just check for technology indicators in the response
                    tech_indicators = {
                        "wordpress": ["wp-content", "wp-includes", "WordPress"],
                        "joomla": ["joomla", "Joomla"],
                        "drupal": ["drupal", "Drupal"],
                        "php": ["PHP"],
                        "asp.net": ["ASP.NET"],
                        "tomcat": ["Tomcat", "Apache Tomcat"],
                        "weblogic": ["WebLogic"],
                        "websphere": ["WebSphere"]
                    }
                    
                    detected_tech = []
                    for tech, indicators in tech_indicators.items():
                        for indicator in indicators:
                            if indicator in body or indicator in str(headers):
                                detected_tech.append(tech)
                                break
                    
                    if detected_tech:
                        service_info.extra_info["web_technologies"] = detected_tech
            
        except Exception as e:
            logger.debug(f"Error enumerating HTTP service at {url}: {e}")
    
    def _enumerate_ssh_service(self, ip: str, service_info: ServiceInfo, 
                              timeout: float, aggressive: bool) -> None:
        """
        Perform detailed enumeration of an SSH service.
        
        Args:
            ip: IP address
            service_info: Service information to update
            timeout: Timeout in seconds
            aggressive: Whether to use aggressive scanning techniques
        """
        # Most SSH information is already in the banner
        # For aggressive scanning, could try to enumerate supported algorithms
        if aggressive:
            # In a real implementation, would use paramiko or similar to check
            # supported algorithms, key exchange methods, etc.
            pass
    
    def _enumerate_ftp_service(self, ip: str, service_info: ServiceInfo, 
                              timeout: float, aggressive: bool) -> None:
        """
        Perform detailed enumeration of an FTP service.
        
        Args:
            ip: IP address
            service_info: Service information to update
            timeout: Timeout in seconds
            aggressive: Whether to use aggressive scanning techniques
        """
        try:
            # Try anonymous login if aggressive scanning is enabled
            if aggressive:
                try:
                    # In a real implementation, would use ftplib to attempt anonymous login
                    # and list directories if successful
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((ip, service_info.port))
                    
                    # Read banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Send USER anonymous
                    sock.send(b"USER anonymous\r\n")
                    resp = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Send PASS anonymous
                    sock.send(b"PASS anonymous\r\n")
                    resp = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if "230" in resp:  # 230 = User logged in
                        service_info.is_default_config = True
                        service_info.extra_info["anonymous_access"] = True
                        
                        # Try to list directories
                        sock.send(b"LIST\r\n")
                        # Would process response here
                    
                    sock.close()
                    
                except Exception as e:
                    logger.debug(f"Anonymous FTP login failed for {ip}: {e}")
        
        except Exception as e:
            logger.debug(f"Error enumerating FTP service at {ip}:{service_info.port}: {e}")
    
    def _enumerate_smtp_service(self, ip: str, service_info: ServiceInfo, 
                               timeout: float, aggressive: bool) -> None:
        """
        Perform detailed enumeration of an SMTP service.
        
        Args:
            ip: IP address
            service_info: Service information to update
            timeout: Timeout in seconds
            aggressive: Whether to use aggressive scanning techniques
        """
        try:
            # For aggressive scanning, could try SMTP commands like VRFY, EXPN, etc.
            if aggressive:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((ip, service_info.port))
                    
                    # Read banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Try EHLO command to get supported features
                    sock.send(b"EHLO example.com\r\n")
                    resp = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if "250" in resp:  # 250 = OK
                        features = resp.split("\n")
                        service_info.extra_info["smtp_features"] = features
                        
                        # Check for open relay (would be more complex in reality)
                        # This is just a placeholder for demonstration
                        service_info.extra_info["open_relay"] = False
                    
                    sock.close()
                    
                except Exception as e:
                    logger.debug(f"SMTP enumeration failed for {ip}: {e}")
        
        except Exception as e:
            logger.debug(f"Error enumerating SMTP service at {ip}:{service_info.port}: {e}")
    
    def _enumerate_database_service(self, ip: str, service_info: ServiceInfo, 
                                   timeout: float, aggressive: bool) -> None:
        """
        Perform detailed enumeration of a database service.
        
        Args:
            ip: IP address
            service_info: Service information to update
            timeout: Timeout in seconds
            aggressive: Whether to use aggressive scanning techniques
        """
        # Database enumeration would typically require authentication
        # For demonstration, just identify the database type from the banner
        
        if "mysql" in service_info.service.lower():
            service_info.product = "MySQL"
        elif "postgresql" in service_info.service.lower():
            service_info.product = "PostgreSQL"
        elif "oracle" in service_info.service.lower():
            service_info.product = "Oracle"
        elif "ms-sql" in service_info.service.lower():
            service_info.product = "Microsoft SQL Server"
        
        # In a real implementation, would attempt to:
        # 1. Identify exact version from banner
        # 2. Check for default credentials if aggressive
        # 3. Enumerate available databases if authenticated
    
    def _check_vulnerabilities(self, service_info: ServiceInfo) -> List[ServiceVulnerability]:
        """
        Check for known vulnerabilities based on service fingerprinting.
        
        Args:
            service_info: Service information
            
        Returns:
            List[ServiceVulnerability]: List of potential vulnerabilities
        """
        vulnerabilities = []
        
        # Check if we have vulnerability patterns for this service
        if service_info.service in self.VULNERABILITY_PATTERNS:
            vuln_patterns = self.VULNERABILITY_PATTERNS[service_info.service]
            
            # Check each vulnerability pattern
            for vuln_id, vuln_info in vuln_patterns.items():
                if re.search(vuln_info["pattern"], service_info.banner):
                    # Potential vulnerability found
                    vulnerability = ServiceVulnerability(
                        service_port=service_info.port,
                        service_name=service_info.service,
                        vulnerability_id=vuln_id,
                        severity=vuln_info["severity"],
                        description=vuln_info["description"]
                    )
                    vulnerabilities.append(vulnerability)
        
        # In a real implementation, would also check:
        # 1. Version-specific vulnerabilities
        # 2. Configuration vulnerabilities
        # 3. Default credential vulnerabilities
        
        return vulnerabilities
    
    def _check_default_credentials(self, ip: str, service_info: ServiceInfo, 
                                  result: ServiceEnumResult) -> None:
        """
        Check for default credentials on the service.
        
        Args:
            ip: IP address
            service_info: Service information
            result: Result object to update with findings
        """
        # This is a placeholder for demonstration
        # In a real implementation, would attempt to authenticate with default credentials
        
        service_key = service_info.service
        
        # Map HTTP with basic auth to http-basic
        if service_info.service in ("http", "https") and service_info.auth_type == "basic":
            service_key = "http-basic"
        
        # Check if we have default credentials for this service
        if service_key in self.DEFAULT_CREDENTIALS:
            # In a real implementation, would attempt to authenticate with each credential pair
            # For demonstration, just add a note
            result.notes.append(
                f"Default credential check for {service_info.service} on port {service_info.port} would be performed here"
            )