import os
import re
import socket
import time
import json
import ipaddress
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass, field, asdict

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils

logger = get_module_logger("recon")

@dataclass
class DNSRecord:
    """Data class for DNS record information"""
    hostname: str
    record_type: str
    value: str
    ttl: int = 0

@dataclass
class PortInfo:
    """Data class for port information"""
    port: int
    state: str
    service: str = ""
    version: str = ""
    protocol: str = "tcp"
    banner: str = ""

@dataclass
class HostInfo:
    """Data class for host information"""
    ip_address: str
    hostname: str = ""
    status: str = "unknown"  # up, down, unknown
    os_info: str = ""
    response_time: float = 0.0
    last_seen: float = 0.0
    open_ports: List[PortInfo] = field(default_factory=list)
    mac_address: str = ""

@dataclass
class DomainInfo:
    """Data class for domain information"""
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    whois_data: Dict[str, str] = field(default_factory=dict)

@dataclass
class ReconResult:
    """Data class for reconnaissance results"""
    target: str
    scan_time: float = field(default_factory=time.time)
    hosts: List[HostInfo] = field(default_factory=list)
    domains: List[DomainInfo] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    end_time: float = 0.0  # New field to track end time

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
            logger.info(f"Saved reconnaissance results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results to {filename}: {e}")
            return False
            
    def get_duration(self) -> float:
        """Get scan duration in seconds"""
        if self.end_time > 0:
            return self.end_time - self.scan_time
        else:
            return time.time() - self.scan_time


class ReconModule:
    """
    Reconnaissance module for gathering target information.
    Includes DNS enumeration, port scanning, and WHOIS lookup.
    """
    
    # Common ports to scan by default
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 
        443, 445, 464, 465, 587, 593, 636, 993, 995, 1025, 1433, 
        1521, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443
    ]
    
    # Default DNS record types to query
    DEFAULT_DNS_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"]
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the reconnaissance module.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Initialize the network utilities
        if config:
            self.network = NetworkUtils(config)
        else:
            self.network = network_utils
            
        # Load configuration settings
        self.timeout = 5
        self.max_threads = 20
        self.max_ports = 1000
        self.aggressive_scan = False
        self.dns_wordlist = []
        
        if config:
            self.timeout = config.get("modules.recon.timeout", 5)
            self.max_threads = config.get("modules.recon.max_threads", 20)
            self.max_ports = config.get("modules.recon.max_ports", 1000)
            self.aggressive_scan = config.get("modules.recon.aggressive", False)
            
            # Load DNS wordlist if specified
            wordlist_path = config.get("modules.recon.dns_wordlist", "")
            if wordlist_path and os.path.exists(wordlist_path):
                self._load_dns_wordlist(wordlist_path)
                
    def _load_dns_wordlist(self, wordlist_path: str) -> None:
        """
        Load DNS subdomain wordlist from file.
        
        Args:
            wordlist_path: Path to the wordlist file.
        """
        try:
            with open(wordlist_path, 'r') as f:
                self.dns_wordlist = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(self.dns_wordlist)} entries from {wordlist_path}")
        except Exception as e:
            logger.error(f"Failed to load DNS wordlist from {wordlist_path}: {e}")
    
    def scan(self, target: str, **kwargs) -> ReconResult:
        """
        Perform a comprehensive reconnaissance scan on a target.
    
    Args:
            target: Target to scan (IP, hostname, or domain)
            **kwargs: Optional scan parameters:
                - ports: List of ports or port ranges to scan
                - dns_types: List of DNS record types to query
                - timeout: Scan timeout in seconds
                - max_threads: Maximum number of concurrent threads
                - ping: Whether to ping hosts (default: True)
                - whois: Whether to perform WHOIS lookup (default: True)
                - dns_enum: Whether to enumerate DNS records (default: True)
                - subdomain_enum: Whether to enumerate subdomains (default: True)
                - traceroute: Whether to perform traceroute (default: False)
                - port_scan: Whether to perform port scanning (default: True)
                - aggressive: Whether to use aggressive scanning techniques (default: False)

    Returns:
            ReconResult: Comprehensive scan results
        """
        start_time = time.time()
        
        # Parse scan parameters
        ports = kwargs.get("ports", self.DEFAULT_PORTS)
        dns_types = kwargs.get("dns_types", self.DEFAULT_DNS_TYPES)
        timeout = kwargs.get("timeout", self.timeout)
        max_threads = kwargs.get("max_threads", self.max_threads)
        ping = kwargs.get("ping", True)
        whois = kwargs.get("whois", True)
        dns_enum = kwargs.get("dns_enum", True)
        subdomain_enum = kwargs.get("subdomain_enum", True)
        traceroute = kwargs.get("traceroute", False)
        port_scan = kwargs.get("port_scan", True)
        aggressive = kwargs.get("aggressive", self.aggressive_scan)
        
        # Initialize result object
        result = ReconResult(target=target)
        
        # Determine target type (IP, domain, etc.)
        target_type = self._identify_target_type(target)
        
        # Process based on target type
        if target_type == "IP":
            # Single IP address
            host_info = self._scan_host(
                target, 
                ping=ping, 
                ports=ports if port_scan else [], 
                timeout=timeout,
                traceroute=traceroute
            )
            result.hosts.append(host_info)
            
        elif target_type == "DOMAIN":
            # Domain name - do DNS and domain reconnaissance
            logger.info(f"Starting domain reconnaissance for {target}")
            
            # WHOIS lookup
            if whois:
                domain_info = self._domain_whois(target)
                result.domains.append(domain_info)
            
            # DNS enumeration
            if dns_enum:
                if not result.domains:
                    domain_info = DomainInfo(domain=target)
                    result.domains.append(domain_info)
                    
                dns_records = self._dns_enumeration(target, record_types=dns_types)
                result.domains[0].dns_records = dns_records
                
                # Extract IP addresses from DNS records
                ip_addresses = self._extract_ips_from_dns(dns_records)
                
                # Add hosts from DNS records
                for ip in ip_addresses:
                    host_info = self._scan_host(
                        ip, 
                        ping=ping, 
                        ports=ports if port_scan else [], 
                        timeout=timeout,
                        hostname=target
                    )
                    result.hosts.append(host_info)
            
            # Subdomain enumeration
            if subdomain_enum:
                subdomains = self._subdomain_enumeration(target)
                if result.domains:
                    result.domains[0].subdomains = subdomains
                
                # Scan discovered subdomains if aggressive scanning is enabled
                if aggressive and subdomains:
                    logger.info(f"Scanning {len(subdomains)} discovered subdomains")
                    for subdomain in subdomains:
                        try:
                            ip = self.network.resolve_hostname(subdomain, timeout)
                            if ip:
                                host_info = self._scan_host(
                                    ip, 
                                    ping=ping, 
                                    ports=ports if port_scan else [], 
                                    timeout=timeout,
                                    hostname=subdomain
                                )
                                result.hosts.append(host_info)
                        except Exception as e:
                            logger.debug(f"Error scanning subdomain {subdomain}: {e}")
            
        elif target_type == "CIDR":
            # Network range in CIDR notation
            logger.info(f"Starting network range reconnaissance for {target}")
            
            # Generate IP list from CIDR
            ip_list = self.network.cidr_to_ip_range(target)
            logger.info(f"Network range contains {len(ip_list)} hosts")
            
            # Use thread pool for scanning multiple hosts
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                scan_tasks = []
                
                for ip in ip_list:
                    scan_tasks.append(executor.submit(
                        self._scan_host,
                        ip,
                        ping=ping,
                        ports=ports if port_scan else [],
                        timeout=timeout
                    ))
                
                # Collect results as they complete
                for future in concurrent.futures.as_completed(scan_tasks):
                    try:
                        host_info = future.result()
                        if host_info and host_info.status == "up":
                            result.hosts.append(host_info)
                    except Exception as e:
                        logger.error(f"Error in host scan task: {e}")
        
        # Perform traceroute if requested
        if traceroute and target_type in ["IP", "DOMAIN"]:
            trace_target = target
            if target_type == "DOMAIN":
                # Resolve domain to IP for traceroute
                ip = self.network.resolve_hostname(target)
                if ip:
                    trace_target = ip
            
            try:
                route = self.network.traceroute(trace_target, timeout=timeout)
                result.routes = route
            except Exception as e:
                logger.error(f"Error performing traceroute to {trace_target}: {e}")
                
        # Calculate scan duration
        scan_duration = time.time() - start_time
        result.notes.append(f"Scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Reconnaissance scan of {target} completed in {scan_duration:.2f} seconds")
        
        # Set the end time
        result.end_time = time.time()
        
        return result
    
    def _identify_target_type(self, target: str) -> str:
        """
        Identify the type of target (IP, domain, CIDR, etc.)
        
        Args:
            target: Target string to identify
            
        Returns:
            str: Target type ("IP", "DOMAIN", "CIDR", or "UNKNOWN")
        """
        # Check if it's an IP address
        if self.network.is_valid_ip(target):
            return "IP"
        
        # Check if it's a CIDR range
        if '/' in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return "CIDR"
            except ValueError:
                pass
        
        # Check if it's a domain
        if self.network.is_valid_hostname(target):
            return "DOMAIN"
        
        # Unknown target type
        return "UNKNOWN"
    
    def _scan_host(self, ip_address: str, ping: bool = True, ports: List[int] = None, 
                  timeout: Optional[float] = None, hostname: str = "", 
                  traceroute: bool = False) -> HostInfo:
        """
        Scan a single host for information.
        
        Args:
            ip_address: IP address to scan
            ping: Whether to ping the host
            ports: List of ports to scan
            timeout: Scan timeout in seconds
            hostname: Hostname if known
            traceroute: Whether to perform traceroute
            
        Returns:
            HostInfo: Host information object
        """
        if not timeout:
            timeout = self.timeout
            
        # Initialize host info
        host = HostInfo(
            ip_address=ip_address,
            hostname=hostname,
            last_seen=time.time()
        )
        
        # Try to get hostname if not provided
        if not hostname:
            try:
                resolved_name = self.network.reverse_dns_lookup(ip_address, timeout)
                if resolved_name:
                    host.hostname = resolved_name
            except Exception as e:
                logger.debug(f"Error in reverse DNS lookup for {ip_address}: {e}")
        
        # Ping the host to check if it's up
        if ping:
            try:
                is_up, response_time = self.network.ping(ip_address, timeout=timeout)
                if is_up:
                    host.status = "up"
                    host.response_time = response_time
                else:
                    host.status = "down"
            except Exception as e:
                logger.debug(f"Error pinging host {ip_address}: {e}")
        
        # Scan ports if requested and host is up (or ping was skipped)
        if ports and (host.status != "down" or not ping):
            self._scan_ports(host, ports, timeout)
        
        # Get MAC address for local hosts
        try:
            if self._is_private_ip(ip_address):
                mac = self.network.get_mac_address()
                if mac:
                    host.mac_address = mac
        except Exception as e:
            logger.debug(f"Error getting MAC address for {ip_address}: {e}")
            
        return host
    
    def _scan_ports(self, host: HostInfo, ports: List[int], timeout: Optional[float] = None) -> None:
        """
        Scan a host for open ports.
        
        Args:
            host: HostInfo object to update with port information
            ports: List of ports to scan
            timeout: Scan timeout in seconds
        """
        if not timeout:
            timeout = self.timeout
            
        logger.info(f"Scanning {len(ports)} ports on {host.ip_address}")
        
        try:
            # Use the port_scan method from NetworkUtils
            port_results = self.network.port_scan(host.ip_address, ports, timeout)
            
            # Process the results
            for port, is_open in port_results.items():
                if is_open:
                    # Try to get service info based on port number
                    service = self._get_service_by_port(port)
                    
                    port_info = PortInfo(
                        port=port,
                        state="open",
                        service=service,
                        protocol="tcp"
                    )
                    
                    # Try to get banner if it's a common service port
                    if service and self._should_get_banner(port, service):
                        try:
                            banner = self._get_service_banner(host.ip_address, port, service, timeout)
                            if banner:
                                port_info.banner = banner
                                # Try to extract version from banner
                                version = self._extract_version_from_banner(banner, service)
                                if version:
                                    port_info.version = version
                        except Exception as e:
                            logger.debug(f"Error getting banner for {host.ip_address}:{port}: {e}")
                    
                    host.open_ports.append(port_info)
                    
            # If we found open ports, the host is definitely up
            if host.open_ports and host.status == "unknown":
                host.status = "up"
                
        except Exception as e:
            logger.error(f"Error scanning ports on {host.ip_address}: {e}")
    
    def _get_service_by_port(self, port: int) -> str:
        """
        Get service name based on port number.
        
        Args:
            port: Port number
            
        Returns:
            str: Service name or empty string if unknown
        """
        # Common port to service mappings
        port_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            88: "kerberos",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            389: "ldap",
            443: "https",
            445: "microsoft-ds",
            464: "kpasswd",
            465: "smtps",
            587: "submission",
            593: "http-rpc-epmap",
            636: "ldaps",
            993: "imaps",
            995: "pop3s",
            1025: "nfs",
            1433: "ms-sql-s",
            1521: "oracle",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            5985: "wsman",
            5986: "wsmans",
            8080: "http-proxy",
            8443: "https-alt"
        }
        
        return port_map.get(port, "")
    
    def _should_get_banner(self, port: int, service: str) -> bool:
        """
        Determine if we should try to get a service banner.
        
        Args:
            port: Port number
            service: Service name
            
        Returns:
            bool: True if we should try to get a banner
        """
        # Services that typically provide banners
        banner_services = {
            "ftp", "ssh", "smtp", "pop3", "imap", "http", "https", 
            "telnet", "mysql", "ms-sql-s", "postgresql", "vnc"
        }
        
        return service in banner_services
    
    def _get_service_banner(self, ip: str, port: int, service: str, timeout: float) -> str:
        """
        Try to get a service banner.
        
        Args:
            ip: IP address
            port: Port number
            service: Service name
            timeout: Timeout in seconds
            
        Returns:
            str: Service banner or empty string
        """
        banner = ""
        
        try:
            if service in ("http", "https"):
                # For HTTP/HTTPS, use a GET request to get the server header
                proto = "https" if service == "https" or port == 443 else "http"
                url = f"{proto}://{ip}:{port}"
                
                status, headers, _ = self.network.get_http_request(
                    url,
                    timeout=timeout,
                    verify_ssl=False,
                    headers={"User-Agent": self.network.get_random_user_agent()}
                )
                
                if status > 0:
                    server = headers.get("Server", "")
                    if server:
                        banner = f"Server: {server}"
                    
            else:
                # For other services, try a simple socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # Some services send a banner immediately
                if service in ("ftp", "smtp", "pop3", "imap", "ssh"):
                    # Wait a moment for the banner
                    time.sleep(0.2)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                # For others, we might need to send a probe
                elif service == "telnet":
                    sock.recv(1024)  # Receive initial telnet negotiation
                    banner = "TELNET Service"
                
                sock.close()
                
        except Exception as e:
            logger.debug(f"Error getting banner from {ip}:{port} ({service}): {e}")
            
        return banner
    
    def _extract_version_from_banner(self, banner: str, service: str) -> str:
        """
        Try to extract version information from a service banner.
        
        Args:
            banner: Service banner string
            service: Service name
            
        Returns:
            str: Version string or empty string
        """
        version = ""
        
        # Common version regex patterns based on service
        patterns = {
            "ssh": r"SSH-[\d\.]+-([\w\.\-\_\+]+)",
            "ftp": r"([\d\.]+)",
            "http": r"Server: .*?([\d\.]+)",
            "https": r"Server: .*?([\d\.]+)",
            "smtp": r"([\d\.]+)",
            "pop3": r"([\d\.]+)",
            "imap": r"([\d\.]+)"
        }
        
        if service in patterns:
            match = re.search(patterns[service], banner)
            if match:
                version = match.group(1)
                
        return version
    
    def _domain_whois(self, domain: str) -> DomainInfo:
        """
        Perform WHOIS lookup for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            DomainInfo: Domain information
        """
        domain_info = DomainInfo(domain=domain)
        
        try:
            whois_data = self.network.whois_lookup(domain)
            domain_info.whois_data = whois_data
            
            # Extract key information from WHOIS data
            domain_info.registrar = whois_data.get("registrar", "")
            domain_info.creation_date = whois_data.get("creation date", "")
            domain_info.expiration_date = whois_data.get("expiration date", "")
            
            # Extract name servers
            if "name server" in whois_data:
                ns_value = whois_data["name server"]
                name_servers = [ns.strip() for ns in ns_value.split() if ns.strip()]
                domain_info.name_servers = name_servers
                
        except Exception as e:
            logger.error(f"Error performing WHOIS lookup for {domain}: {e}")
            
        return domain_info
    
    def _dns_enumeration(self, domain: str, record_types: List[str] = None) -> List[DNSRecord]:
        """
        Enumerate DNS records for a domain.
        
        Args:
            domain: Domain name
            record_types: List of DNS record types to query
            
        Returns:
            List[DNSRecord]: List of DNS records
        """
        if not record_types:
            record_types = self.DEFAULT_DNS_TYPES
            
        dns_records = []
        
        try:
            # We need to use the 'dig' command or a DNS library like dnspython
            # For simplicity, we'll use basic socket resolution for A records
            # and some mock data for other types
            # In a real implementation, use dnspython or subprocess with dig
            
            # Simulate A record lookup using socket
            try:
                ip = socket.gethostbyname(domain)
                dns_records.append(DNSRecord(
                    hostname=domain,
                    record_type="A",
                    value=ip,
                    ttl=3600
                ))
            except socket.gaierror:
                pass
            
            # This is a simplified simulation - in a real implementation,
            # you would use dnspython or a similar library for proper DNS queries
            if "MX" in record_types:
                # Simulate MX records
                try:
                    mx_records = socket.getaddrinfo(f"mail.{domain}", None)
                    if mx_records:
                        dns_records.append(DNSRecord(
                            hostname=domain,
                            record_type="MX",
                            value=f"10 mail.{domain}",
                            ttl=3600
                        ))
                except socket.gaierror:
                    pass
            
            if "NS" in record_types and hasattr(self, "_domain_info"):
                domain_info = getattr(self, "_domain_info", None)
                # Use name servers from WHOIS data if available
                for ns in domain_info.name_servers:
                    dns_records.append(DNSRecord(
                        hostname=domain,
                        record_type="NS",
                        value=ns,
                        ttl=3600
                    ))
            
            # Note: In a real implementation, you would use proper DNS libraries
            # to query all record types correctly

        except Exception as e:
                logger.error(f"Error enumerating DNS records for {domain}: {e}")
                
        return dns_records
    
    def _subdomain_enumeration(self, domain: str) -> List[str]:
        """
        Enumerate subdomains for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            List[str]: List of discovered subdomains
        """
        discovered_subdomains = set()
        
        # Use DNS wordlist for brute-force enumeration
        if self.dns_wordlist:
            logger.info(f"Starting subdomain brute-force with {len(self.dns_wordlist)} names")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                for name in self.dns_wordlist:
                    subdomain = f"{name}.{domain}"
                    futures.append(executor.submit(
                        self._check_subdomain_exists, subdomain
                    ))
                
                for future in concurrent.futures.as_completed(futures):
                    subdomain = future.result()
                    if subdomain:
                        discovered_subdomains.add(subdomain)
        
        # Try common subdomains if no wordlist is available
        else:
            common_subdomains = [
                "www", "mail", "webmail", "smtp", "pop", "ns1", "ns2", 
                "dns", "dns1", "dns2", "mx", "mx1", "mx2", "ftp", "sftp", 
                "ssh", "admin", "dev", "stage", "test", "beta", "api", 
                "intranet", "vpn", "secure", "cloud", "shop", "blog", 
                "portal", "remote", "support", "docs", "gitlab", "git"
            ]
            
            logger.info(f"Starting subdomain check with {len(common_subdomains)} common names")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                for name in common_subdomains:
                    subdomain = f"{name}.{domain}"
                    futures.append(executor.submit(
                        self._check_subdomain_exists, subdomain
                    ))
                
                for future in concurrent.futures.as_completed(futures):
                    subdomain = future.result()
                    if subdomain:
                        discovered_subdomains.add(subdomain)
        
        logger.info(f"Discovered {len(discovered_subdomains)} subdomains for {domain}")
        return list(discovered_subdomains)
    
    def _check_subdomain_exists(self, subdomain: str) -> Optional[str]:
        """
        Check if a subdomain exists via DNS resolution.
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            str: Subdomain if it exists, None otherwise
        """
        try:
            # Try to resolve the subdomain
            ip = socket.gethostbyname(subdomain)
            if ip:
                logger.debug(f"Discovered subdomain: {subdomain} ({ip})")
                return subdomain
        except socket.gaierror:
            pass
        
        return None
    
    def _extract_ips_from_dns(self, dns_records: List[DNSRecord]) -> List[str]:
        """
        Extract IP addresses from DNS records.
        
        Args:
            dns_records: List of DNS records
            
        Returns:
            List[str]: List of IP addresses
        """
        ip_addresses = []
        
        for record in dns_records:
            if record.record_type == "A" or record.record_type == "AAAA":
                if self.network.is_valid_ip(record.value):
                    ip_addresses.append(record.value)
        
        return ip_addresses
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address is in a private range.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if the IP is in a private range
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False

def run(target, logger=None, return_object=False):
    """
    Run reconnaissance on a target and return a list of human-readable text results.
    This function serves as a bridge between the UI and the ReconModule class.
    
    Args:
        target (str): Target to scan (IP, hostname, domain, CIDR, etc.)
        logger: Optional logger instance
        return_object (bool): Whether to return the ReconResult object along with text results
        
    Returns:
        If return_object is False:
            List[str]: List of human-readable result lines
        If return_object is True:
            Tuple[List[str], ReconResult]: Both the text results and the ReconResult object
    """
    try:
        # Initialize the recon module
        recon_module = ReconModule()
        
        # Log the operation
        if logger:
            logger.info(f"Starting reconnaissance on {target}")
        
        # Run the recon module scan
        results = []
        results.append(f"[*] Starting reconnaissance on {target}")
        
        # Perform the actual scan
        scan_result = recon_module.scan(target)
        
        # Set the end time
        scan_result.end_time = time.time()
        
        # Process host information
        if scan_result.hosts:
            results.append(f"\n[+] Found {len(scan_result.hosts)} hosts:")
            for host in scan_result.hosts:
                results.append(f"  - {host.ip_address} ({host.hostname or 'Unknown'})")
                if host.status:
                    results.append(f"    Status: {host.status}")
                if host.open_ports:
                    results.append(f"    Open ports:")
                    for port in host.open_ports:
                        service_info = f"{port.service} {port.version}".strip()
                        results.append(f"      - {port.port}/{port.protocol}: {service_info}")
                        if port.banner:
                            results.append(f"        Banner: {port.banner[:50]}...")
        else:
            results.append("[!] No hosts found.")
        
        # Process domain information
        if scan_result.domains:
            results.append(f"\n[+] Found {len(scan_result.domains)} domains:")
            for domain in scan_result.domains:
                results.append(f"  - {domain.domain}")
                if domain.registrar:
                    results.append(f"    Registrar: {domain.registrar}")
                if domain.creation_date:
                    results.append(f"    Creation Date: {domain.creation_date}")
                if domain.expiration_date:
                    results.append(f"    Expiration Date: {domain.expiration_date}")
                if domain.name_servers:
                    results.append(f"    Name Servers:")
                    for ns in domain.name_servers:
                        results.append(f"      - {ns}")
                
                # Process DNS records
                if domain.dns_records:
                    results.append(f"    DNS Records:")
                    for record in domain.dns_records:
                        results.append(f"      - {record.record_type}: {record.hostname} -> {record.value}")
                
                # Process subdomains
                if domain.subdomains:
                    results.append(f"    Subdomains:")
                    for subdomain in domain.subdomains[:5]:  # Show only first 5
                        results.append(f"      - {subdomain}")
                    if len(domain.subdomains) > 5:
                        results.append(f"      ... and {len(domain.subdomains) - 5} more")
        
        # Add scan duration
        scan_duration = scan_result.get_duration()
        results.append(f"\n[+] Reconnaissance on {target} completed in {scan_duration:.2f} seconds")
        
        if logger:
            logger.info(f"Reconnaissance scan of {target} completed in {scan_duration:.2f} seconds")
        
        if return_object:
            return results, scan_result
        else:
            return results
            
    except Exception as e:
        error_msg = f"Error during reconnaissance: {str(e)}"
        if logger:
            logger.error(error_msg)
        
        # Return error as result
        if return_object:
            # Create an empty result with just the error
            empty_result = ReconResult(target=target)
            empty_result.notes.append(f"Error: {str(e)}")
            empty_result.end_time = time.time()
            return [error_msg], empty_result
        else:
            return [error_msg]
