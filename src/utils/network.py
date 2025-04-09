import os
import re
import socket
import struct
import ipaddress
import subprocess
import time
import random
import ssl
import json
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import urlparse, urljoin
import requests
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager

# Initialize logger for this module
logger = get_module_logger("network")

class NetworkUtils:
    """Network utility functions for common operations like ping, DNS resolution, port scanning, etc."""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the network utilities with optional configuration.
        
        Args:
            config: Optional ConfigManager instance for network settings.
        """
        self.config = config
        self.default_timeout = 5
        self.max_retries = 3
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Load configuration if provided
        if config:
            self.default_timeout = config.get("network.default_timeout", 5)
            self.max_retries = config.get("network.max_retries", 3)
            self.user_agent = config.get("network.user_agent", self.user_agent)
    
    def is_valid_ip(self, ip_address: str) -> bool:
        """
        Check if a string is a valid IP address (IPv4 or IPv6).
        
        Args:
            ip_address: String to validate as IP address.
            
        Returns:
            bool: True if valid IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def is_valid_hostname(self, hostname: str) -> bool:
        """
        Check if a string is a valid hostname.
        
        Args:
            hostname: String to validate as hostname.
            
        Returns:
            bool: True if valid hostname, False otherwise.
        """
        if not hostname or len(hostname) > 255:
            return False
        
        hostname_regex = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        return hostname_regex.match(hostname) is not None
    
    def resolve_hostname(self, hostname: str, timeout: Optional[int] = None) -> Optional[str]:
        """
        Resolve a hostname to an IP address.
        
        Args:
            hostname: Hostname to resolve.
            timeout: Timeout in seconds (uses default_timeout if None).
            
        Returns:
            str: IP address or None if resolution failed.
        """
        if not timeout:
            timeout = self.default_timeout
            
        try:
            socket.setdefaulttimeout(timeout)
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            logger.warning(f"Failed to resolve hostname {hostname}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error resolving hostname {hostname}: {e}")
            return None
    
    def reverse_dns_lookup(self, ip_address: str, timeout: Optional[int] = None) -> Optional[str]:
        """
        Perform a reverse DNS lookup on an IP address.
        
        Args:
            ip_address: IP address to look up.
            timeout: Timeout in seconds (uses default_timeout if None).
            
        Returns:
            str: Hostname or None if lookup failed.
        """
        if not timeout:
            timeout = self.default_timeout
            
        try:
            socket.setdefaulttimeout(timeout)
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror) as e:
            logger.warning(f"Failed to perform reverse DNS lookup for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error in reverse DNS lookup for {ip_address}: {e}")
            return None
    
    def ping(self, target: str, count: int = 4, timeout: Optional[int] = None) -> Tuple[bool, float]:
        """
        Ping a target host and return status and response time.
        
        Args:
            target: Hostname or IP address to ping.
            count: Number of ping packets to send.
            timeout: Timeout in seconds (uses default_timeout if None).
            
        Returns:
            Tuple[bool, float]: (success, average_response_time_ms)
            If ping fails, returns (False, 0.0)
        """
        if not timeout:
            timeout = self.default_timeout
            
        if not self.is_valid_ip(target) and not self.is_valid_hostname(target):
            logger.error(f"Invalid target for ping: {target}")
            return False, 0.0
        
        # Determine platform-specific ping command
        if os.name == 'nt':  # Windows
            ping_cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
        else:  # Unix/Linux/MacOS
            ping_cmd = ["ping", "-c", str(count), "-W", str(timeout), target]
        
        try:
            result = subprocess.run(
                ping_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                # Extract average time from ping output
                if os.name == 'nt':  # Windows format
                    match = re.search(r'Average = (\d+)ms', result.stdout)
                else:  # Unix format
                    match = re.search(r'min/avg/max/mdev = [\d.]+/([\d.]+)/', result.stdout)
                
                if match:
                    avg_time = float(match.group(1))
                    return True, avg_time
                return True, 0.0
            else:
                return False, 0.0
                
        except Exception as e:
            logger.error(f"Error pinging {target}: {e}")
            return False, 0.0
    
    def port_scan(self, target: str, ports: Union[List[int], range], 
                 timeout: Optional[float] = None, threads: int = 10) -> Dict[int, bool]:
        """
        Scan for open ports on a target host.
        
        Args:
            target: Hostname or IP address to scan.
            ports: List of ports or range to scan.
            timeout: Timeout in seconds (uses default_timeout if None).
            threads: Number of concurrent threads for scanning.
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status (True=open).
        """
        if not timeout:
            timeout = self.default_timeout / 2  # Shorter timeout for port scans
        
        # Resolve hostname to IP if needed
        ip = target
        if not self.is_valid_ip(target):
            ip = self.resolve_hostname(target)
            if not ip:
                logger.error(f"Could not resolve hostname for port scan: {target}")
                return {}
        
        def check_port(port: int) -> Tuple[int, bool]:
            """Check if a specific port is open."""
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((ip, port))
                is_open = (result == 0)
                if is_open:
                    logger.debug(f"Port {port} is open on {target}")
                return port, is_open
            except Exception as e:
                logger.debug(f"Error scanning port {port} on {target}: {e}")
                return port, False
            finally:
                sock.close()
        
        # Use ThreadPoolExecutor for concurrent scanning
        results = {}
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for port, is_open in executor.map(check_port, ports):
                results[port] = is_open
                
        return results
    
    def check_port(self, target: str, port: int, timeout: Optional[float] = None) -> bool:
        """
        Check if a specific port is open on a target host.
        
        Args:
            target: Hostname or IP address to check.
            port: Port number to check.
            timeout: Timeout in seconds (uses default_timeout if None).
            
        Returns:
            bool: True if port is open, False otherwise.
        """
        # Reuse the port_scan function for a single port
        result = self.port_scan(target, [port], timeout)
        return result.get(port, False)
    
    def get_http_request(self, url: str, params: Optional[Dict] = None, 
                        headers: Optional[Dict] = None, timeout: Optional[int] = None, 
                        verify_ssl: bool = True, allow_redirects: bool = True) -> Tuple[int, Dict, bytes]:
        """
        Make an HTTP GET request and return the response.
        
        Args:
            url: URL to request.
            params: Optional query parameters.
            headers: Optional HTTP headers.
            timeout: Request timeout in seconds (uses default_timeout if None).
            verify_ssl: Whether to verify SSL certificates.
            allow_redirects: Whether to follow redirects.
            
        Returns:
            Tuple[int, Dict, bytes]: (status_code, headers, content)
            If request fails, returns (0, {}, b'')
        """
        if not timeout:
            timeout = self.default_timeout
            
        # Set default headers if none provided
        if headers is None:
            headers = {"User-Agent": self.user_agent}
        elif "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
            
        # Get proxy settings from config if available
        proxies = None
        if self.config:
            proxy_settings = self.config.get("network.proxy", {})
            if proxy_settings:
                proxies = {
                    "http": proxy_settings.get("http"),
                    "https": proxy_settings.get("https")
                }
                # Filter out None values
                proxies = {k: v for k, v in proxies.items() if v}
                if not proxies:
                    proxies = None
        
        # Make the request with retries
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=allow_redirects,
                    proxies=proxies
                )
                return response.status_code, dict(response.headers), response.content
                
            except RequestException as e:
                logger.warning(f"HTTP request failed (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt == self.max_retries - 1:
                    logger.error(f"All HTTP request attempts failed for {url}: {e}")
                    return 0, {}, b''
                time.sleep(1)  # Wait before retrying
    
    def post_http_request(self, url: str, data: Optional[Dict] = None, 
                         json_data: Optional[Dict] = None, headers: Optional[Dict] = None,
                         timeout: Optional[int] = None, verify_ssl: bool = True) -> Tuple[int, Dict, bytes]:
        """
        Make an HTTP POST request and return the response.
        
        Args:
            url: URL to request.
            data: Optional form data.
            json_data: Optional JSON data (takes precedence over data if both provided).
            headers: Optional HTTP headers.
            timeout: Request timeout in seconds (uses default_timeout if None).
            verify_ssl: Whether to verify SSL certificates.
            
        Returns:
            Tuple[int, Dict, bytes]: (status_code, headers, content)
            If request fails, returns (0, {}, b'')
        """
        if not timeout:
            timeout = self.default_timeout
            
        # Set default headers if none provided
        if headers is None:
            headers = {"User-Agent": self.user_agent}
        elif "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
            
        # Set content type for JSON if not specified
        if json_data and headers and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
            
        # Get proxy settings from config if available
        proxies = None
        if self.config:
            proxy_settings = self.config.get("network.proxy", {})
            if proxy_settings:
                proxies = {
                    "http": proxy_settings.get("http"),
                    "https": proxy_settings.get("https")
                }
                # Filter out None values
                proxies = {k: v for k, v in proxies.items() if v}
                if not proxies:
                    proxies = None
        
        # Make the request with retries
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    url,
                    data=data,
                    json=json_data,
                    headers=headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies
                )
                return response.status_code, dict(response.headers), response.content
                
            except RequestException as e:
                logger.warning(f"HTTP POST request failed (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt == self.max_retries - 1:
                    logger.error(f"All HTTP POST request attempts failed for {url}: {e}")
                    return 0, {}, b''
                time.sleep(1)  # Wait before retrying
    
    def get_mac_address(self, interface: str = None) -> Optional[str]:
        """
        Get the MAC address of a network interface.
        
        Args:
            interface: Network interface name (uses default interface if None).
            
        Returns:
            str: MAC address or None if not found.
        """
        if not interface:
            # Try to determine default interface
            if os.name == 'nt':  # Windows
                # On Windows, this is more complex and might require additional libraries
                return None
            else:  # Unix-like
                try:
                    # Get default route interface
                    with open('/proc/net/route', 'r') as f:
                        for line in f.readlines()[1:]:
                            fields = line.strip().split()
                            if fields[1] == '00000000':  # Default route
                                interface = fields[0]
                                break
                except Exception as e:
                    logger.error(f"Could not determine default interface: {e}")
                    return None
        
        if not interface:
            return None
            
        try:
            if os.name == 'nt':  # Windows
                # Uses ipconfig, but parsing is complex
                # This is a simplified implementation
                output = subprocess.check_output('ipconfig /all', shell=True).decode('utf-8')
                for line in output.split('\n'):
                    if interface.lower() in line.lower() and 'Physical Address' in line:
                        mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', line, re.I)
                        if mac:
                            return mac.group(0)
            else:  # Unix-like
                output = subprocess.check_output(f'ifconfig {interface}', shell=True).decode('utf-8')
                mac = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', output, re.I)
                if mac:
                    return mac.group(0)
        except Exception as e:
            logger.error(f"Error getting MAC address for interface {interface}: {e}")
            
        return None
    
    def traceroute(self, target: str, max_hops: int = 30, timeout: Optional[int] = None) -> List[Dict[str, Union[int, str, float]]]:
        """
        Perform a traceroute to a target host.
        
        Args:
            target: Hostname or IP address to trace.
            max_hops: Maximum number of hops to trace.
            timeout: Timeout per hop in seconds (uses default_timeout if None).
            
        Returns:
            List[Dict]: List of hops with hop number, IP, hostname (if resolved), and response time.
            Each dict has keys: 'hop', 'ip', 'hostname', 'time_ms'
        """
        if not timeout:
            timeout = self.default_timeout
            
        result = []
        
        # Resolve hostname to IP if needed
        if not self.is_valid_ip(target):
            ip = self.resolve_hostname(target)
            if not ip:
                logger.error(f"Could not resolve hostname for traceroute: {target}")
                return result
            target = ip
        
        # Different command parameters based on OS
        if os.name == 'nt':  # Windows
            cmd = ["tracert", "-d", "-w", str(timeout * 1000), "-h", str(max_hops), target]
        else:  # Unix-like
            cmd = ["traceroute", "-n", "-w", str(timeout), "-m", str(max_hops), target]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Skip header lines
            for i in range(1 if os.name == 'nt' else 2):
                process.stdout.readline()
            
            for i in range(max_hops):
                line = process.stdout.readline()
                if not line:
                    break
                
                # Extract hop info from the line
                if os.name == 'nt':  # Windows format
                    match = re.search(r'^\s*(\d+)\s+(\d+|\*)\s+ms\s+(\d+|\*)\s+ms\s+(\d+|\*)\s+ms\s+(.+)$', line)
                    if match:
                        hop_num = int(match.group(1))
                        times = [float(t) if t != '*' else None for t in [match.group(2), match.group(3), match.group(4)]]
                        times = [t for t in times if t is not None]
                        avg_time = sum(times) / len(times) if times else None
                        ip = match.group(5).strip()
                else:  # Unix format
                    parts = line.split()
                    if len(parts) >= 4:
                        hop_num = int(parts[0])
                        ip = parts[1] if parts[1] != '*' else None
                        times = []
                        for i in range(2, min(5, len(parts))):
                            try:
                                time_val = float(parts[i].replace('ms', ''))
                                times.append(time_val)
                            except (ValueError, IndexError):
                                pass
                        avg_time = sum(times) / len(times) if times else None
                
                if ip and ip != '*':
                    # Try reverse DNS lookup for the hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror):
                        hostname = None
                    
                    result.append({
                        'hop': hop_num,
                        'ip': ip,
                        'hostname': hostname,
                        'time_ms': avg_time
                    })
                else:
                    result.append({
                        'hop': hop_num,
                        'ip': None,
                        'hostname': None,
                        'time_ms': None
                    })
                
                # If we've reached the target, stop
                if ip == target:
                    break
                
            process.terminate()
            return result
            
        except Exception as e:
            logger.error(f"Error performing traceroute to {target}: {e}")
            return result
            
    def whois_lookup(self, domain: str) -> Dict[str, str]:
        """
        Perform a WHOIS lookup for a domain name.
        
        Args:
            domain: Domain name to lookup.
            
        Returns:
            Dict[str, str]: Dictionary of WHOIS information.
        """
        try:
            # Check if whois command is available
            if os.name == 'nt':  # Windows
                whois_cmd = ["whois", domain]
            else:  # Unix-like
                whois_cmd = ["whois", domain]
            
            result = subprocess.run(
                whois_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                logger.error(f"WHOIS lookup failed for {domain}: {result.stderr}")
                return {}
            
            # Parse the WHOIS output - simplified parsing
            whois_info = {}
            current_key = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('%') or line.startswith('#'):
                    continue
                    
                if ':' in line:
                    parts = line.split(':', 1)
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    
                    # Common WHOIS fields to capture
                    if key in ['domain name', 'registrar', 'whois server', 
                              'name server', 'updated date', 'creation date', 
                              'expiration date', 'registrant name', 'registrant organization']:
                        whois_info[key] = value
                        current_key = key
                elif current_key:
                    # Continuation of previous field
                    whois_info[current_key] += f" {line}"
            
            return whois_info
                
        except Exception as e:
            logger.error(f"Error in WHOIS lookup for {domain}: {e}")
            return {}
                
    def ip_to_int(self, ip_address: str) -> int:
        """
        Convert an IP address to an integer.
        
        Args:
            ip_address: IP address as a string.
            
        Returns:
            int: Numeric representation of the IP address.
        """
        try:
            return struct.unpack("!I", socket.inet_aton(ip_address))[0]
        except Exception as e:
            logger.error(f"Error converting IP {ip_address} to integer: {e}")
            return 0
    
    def int_to_ip(self, ip_int: int) -> str:
        """
        Convert an integer to an IP address.
        
        Args:
            ip_int: Integer representation of an IP address.
            
        Returns:
            str: IP address as a string.
        """
        try:
            return socket.inet_ntoa(struct.pack("!I", ip_int))
        except Exception as e:
            logger.error(f"Error converting integer {ip_int} to IP: {e}")
            return ""
    
    def get_random_user_agent(self) -> str:
        """
        Get a random user agent string from a predefined list.
        
        Returns:
            str: Random user agent string.
        """
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
        ]
        return random.choice(user_agents)
    
    def cidr_to_ip_range(self, cidr: str) -> List[str]:
        """
        Convert a CIDR notation string to a list of IP addresses.
        
        Args:
            cidr: CIDR notation string (e.g., '192.168.1.0/24').
            
        Returns:
            List[str]: List of IP addresses in the range.
        """
        try:
            ip_network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in ip_network.hosts()]
        except Exception as e:
            logger.error(f"Error converting CIDR {cidr} to IP range: {e}")
            return []
    
    def is_port_open(self, target: str, port: int, timeout: Optional[float] = None) -> bool:
        """
        Alias for check_port for backward compatibility.
        """
        return self.check_port(target, port, timeout)
            
# Create a default instance for easy import
network_utils = NetworkUtils()
