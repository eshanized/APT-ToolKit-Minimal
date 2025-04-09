import os
import time
import json
import socket
import ipaddress
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import networkx as nx  # For network graph representation
import nmap  # For network scanning
import shutil  # For checking sudo availability

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils
from src.modules.recon import ReconModule, HostInfo, ReconResult

logger = get_module_logger("network_mapper")

@dataclass
class NetworkNode:
    """Data class for a node in the network"""
    ip_address: str
    hostname: str = ""
    node_type: str = "host"  # host, router, firewall, switch, etc.
    os_info: str = ""
    vendor: str = ""
    mac_address: str = ""
    status: str = "unknown"  # up, down, unknown
    coordinates: Tuple[float, float] = field(default_factory=lambda: (0.0, 0.0))  # For visualization
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    nmap_data: Dict[str, Any] = field(default_factory=dict)  # To store nmap scan results

@dataclass
class NetworkLink:
    """Data class for a link between network nodes"""
    source: str  # Source IP address
    target: str  # Target IP address
    latency: float = 0.0  # in milliseconds
    packet_loss: float = 0.0  # percentage
    link_type: str = "unknown"  # ethernet, wifi, vpn, etc.
    bandwidth: float = 0.0  # in Mbps
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NetworkMapResult:
    """Data class for network mapping results"""
    target_network: str
    scan_time: float = field(default_factory=time.time)
    nodes: List[NetworkNode] = field(default_factory=list)
    links: List[NetworkLink] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
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
            logger.info(f"Saved network map results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save network map to {filename}: {e}")
            return False

    def to_graph(self) -> nx.Graph:
        """Convert the network map to a NetworkX graph for analysis"""
        G = nx.Graph()
        
        # Add nodes with attributes
        for node in self.nodes:
            G.add_node(
                node.ip_address,
                hostname=node.hostname,
                node_type=node.node_type,
                os_info=node.os_info,
                vendor=node.vendor,
                status=node.status,
                mac_address=node.mac_address,
                coordinates=node.coordinates,
                last_seen=node.last_seen,
                metadata=node.metadata
            )
        
        # Add edges with attributes
        for link in self.links:
            G.add_edge(
                link.source,
                link.target,
                latency=link.latency,
                packet_loss=link.packet_loss,
                link_type=link.link_type,
                bandwidth=link.bandwidth,
                metadata=link.metadata
            )
        
        return G


class NetworkMapper:
    """
    Network mapping module for discovering network topology.
    Builds on reconnaissance capabilities to map out network structure.
    """
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the network mapper.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Initialize network utilities
        if config:
            self.network = NetworkUtils(config)
        else:
            self.network = network_utils
        
        # Initialize the recon module for basic host discovery
        self.recon = ReconModule(config)
        
        # Initialize nmap scanner
        self.nmap_scanner = nmap.PortScanner()
        
        # Load configuration settings
        self.timeout = 5
        self.max_threads = 20
        self.max_hops = 30
        self.ping_sweep = True
        self.node_discovery = True
        self.topology_detection = True
        self.detail_level = "medium"  # low, medium, high
        
        if config:
            self.timeout = config.get("modules.network_mapper.timeout", 5)
            self.max_threads = config.get("modules.network_mapper.max_threads", 20)
            self.max_hops = config.get("modules.network_mapper.max_hops", 30)
            self.ping_sweep = config.get("modules.network_mapper.ping_sweep", True)
            self.node_discovery = config.get("modules.network_mapper.node_discovery", True)
            self.topology_detection = config.get("modules.network_mapper.topology_detection", True)
            self.detail_level = config.get("modules.network_mapper.detail_level", "medium")
        
        # Initialize callback functions
        self._progress_callback = None
        self._log_callback = None
    
    def map_network(self, target: str, **kwargs) -> NetworkMapResult:
        """
        Map a network to discover topology and hosts.
        
        Args:
            target: Network to map (IP, CIDR, hostname)
            **kwargs: Optional scan parameters:
                - max_hops: Maximum hop count for traceroute
                - timeout: Scan timeout in seconds
                - max_threads: Maximum number of concurrent threads
                - ping_sweep: Whether to perform ping sweep (default: True)
                - ports: List of ports to check during host discovery
                - node_discovery: Whether to perform node discovery (default: True)
                - topology_detection: Whether to detect network topology (default: True)
                - detail_level: Scan detail level (low, medium, high)
                - use_nmap: Whether to use nmap for scanning (default: True)
                
        Returns:
            NetworkMapResult: Network mapping results
        """
        start_time = time.time()
        
        # Parse scan parameters
        max_hops = kwargs.get("max_hops", self.max_hops)
        timeout = kwargs.get("timeout", self.timeout)
        max_threads = kwargs.get("max_threads", self.max_threads)
        ping_sweep = kwargs.get("ping_sweep", self.ping_sweep)
        ports = kwargs.get("ports", [22, 80, 443, 3389])  # Default important ports
        node_discovery = kwargs.get("node_discovery", self.node_discovery)
        topology_detection = kwargs.get("topology_detection", self.topology_detection)
        detail_level = kwargs.get("detail_level", self.detail_level)
        use_nmap = kwargs.get("use_nmap", True)  # Default to using nmap
        
        # Initialize result object
        result = NetworkMapResult(target_network=target)
        
        # Expand target to network range if it's a CIDR or subnet
        target_type = self._identify_target_type(target)
        if target_type == "IP":
            # Single IP - convert to /32 CIDR
            target_network = f"{target}/32"
            # Also try to detect the actual network this IP belongs to
            actual_network = self._detect_network_from_ip(target)
            if actual_network:
                target_network = actual_network
                result.notes.append(f"Expanded single IP to detected network: {actual_network}")
        elif target_type == "CIDR":
            # Already a network range
            target_network = target
        elif target_type == "DOMAIN":
            # Resolve domain to IP and convert to /32 CIDR
            ip = self.network.resolve_hostname(target)
            if ip:
                target_network = f"{ip}/32"
                # Try to detect the actual network this IP belongs to
                actual_network = self._detect_network_from_ip(ip)
                if actual_network:
                    target_network = actual_network
                    result.notes.append(f"Expanded domain {target} to detected network: {actual_network}")
            else:
                result.notes.append(f"Failed to resolve domain {target}")
                return result
        else:
            result.notes.append(f"Unknown target type: {target}")
            return result
        
        # Store the target network in the result
        result.target_network = target_network
        
        # Add the target network to the subnets list
        result.subnets.append(target_network)
        
        # Generate the list of IPs in the target network
        ip_list = self.network.cidr_to_ip_range(target_network)
        logger.info(f"Starting network mapping of {target_network} ({len(ip_list)} hosts)")
        
        # Log scanning information
        if self._log_callback:
            self._log_callback(f"Starting network mapping of {target_network} ({len(ip_list)} hosts)")
        
        # Phase 1: Host discovery with ping sweep or nmap scan
        if use_nmap:
            if self._log_callback:
                self._log_callback(f"[*] Starting Nmap scan on {target_network}")
            
            # Run nmap scan
            hosts_data = self._run_nmap_scan(target_network, detail_level, kwargs.get("nmap_options", {}))
            
            # Process nmap data into nodes
            network_nodes = {}
            for host_ip, host_data in hosts_data.items():
                # Check if we already have a node for this IP
                if host_ip in network_nodes:
                    node = network_nodes[host_ip]
                else:
                    # Create a new node
                    node = NetworkNode(ip_address=host_ip)
                    network_nodes[host_ip] = node
                
                # Update with nmap data
                if 'hostnames' in host_data and host_data['hostnames']:
                    for entry in host_data['hostnames']:
                        if entry.get('name'):
                            node.hostname = entry.get('name')
                            break
                
                # Extract OS information
                if 'osmatch' in host_data and host_data['osmatch']:
                    # Sort by accuracy and take the top match
                    os_matches = sorted(host_data['osmatch'], key=lambda x: int(x.get('accuracy', 0)), reverse=True)
                    if os_matches:
                        node.os_info = os_matches[0].get('name', 'Unknown')
                
                # Extract open ports and services
                ports_info = []
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data.get('state') == 'open':
                            # Add to ports info for debugging
                            service = port_data.get('name', 'unknown')
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            service_str = service
                            if product:
                                service_str += f" ({product}"
                                if version:
                                    service_str += f" {version}"
                                service_str += ")"
                            
                            ports_info.append(f"{port}/tcp: {service_str}")
                
                # Store the full nmap data in the node
                node.nmap_data = host_data
                
                # Log found services for debugging
                if self._log_callback and ports_info:
                    self._log_callback(f"[*] Host {host_ip} has open ports: {', '.join(ports_info)}")
                
                # Update node type based on services
                node.node_type = self._determine_node_type_from_nmap(host_data)
                
                # Add the node to the result
                result.nodes.append(node)
                
                # Report progress
                if self._progress_callback:
                    current_host_index = len(result.nodes)
                    max_hosts = len(ip_list)
                    message = f"Processed {current_host_index}/{max_hosts} hosts"
                    if not self._progress_callback(current_host_index, max_hosts, message):
                        # User requested stop
                        logger.info("Network mapping was stopped by user request")
                        result.notes.append("Network mapping was stopped by user request")
                        break
                
                if self._log_callback:
                    self._log_callback(f"[+] Discovered host {host_ip}")
                    if node.hostname:
                        self._log_callback(f"    - Hostname: {node.hostname}")
                    if node.os_info:
                        self._log_callback(f"    - OS: {node.os_info}")
                    if node.mac_address:
                        self._log_callback(f"    - MAC: {node.mac_address}")
                    if node.vendor:
                        self._log_callback(f"    - Vendor: {node.vendor}")
                    
                    # Show open ports
                    if ports_info:
                        self._log_callback(f"    - Open TCP ports:")
                        for port_info in ports_info:
                            self._log_callback(f"      {port_info}")
        elif ping_sweep:
            # Use the original ping sweep method
            if self._log_callback:
                self._log_callback(f"[*] Starting ping sweep on {len(ip_list)} hosts")
            
            hosts = self._ping_sweep(ip_list, max_threads, timeout)
            # Convert hosts to network nodes
            for host_ip, is_up in hosts.items():
                node = NetworkNode(
                    ip_address=host_ip,
                    status="up" if is_up else "down"
                )
                
                if is_up:
                    # Try to get hostname
                    hostname = self.network.reverse_dns_lookup(host_ip)
                    if hostname:
                        node.hostname = hostname
                    
                    # Try to get MAC address for local hosts
                    if self._is_private_ip(host_ip):
                        mac = self.network.get_mac_address()
                        if mac:
                            node.mac_address = mac
                            # Try to determine vendor from MAC
                            node.vendor = self._get_vendor_from_mac(mac)
                
                result.nodes.append(node)
        
        # Phase 2: More detailed node discovery
        if node_discovery:
            # Use the recon module for more detailed host information
            if detail_level in ("medium", "high"):
                # Convert list of IPs to a subset for detailed scanning
                # For medium detail, scan up to 100 hosts; for high detail, scan up to 255
                max_hosts = 255 if detail_level == "high" else 100
                if len(ip_list) > max_hosts:
                    logger.info(f"Limiting detailed node discovery to {max_hosts} hosts due to {detail_level} detail level")
                    # Prioritize hosts that responded to ping
                    up_hosts = [node.ip_address for node in result.nodes if node.status == "up"]
                    if len(up_hosts) < max_hosts:
                        # Add more hosts until we reach the limit
                        remaining = max_hosts - len(up_hosts)
                        down_hosts = [node.ip_address for node in result.nodes if node.status == "down"]
                        scan_ips = up_hosts + down_hosts[:remaining]
                    else:
                        scan_ips = up_hosts[:max_hosts]
                else:
                    scan_ips = ip_list
                
                # Perform detailed host scanning
                logger.info(f"Starting detailed node discovery for {len(scan_ips)} hosts")
                recon_results = self._scan_hosts(scan_ips, ports, max_threads, timeout)
                
                # Update nodes with detailed information
                for host_info in recon_results.hosts:
                    # Find the corresponding node
                    matching_nodes = [node for node in result.nodes if node.ip_address == host_info.ip_address]
                    
                    if matching_nodes:
                        # Update existing node
                        node = matching_nodes[0]
                        node.hostname = host_info.hostname or node.hostname
                        node.status = host_info.status
                        node.mac_address = host_info.mac_address or node.mac_address
                        node.os_info = host_info.os_info
                        
                        # Determine node type based on open ports
                        node.node_type = self._determine_node_type(host_info)
                    else:
                        # Create a new node
                        node = NetworkNode(
                            ip_address=host_info.ip_address,
                            hostname=host_info.hostname,
                            status=host_info.status,
                            mac_address=host_info.mac_address,
                            os_info=host_info.os_info,
                            node_type=self._determine_node_type(host_info)
                        )
                        result.nodes.append(node)
            
        # Phase 3: Topology detection with traceroutes
        if topology_detection:
            logger.info("Starting network topology detection")
            
            # Get up nodes for traceroute targets
            up_nodes = [node for node in result.nodes if node.status == "up"]
            
            # If no nodes are up, use the original target
            if not up_nodes:
                traceroute_targets = [target] if target_type in ("IP", "DOMAIN") else []
            else:
                # Select a subset of nodes for traceroute targets
                # For low detail, use up to 5 nodes; for medium, up to 10; for high, up to 20
                max_targets = 5 if detail_level == "low" else (10 if detail_level == "medium" else 20)
                traceroute_targets = [node.ip_address for node in up_nodes[:max_targets]]
            
            # Perform traceroutes to discover network topology
            if traceroute_targets:
                logger.info(f"Performing traceroutes to {len(traceroute_targets)} targets")
                router_nodes, network_links = self._discover_topology(traceroute_targets, max_hops, timeout)
                
                # Add router nodes to the result
                for router_ip, router_data in router_nodes.items():
                    # Check if this router is already in our nodes
                    existing_nodes = [node for node in result.nodes if node.ip_address == router_ip]
                    
                    if existing_nodes:
                        # Update existing node
                        existing_nodes[0].node_type = "router"
                    else:
                        # Create a new router node
                        router_node = NetworkNode(
                            ip_address=router_ip,
                            hostname=router_data.get("hostname", ""),
                            node_type="router",
                            status="up"
                        )
                        result.nodes.append(router_node)
                
                # Add network links to the result
                for link in network_links:
                    result.links.append(link)
                
                # Try to identify subnets from the traceroute data
                discovered_subnets = self._identify_subnets(result.nodes, network_links)
                for subnet in discovered_subnets:
                    if subnet not in result.subnets:
                        result.subnets.append(subnet)
        
        # Phase 4: Analysis and layout calculation
        # Calculate node coordinates for visualization
        if len(result.nodes) > 0:
            self._calculate_node_positions(result)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        result.notes.append(f"Network mapping completed in {scan_duration:.2f} seconds")
        logger.info(f"Network mapping of {target_network} completed in {scan_duration:.2f} seconds")
        
        return result
    
    def _identify_target_type(self, target: str) -> str:
        """Identify the type of target (reusing from ReconModule)"""
        return self.recon._identify_target_type(target)
    
    def _detect_network_from_ip(self, ip: str) -> Optional[str]:
        """
        Try to detect the actual network an IP belongs to.
        
        Args:
            ip: IP address to analyze
            
        Returns:
            str: CIDR notation of detected network, or None if detection failed
        """
        try:
            # For private IPs, try to determine local network
            if self._is_private_ip(ip):
                # Try common private subnets
                if ip.startswith("192.168."):
                    # Typical home/small office network
                    return f"192.168.{ip.split('.')[2]}.0/24"
                elif ip.startswith("10."):
                    # Enterprise network, assume /24 subnet
                    parts = ip.split('.')
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                elif ip.startswith("172."):
                    second = int(ip.split('.')[1])
                    if 16 <= second <= 31:
                        # Medium business network, assume /24 subnet
                        parts = ip.split('.')
                        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            
            # For non-private IPs, just use /32 (single host)
            return f"{ip}/32"
            
        except Exception as e:
            logger.debug(f"Error detecting network from IP {ip}: {e}")
            return None
    
    def _ping_sweep(self, ip_list: List[str], max_threads: int, timeout: float) -> Dict[str, bool]:
        """
        Perform a ping sweep on a list of IP addresses.
        
        Args:
            ip_list: List of IP addresses to ping
            max_threads: Maximum number of concurrent threads
            timeout: Ping timeout in seconds
            
        Returns:
            Dict[str, bool]: Dictionary mapping IP addresses to ping status
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit ping tasks
            future_to_ip = {
                executor.submit(self.network.ping, ip, 1, timeout): ip
                for ip in ip_list
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_up, _ = future.result()
                    results[ip] = is_up
                    if is_up:
                        logger.debug(f"Host {ip} is up")
                except Exception as e:
                    logger.debug(f"Error pinging {ip}: {e}")
                    results[ip] = False
        
        return results
    
    def _scan_hosts(self, ip_list: List[str], ports: List[int], max_threads: int, timeout: float) -> ReconResult:
        """
        Perform detailed scanning of hosts using the ReconModule.
        
        Args:
            ip_list: List of IP addresses to scan
            ports: List of ports to scan
            max_threads: Maximum number of concurrent threads
            timeout: Scan timeout in seconds
            
        Returns:
            ReconResult: Reconnaissance results
        """
        # Create a CIDR that encompasses all IPs (this is just a convenience for the ReconModule)
        target = f"{ip_list[0]}/24"  # Approximate - the ReconModule will scan the individual IPs
        
        # Use the ReconModule for detailed host scanning
        result = self.recon.scan(
            target,
            ports=ports,
            timeout=timeout,
            max_threads=max_threads,
            ping=True,
            whois=False,  # Skip WHOIS for network mapping
            dns_enum=False,  # Skip DNS enumeration for network mapping
            subdomain_enum=False,  # Skip subdomain enumeration for network mapping
            traceroute=False,  # We'll do traceroutes separately
            port_scan=True,
            aggressive=False
        )
        
        return result
    
    def _determine_node_type(self, host_info: HostInfo) -> str:
        """
        Determine the type of network node based on open ports and other characteristics.
        
        Args:
            host_info: Host information
            
        Returns:
            str: Node type (server, workstation, router, firewall, etc.)
        """
        # Extract service information from open ports
        services = {port_info.service for port_info in host_info.open_ports}
        ports = {port_info.port for port_info in host_info.open_ports}
        
        # Check for router/networking device indicators
        if 161 in ports or 123 in ports or 22 in ports:  # SNMP, NTP, SSH
            if any(p in ports for p in [80, 443, 8080, 8443]):  # Web interface
                return "router"
        
        # Check for firewall indicators
        if 443 in ports and len(ports) < 5:
            if all(p in [22, 80, 443, 8080, 8443] for p in ports):
                return "firewall"
        
        # Check for server indicators
        server_services = {
            "http", "https", "ftp", "ssh", "smtp", "dns", "ldap",
            "mysql", "ms-sql-s", "postgresql", "oracle", "vnc"
        }
        if len(services & server_services) >= 2:
            return "server"
        
        # Check for common workstation ports
        if 3389 in ports or 445 in ports:  # RDP or SMB
            return "workstation"
        
        # Default to host if we can't determine
        return "host"
    
    def _discover_topology(self, targets: List[str], max_hops: int, timeout: float) -> Tuple[Dict[str, Dict], List[NetworkLink]]:
        """
        Discover network topology using traceroutes.
        
        Args:
            targets: List of target IP addresses for traceroutes
            max_hops: Maximum number of hops for traceroute
            timeout: Timeout for each hop in seconds
            
        Returns:
            Tuple[Dict[str, Dict], List[NetworkLink]]: Router nodes and network links
        """
        router_nodes = {}
        network_links = []
        
        for target in targets:
            try:
                logger.debug(f"Performing traceroute to {target}")
                
                # Perform traceroute
                trace_result = self.network.traceroute(target, max_hops, timeout)
                
                # Process traceroute results
                prev_hop_ip = None
                
                for hop in trace_result:
                    hop_ip = hop.get('ip')
                    
                    if not hop_ip or hop_ip == "*":
                        # Skip hops with no IP (could be filtered/blocked)
                        continue
                    
                    # Record the router node if not already known
                    if hop_ip not in router_nodes:
                        router_nodes[hop_ip] = {
                            "hostname": hop.get('hostname', ''),
                            "hops": []
                        }
                    
                    # Record this hop in the router's data
                    router_nodes[hop_ip]["hops"].append({
                        "target": target,
                        "hop_num": hop.get('hop'),
                        "time_ms": hop.get('time_ms')
                    })
                    
                    # Create a link between this hop and the previous one
                    if prev_hop_ip:
                        # Check if this link already exists
                        link_exists = any(
                            (link.source == prev_hop_ip and link.target == hop_ip) or
                            (link.source == hop_ip and link.target == prev_hop_ip)
                            for link in network_links
                        )
                        
                        if not link_exists:
                            network_links.append(NetworkLink(
                                source=prev_hop_ip,
                                target=hop_ip,
                                latency=hop.get('time_ms', 0.0),
                                link_type="traceroute"
                            ))
                    
                    # Update previous hop for the next iteration
                    prev_hop_ip = hop_ip
                
                # Create a link to the final target if not already a router
                if prev_hop_ip and target not in router_nodes:
                    # Check if this link already exists
                    link_exists = any(
                        (link.source == prev_hop_ip and link.target == target) or
                        (link.source == target and link.target == prev_hop_ip)
                        for link in network_links
                    )
                    
                    if not link_exists:
                        network_links.append(NetworkLink(
                            source=prev_hop_ip,
                            target=target,
                            link_type="endpoint"
                        ))
                
            except Exception as e:
                logger.error(f"Error performing traceroute to {target}: {e}")
        
        return router_nodes, network_links
    
    def _identify_subnets(self, nodes: List[NetworkNode], links: List[NetworkLink]) -> List[str]:
        """
        Identify potential subnets based on node IP addresses and network links.
        
        Args:
            nodes: List of network nodes
            links: List of network links
            
        Returns:
            List[str]: List of identified subnets in CIDR notation
        """
        subnets = set()
        
        # Group nodes by first 3 octets of IP address
        ip_groups = defaultdict(list)
        for node in nodes:
            # Skip non-private IPs
            if not self._is_private_ip(node.ip_address):
                continue
                
            # Group by the first 3 octets (potential /24 subnet)
            octets = node.ip_address.split('.')
            if len(octets) == 4:
                subnet_key = f"{octets[0]}.{octets[1]}.{octets[2]}"
                ip_groups[subnet_key].append(node)
        
        # Create subnets for groups with multiple hosts
        for subnet_key, subnet_nodes in ip_groups.items():
            if len(subnet_nodes) > 1:
                subnets.add(f"{subnet_key}.0/24")
        
        # Add potential gateway-based subnets from router links
        for link in links:
            if self._is_private_ip(link.source) and self._is_private_ip(link.target):
                # Check if one end might be a router/gateway
                for ip in [link.source, link.target]:
                    octets = ip.split('.')
                    if len(octets) == 4 and octets[3] in ["1", "254"]:  # Common gateway IPs
                        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                        subnets.add(subnet)
        
        return list(subnets)
    
    def _calculate_node_positions(self, result: NetworkMapResult) -> None:
        """
        Calculate positions for nodes in the network map for visualization.
        
        Args:
            result: Network mapping result to update with node positions
        """
        # Convert to NetworkX graph for layout algorithms
        G = result.to_graph()
        
        if len(G.nodes) == 0:
            return
        
        try:
            # Use spring layout for natural network topology representation
            pos = nx.spring_layout(G)
            
            # Update node coordinates
            for node in result.nodes:
                if node.ip_address in pos:
                    x, y = pos[node.ip_address]
                    node.coordinates = (float(x), float(y))
                    
        except Exception as e:
            logger.error(f"Error calculating node positions: {e}")
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if an IP address is private (reusing from ReconModule)"""
        return self.recon._is_private_ip(ip_address)
        
    def _get_vendor_from_mac(self, mac_address: str) -> str:
        """
        Try to determine the hardware vendor from a MAC address.
        
        Args:
            mac_address: MAC address to lookup
            
        Returns:
            str: Vendor name or empty string if unknown
        """
        # This would normally use a MAC address vendor database
        # For simplicity, we'll return an empty string
        # In a real implementation, you would use a library like manuf or a MAC vendor API
        return ""

    def _run_nmap_scan(self, target: str, detail_level: str = "medium", scan_options: Dict = None) -> Dict[str, Dict]:
        """
        Run an nmap scan on the target network.
        
        Args:
            target: Target to scan (IP, CIDR, hostname)
            detail_level: Scan detail level (low, medium, high)
            scan_options: Dictionary containing advanced nmap scan options
            
        Returns:
            Dict[str, Dict]: Dictionary mapping IP addresses to nmap scan results
        """
        if self._log_callback:
            self._log_callback(f"[*] Running nmap scan on {target} with {detail_level} detail level")
        
        # Import OS module with alias to avoid any shadowing
        import os as os_module
        # Check if we're running as root
        is_root = os_module.geteuid() == 0 if hasattr(os_module, 'geteuid') else False
        
        # Base arguments depending on detail level
        if detail_level == "low":
            # Fast scan with ping discovery - compatible with non-root
            args = "-sT --top-ports 100"  # Connect scan which doesn't require root
        elif detail_level == "medium":
            # Default scan for most common ports with service detection
            args = "-sT -sV --top-ports 100"  # Connect scan with service detection
        else:  # high
            # Comprehensive scan
            args = "-sT -sV -A --top-ports 1000"  # Connect scan with service detection and script scanning
        
        # If scan options are provided, build custom arguments
        if scan_options:
            # Reset args as we'll build them from scratch
            args = ""
            selected_scan_types = []
            
            # Scan types - avoid privileged scans if not root
            # 1. TCP SYN Scan (requires root)
            if scan_options.get("tcp_syn_scan"):
                if is_root:
                    selected_scan_types.append("-sS")
                    if self._log_callback:
                        self._log_callback(f"[*] Using TCP SYN scan (-sS)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] SYN scan requires root privileges, using TCP Connect scan instead.")
                    selected_scan_types.append("-sT")
            
            # 2. TCP Connect Scan (doesn't require root)
            if scan_options.get("tcp_connect_scan"):
                selected_scan_types.append("-sT")
                if self._log_callback:
                    self._log_callback(f"[*] Using TCP Connect scan (-sT)")
            
            # 3. UDP Scan (requires root)
            if scan_options.get("udp_scan"):
                if is_root:
                    selected_scan_types.append("-sU")
                    if self._log_callback:
                        self._log_callback(f"[*] Using UDP scan (-sU)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] UDP scan requires root privileges, skipping.")
            
            # 4. Ping Scan
            if scan_options.get("ping_scan"):
                selected_scan_types.append("-sn")
                if self._log_callback:
                    self._log_callback(f"[*] Using Ping scan (-sn)")
            
            # 5. FIN Scan (requires root)
            if scan_options.get("fin_scan"):
                if is_root:
                    selected_scan_types.append("-sF")
                    if self._log_callback:
                        self._log_callback(f"[*] Using FIN scan (-sF)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] FIN scan requires root privileges, skipping.")
            
            # 6. NULL Scan (requires root)
            if scan_options.get("null_scan"):
                if is_root:
                    selected_scan_types.append("-sN")
                    if self._log_callback:
                        self._log_callback(f"[*] Using NULL scan (-sN)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] NULL scan requires root privileges, skipping.")
            
            # 7. XMAS Scan (requires root)
            if scan_options.get("xmas_scan"):
                if is_root:
                    selected_scan_types.append("-sX")
                    if self._log_callback:
                        self._log_callback(f"[*] Using XMAS scan (-sX)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] XMAS scan requires root privileges, skipping.")
            
            # 8. IDLE Scan (requires root)
            if scan_options.get("idle_scan") and scan_options.get("idle_zombie"):
                if is_root:
                    zombie = self._validate_ip(scan_options.get('idle_zombie', ''))
                    if zombie:
                        selected_scan_types.append(f"-sI {zombie}")
                        if self._log_callback:
                            self._log_callback(f"[*] Using IDLE scan (-sI) with zombie {zombie}")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] IDLE scan requires root privileges, skipping.")
            
            # 9. IP Protocol Scan (requires root)
            if scan_options.get("ip_protocol_scan"):
                if is_root:
                    selected_scan_types.append("-sO")
                    if self._log_callback:
                        self._log_callback(f"[*] Using IP Protocol scan (-sO)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] IP Protocol scan requires root privileges, skipping.")
            
            # If no scan type was selected, add TCP Connect scan as default
            if not selected_scan_types:
                selected_scan_types.append("-sT")
                if self._log_callback:
                    self._log_callback(f"[*] No valid scan types selected, using default TCP Connect scan (-sT)")
            
            # Add the selected scan types to arguments
            args += " ".join(selected_scan_types)
            
            # Discovery options
            discovery_options = []
            
            if scan_options.get("disable_ping"):
                discovery_options.append("-Pn")
                if self._log_callback:
                    self._log_callback(f"[*] Disabling ping (-Pn)")
            
            if scan_options.get("tcp_syn_ping"):
                discovery_options.append("-PS")
                if self._log_callback:
                    self._log_callback(f"[*] Using TCP SYN ping (-PS)")
            
            if scan_options.get("tcp_ack_ping"):
                if is_root:
                    discovery_options.append("-PA")
                    if self._log_callback:
                        self._log_callback(f"[*] Using TCP ACK ping (-PA)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] TCP ACK ping requires root privileges, skipping.")
            
            if scan_options.get("udp_ping"):
                if is_root:
                    discovery_options.append("-PU")
                    if self._log_callback:
                        self._log_callback(f"[*] Using UDP ping (-PU)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] UDP ping requires root privileges, skipping.")
            
            if scan_options.get("sctp_ping"):
                if is_root:
                    discovery_options.append("-PY")
                    if self._log_callback:
                        self._log_callback(f"[*] Using SCTP ping (-PY)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] SCTP ping requires root privileges, skipping.")
            
            if scan_options.get("icmp_echo_ping"):
                if is_root:
                    discovery_options.append("-PE")
                    if self._log_callback:
                        self._log_callback(f"[*] Using ICMP echo ping (-PE)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] ICMP echo ping requires root privileges, skipping.")
            
            # Add discovery options to arguments
            if discovery_options:
                args += " " + " ".join(discovery_options)
            
            # Advanced options
            port_range = self._validate_port_range(scan_options.get('port_range', ''))
            if port_range:
                args += f" -p {port_range}"
                if self._log_callback:
                    self._log_callback(f"[*] Using port range: {port_range}")
            
            # Timing template
            timing_idx = scan_options.get("timing_template")
            if timing_idx is not None:
                if 0 <= timing_idx <= 5:
                    args += f" -T{timing_idx}"
                    if self._log_callback:
                        self._log_callback(f"[*] Using timing template: T{timing_idx}")
            
            # Script scan
            if scan_options.get("script_scan"):
                if scan_options.get("script_args"):
                    script_args = self._validate_script_args(scan_options.get('script_args', ''))
                    if script_args:
                        args += f" --script={script_args}"
                        if self._log_callback:
                            self._log_callback(f"[*] Running scripts: {script_args}")
                else:
                    args += " -sC"  # Default scripts
                    if self._log_callback:
                        self._log_callback(f"[*] Using default scripts (-sC)")
            
            # Version detection
            if scan_options.get("version_detection"):
                args += " -sV"
                if self._log_callback:
                    self._log_callback(f"[*] Enabling version detection (-sV)")
                
                if scan_options.get("version_intensity") is not None:
                    intensity = scan_options.get("version_intensity")
                    if 0 <= intensity <= 9:
                        args += f" --version-intensity {intensity}"
                        if self._log_callback:
                            self._log_callback(f"[*] Using version intensity: {intensity}")
            
            # OS Detection if requested
            if scan_options.get("os_detection"):
                if is_root:
                    args += " -O"
                    if self._log_callback:
                        self._log_callback(f"[*] Enabling OS detection (-O)")
                else:
                    if self._log_callback:
                        self._log_callback(f"[!] OS detection requires root privileges, skipping.")
            
            # Always add -v for verbosity
            args += " -v"
            
            # Custom arguments (overrides everything if specified, but validate first)
            if scan_options.get("custom_args"):
                custom_args = self._validate_custom_args(scan_options.get('custom_args', ''))
                if custom_args:
                    args = custom_args
                    if self._log_callback:
                        self._log_callback(f"[*] Using custom arguments: {custom_args}")
        
        # Trim leading/trailing whitespace
        args = args.strip()
        
        # If no scan type included, add a basic connect scan
        if not any(arg in args for arg in ["-sS", "-sT", "-sU", "-sF", "-sN", "-sX", "-sI", "-sO", "-sn"]):
            args = "-sT " + args
            if self._log_callback:
                self._log_callback(f"[*] No scan type specified, using TCP Connect scan (-sT)")

        # Always use -Pn if not already specified to avoid ping issues
        if "-Pn" not in args:
            args += " -Pn"
        
        # Log the nmap command
        if self._log_callback:
            self._log_callback(f"[*] Running nmap command: nmap {args} {target}")
            
        # Make sure the target is sanitized
        target = self._validate_target(target)
        if not target:
            if self._log_callback:
                self._log_callback(f"[!] Invalid target: Security validation failed")
            return {}
        
        try:
            # Check if we need to try sudo
            if not is_root and any(opt in args for opt in ["-sS", "-sU", "-sF", "-sN", "-sX", "-sI", "-sO", "-O"]):
                # Try to use sudo if available
                if shutil.which('sudo'):
                    if self._log_callback:
                        self._log_callback(f"[*] Attempting to use sudo for privileged scan...")
                    
                    try:
                        import subprocess
                        sudo_args = f"sudo nmap {args} {target} -oX -"
                        process = subprocess.Popen(sudo_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = process.communicate()
                        
                        if process.returncode == 0:
                            # Parse XML output
                            self.nmap_scanner._nmap_last_output = stdout
                            xml_output = stdout.decode('utf-8')
                            self.nmap_scanner._nmap_run_command = sudo_args
                            self.nmap_scanner._scan_result = self.nmap_scanner._parse_xml_output(xml_output)
                            
                            if self._log_callback:
                                self._log_callback(f"[+] Sudo nmap scan completed successfully.")
                            
                            # Process the scan results normally
                        else:
                            error_msg = stderr.decode('utf-8')
                            if self._log_callback:
                                self._log_callback(f"[!] Error with sudo nmap: {error_msg}")
                            
                            # Fall back to regular scan
                            args = args.replace("-sS", "-sT")
                            args = args.replace("-sO", "")
                            args = args.replace("-O", "")
                            args = ''.join([c for c in args if c not in "-sU -sF -sN -sX -sI"])
                            if self._log_callback:
                                self._log_callback(f"[*] Falling back to unprivileged scan: nmap {args} {target}")
                            
                            self.nmap_scanner.scan(hosts=target, arguments=args)
                    except Exception as e:
                        if self._log_callback:
                            self._log_callback(f"[!] Error with sudo approach: {str(e)}")
                        
                        # Fall back to regular scan with non-privileged options
                        args = args.replace("-sS", "-sT")
                        args = args.replace("-sO", "")
                        args = args.replace("-O", "")
                        args = ''.join([c for c in args if c not in "-sU -sF -sN -sX -sI"])
                        if self._log_callback:
                            self._log_callback(f"[*] Falling back to unprivileged scan: nmap {args} {target}")
                        
                        self.nmap_scanner.scan(hosts=target, arguments=args)
                else:
                    # No sudo available, strip privileged options
                    args = args.replace("-sS", "-sT")
                    args = args.replace("-sO", "")
                    args = args.replace("-O", "")
                    args = ''.join([c for c in args if c not in "-sU -sF -sN -sX -sI"])
                    if self._log_callback:
                        self._log_callback(f"[*] Using unprivileged scan: nmap {args} {target}")
                    
                    self.nmap_scanner.scan(hosts=target, arguments=args)
            else:
                # Run the nmap scan normally
                self.nmap_scanner.scan(hosts=target, arguments=args)
            
            # Get the raw XML output
            raw_output = self.nmap_scanner.get_nmap_last_output().decode('utf-8', errors='ignore')
            
            # Log the raw output for debugging if needed
            logger.debug(f"Nmap raw output: {raw_output}")
            
            # Extract and display the command line output for the UI
            if self._log_callback:
                self._log_callback(f"\n[+] NMAP SCAN OUTPUT:")
                
                # Extract simplified version of the nmap output from the XML for displaying in UI
                # Parse the raw output and extract the key elements
                import xml.etree.ElementTree as ET
                try:
                    # Try to parse the XML output
                    if raw_output.strip():
                        xml_root = ET.fromstring(raw_output)
                        
                        # Extract nmap command and scan info
                        nmap_command = xml_root.attrib.get('args', 'nmap command not found')
                        self._log_callback(f"  Command: {nmap_command}")
                        
                        # Extract scanner version
                        xml_scaninfo = xml_root.find('scaninfo')
                        if xml_scaninfo is not None:
                            scan_type = xml_scaninfo.attrib.get('type', 'unknown')
                            protocol = xml_scaninfo.attrib.get('protocol', 'unknown')
                            self._log_callback(f"  Scan type: {scan_type} ({protocol})")
                        
                        # Extract host information
                        for xml_host in xml_root.findall('host'):
                            xml_status = xml_host.find('status')
                            if xml_status is not None and xml_status.attrib.get('state') == 'up':
                                # Get IP address
                                host_ip = "unknown"
                                for xml_addr in xml_host.findall('address'):
                                    if xml_addr.attrib.get('addrtype') == 'ipv4':
                                        host_ip = xml_addr.attrib.get('addr')
                                
                                self._log_callback(f"\n  Host: {host_ip} is up")
                                
                                # Get hostnames
                                xml_hostnames = xml_host.find('hostnames')
                                if xml_hostnames is not None:
                                    for xml_hostname in xml_hostnames.findall('hostname'):
                                        name = xml_hostname.attrib.get('name')
                                        self._log_callback(f"  Hostname: {name}")
                                
                                # Get ports
                                xml_ports = xml_host.find('ports')
                                if xml_ports is not None:
                                    self._log_callback(f"  Ports:")
                                    for xml_port in xml_ports.findall('port'):
                                        port_id = xml_port.attrib.get('portid')
                                        protocol = xml_port.attrib.get('protocol')
                                        xml_state = xml_port.find('state')
                                        state = xml_state.attrib.get('state') if xml_state is not None else 'unknown'
                                        
                                        service_info = ""
                                        xml_service = xml_port.find('service')
                                        if xml_service is not None:
                                            service_name = xml_service.attrib.get('name', 'unknown')
                                            product = xml_service.attrib.get('product', '')
                                            version = xml_service.attrib.get('version', '')
                                            
                                            service_info = f"{service_name}"
                                            if product:
                                                service_info += f" {product}"
                                                if version:
                                                    service_info += f" {version}"
                                        
                                        self._log_callback(f"    {port_id}/{protocol} {state} {service_info}")
                                        
                                        # Display script output for this port if available
                                        for xml_script in xml_port.findall('script'):
                                            script_id = xml_script.attrib.get('id', 'unknown')
                                            output = xml_script.attrib.get('output', '').strip()
                                            # Only show the first 100 chars of script output
                                            if len(output) > 100:
                                                output = output[:100] + "..."
                                            self._log_callback(f"      {script_id}: {output}")
                                
                                # Get OS information
                                xml_os = xml_host.find('os')
                                if xml_os is not None:
                                    self._log_callback(f"  OS Detection:")
                                    for xml_osmatch in xml_os.findall('osmatch'):
                                        name = xml_osmatch.attrib.get('name', 'Unknown')
                                        accuracy = xml_osmatch.attrib.get('accuracy', '0')
                                        self._log_callback(f"    {name} (Accuracy: {accuracy}%)")
                                
                                # Get hostname from host-level scripts
                                xml_hostscripts = xml_host.find('hostscripts')
                                if xml_hostscripts is not None:
                                    self._log_callback(f"  Host Scripts:")
                                    for xml_script in xml_hostscripts.findall('script'):
                                        script_id = xml_script.attrib.get('id', 'unknown')
                                        output = xml_script.attrib.get('output', '').strip()
                                        # Only show the first 100 chars of script output
                                        if len(output) > 100:
                                            output = output[:100] + "..."
                                        self._log_callback(f"    {script_id}: {output}")
                    else:
                        self._log_callback("[!] No XML output received from nmap")
                except ET.ParseError:
                    self._log_callback("[!] Could not parse XML output from nmap")
                    # If XML parsing fails, just provide the command and basic info
                    self._log_callback(f"  Command: nmap {args} {target}")
                    self._log_callback("  Raw output:")
                    
                    # Try to display some meaningful information from the non-XML output
                    lines = raw_output.split('\n')
                    for line in lines[:20]:  # Show first 20 lines
                        if line.strip():
                            self._log_callback(f"    {line}")
                except Exception as e:
                    # If XML parsing fails, just provide the command and basic info
                    self._log_callback(f"  Command: nmap {args} {target}")
                    self._log_callback(f"  Error parsing detailed output: {str(e)}")
                
                # Log scan completion info
                self._log_callback(f"\n[+] Nmap scan completed: {self.nmap_scanner.command_line()}")
                
                # Log scan stats if available
                try:
                    scaninfo = self.nmap_scanner.scaninfo()
                    self._log_callback(f"[+] Scan info: {scaninfo}")
                except:
                    pass
                
                try:
                    scanstats = self.nmap_scanner.scanstats()
                    self._log_callback(f"[+] Scan stats: {scanstats}")
                except:
                    pass
                
                try:
                    all_hosts = self.nmap_scanner.all_hosts()
                    self._log_callback(f"[+] Found {len(all_hosts)} hosts up")
                except:
                    pass
            
            # Return the scan results
            hosts = {}
            try:
                for host in self.nmap_scanner.all_hosts():
                    hosts[host] = self.nmap_scanner[host]
            except Exception as e:
                if self._log_callback:
                    self._log_callback(f"[!] Error processing scan results: {str(e)}")
            
            # If no hosts were found but we know the scan ran, add at least the target
            if not hosts and target:
                if self._log_callback:
                    self._log_callback(f"[!] No host data returned by nmap, adding target as placeholder")
                hosts[target] = {'status': {'state': 'unknown'}}
                
            return hosts
        except Exception as e:
            logger.error(f"Error running nmap scan: {e}")
            if self._log_callback:
                self._log_callback(f"[!] Error running nmap scan: {e}")
            return {}
    
    def _determine_node_type_from_nmap(self, host_data: Dict) -> str:
        """
        Determine the device type based on nmap scan data
        """
        # Default node type is 'host'
        node_type = 'host'
        
        try:
            # Extract services from TCP ports
            services = []
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    service = port_data.get('name', '').lower()
                    product = port_data.get('product', '').lower()
                    
                    if service:
                        services.append(service)
                    if product:
                        services.append(product)
            
            # Examine OS information
            os_info = ''
            if 'osmatch' in host_data and host_data['osmatch']:
                os_matches = sorted(host_data['osmatch'], key=lambda x: int(x.get('accuracy', 0)), reverse=True)
                if os_matches:
                    os_info = os_matches[0].get('name', '').lower()
            
            # Check for router/gateway
            if any(s in services for s in ['router', 'gateway']) or 'mikrotik' in str(services).lower():
                node_type = 'Router'
            
            # Check for switches
            elif any(s in services for s in ['snmp', 'switch']):
                node_type = 'switch'
            
            # Check for printers
            elif any(s in services for s in ['printer', 'ipp', 'jetdirect']):
                node_type = 'Printer'
            
            # Check for firewalls
            elif any(s in services for s in ['firewall', 'pfsense']):
                node_type = 'firewall'
            
            # Check for surveillance cameras
            elif any(s in services for s in ['rtsp', 'onvif', 'camera']):
                node_type = 'IP Camera'
            
            # Check for IoT devices
            elif any(s in services for s in ['mqtt', 'iot']):
                node_type = 'IoT Device'
            
            # Check for servers by port
            elif 'ssh' in services and 'http' in services:
                if 'apache' in str(services).lower() or 'nginx' in str(services).lower():
                    node_type = 'Web Server'
                elif 'mysql' in str(services).lower() or 'postgresql' in str(services).lower():
                    node_type = 'Database Server'
                else:
                    node_type = 'Linux Server'
            
            # Check for database servers
            elif any(s in services for s in ['mysql', 'postgresql', 'oracle', 'db2', 'mssql']):
                node_type = 'Database Server'
            
            # Check for web servers
            elif any(s in services for s in ['http', 'https', 'apache', 'nginx', 'iis']):
                node_type = 'Web Server'
            
            # Check for mail servers
            elif any(s in services for s in ['smtp', 'pop3', 'imap', 'exchange']):
                node_type = 'Mail Server'
            
            # Check for DNS servers
            elif 'domain' in services:
                node_type = 'DNS Server'
            
            # Check for FTP servers
            elif 'ftp' in services:
                node_type = 'FTP Server'
            
            # Check for application servers
            elif any(s in services for s in ['tomcat', 'jboss', 'weblogic', 'websphere']):
                node_type = 'Application Server'
            
            # Determine based on OS
            elif os_info:
                if 'windows' in os_info:
                    if 'server' in os_info:
                        node_type = 'Windows Server'
                    else:
                        node_type = 'Windows Workstation'
                elif any(os in os_info for os in ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'fedora']):
                    node_type = 'Linux Server'
                elif 'mac' in os_info or 'apple' in os_info:
                    node_type = 'Workstation'
            
            # Fallback based on open ports
            elif 22 in host_data.get('tcp', {}):  # SSH port
                node_type = 'Linux Server'
            elif 3389 in host_data.get('tcp', {}):  # RDP port
                node_type = 'Windows Server'
        
        except Exception as e:
            logger.error(f"Error determining node type: {e}")
        
        return node_type

    def _validate_ip(self, ip: str) -> str:
        """
        Validate that a string is a valid IP address.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            str: Validated IP or empty string if invalid
        """
        ip = ip.strip()
        # Basic validation for IPv4 address format
        import re
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ipv4_pattern.match(ip):
            # Check each octet is in range 0-255
            try:
                if all(0 <= int(octet) <= 255 for octet in ip.split('.')):
                    return ip
            except ValueError:
                pass
        return ""
    
    def _validate_port_range(self, port_range: str) -> str:
        """
        Validate port range format.
        
        Args:
            port_range: Port range string to validate
            
        Returns:
            str: Validated port range or empty string if invalid
        """
        port_range = port_range.strip()
        # Check common port range formats
        import re
        
        # Format: single port (e.g., 80)
        if re.match(r'^\d+$', port_range):
            port = int(port_range)
            if 1 <= port <= 65535:
                return port_range
        
        # Format: port range (e.g., 1-1000)
        elif re.match(r'^\d+-\d+$', port_range):
            start, end = map(int, port_range.split('-'))
            if 1 <= start <= end <= 65535:
                return port_range
        
        # Format: comma-separated ports (e.g., 22,80,443)
        elif re.match(r'^(\d+,)+\d+$', port_range):
            ports = port_range.split(',')
            if all(1 <= int(port) <= 65535 for port in ports):
                return port_range
        
        # Format: combination (e.g., 22,80,100-200)
        elif re.match(r'^((\d+)|(\d+-\d+))(,((\d+)|(\d+-\d+)))*$', port_range):
            parts = port_range.split(',')
            valid = True
            
            for part in parts:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if not (1 <= start <= end <= 65535):
                        valid = False
                        break
                else:
                    try:
                        port = int(part)
                        if not (1 <= port <= 65535):
                            valid = False
                            break
                    except ValueError:
                        valid = False
                        break
            
            if valid:
                return port_range
        
        return ""
    
    def _validate_script_args(self, script_args: str) -> str:
        """
        Validate and sanitize script arguments.
        
        Args:
            script_args: Script arguments string to validate
            
        Returns:
            str: Sanitized script arguments or empty string if invalid
        """
        script_args = script_args.strip()
        
        # Whitelist approach: allow only known script categories and common scripts
        allowed_categories = [
            "auth", "broadcast", "brute", "default", "discovery", "dos", "exploit", 
            "external", "fuzzer", "intrusive", "malware", "safe", "version", "vuln"
        ]
        
        # Allow comma-separated list of categories/scripts
        parts = script_args.split(',')
        valid_parts = []
        
        import re
        for part in parts:
            part = part.strip()
            # Allow script categories
            if part in allowed_categories:
                valid_parts.append(part)
            # Allow script names with alphanumeric chars, hyphens, and underscores
            elif re.match(r'^[a-zA-Z0-9_\-]+$', part):
                valid_parts.append(part)
        
        if valid_parts:
            return ','.join(valid_parts)
        
        return ""
    
    def _validate_custom_args(self, custom_args: str) -> str:
        """
        Validate and sanitize custom nmap arguments.
        
        Args:
            custom_args: Custom arguments string to validate
            
        Returns:
            str: Sanitized custom arguments or empty string if dangerous commands detected
        """
        custom_args = custom_args.strip()
        
        # Check for shell command injection attempts
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '{', '}']
        if any(char in custom_args for char in dangerous_chars):
            logger.warning(f"Potential command injection detected in nmap args: {custom_args}")
            return ""
        
        # Strip any sudo or nmap command itself
        custom_args = custom_args.replace("sudo", "").replace("nmap", "").strip()
        
        return custom_args
    
    def _validate_target(self, target: str) -> str:
        """
        Validate and sanitize target specification.
        
        Args:
            target: Target string to validate
            
        Returns:
            str: Sanitized target or empty string if invalid
        """
        target = target.strip()
        
        # Check for shell command injection attempts
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '{', '}']
        if any(char in target for char in dangerous_chars):
            logger.warning(f"Potential command injection detected in target: {target}")
            return ""
        
        # Basic validation for IP, CIDR, or hostname
        import re
        
        # IPv4 address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            if all(0 <= int(octet) <= 255 for octet in target.split('.')):
                return target
        
        # CIDR notation
        elif re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', target):
            ip, prefix = target.split('/')
            if all(0 <= int(octet) <= 255 for octet in ip.split('.')) and 0 <= int(prefix) <= 32:
                return target
        
        # Domain/hostname validation - basic check
        elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]+)?[a-zA-Z0-9](\.[a-zA-Z]{2,})+$', target):
            return target
        
        # IP range in nmap format: 192.168.1.1-254
        elif re.match(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$', target):
            base, range_end = target.rsplit('-', 1)
            if all(0 <= int(octet) <= 255 for octet in base.split('.')) and 0 <= int(range_end) <= 255:
                return target
        
        # Return the original target if we can't determine its validity
        # The python-nmap library will handle errors
        return target
