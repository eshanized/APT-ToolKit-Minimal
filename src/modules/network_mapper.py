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
        
        # Phase 1: Host discovery with ping sweep
        if ping_sweep:
            logger.info(f"Starting ping sweep of {len(ip_list)} hosts")
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
