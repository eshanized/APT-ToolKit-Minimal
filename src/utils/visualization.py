import os
import json
import matplotlib
matplotlib.use('Qt5Agg')  # Use Qt5 backend for matplotlib
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from PyQt6 import QtWidgets, QtCore
from typing import Dict, List, Optional, Union, Any, Tuple

class MplCanvas(FigureCanvas):
    """Matplotlib canvas class for embedding plots in PyQt"""
    def __init__(self, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        super(MplCanvas, self).__init__(self.fig)
        self.fig.tight_layout()

class ReconVisualization:
    """
    Class for visualizing reconnaissance data
    """
    def __init__(self):
        """Initialize visualization module"""
        self.current_data = None
        self.current_canvas = None
    
    def load_data(self, data: Dict[str, Any]) -> None:
        """
        Load recon data for visualization
        
        Args:
            data: Dictionary containing recon results
        """
        self.current_data = data
    
    def create_host_network_graph(self, parent_widget: QtWidgets.QWidget) -> MplCanvas:
        """
        Create a network graph visualization of hosts
        
        Args:
            parent_widget: The parent widget to embed the visualization in
            
        Returns:
            MplCanvas: The canvas containing the visualization
        """
        # Clear any existing layout
        if parent_widget.layout():
            while parent_widget.layout().count():
                item = parent_widget.layout().takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
        else:
            parent_widget.setLayout(QtWidgets.QVBoxLayout())
        
        # Create canvas for the plot
        canvas = MplCanvas(width=5, height=4, dpi=100)
        
        # Create network graph if we have data
        if not self.current_data or 'hosts' not in self.current_data:
            canvas.axes.text(0.5, 0.5, "No host data available", 
                            horizontalalignment='center',
                            verticalalignment='center')
            parent_widget.layout().addWidget(canvas)
            return canvas
        
        # Create a directed graph
        G = nx.DiGraph()
        
        # Get hosts from the data
        hosts = self.current_data.get('hosts', [])
        target = self.current_data.get('target', 'Unknown')
        
        # Add the target as the central node
        G.add_node(target, type='target')
        
        # Add each host and connect to the target
        for host in hosts:
            ip = host.get('ip_address', '')
            hostname = host.get('hostname', '')
            status = host.get('status', 'unknown')
            
            # Use hostname if available, otherwise IP
            node_label = hostname if hostname else ip
            
            # Add the host node
            G.add_node(node_label, type='host', status=status)
            
            # Connect the host to the target
            G.add_edge(target, node_label)
            
            # Add ports as leaf nodes if available
            for port in host.get('open_ports', []):
                port_num = port.get('port', 0)
                service = port.get('service', '')
                port_label = f"{port_num}/{service}" if service else f"{port_num}"
                
                # Add the port node
                G.add_node(port_label, type='port')
                
                # Connect the port to the host
                G.add_edge(node_label, port_label)
        
        # Draw the graph
        canvas.axes.clear()
        pos = nx.spring_layout(G)
        
        # Node colors based on type
        node_colors = []
        for node in G.nodes():
            node_type = G.nodes[node].get('type', '')
            if node_type == 'target':
                node_colors.append('red')
            elif node_type == 'host':
                status = G.nodes[node].get('status', '')
                if status == 'up':
                    node_colors.append('green')
                elif status == 'down':
                    node_colors.append('gray')
                else:
                    node_colors.append('blue')
            elif node_type == 'port':
                node_colors.append('orange')
        
        # Draw nodes and edges
        nx.draw(G, pos, with_labels=True, node_color=node_colors, 
                node_size=500, alpha=0.8, arrows=True,
                ax=canvas.axes)
        
        canvas.fig.tight_layout()
        parent_widget.layout().addWidget(canvas)
        return canvas
    
    def create_port_distribution(self, parent_widget: QtWidgets.QWidget) -> MplCanvas:
        """
        Create a bar chart showing port distribution
        
        Args:
            parent_widget: The parent widget to embed the visualization in
            
        Returns:
            MplCanvas: The canvas containing the visualization
        """
        # Clear any existing layout
        if parent_widget.layout():
            while parent_widget.layout().count():
                item = parent_widget.layout().takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
        else:
            parent_widget.setLayout(QtWidgets.QVBoxLayout())
        
        # Create canvas for the plot
        canvas = MplCanvas(width=5, height=4, dpi=100)
        
        # Check if we have data
        if not self.current_data or 'hosts' not in self.current_data:
            canvas.axes.text(0.5, 0.5, "No port data available", 
                            horizontalalignment='center',
                            verticalalignment='center')
            parent_widget.layout().addWidget(canvas)
            return canvas
        
        # Count ports and services
        port_counts = {}
        service_counts = {}
        
        # Get hosts from the data
        hosts = self.current_data.get('hosts', [])
        
        # Count ports and services across all hosts
        for host in hosts:
            for port in host.get('open_ports', []):
                port_num = port.get('port', 0)
                service = port.get('service', 'unknown')
                
                if port_num in port_counts:
                    port_counts[port_num] += 1
                else:
                    port_counts[port_num] = 1
                    
                if service in service_counts:
                    service_counts[service] += 1
                else:
                    service_counts[service] = 1
        
        # Sort ports by frequency
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        top_ports = sorted_ports[:15]  # Show top 15 ports
        
        # Extract port numbers and counts
        port_nums = [str(port[0]) for port in top_ports]
        counts = [port[1] for port in top_ports]
        
        # Draw the bar chart
        canvas.axes.clear()
        bars = canvas.axes.bar(port_nums, counts, color='skyblue')
        
        # Add service labels to the bars
        for i, bar in enumerate(bars):
            port_num = int(port_nums[i])
            # Find a service for this port from any host
            service = "unknown"
            for host in hosts:
                for port in host.get('open_ports', []):
                    if port.get('port', 0) == port_num:
                        service = port.get('service', 'unknown')
                        break
                if service != "unknown":
                    break
            
            if service != "unknown":
                canvas.axes.text(bar.get_x() + bar.get_width()/2, 0.1 + bar.get_height(),
                        service, ha='center', va='bottom', rotation=45, fontsize=8)
        
        canvas.axes.set_xlabel('Ports')
        canvas.axes.set_ylabel('Count')
        canvas.axes.set_title('Port Distribution')
        canvas.axes.tick_params(axis='x', rotation=45)
        
        canvas.fig.tight_layout()
        parent_widget.layout().addWidget(canvas)
        return canvas
    
    def create_subdomain_visualization(self, parent_widget: QtWidgets.QWidget) -> MplCanvas:
        """
        Create a treemap of subdomains
        
        Args:
            parent_widget: The parent widget to embed the visualization in
            
        Returns:
            MplCanvas: The canvas containing the visualization
        """
        # Clear any existing layout
        if parent_widget.layout():
            while parent_widget.layout().count():
                item = parent_widget.layout().takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
        else:
            parent_widget.setLayout(QtWidgets.QVBoxLayout())
        
        # Create canvas for the plot
        canvas = MplCanvas(width=5, height=4, dpi=100)
        
        # Check if we have data
        if not self.current_data or 'domains' not in self.current_data:
            canvas.axes.text(0.5, 0.5, "No subdomain data available", 
                            horizontalalignment='center',
                            verticalalignment='center')
            parent_widget.layout().addWidget(canvas)
            return canvas
        
        # Get domains from the data
        domains = self.current_data.get('domains', [])
        
        if not domains:
            canvas.axes.text(0.5, 0.5, "No subdomain data available", 
                            horizontalalignment='center',
                            verticalalignment='center')
            parent_widget.layout().addWidget(canvas)
            return canvas
        
        # Create a network graph for subdomains
        G = nx.Graph()
        
        # Get the primary domain and subdomains
        primary_domain = domains[0].get('domain', 'Unknown')
        subdomains = domains[0].get('subdomains', [])
        
        # Add the primary domain as the central node
        G.add_node(primary_domain, size=1000)
        
        # Group subdomains by their first level
        subdomain_groups = {}
        
        for subdomain in subdomains:
            # Remove the primary domain part to get the subdomain prefix
            if primary_domain in subdomain:
                prefix = subdomain.replace("." + primary_domain, "")
                parts = prefix.split('.')
                
                if len(parts) > 0:
                    # Get the first level of the subdomain
                    first_level = parts[-1]  # Last part is closest to primary domain
                    
                    if first_level in subdomain_groups:
                        subdomain_groups[first_level].append(subdomain)
                    else:
                        subdomain_groups[first_level] = [subdomain]
            else:
                # If it doesn't contain the primary domain, use the full subdomain
                if "other" in subdomain_groups:
                    subdomain_groups["other"].append(subdomain)
                else:
                    subdomain_groups["other"] = [subdomain]
        
        # Add subdomain groups as nodes connected to primary domain
        for group, subs in subdomain_groups.items():
            group_node = f"{group}.{primary_domain}"
            G.add_node(group_node, size=500)
            G.add_edge(primary_domain, group_node)
            
            # Add individual subdomains as leaf nodes
            for sub in subs:
                G.add_node(sub, size=100)
                G.add_edge(group_node, sub)
        
        # Draw the graph
        canvas.axes.clear()
        
        # Use hierarchical layout
        pos = nx.kamada_kawai_layout(G)
        
        # Node sizes based on hierarchy
        node_sizes = [G.nodes[node].get('size', 300) for node in G.nodes()]
        
        # Draw nodes and edges
        nx.draw(G, pos, with_labels=True, 
                node_size=node_sizes, alpha=0.8, 
                node_color='lightblue', font_size=8,
                ax=canvas.axes)
        
        canvas.fig.tight_layout()
        parent_widget.layout().addWidget(canvas)
        return canvas
    
    def create_summary_visualization(self, parent_widget: QtWidgets.QWidget) -> MplCanvas:
        """
        Create a summary visualization with multiple charts
        
        Args:
            parent_widget: The parent widget to embed the visualization in
            
        Returns:
            MplCanvas: The canvas containing the visualization
        """
        # Clear any existing layout
        if parent_widget.layout():
            while parent_widget.layout().count():
                item = parent_widget.layout().takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
        else:
            parent_widget.setLayout(QtWidgets.QVBoxLayout())
        
        # Create canvas for the plot
        canvas = MplCanvas(width=5, height=4, dpi=100)
        
        # Check if we have data
        if not self.current_data:
            canvas.axes.text(0.5, 0.5, "No data available", 
                            horizontalalignment='center',
                            verticalalignment='center')
            parent_widget.layout().addWidget(canvas)
            return canvas
        
        # Create a grid of subplots
        canvas.fig.clear()  # Clear the figure first
        gs = canvas.fig.add_gridspec(2, 2)  # 2x2 grid
        ax1 = canvas.fig.add_subplot(gs[0, 0])  # Top left
        ax2 = canvas.fig.add_subplot(gs[0, 1])  # Top right
        ax3 = canvas.fig.add_subplot(gs[1, 0])  # Bottom left
        ax4 = canvas.fig.add_subplot(gs[1, 1])  # Bottom right
        
        # Get data
        hosts = self.current_data.get('hosts', [])
        domains = self.current_data.get('domains', [])
        
        # 1. Host Status Pie Chart (Top Left)
        host_status_counts = {'up': 0, 'down': 0, 'unknown': 0}
        
        for host in hosts:
            status = host.get('status', 'unknown')
            host_status_counts[status] += 1
        
        status_labels = list(host_status_counts.keys())
        status_counts = list(host_status_counts.values())
        
        ax1.pie(status_counts, labels=status_labels, autopct='%1.1f%%',
                colors=['green', 'red', 'gray'])
        ax1.set_title('Host Status')
        
        # 2. Top Services Bar Chart (Top Right)
        service_counts = {}
        
        for host in hosts:
            for port in host.get('open_ports', []):
                service = port.get('service', 'unknown')
                
                if service in service_counts:
                    service_counts[service] += 1
                else:
                    service_counts[service] = 1
        
        sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)
        top_services = sorted_services[:5]  # Show top 5 services
        
        service_names = [service[0] for service in top_services]
        service_counts = [service[1] for service in top_services]
        
        ax2.bar(service_names, service_counts, color='orange')
        ax2.set_title('Top Services')
        ax2.tick_params(axis='x', rotation=45)
        
        # 3. Port Protocol Distribution (Bottom Left)
        tcp_ports = 0
        udp_ports = 0
        
        for host in hosts:
            for port in host.get('open_ports', []):
                protocol = port.get('protocol', 'tcp').lower()
                
                if protocol == 'tcp':
                    tcp_ports += 1
                elif protocol == 'udp':
                    udp_ports += 1
        
        protocol_labels = ['TCP', 'UDP']
        protocol_counts = [tcp_ports, udp_ports]
        
        ax3.bar(protocol_labels, protocol_counts, color=['blue', 'green'])
        ax3.set_title('Protocol Distribution')
        
        # 4. Scan Duration (Bottom Right)
        duration = self.current_data.get('end_time', 0) - self.current_data.get('scan_time', 0)
        if duration <= 0:
            duration = 0
        
        ax4.text(0.5, 0.5, f"Scan Duration:\n{duration:.2f} seconds", 
                horizontalalignment='center',
                verticalalignment='center',
                fontsize=12)
        ax4.set_title('Scan Information')
        ax4.axis('off')
        
        canvas.fig.tight_layout()
        parent_widget.layout().addWidget(canvas)
        return canvas
    
    def export_current_visualization(self, file_path: str) -> bool:
        """
        Export the current visualization to a file
        
        Args:
            file_path: Path to save the visualization
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.current_canvas:
            return False
        
        try:
            self.current_canvas.fig.savefig(file_path, dpi=300, bbox_inches='tight')
            return True
        except Exception as e:
            print(f"Error exporting visualization: {e}")
            return False