"""
Report Generation module for the APT toolkit.

This module provides functionality for generating reports based on the results
of various operations performed by the APT toolkit, including reconnaissance,
scanning, vulnerability assessment, and exploitation.
"""

import os
import json
import yaml
import csv
import time
import logging
import datetime
import base64
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import traceback
import jinja2

# Local imports
from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager


class ReportFormat(Enum):
    """Enumeration of supported report formats."""
    HTML = auto()
    PDF = auto()
    JSON = auto()
    YAML = auto()
    CSV = auto()
    TEXT = auto()
    MARKDOWN = auto()
    XML = auto()


class ReportSeverity(Enum):
    """Enumeration of report severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


@dataclass
class ReportItem:
    """Data class for a report item."""
    title: str
    description: str
    severity: ReportSeverity = ReportSeverity.INFO
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "details": self.details,
            "timestamp": self.timestamp,
            "datetime": datetime.datetime.fromtimestamp(self.timestamp).isoformat()
        }
        return result


@dataclass
class ReportSection:
    """Data class for a report section."""
    title: str
    items: List[ReportItem] = field(default_factory=list)
    subsections: List['ReportSection'] = field(default_factory=list)
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_item(self, item: ReportItem) -> None:
        """Add an item to the section."""
        self.items.append(item)
    
    def add_subsection(self, subsection: 'ReportSection') -> None:
        """Add a subsection to the section."""
        self.subsections.append(subsection)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "title": self.title,
            "summary": self.summary,
            "items": [item.to_dict() for item in self.items],
            "subsections": [subsection.to_dict() for subsection in self.subsections],
            "metadata": self.metadata
        }


@dataclass
class Report:
    """Data class for a complete report."""
    title: str
    target: str
    sections: List[ReportSection] = field(default_factory=list)
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    creation_time: float = field(default_factory=time.time)
    
    def add_section(self, section: ReportSection) -> None:
        """Add a section to the report."""
        self.sections.append(section)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "title": self.title,
            "target": self.target,
            "summary": self.summary,
            "sections": [section.to_dict() for section in self.sections],
            "metadata": self.metadata,
            "creation_time": self.creation_time,
            "creation_datetime": datetime.datetime.fromtimestamp(self.creation_time).isoformat()
        }
    
    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string."""
        if pretty:
            return json.dumps(self.to_dict(), indent=4)
        return json.dumps(self.to_dict())
    
    def to_yaml(self) -> str:
        """Convert to YAML string."""
        return yaml.dump(self.to_dict(), sort_keys=False)


@dataclass
class ReportTemplate:
    """Data class for a report template."""
    name: str
    description: str
    format: ReportFormat
    template_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "format": self.format.name,
            "metadata": self.metadata
        }


class ReportGenerator:
    """
    Report generator for the APT toolkit.
    
    This class provides functionality for generating reports based on the results
    of various operations performed by the APT toolkit.
    """
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the report generator.
        
        Args:
            config: Optional configuration manager
        """
        self.logger = get_module_logger("report_gen")
        self.config = config
        
        # Set default values
        self.reports_dir = "reports"
        self.templates_dir = "templates"
        self.default_template = "default"
        
        # Load configuration if provided
        if config:
            self.reports_dir = config.get("modules.report_gen.reports_dir", "reports")
            self.templates_dir = config.get("modules.report_gen.templates_dir", "templates")
            self.default_template = config.get("modules.report_gen.default_template", "default")
        
        # Create directories if they don't exist
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.templates_dir, exist_ok=True)
        
        # Initialize Jinja2 environment for templates
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.templates_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.jinja_env.filters['to_json'] = lambda obj: json.dumps(obj)
        self.jinja_env.filters['to_yaml'] = lambda obj: yaml.dump(obj, sort_keys=False)
        self.jinja_env.filters['format_datetime'] = lambda timestamp: datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Load templates
        self.templates = self._load_templates()
        
        self.logger.info("Report generator initialized")
    
    def _load_templates(self) -> Dict[str, ReportTemplate]:
        """
        Load report templates from the templates directory.
        
        Returns:
            Dictionary mapping template names to ReportTemplate objects
        """
        templates = {}
        
        # Check if templates directory exists
        if not os.path.exists(self.templates_dir):
            self.logger.warning(f"Templates directory not found: {self.templates_dir}")
            return templates
        
        # Load templates from files
        for filename in os.listdir(self.templates_dir):
            if filename.endswith('.html'):
                name = filename[:-5]  # Remove .html extension
                format_type = ReportFormat.HTML
            elif filename.endswith('.md'):
                name = filename[:-3]  # Remove .md extension
                format_type = ReportFormat.MARKDOWN
            elif filename.endswith('.txt'):
                name = filename[:-4]  # Remove .txt extension
                format_type = ReportFormat.TEXT
            else:
                continue
            
            try:
                with open(os.path.join(self.templates_dir, filename), 'r') as f:
                    template_content = f.read()
                
                # Extract description from template comment
                description = "Report template"
                match = re.search(r'<!--\s*Description:\s*(.*?)\s*-->', template_content)
                if match:
                    description = match.group(1)
                
                # Create template object
                template = ReportTemplate(
                    name=name,
                    description=description,
                    format=format_type,
                    template_content=template_content
                )
                
                templates[name] = template
                self.logger.debug(f"Loaded template: {name}")
                
            except Exception as e:
                self.logger.error(f"Error loading template {filename}: {str(e)}")
        
        return templates
    
    def create_report(self, title: str, target: str, summary: str = "") -> Report:
        """
        Create a new report.
        
        Args:
            title: Report title
            target: Target of the report (e.g., hostname, IP, domain)
            summary: Optional report summary
            
        Returns:
            New Report object
        """
        return Report(
            title=title,
            target=target,
            summary=summary,
            metadata={
                "generator": "APT Toolkit Report Generator",
                "version": "1.0.0"
            }
        )
    
    def add_recon_results(self, report: Report, recon_results: Dict[str, Any]) -> None:
        """
        Add reconnaissance results to a report.
        
        Args:
            report: Report to add results to
            recon_results: Reconnaissance results
        """
        # Create reconnaissance section
        recon_section = ReportSection(
            title="Reconnaissance",
            summary="Results of reconnaissance operations"
        )
        
        # Add DNS information if available
        if "dns_records" in recon_results:
            dns_section = ReportSection(
                title="DNS Information",
                summary="DNS records and information"
            )
            
            for record in recon_results["dns_records"]:
                dns_section.add_item(ReportItem(
                    title=f"DNS Record: {record.get('type', 'Unknown')}",
                    description=f"DNS record for {record.get('name', 'Unknown')}",
                    details=record,
                    severity=ReportSeverity.INFO
                ))
            
            recon_section.add_subsection(dns_section)
        
        # Add port scan information if available
        if "ports" in recon_results:
            ports_section = ReportSection(
                title="Port Scan",
                summary="Open ports and services"
            )
            
            for port_info in recon_results["ports"]:
                port = port_info.get("port", 0)
                protocol = port_info.get("protocol", "tcp")
                service = port_info.get("service", "unknown")
                
                # Determine severity based on port/service
                severity = ReportSeverity.INFO
                if service in ["ssh", "telnet", "ftp", "smtp", "http", "https"]:
                    severity = ReportSeverity.LOW
                if port in [21, 22, 23, 25, 80, 443, 3389, 5900]:
                    severity = ReportSeverity.MEDIUM
                
                ports_section.add_item(ReportItem(
                    title=f"Open Port: {port}/{protocol}",
                    description=f"Service: {service}",
                    details=port_info,
                    severity=severity
                ))
            
            recon_section.add_subsection(ports_section)
        
        # Add WHOIS information if available
        if "whois" in recon_results:
            whois_section = ReportSection(
                title="WHOIS Information",
                summary="Domain registration information"
            )
            
            whois_data = recon_results["whois"]
            whois_section.add_item(ReportItem(
                title="WHOIS Information",
                description=f"Registration information for {whois_data.get('domain', 'Unknown')}",
                details=whois_data,
                severity=ReportSeverity.INFO
            ))
            
            recon_section.add_subsection(whois_section)
        
        # Add host information if available
        if "hosts" in recon_results:
            hosts_section = ReportSection(
                title="Host Information",
                summary="Information about discovered hosts"
            )
            
            for host_info in recon_results["hosts"]:
                hosts_section.add_item(ReportItem(
                    title=f"Host: {host_info.get('ip', 'Unknown')}",
                    description=f"Hostname: {host_info.get('hostname', 'Unknown')}",
                    details=host_info,
                    severity=ReportSeverity.INFO
                ))
            
            recon_section.add_subsection(hosts_section)
        
        # Add the reconnaissance section to the report
        report.add_section(recon_section)
    
    def add_network_map_results(self, report: Report, network_map_results: Dict[str, Any]) -> None:
        """
        Add network mapping results to a report.
        
        Args:
            report: Report to add results to
            network_map_results: Network mapping results
        """
        # Create network mapping section
        network_section = ReportSection(
            title="Network Mapping",
            summary="Results of network mapping operations"
        )
        
        # Add network nodes if available
        if "nodes" in network_map_results:
            nodes_section = ReportSection(
                title="Network Nodes",
                summary="Discovered network nodes"
            )
            
            for node in network_map_results["nodes"]:
                node_type = node.get("type", "unknown")
                ip = node.get("ip", "Unknown")
                hostname = node.get("hostname", "Unknown")
                
                nodes_section.add_item(ReportItem(
                    title=f"{node_type.capitalize()}: {ip}",
                    description=f"Hostname: {hostname}",
                    details=node,
                    severity=ReportSeverity.INFO
                ))
            
            network_section.add_subsection(nodes_section)
        
        # Add network links if available
        if "links" in network_map_results:
            links_section = ReportSection(
                title="Network Links",
                summary="Discovered network links"
            )
            
            for link in network_map_results["links"]:
                source = link.get("source", "Unknown")
                target = link.get("target", "Unknown")
                
                links_section.add_item(ReportItem(
                    title=f"Link: {source} -> {target}",
                    description=f"Network link between {source} and {target}",
                    details=link,
                    severity=ReportSeverity.INFO
                ))
            
            network_section.add_subsection(links_section)
        
        # Add subnets if available
        if "subnets" in network_map_results:
            subnets_section = ReportSection(
                title="Subnets",
                summary="Discovered subnets"
            )
            
            for subnet in network_map_results["subnets"]:
                cidr = subnet.get("cidr", "Unknown")
                
                subnets_section.add_item(ReportItem(
                    title=f"Subnet: {cidr}",
                    description=f"Network subnet: {cidr}",
                    details=subnet,
                    severity=ReportSeverity.INFO
                ))
            
            network_section.add_subsection(subnets_section)
        
        # Add the network mapping section to the report
        report.add_section(network_section)
    
    def add_service_enum_results(self, report: Report, service_enum_results: Dict[str, Any]) -> None:
        """
        Add service enumeration results to a report.
        
        Args:
            report: Report to add results to
            service_enum_results: Service enumeration results
        """
        # Create service enumeration section
        service_section = ReportSection(
            title="Service Enumeration",
            summary="Results of service enumeration operations"
        )
        
        # Add services if available
        if "services" in service_enum_results:
            for service_info in service_enum_results["services"]:
                service_type = service_info.get("type", "unknown")
                host = service_info.get("host", "Unknown")
                port = service_info.get("port", 0)
                version = service_info.get("version", "Unknown")
                
                # Determine severity based on service type and version
                severity = ReportSeverity.INFO
                if service_type in ["ssh", "telnet", "ftp", "smtp", "http", "https"]:
                    severity = ReportSeverity.LOW
                if "outdated" in service_info and service_info["outdated"]:
                    severity = ReportSeverity.MEDIUM
                
                service_section.add_item(ReportItem(
                    title=f"{service_type.upper()} Service: {host}:{port}",
                    description=f"Version: {version}",
                    details=service_info,
                    severity=severity
                ))
        
        # Add vulnerabilities if available
        if "vulnerabilities" in service_enum_results:
            vulns_section = ReportSection(
                title="Service Vulnerabilities",
                summary="Vulnerabilities found in services"
            )
            
            for vuln_info in service_enum_results["vulnerabilities"]:
                vuln_type = vuln_info.get("type", "unknown")
                service = vuln_info.get("service", "Unknown")
                severity_str = vuln_info.get("severity", "info").upper()
                
                # Map severity string to ReportSeverity enum
                severity = ReportSeverity.INFO
                if severity_str == "CRITICAL":
                    severity = ReportSeverity.CRITICAL
                elif severity_str == "HIGH":
                    severity = ReportSeverity.HIGH
                elif severity_str == "MEDIUM":
                    severity = ReportSeverity.MEDIUM
                elif severity_str == "LOW":
                    severity = ReportSeverity.LOW
                
                vulns_section.add_item(ReportItem(
                    title=f"Vulnerability: {vuln_type}",
                    description=f"Service: {service}",
                    details=vuln_info,
                    severity=severity
                ))
            
            service_section.add_subsection(vulns_section)
        
        # Add the service enumeration section to the report
        report.add_section(service_section)
    
    def add_web_scan_results(self, report: Report, web_scan_results: Dict[str, Any]) -> None:
        """
        Add web scanning results to a report.
        
        Args:
            report: Report to add results to
            web_scan_results: Web scanning results
        """
        # Create web scanning section
        web_section = ReportSection(
            title="Web Application Scanning",
            summary="Results of web application scanning operations"
        )
        
        # Add technologies if available
        if "technologies" in web_scan_results:
            tech_section = ReportSection(
                title="Web Technologies",
                summary="Detected web technologies"
            )
            
            for tech_info in web_scan_results["technologies"]:
                tech_name = tech_info.get("name", "Unknown")
                version = tech_info.get("version", "Unknown")
                
                tech_section.add_item(ReportItem(
                    title=f"Technology: {tech_name}",
                    description=f"Version: {version}",
                    details=tech_info,
                    severity=ReportSeverity.INFO
                ))
            
            web_section.add_subsection(tech_section)
        
        # Add endpoints if available
        if "endpoints" in web_scan_results:
            endpoints_section = ReportSection(
                title="Web Endpoints",
                summary="Discovered web endpoints"
            )
            
            for endpoint_info in web_scan_results["endpoints"]:
                url = endpoint_info.get("url", "Unknown")
                method = endpoint_info.get("method", "GET")
                status = endpoint_info.get("status", 0)
                
                endpoints_section.add_item(ReportItem(
                    title=f"Endpoint: {method} {url}",
                    description=f"Status: {status}",
                    details=endpoint_info,
                    severity=ReportSeverity.INFO
                ))
            
            web_section.add_subsection(endpoints_section)
        
        # Add vulnerabilities if available
        if "vulnerabilities" in web_scan_results:
            vulns_section = ReportSection(
                title="Web Vulnerabilities",
                summary="Vulnerabilities found in web applications"
            )
            
            for vuln_info in web_scan_results["vulnerabilities"]:
                vuln_type = vuln_info.get("type", "unknown")
                url = vuln_info.get("url", "Unknown")
                severity_str = vuln_info.get("severity", "info").upper()
                
                # Map severity string to ReportSeverity enum
                severity = ReportSeverity.INFO
                if severity_str == "CRITICAL":
                    severity = ReportSeverity.CRITICAL
                elif severity_str == "HIGH":
                    severity = ReportSeverity.HIGH
                elif severity_str == "MEDIUM":
                    severity = ReportSeverity.MEDIUM
                elif severity_str == "LOW":
                    severity = ReportSeverity.LOW
                
                vulns_section.add_item(ReportItem(
                    title=f"Vulnerability: {vuln_type}",
                    description=f"URL: {url}",
                    details=vuln_info,
                    severity=severity
                ))
            
            web_section.add_subsection(vulns_section)
        
        # Add the web scanning section to the report
        report.add_section(web_section)
    
    def add_vuln_scan_results(self, report: Report, vuln_scan_results: Dict[str, Any]) -> None:
        """
        Add vulnerability scanning results to a report.
        
        Args:
            report: Report to add results to
            vuln_scan_results: Vulnerability scanning results
        """
        # Create vulnerability scanning section
        vuln_section = ReportSection(
            title="Vulnerability Scanning",
            summary="Results of vulnerability scanning operations"
        )
        
        # Add vulnerabilities if available
        if "vulnerabilities" in vuln_scan_results:
            # Group vulnerabilities by severity
            vulns_by_severity = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }
            
            for vuln_info in vuln_scan_results["vulnerabilities"]:
                severity_str = vuln_info.get("severity", "info").lower()
                if severity_str in vulns_by_severity:
                    vulns_by_severity[severity_str].append(vuln_info)
            
            # Create subsections for each severity level
            for severity_str, vulns in vulns_by_severity.items():
                if not vulns:
                    continue
                
                severity_section = ReportSection(
                    title=f"{severity_str.capitalize()} Severity Vulnerabilities",
                    summary=f"Vulnerabilities with {severity_str} severity"
                )
                
                for vuln_info in vulns:
                    vuln_type = vuln_info.get("type", "unknown")
                    target = vuln_info.get("target", "Unknown")
                    
                    # Map severity string to ReportSeverity enum
                    severity = ReportSeverity.INFO
                    if severity_str == "critical":
                        severity = ReportSeverity.CRITICAL
                    elif severity_str == "high":
                        severity = ReportSeverity.HIGH
                    elif severity_str == "medium":
                        severity = ReportSeverity.MEDIUM
                    elif severity_str == "low":
                        severity = ReportSeverity.LOW
                    
                    severity_section.add_item(ReportItem(
                        title=f"Vulnerability: {vuln_type}",
                        description=f"Target: {target}",
                        details=vuln_info,
                        severity=severity
                    ))
                
                vuln_section.add_subsection(severity_section)
        
        # Add vulnerability statistics if available
        if "statistics" in vuln_scan_results:
            stats_section = ReportSection(
                title="Vulnerability Statistics",
                summary="Statistics about discovered vulnerabilities"
            )
            
            stats = vuln_scan_results["statistics"]
            stats_section.add_item(ReportItem(
                title="Vulnerability Statistics",
                description="Summary of vulnerability findings",
                details=stats,
                severity=ReportSeverity.INFO
            ))
            
            vuln_section.add_subsection(stats_section)
        
        # Add the vulnerability scanning section to the report
        report.add_section(vuln_section)
    
    def add_brute_force_results(self, report: Report, brute_force_results: Dict[str, Any]) -> None:
        """
        Add brute force attack results to a report.
        
        Args:
            report: Report to add results to
            brute_force_results: Brute force attack results
        """
        # Create brute force section
        brute_force_section = ReportSection(
            title="Brute Force Attacks",
            summary="Results of brute force attack operations"
        )
        
        # Add successful credentials if available
        if "credentials" in brute_force_results:
            creds_section = ReportSection(
                title="Discovered Credentials",
                summary="Credentials discovered through brute force attacks"
            )
            
            for cred_info in brute_force_results["credentials"]:
                service = cred_info.get("service", "Unknown")
                target = cred_info.get("target", "Unknown")
                username = cred_info.get("username", "Unknown")
                
                # Determine severity based on service
                severity = ReportSeverity.MEDIUM
                if service in ["ssh", "telnet", "ftp", "database"]:
                    severity = ReportSeverity.HIGH
                if service in ["admin", "root"]:
                    severity = ReportSeverity.CRITICAL
                
                creds_section.add_item(ReportItem(
                    title=f"Credentials: {service}",
                    description=f"Target: {target}, Username: {username}",
                    details=cred_info,
                    severity=severity
                ))
            
            brute_force_section.add_subsection(creds_section)
        
        # Add attack statistics if available
        if "statistics" in brute_force_results:
            stats_section = ReportSection(
                title="Attack Statistics",
                summary="Statistics about brute force attacks"
            )
            
            stats = brute_force_results["statistics"]
            stats_section.add_item(ReportItem(
                title="Attack Statistics",
                description="Summary of brute force attack attempts",
                details=stats,
                severity=ReportSeverity.INFO
            ))
            
            brute_force_section.add_subsection(stats_section)
        
        # Add the brute force section to the report
        report.add_section(brute_force_section)
    
    def add_auth_bypass_results(self, report: Report, auth_bypass_results: Dict[str, Any]) -> None:
        """
        Add authentication bypass results to a report.
        
        Args:
            report: Report to add results to
            auth_bypass_results: Authentication bypass results
        """
        # Create authentication bypass section
        auth_bypass_section = ReportSection(
            title="Authentication Bypass",
            summary="Results of authentication bypass operations"
        )
        
        # Add successful bypasses if available
        if "bypasses" in auth_bypass_results:
            bypasses_section = ReportSection(
                title="Successful Bypasses",
                summary="Successful authentication bypass attempts"
            )
            
            for bypass_info in auth_bypass_results["bypasses"]:
                technique = bypass_info.get("technique", "Unknown")
                target = bypass_info.get("target", "Unknown")
                
                # Determine severity based on technique
                severity = ReportSeverity.HIGH
                if technique in ["sql_injection", "default_credentials"]:
                    severity = ReportSeverity.CRITICAL
                
                bypasses_section.add_item(ReportItem(
                    title=f"Bypass: {technique}",
                    description=f"Target: {target}",
                    details=bypass_info,
                    severity=severity
                ))
            
            auth_bypass_section.add_subsection(bypasses_section)
        
        # Add vulnerabilities if available
        if "vulnerabilities" in auth_bypass_results:
            vulns_section = ReportSection(
                title="Authentication Vulnerabilities",
                summary="Vulnerabilities in authentication mechanisms"
            )
            
            for vuln_info in auth_bypass_results["vulnerabilities"]:
                vuln_type = vuln_info.get("type", "unknown")
                target = vuln_info.get("target", "Unknown")
                severity_str = vuln_info.get("severity", "high").upper()
                
                # Map severity string to ReportSeverity enum
                severity = ReportSeverity.HIGH
                if severity_str == "CRITICAL":
                    severity = ReportSeverity.CRITICAL
                elif severity_str == "HIGH":
                    severity = ReportSeverity.HIGH
                elif severity_str == "MEDIUM":
                    severity = ReportSeverity.MEDIUM
                elif severity_str == "LOW":
                    severity = ReportSeverity.LOW
                
                vulns_section.add_item(ReportItem(
                    title=f"Vulnerability: {vuln_type}",
                    description=f"Target: {target}",
                    details=vuln_info,
                    severity=severity
                ))
            
            auth_bypass_section.add_subsection(vulns_section)
        
        # Add the authentication bypass section to the report
        report.add_section(auth_bypass_section)
    
    def add_exploit_results(self, report: Report, exploit_results: Dict[str, Any]) -> None:
        """
        Add exploit execution results to a report.
        
        Args:
            report: Report to add results to
            exploit_results: Exploit execution results
        """
        # Create exploit section
        exploit_section = ReportSection(
            title="Exploit Execution",
            summary="Results of exploit execution operations"
        )
        
        # Add successful exploits if available
        if "exploits" in exploit_results:
            exploits_section = ReportSection(
                title="Successful Exploits",
                summary="Successful exploit execution attempts"
            )
            
            for exploit_info in exploit_results["exploits"]:
                name = exploit_info.get("name", "Unknown")
                target = exploit_info.get("target", "Unknown")
                
                # Determine severity based on exploit type
                severity = ReportSeverity.HIGH
                if "remote_code_execution" in name.lower():
                    severity = ReportSeverity.CRITICAL
                
                exploits_section.add_item(ReportItem(
                    title=f"Exploit: {name}",
                    description=f"Target: {target}",
                    details=exploit_info,
                    severity=severity
                ))
            
            exploit_section.add_subsection(exploits_section)
        
        # Add sessions if available
        if "sessions" in exploit_results:
            sessions_section = ReportSection(
                title="Established Sessions",
                summary="Sessions established through exploits"
            )
            
            for session_info in exploit_results["sessions"]:
                session_id = session_info.get("id", "Unknown")
                session_type = session_info.get("type", "Unknown")
                target = session_info.get("target", "Unknown")
                
                sessions_section.add_item(ReportItem(
                    title=f"Session: {session_type}",
                    description=f"Target: {target}, ID: {session_id}",
                    details=session_info,
                    severity=ReportSeverity.CRITICAL
                ))
            
            exploit_section.add_subsection(sessions_section)
        
        # Add the exploit section to the report
        report.add_section(exploit_section)
    
    def add_scan_results(self, report: Report, scan_results: Dict[str, Any]) -> None:
        """
        Add scan results to a report.
        
        Args:
            report: Report to add results to
            scan_results: Scan results
        """
        # Process different types of scan results
        if "recon" in scan_results:
            self.add_recon_results(report, scan_results["recon"])
        
        if "network_map" in scan_results:
            self.add_network_map_results(report, scan_results["network_map"])
        
        if "service_enum" in scan_results:
            self.add_service_enum_results(report, scan_results["service_enum"])
        
        if "web_scan" in scan_results:
            self.add_web_scan_results(report, scan_results["web_scan"])
        
        if "vuln_scan" in scan_results:
            self.add_vuln_scan_results(report, scan_results["vuln_scan"])
        
        if "brute_force" in scan_results:
            self.add_brute_force_results(report, scan_results["brute_force"])
        
        if "auth_bypass" in scan_results:
            self.add_auth_bypass_results(report, scan_results["auth_bypass"])
        
        if "exploit" in scan_results:
            self.add_exploit_results(report, scan_results["exploit"])
    
    def generate_report(self, report: Report, format: ReportFormat = ReportFormat.HTML, 
                       template_name: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate a report in the specified format.
        
        Args:
            report: Report to generate
            format: Report format
            template_name: Optional template name to use
            
        Returns:
            Tuple of (report content, file extension)
        """
        # Use default template if none specified
        if template_name is None:
            template_name = self.default_template
        
        # Generate report based on format
        if format == ReportFormat.HTML:
            return self._generate_html_report(report, template_name), "html"
        elif format == ReportFormat.PDF:
            return self._generate_pdf_report(report, template_name), "pdf"
        elif format == ReportFormat.JSON:
            return report.to_json(), "json"
        elif format == ReportFormat.YAML:
            return report.to_yaml(), "yaml"
        elif format == ReportFormat.CSV:
            return self._generate_csv_report(report), "csv"
        elif format == ReportFormat.TEXT:
            return self._generate_text_report(report, template_name), "txt"
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report(report, template_name), "md"
        elif format == ReportFormat.XML:
            return self._generate_xml_report(report), "xml"
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_html_report(self, report: Report, template_name: str) -> str:
        """
        Generate an HTML report.
        
        Args:
            report: Report to generate
            template_name: Template name to use
            
        Returns:
            HTML report content
        """
        try:
            # Try to get the specified template
            template = self.jinja_env.get_template(f"{template_name}.html")
        except jinja2.exceptions.TemplateNotFound:
            # Fall back to default template
            self.logger.warning(f"Template {template_name}.html not found, using default")
            
            # Check if default template exists
            try:
                template = self.jinja_env.get_template("default.html")
            except jinja2.exceptions.TemplateNotFound:
                # Create a basic default template
                self.logger.warning("Default template not found, using built-in template")
                template_str = """<!DOCTYPE html>
<html>
<head>
    <title>{{ report.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        .section { margin-bottom: 20px; }
        .subsection { margin-left: 20px; margin-bottom: 15px; }
        .item { margin-left: 40px; margin-bottom: 10px; }
        .critical { color: #d9534f; }
        .high { color: #f0ad4e; }
        .medium { color: #5bc0de; }
        .low { color: #5cb85c; }
        .info { color: #5bc0de; }
    </style>
</head>
<body>
    <h1>{{ report.title }}</h1>
    <p><strong>Target:</strong> {{ report.target }}</p>
    <p><strong>Date:</strong> {{ report.creation_time|format_datetime }}</p>
    
    {% if report.summary %}
    <div class="summary">
        <h2>Summary</h2>
        <p>{{ report.summary }}</p>
    </div>
    {% endif %}
    
    {% for section in report.sections %}
    <div class="section">
        <h2>{{ section.title }}</h2>
        
        {% if section.summary %}
        <p>{{ section.summary }}</p>
        {% endif %}
        
        {% for item in section.items %}
        <div class="item {{ item.severity|lower }}">
            <h4>{{ item.title }}</h4>
            <p>{{ item.description }}</p>
        </div>
        {% endfor %}
        
        {% for subsection in section.subsections %}
        <div class="subsection">
            <h3>{{ subsection.title }}</h3>
            
            {% if subsection.summary %}
            <p>{{ subsection.summary }}</p>
            {% endif %}
            
            {% for item in subsection.items %}
            <div class="item {{ item.severity|lower }}">
                <h4>{{ item.title }}</h4>
                <p>{{ item.description }}</p>
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </div>
    {% endfor %}
</body>
</html>"""
                template = jinja2.Template(template_str)
        
        # Render the template
        return template.render(report=report.to_dict())
    
    def _generate_pdf_report(self, report: Report, template_name: str) -> str:
        """
        Generate a PDF report.
        
        Args:
            report: Report to generate
            template_name: Template name to use
            
        Returns:
            PDF report content as base64 encoded string
        """
        # Generate HTML report first
        html_content = self._generate_html_report(report, template_name)
        
        # TODO: Implement PDF generation
        # This would typically use a library like weasyprint or pdfkit
        # For now, return a placeholder message
        self.logger.warning("PDF generation not implemented, returning HTML")
        return html_content
    
    def _generate_csv_report(self, report: Report) -> str:
        """
        Generate a CSV report.
        
        Args:
            report: Report to generate
            
        Returns:
            CSV report content
        """
        # Create CSV content
        csv_rows = []
        
        # Add header row
        csv_rows.append(["Section", "Subsection", "Title", "Description", "Severity", "Timestamp"])
        
        # Add rows for each item in the report
        for section in report.sections:
            # Add section items
            for item in section.items:
                csv_rows.append([
                    section.title,
                    "",
                    item.title,
                    item.description,
                    item.severity.name,
                    datetime.datetime.fromtimestamp(item.timestamp).isoformat()
                ])
            
            # Add subsection items
            for subsection in section.subsections:
                for item in subsection.items:
                    csv_rows.append([
                        section.title,
                        subsection.title,
                        item.title,
                        item.description,
                        item.severity.name,
                        datetime.datetime.fromtimestamp(item.timestamp).isoformat()
                    ])
        
        # Convert to CSV string
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(csv_rows)
        return output.getvalue()
    
    def _generate_text_report(self, report: Report, template_name: str) -> str:
        """
        Generate a text report.
        
        Args:
            report: Report to generate
            template_name: Template name to use
            
        Returns:
            Text report content
        """
        try:
            # Try to get the specified template
            template = self.jinja_env.get_template(f"{template_name}.txt")
        except jinja2.exceptions.TemplateNotFound:
            # Fall back to default template
            self.logger.warning(f"Template {template_name}.txt not found, using default")
            
            # Check if default template exists
            try:
                template = self.jinja_env.get_template("default.txt")
            except jinja2.exceptions.TemplateNotFound:
                # Create a basic default template
                self.logger.warning("Default text template not found, using built-in template")
                template_str = """{{ report.title }}
Target: {{ report.target }}
Date: {{ report.creation_time|format_datetime }}

{% if report.summary %}
SUMMARY
-------
{{ report.summary }}

{% endif %}
{% for section in report.sections %}
{{ section.title }}
{{ '=' * section.title|length }}

{% if section.summary %}
{{ section.summary }}

{% endif %}
{% for item in section.items %}
* {{ item.title }} [{{ item.severity }}]
  {{ item.description }}

{% endfor %}
{% for subsection in section.subsections %}
{{ subsection.title }}
{{ '-' * subsection.title|length }}

{% if subsection.summary %}
{{ subsection.summary }}

{% endif %}
{% for item in subsection.items %}
* {{ item.title }} [{{ item.severity }}]
  {{ item.description }}

{% endfor %}
{% endfor %}
{% endfor %}"""
                template = jinja2.Template(template_str)
        
        # Render the template
        return template.render(report=report.to_dict())
    
    def _generate_markdown_report(self, report: Report, template_name: str) -> str:
        """
        Generate a Markdown report.
        
        Args:
            report: Report to generate
            template_name: Template name to use
            
        Returns:
            Markdown report content
        """
        try:
            # Try to get the specified template
            template = self.jinja_env.get_template(f"{template_name}.md")
        except jinja2.exceptions.TemplateNotFound:
            # Fall back to default template
            self.logger.warning(f"Template {template_name}.md not found, using default")
            
            # Check if default template exists
            try:
                template = self.jinja_env.get_template("default.md")
            except jinja2.exceptions.TemplateNotFound:
                # Create a basic default template
                self.logger.warning("Default markdown template not found, using built-in template")
                template_str = """# {{ report.title }}

**Target:** {{ report.target }}  
**Date:** {{ report.creation_time|format_datetime }}

{% if report.summary %}
## Summary

{{ report.summary }}

{% endif %}
{% for section in report.sections %}
## {{ section.title }}

{% if section.summary %}
{{ section.summary }}

{% endif %}
{% for item in section.items %}
### {{ item.title }}

**Severity:** {{ item.severity }}  
{{ item.description }}

{% endfor %}
{% for subsection in section.subsections %}
### {{ subsection.title }}

{% if subsection.summary %}
{{ subsection.summary }}

{% endif %}
{% for item in subsection.items %}
#### {{ item.title }}

**Severity:** {{ item.severity }}  
{{ item.description }}

{% endfor %}
{% endfor %}
{% endfor %}"""
                template = jinja2.Template(template_str)
        
        # Render the template
        return template.render(report=report.to_dict())
    
    def _generate_xml_report(self, report: Report) -> str:
        """
        Generate an XML report.
        
        Args:
            report: Report to generate
            
        Returns:
            XML report content
        """
        # Create XML content
        xml_lines = []
        xml_lines.append('<?xml version="1.0" encoding="UTF-8"?>')
        xml_lines.append(f'<report title="{report.title}" target="{report.target}" timestamp="{report.creation_time}">')
        
        if report.summary:
            xml_lines.append(f'  <summary>{report.summary}</summary>')
        
        for section in report.sections:
            xml_lines.append(f'  <section title="{section.title}">')
            
            if section.summary:
                xml_lines.append(f'    <summary>{section.summary}</summary>')
            
            for item in section.items:
                xml_lines.append(f'    <item title="{item.title}" severity="{item.severity.name}" timestamp="{item.timestamp}">')
                xml_lines.append(f'      <description>{item.description}</description>')
                xml_lines.append('    </item>')
            
            for subsection in section.subsections:
                xml_lines.append(f'    <subsection title="{subsection.title}">')
                
                if subsection.summary:
                    xml_lines.append(f'      <summary>{subsection.summary}</summary>')
                
                for item in subsection.items:
                    xml_lines.append(f'      <item title="{item.title}" severity="{item.severity.name}" timestamp="{item.timestamp}">')
                    xml_lines.append(f'        <description>{item.description}</description>')
                    xml_lines.append('      </item>')
                
                xml_lines.append('    </subsection>')
            
            xml_lines.append('  </section>')
        
        xml_lines.append('</report>')
        
        return '\n'.join(xml_lines)
    
    def save_report(self, report: Report, format: ReportFormat = ReportFormat.HTML, 
                   template_name: Optional[str] = None, filename: Optional[str] = None) -> str:
        """
        Generate and save a report to a file.
        
        Args:
            report: Report to generate
            format: Report format
            template_name: Optional template name to use
            filename: Optional filename to use (without extension)
            
        Returns:
            Path to the saved report file
        """
        # Generate report content
        content, extension = self.generate_report(report, format, template_name)
        
        # Generate filename if not provided
        if filename is None:
            timestamp = int(time.time())
            safe_title = re.sub(r'[^\w\-]', '_', report.title.lower())
            filename = f"{safe_title}_{timestamp}"
        
        # Ensure reports directory exists
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Save report to file
        filepath = os.path.join(self.reports_dir, f"{filename}.{extension}")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.logger.info(f"Saved report to {filepath}")
        return filepath
    
    def list_reports(self) -> List[Dict[str, Any]]:
        """
        List all saved reports.
        
        Returns:
            List of dictionaries with report information
        """
        reports = []
        
        # Ensure reports directory exists
        if not os.path.exists(self.reports_dir):
            return reports
        
        # List all report files
        for filename in os.listdir(self.reports_dir):
            filepath = os.path.join(self.reports_dir, filename)
            
            if os.path.isfile(filepath):
                # Get file information
                stat = os.stat(filepath)
                
                # Extract extension
                name, ext = os.path.splitext(filename)
                ext = ext.lstrip('.')
                
                # Map extension to format
                format_name = ext.upper()
                try:
                    format_enum = ReportFormat[format_name]
                except (KeyError, ValueError):
                    format_enum = None
                
                reports.append({
                    "filename": filename,
                    "path": filepath,
                    "name": name,
                    "format": format_name,
                    "size": stat.st_size,
                    "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        # Sort by modification time (newest first)
        reports.sort(key=lambda r: r["modified"], reverse=True)
        
        return reports
    
    def get_report(self, filename: str) -> Optional[str]:
        """
        Get the content of a saved report.
        
        Args:
            filename: Name of the report file
            
        Returns:
            Report content or None if not found
        """
        filepath = os.path.join(self.reports_dir, filename)
        
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.logger.warning(f"Report file not found: {filepath}")
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading report file {filepath}: {str(e)}")
            return None
    
    def delete_report(self, filename: str) -> bool:
        """
        Delete a saved report.
        
        Args:
            filename: Name of the report file
            
        Returns:
            True if report was deleted, False otherwise
        """
        filepath = os.path.join(self.reports_dir, filename)
        
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.logger.warning(f"Report file not found: {filepath}")
            return False
        
        try:
            os.remove(filepath)
            self.logger.info(f"Deleted report file: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting report file {filepath}: {str(e)}")
            return False