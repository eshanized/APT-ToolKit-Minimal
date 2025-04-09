"""
Validators module for the apt toolkit.

This module provides validation functions to ensure inputs meet expected formats and requirements.
"""

import os
import re
import ipaddress
from typing import Union, Optional, List, Dict, Any


def validate_path(path: str, must_exist: bool = True, must_be_dir: bool = False,
                 must_be_file: bool = False, writable: bool = False) -> bool:
    """
    Validate that a path exists and meets specified requirements.
    
    Args:
        path: The file system path to validate
        must_exist: If True, the path must exist
        must_be_dir: If True, the path must be a directory
        must_be_file: If True, the path must be a file
        writable: If True, the path must be writable
        
    Returns:
        bool: True if path meets all specified requirements, False otherwise
    """
    if not path:
        return False
        
    if must_exist and not os.path.exists(path):
        return False
        
    if must_be_dir and not os.path.isdir(path):
        return False
        
    if must_be_file and not os.path.isfile(path):
        return False
        
    if writable and not os.access(path, os.W_OK):
        return False
        
    return True


def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 or IPv6 address.
    
    Args:
        ip: String to validate as IP address
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ip_network(network: str) -> bool:
    """
    Validate if a string is a valid IPv4 or IPv6 network/CIDR notation.
    
    Args:
        network: String to validate as IP network (e.g., "192.168.1.0/24")
        
    Returns:
        bool: True if valid IP network, False otherwise
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: Union[str, int]) -> bool:
    """
    Validate if a value is a valid port number (1-65535).
    
    Args:
        port: Value to validate as port number
        
    Returns:
        bool: True if valid port, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_hostname(hostname: str) -> bool:
    """
    Validate if a string is a valid hostname.
    
    Args:
        hostname: String to validate as hostname
        
    Returns:
        bool: True if valid hostname, False otherwise
    """
    if not hostname or len(hostname) > 255:
        return False
        
    # RFC 1123 hostname pattern
    hostname_pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*$'
    return bool(re.match(hostname_pattern, hostname))


def validate_url(url: str) -> bool:
    """
    Validate if a string is a valid URL.
    
    Args:
        url: String to validate as URL
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    # Basic URL validation pattern
    url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    return bool(re.match(url_pattern, url))


def validate_email(email: str) -> bool:
    """
    Validate if a string is a formatted as a valid email address.
    
    Args:
        email: String to validate as email
        
    Returns:
        bool: True if valid email format, False otherwise
    """
    # RFC 5322 compliant email regex pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


def validate_package_name(package_name: str) -> bool:
    """
    Validate if a string is a valid apt package name.
    
    Args:
        package_name: String to validate as package name
        
    Returns:
        bool: True if valid package name, False otherwise
    """
    # Debian package naming convention
    pkg_pattern = r'^[a-z0-9][-a-z0-9+.]*$'
    return bool(re.match(pkg_pattern, package_name))


def validate_version_string(version: str) -> bool:
    """
    Validate if a string is formatted as a valid semantic version.
    
    Args:
        version: String to validate as version
        
    Returns:
        bool: True if valid version format, False otherwise
    """
    # Semantic versioning pattern (major.minor.patch with optional pre-release/build metadata)
    semver_pattern = r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
    return bool(re.match(semver_pattern, version))


def validate_config_dict(config: Dict[str, Any], required_keys: List[str] = None, 
                        allowed_keys: List[str] = None) -> bool:
    """
    Validate a configuration dictionary.
    
    Args:
        config: Dictionary to validate
        required_keys: List of keys that must be in the dictionary
        allowed_keys: List of all allowed keys (if specified, all other keys are invalid)
        
    Returns:
        bool: True if valid config, False otherwise
    """
    if not isinstance(config, dict):
        return False
        
    if required_keys:
        if not all(key in config for key in required_keys):
            return False
            
    if allowed_keys:
        if not all(key in allowed_keys for key in config.keys()):
            return False
            
    return True


def validate_uuid(uuid_str: str) -> bool:
    """
    Validate if a string is formatted as a valid UUID.
    
    Args:
        uuid_str: String to validate as UUID
        
    Returns:
        bool: True if valid UUID format, False otherwise
    """
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    return bool(re.match(uuid_pattern, uuid_str, re.I))


def validate_mac_address(mac: str) -> bool:
    """
    Validate if a string is formatted as a valid MAC address.
    
    Args:
        mac: String to validate as MAC address
        
    Returns:
        bool: True if valid MAC address format, False otherwise
    """
    # Support various MAC address formats (with or without separators)
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$|^([0-9A-Fa-f]{12})$'
    return bool(re.match(mac_pattern, mac))