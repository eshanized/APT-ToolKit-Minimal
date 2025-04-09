import os
import re
import sys
import time
import json
import shutil
import socket
import hashlib
import platform
import subprocess
import random
import string
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union, Set, Callable
from urllib.parse import urlparse, urljoin

from src.utils.logger import get_module_logger

# Initialize the logger
logger = get_module_logger("helpers")


def is_root() -> bool:
    """
    Check if the current process is running with root/administrator privileges.
    
    Returns:
        bool: True if running as root/administrator, False otherwise.
    """
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning(f"Error checking admin privileges: {e}")
            return False
    else:
        return os.geteuid() == 0


def get_timestamp(format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Get the current timestamp in the specified format.
    
    Args:
        format_str: The format string for the timestamp.
        
    Returns:
        str: Formatted timestamp string.
    """
    return datetime.now().strftime(format_str)


def generate_random_string(length: int = 8, include_special: bool = False) -> str:
    """
    Generate a random string of specified length.
    
    Args:
        length: Length of the random string.
        include_special: Whether to include special characters.
        
    Returns:
        str: The random string.
    """
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += string.punctuation
    
    return ''.join(random.choice(chars) for _ in range(length))


def get_file_hash(file_path: str, hash_type: str = "sha256") -> str:
    """
    Calculate the hash of a file.
    
    Args:
        file_path: Path to the file.
        hash_type: Type of hash to calculate (md5, sha1, sha256, etc.).
        
    Returns:
        str: The calculated hash as a hexadecimal string.
        
    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the hash type is not supported.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hash_funcs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    if hash_type.lower() not in hash_funcs:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    hash_func = hash_funcs[hash_type.lower()]()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def url_to_filepath(url: str, base_dir: str = "") -> str:
    """
    Convert a URL to a safe file path.
    
    Args:
        url: The URL to convert.
        base_dir: Base directory to prepend to the file path.
        
    Returns:
        str: The file path.
    """
    # Parse the URL
    parsed = urlparse(url)
    
    # Create a directory structure based on the host
    directory = os.path.join(base_dir, parsed.netloc)
    
    # Create a file name from the path
    path = parsed.path.strip("/").replace("/", "_")
    query = parsed.query
    
    if not path:
        path = "index"
    
    if query:
        # Hash the query string if it's too long
        if len(query) > 50:
            query = hashlib.md5(query.encode()).hexdigest()
        path = f"{path}_{query}"
    
    # Remove any invalid characters and limit the length
    path = re.sub(r'[\\/*?:"<>|]', '_', path)
    path = path[:100]  # Limit to reasonable filename length
    
    return os.path.join(directory, path)


def run_command(command: Union[str, List[str]], 
                timeout: Optional[int] = None, 
                shell: bool = False,
                capture_output: bool = True) -> Tuple[int, str, str]:
    """
    Run a system command and return the output.
    
    Args:
        command: Command to run, either as a string or list of arguments.
        timeout: Command timeout in seconds.
        shell: Whether to use shell execution.
        capture_output: Whether to capture the command output.
        
    Returns:
        Tuple containing the return code, stdout and stderr.
        
    Raises:
        subprocess.TimeoutExpired: If the command times out.
        subprocess.SubprocessError: For other subprocess errors.
    """
    try:
        if capture_output:
            result = subprocess.run(
                command,
                timeout=timeout,
                shell=shell,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            return result.returncode, result.stdout, result.stderr
        else:
            result = subprocess.run(
                command,
                timeout=timeout,
                shell=shell,
                check=False
            )
            return result.returncode, "", ""
            
    except subprocess.TimeoutExpired as e:
        logger.warning(f"Command timed out after {timeout} seconds: {command}")
        return 124, "", str(e)
    except subprocess.SubprocessError as e:
        logger.error(f"Error running command: {e}")
        return 1, "", str(e)


def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip: String to check.
        
    Returns:
        bool: True if the string is a valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    """
    Check if a string is a valid IPv4 address.
    
    Args:
        ip: String to check.
        
    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """
    Check if a string is a valid IPv6 address.
    
    Args:
        ip: String to check.
        
    Returns:
        bool: True if the string is a valid IPv6 address, False otherwise.
    """
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def parse_ip_range(ip_range: str) -> List[str]:
    """
    Parse an IP range string and return a list of IP addresses.
    
    Args:
        ip_range: IP range string (e.g., "192.168.1.1-192.168.1.10" or "192.168.1.0/24").
        
    Returns:
        List of IP addresses.
        
    Raises:
        ValueError: If the IP range format is invalid.
    """
    # Try CIDR notation
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network]
        except ValueError:
            pass
    
    # Try range notation
    if '-' in ip_range:
        try:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # If only the last part of the IP is specified in the end range
            if '.' not in end_ip:
                parts = start_ip.split('.')
                parts[-1] = end_ip
                end_ip = '.'.join(parts)
            
            if not is_valid_ipv4(start_ip) or not is_valid_ipv4(end_ip):
                raise ValueError(f"Invalid IP range: {ip_range}")
            
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            
            if end_int < start_int:
                raise ValueError(f"End IP must be greater than start IP: {ip_range}")
            
            # Limit to reasonable range size to prevent memory issues
            if end_int - start_int > 65535:
                raise ValueError(f"IP range too large (max 65535 addresses): {ip_range}")
            
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]
        except ValueError as e:
            raise ValueError(f"Invalid IP range: {ip_range} - {str(e)}")
    
    # Single IP
    if is_valid_ip(ip_range):
        return [ip_range]
    
    raise ValueError(f"Invalid IP range format: {ip_range}")


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse a port range string and return a list of ports.
    
    Args:
        port_range: Port range string (e.g., "80,443,8000-8100").
        
    Returns:
        List of port numbers.
        
    Raises:
        ValueError: If the port range format is invalid.
    """
    ports = []
    
    for part in port_range.split(','):
        part = part.strip()
        
        if '-' in part:
            # Range
            try:
                start, end = map(int, part.split('-'))
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                ports.extend(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port number: {port}")
                ports.append(port)
            except ValueError:
                raise ValueError(f"Invalid port: {part}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host.
    
    Args:
        host: Host name or IP address.
        port: Port number to check.
        timeout: Timeout in seconds.
        
    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.gaierror, socket.error) as e:
        logger.debug(f"Error checking port {port} on {host}: {e}")
        return False


def is_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: String to check.
        
    Returns:
        bool: True if the string is a valid URL, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has a scheme and proper formatting.
    
    Args:
        url: URL to normalize.
        
    Returns:
        str: Normalized URL.
    """
    if not url:
        return ""
        
    url = url.strip()
    
    if '://' not in url:
        url = 'http://' + url
    
    parsed = urlparse(url)
    
    # Ensure path ends with / if it's empty
    if not parsed.path:
        url += '/'
    
    return url


def get_base_url(url: str) -> str:
    """
    Get the base URL (scheme + netloc) from a URL.
    
    Args:
        url: URL to process.
        
    Returns:
        str: Base URL.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def join_url(base: str, path: str) -> str:
    """
    Join a base URL and a path, handling trailing slashes correctly.
    
    Args:
        base: Base URL.
        path: Path to join.
        
    Returns:
        str: Joined URL.
    """
    return urljoin(base, path)


def format_bytes(bytes_num: int) -> str:
    """
    Format a byte count as a human-readable string.
    
    Args:
        bytes_num: Number of bytes.
        
    Returns:
        str: Formatted string (e.g., "1.23 MB").
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024 or unit == 'TB':
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024


def extract_links(html: str, base_url: str = "") -> List[str]:
    """
    Extract links from HTML content.
    
    Args:
        html: HTML content to parse.
        base_url: Base URL for resolving relative links.
        
    Returns:
        List of URLs found in the HTML.
    """
    if not html:
        return []
        
    # Simple regex pattern for href extraction
    # For production use, consider using a proper HTML parser like BeautifulSoup
    pattern = re.compile(r'href=[\'"]?([^\'" >]+)', re.IGNORECASE)
    links = pattern.findall(html)
    
    # Resolve relative URLs if base_url is provided
    if base_url:
        links = [urljoin(base_url, link) for link in links]
    
    return links


def load_wordlist(file_path: str) -> List[str]:
    """
    Load a wordlist file and return its contents as a list of strings.
    
    Args:
        file_path: Path to the wordlist file.
        
    Returns:
        List of strings from the wordlist.
        
    Raises:
        FileNotFoundError: If the wordlist file doesn't exist.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Wordlist file not found: {file_path}")
        
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def save_json(data: Any, file_path: str, pretty: bool = True) -> None:
    """
    Save data as a JSON file.
    
    Args:
        data: Data to save.
        file_path: Path to save the file.
        pretty: Whether to format the JSON for readability.
        
    Raises:
        IOError: If there's an error writing to the file.
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=4, sort_keys=True)
            else:
                json.dump(data, f)
                
    except Exception as e:
        logger.error(f"Error saving JSON to {file_path}: {e}")
        raise IOError(f"Failed to save JSON file: {e}")


def load_json(file_path: str) -> Any:
    """
    Load data from a JSON file.
    
    Args:
        file_path: Path to the JSON file.
        
    Returns:
        Loaded data.
        
    Raises:
        FileNotFoundError: If the file doesn't exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"JSON file not found: {file_path}")
        
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def is_tool_available(tool_name: str) -> bool:
    """
    Check if an external tool is available in the system PATH.
    
    Args:
        tool_name: Name of the tool to check.
        
    Returns:
        bool: True if the tool is available, False otherwise.
    """
    try:
        if platform.system() == 'Windows':
            # On Windows, check for the tool with a different command
            result = subprocess.run(
                f"where {tool_name}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
        else:
            # On Unix-like systems, use the which command
            result = subprocess.run(
                ["which", tool_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
        return result.returncode == 0
    except Exception:
        return False


def safe_extract_version(output: str, pattern: str) -> Optional[str]:
    """
    Safely extract a version string from command output using a regex pattern.
    
    Args:
        output: Command output to parse.
        pattern: Regex pattern with a single capture group for the version.
        
    Returns:
        The extracted version string or None if not found.
    """
    try:
        match = re.search(pattern, output)
        if match and match.group(1):
            return match.group(1).strip()
        return None
    except Exception as e:
        logger.warning(f"Error extracting version: {e}")
        return None


def check_tool_version(tool_name: str, min_version: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Check if a tool is installed and meets the minimum version requirement.
    
    Args:
        tool_name: Name of the tool to check.
        min_version: Minimum required version (e.g., "2.1.0").
        
    Returns:
        Tuple containing (is_available, version_string).
    """
    if not is_tool_available(tool_name):
        return False, None
        
    # Common version check commands for popular tools
    version_commands = {
        "nmap": [tool_name, "--version"],
        "sqlmap": [tool_name, "--version"],
        "nikto": [tool_name, "-Version"],
        "dirb": [tool_name, "-h"],  # Dirb shows version in help
        "metasploit": ["msfconsole", "-v"],
        "python": [tool_name, "--version"],
        "pip": [tool_name, "--version"]
    }
    
    # Default to --version
    command = version_commands.get(tool_name, [tool_name, "--version"])
    
    # Common regex patterns for version extraction
    version_patterns = {
        "nmap": r"Nmap version (\d+\.\d+(?:\.\d+)?)",
        "sqlmap": r"(\d+\.\d+(?:\.\d+)?)",
        "nikto": r"Nikto v(\d+\.\d+(?:\.\d+)?)",
        "dirb": r"DIRB v(\d+\.\d+(?:\.\d+)?)",
        "metasploit": r"Framework: (\d+\.\d+(?:\.\d+)?)",
        "python": r"Python (\d+\.\d+(?:\.\d+)?)",
        "pip": r"pip (\d+\.\d+(?:\.\d+)?)"
    }
    
    # Default pattern for most tools
    pattern = version_patterns.get(tool_name, r"(\d+\.\d+(?:\.\d+)?)")
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False
        )
        
        # Check both stdout and stderr for version information
        output = result.stdout + result.stderr
        version = safe_extract_version(output, pattern)
        
        if not version:
            return True, None  # Tool exists but couldn't extract version
        
        # Check minimum version if specified
        if min_version:
            from packaging import version as pkg_version
            try:
                current_version = pkg_version.parse(version)
                min_version_parsed = pkg_version.parse(min_version)
                if current_version < min_version_parsed:
                    logger.warning(f"{tool_name} version {version} is less than minimum required {min_version}")
                    return False, version
            except Exception as e:
                logger.warning(f"Error comparing versions: {e}")
                # Continue if version comparison fails
        
        return True, version
    
    except Exception as e:
        logger.warning(f"Error checking {tool_name} version: {e}")
        return True, None  # Tool exists but couldn't get version


def rate_limit(func: Callable, rate: float = 1.0, per: float = 1.0) -> Callable:
    """
    Decorator to rate limit a function.
    
    Args:
        func: Function to rate limit.
        rate: Number of calls allowed in the time period.
        per: Time period in seconds.
        
    Returns:
        Rate-limited function.
    """
    last_called = [0.0]
    min_interval = per / rate

    def wrapper(*args, **kwargs):
        now = time.time()
        elapsed = now - last_called[0]
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)
        result = func(*args, **kwargs)
        last_called[0] = time.time()
        return result

    return wrapper


def retry(func: Callable, 
          retries: int = 3, 
          delay: float = 1.0, 
          backoff: float = 2.0, 
          exceptions: tuple = (Exception,)) -> Callable:
    """
    Decorator to retry a function on failure.
    
    Args:
        func: Function to retry.
        retries: Maximum number of retries.
        delay: Initial delay between retries in seconds.
        backoff: Backoff multiplier.
        exceptions: Tuple of exceptions to catch.
        
    Returns:
        Function with retry logic.
    """
    def wrapper(*args, **kwargs):
        attempt = 0
        current_delay = delay
        
        while attempt < retries:
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                attempt += 1
                if attempt >= retries:
                    logger.warning(f"Function {func.__name__} failed after {retries} retries: {e}")
                    raise
                
                logger.debug(f"Retry {attempt}/{retries} for {func.__name__} after {current_delay}s: {e}")
                time.sleep(current_delay)
                current_delay *= backoff
                
    return wrapper


def ensure_dir(directory: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory: Directory path to ensure exists.
    """
    os.makedirs(directory, exist_ok=True)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a string to be used as a filename.
    
    Args:
        filename: String to sanitize.
        
    Returns:
        str: Sanitized filename.
    """
    # Replace invalid characters with underscore
    sanitized = re.sub(r'[\\/*?:"<>|]', '_', filename)
    
    # Replace multiple underscores with a single one
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Remove leading/trailing underscores and spaces
    sanitized = sanitized.strip('_ ')
    
    # Ensure the filename is not empty
    if not sanitized:
        sanitized = "unnamed"
        
    # Limit the length
    if len(sanitized) > 255:
        # Keep the extension if present
        parts = sanitized.rsplit('.', 1)
        if len(parts) > 1 and len(parts[1]) <= 10:
            sanitized = parts[0][:244] + '.' + parts[1]
        else:
            sanitized = sanitized[:255]
            
    return sanitized


def get_system_info() -> Dict[str, str]:
    """
    Get system information.
    
    Returns:
        Dict containing system information.
    """
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "processor": platform.processor(),
        "python": platform.python_version()
    }
    
    # Add more system-specific information
    if platform.system() == 'Linux':
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        info['os'] = line.split('=', 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
    
    return info


def merge_dicts(dict1: Dict, dict2: Dict, overwrite: bool = True) -> Dict:
    """
    Recursively merge two dictionaries.
    
    Args:
        dict1: First dictionary.
        dict2: Second dictionary.
        overwrite: Whether to overwrite values in dict1 with values from dict2.
        
    Returns:
        Merged dictionary.
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value, overwrite)
        elif key not in result or overwrite:
            result[key] = value
            
    return result


if __name__ == "__main__":
    # Example usage
    print(f"Running as root: {is_root()}")
    print(f"Current timestamp: {get_timestamp()}")
    print(f"Random string: {generate_random_string(12, True)}")
    
    # Test IP and port functions
    ip_range = "192.168.1.1-5"
    print(f"IP range {ip_range}: {parse_ip_range(ip_range)}")
    
    port_range = "80,443,8000-8005"
    print(f"Port range {port_range}: {parse_port_range(port_range)}")
    
    # Test system info
    print("System info:", get_system_info())