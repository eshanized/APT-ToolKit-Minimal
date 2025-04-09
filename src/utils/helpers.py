import os
import socket
import ipaddress
from typing import List, Union, Optional


def is_valid_ip(address: str) -> bool:
    """
    Check if the input string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to an IP address.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def read_wordlist(file_path: str) -> List[str]:
    """
    Load lines from a wordlist file.
    """
    if not os.path.isfile(file_path):
        return []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def normalize_url(url: str) -> str:
    """
    Ensure the URL starts with http:// or https://
    """
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url


def save_output_to_file(output: str, filename: str = "output.txt") -> bool:
    """
    Save a string to a text file.
    """
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write(output)
        return True
    except Exception:
        return False


def chunk_list(lst: List, size: int) -> List[List]:
    """
    Split a list into chunks of a specific size.
    """
    return [lst[i:i + size] for i in range(0, len(lst), size)]
