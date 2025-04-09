import socket
import requests
import whois
import json
from utils.helpers import is_valid_ip, resolve_hostname
from utils.logger import get_logger

logger = get_logger("ReconModule")


def run(target: str, **kwargs) -> dict:
    """
    Reconnaissance module to gather basic information about a domain or IP.
    
    Args:
        target (str): The target domain or IP address.
        **kwargs: Optional arguments (e.g., timeout, headers)

    Returns:
        dict: Recon results.
    """
    logger.info(f"Starting reconnaissance on target: {target}")
    results = {
        "target": target,
        "ip_address": None,
        "whois": None,
        "dns": None,
        "http_headers": None,
        "reverse_dns": None,
        "error": None,
    }

    try:
        # Resolve hostname
        ip = resolve_hostname(target) if not is_valid_ip(target) else target
        results["ip_address"] = ip

        if ip:
            # Reverse DNS lookup
            try:
                rev_dns = socket.gethostbyaddr(ip)[0]
                results["reverse_dns"] = rev_dns
            except Exception:
                results["reverse_dns"] = None

        # Whois lookup
        try:
            whois_data = whois.whois(target)
            results["whois"] = {
                "domain_name": str(whois_data.domain_name),
                "registrar": str(whois_data.registrar),
                "creation_date": str(whois_data.creation_date),
                "expiration_date": str(whois_data.expiration_date),
                "name_servers": whois_data.name_servers,
            }
        except Exception as e:
            logger.warning(f"Whois lookup failed: {e}")

        # DNS Lookup
        try:
            dns_info = socket.gethostbyname_ex(target)
            results["dns"] = {
                "hostname": dns_info[0],
                "aliases": dns_info[1],
                "ip_addresses": dns_info[2]
            }
        except Exception as e:
            logger.warning(f"DNS lookup failed: {e}")

        # HTTP Headers
        try:
            headers = requests.get(f"http://{target}", timeout=kwargs.get("timeout", 5)).headers
            results["http_headers"] = dict(headers)
        except Exception as e:
            logger.warning(f"HTTP header fetch failed: {e}")

    except Exception as e:
        logger.error(f"Recon failed: {e}")
        results["error"] = str(e)

    logger.info(f"Recon completed for {target}")
    return results
