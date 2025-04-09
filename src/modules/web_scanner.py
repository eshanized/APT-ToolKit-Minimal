"""
Web Scanner module for the APT toolkit.

This module provides functionality for scanning web applications,
identifying technologies, discovering content, and detecting vulnerabilities.
"""

import os
import re
import time
import json
import urllib.parse
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from urllib.parse import urlparse, urljoin

from src.utils.logger import get_module_logger
from src.utils.config import ConfigManager
from src.utils.network import NetworkUtils, network_utils

logger = get_module_logger("web_scanner")

class VulnerabilitySeverity(Enum):
    """Enumeration of vulnerability severity levels"""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

@dataclass
class WebTechnology:
    """Data class for web technology information"""
    name: str
    version: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    category: str = ""  # CMS, framework, language, server, etc.
    cpe: str = ""  # Common Platform Enumeration identifier
    website: str = ""
    detection_method: str = ""  # headers, html, js, etc.

@dataclass
class WebEndpoint:
    """Data class for web endpoint information"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    size: int = 0
    response_time: float = 0.0
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    is_dynamic: bool = False
    notes: List[str] = field(default_factory=list)

@dataclass
class WebVulnerability:
    """Data class for web vulnerability information"""
    name: str
    url: str
    severity: VulnerabilitySeverity
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    cwe_id: str = ""  # Common Weakness Enumeration ID
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0

@dataclass
class WebPage:
    """Data class for web page information"""
    url: str
    status_code: int = 0
    title: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    size: int = 0
    response_time: float = 0.0
    technologies: List[WebTechnology] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)

@dataclass
class WebScanResult:
    """Data class for web scanning results"""
    target_url: str
    scan_time: float = field(default_factory=time.time)
    pages: List[WebPage] = field(default_factory=list)
    endpoints: List[WebEndpoint] = field(default_factory=list)
    technologies: List[WebTechnology] = field(default_factory=list)
    vulnerabilities: List[WebVulnerability] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

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
            logger.info(f"Saved web scan results to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results to {filename}: {e}")
            return False


class WebScanner:
    """
    Web application scanner for discovering content, identifying technologies,
    and detecting vulnerabilities in web applications.
    """
    
    # Common web paths to check
    COMMON_PATHS = [
        "/", "/robots.txt", "/sitemap.xml", "/admin", "/login", "/wp-admin",
        "/administrator", "/phpmyadmin", "/manager", "/api", "/console",
        "/.git", "/.env", "/backup", "/config", "/debug", "/test", "/phpinfo.php"
    ]
    
    # Technology fingerprints (simplified for demonstration)
    TECHNOLOGY_FINGERPRINTS = {
        "headers": {
            "Server": {
                "Apache": {"regex": r"Apache(?:/([0-9.]+))?", "category": "server"},
                "Nginx": {"regex": r"nginx(?:/([0-9.]+))?", "category": "server"},
                "IIS": {"regex": r"Microsoft-IIS(?:/([0-9.]+))?", "category": "server"},
                "Tomcat": {"regex": r"Apache-Coyote(?:/([0-9.]+))?", "category": "server"}
            },
            "X-Powered-By": {
                "PHP": {"regex": r"PHP(?:/([0-9.]+))?", "category": "language"},
                "ASP.NET": {"regex": r"ASP\.NET", "category": "framework"},
                "Express": {"regex": r"Express", "category": "framework"}
            },
            "Set-Cookie": {
                "WordPress": {"regex": r"wordpress_[^=]*=", "category": "cms"},
                "Joomla": {"regex": r"joomla_[^=]*=", "category": "cms"},
                "Drupal": {"regex": r"Drupal[^=]*=", "category": "cms"},
                "Laravel": {"regex": r"laravel_session", "category": "framework"}
            }
        },
        "html": {
            "WordPress": {"regex": r"wp-content|wp-includes", "category": "cms"},
            "Joomla": {"regex": r"joomla!|\/administrator\/|com_content", "category": "cms"},
            "Drupal": {"regex": r"Drupal|drupal|sites/all|sites/default", "category": "cms"},
            "Bootstrap": {"regex": r"bootstrap.(?:min.)?css|bootstrap.(?:min.)?js", "category": "framework"},
            "jQuery": {"regex": r"jquery.(?:min.)?js", "category": "library"},
            "React": {"regex": r"react.(?:min.)?js|react-dom", "category": "framework"},
            "Angular": {"regex": r"angular.(?:min.)?js|ng-app|ng-controller", "category": "framework"},
            "Vue": {"regex": r"vue.(?:min.)?js|v-app|v-bind", "category": "framework"}
        },
        "meta": {
            "generator": {
                "WordPress": {"regex": r"WordPress ?(?:([0-9.]+))?", "category": "cms"},
                "Joomla": {"regex": r"Joomla! ?(?:([0-9.]+))?", "category": "cms"},
                "Drupal": {"regex": r"Drupal ?(?:([0-9.]+))?", "category": "cms"},
                "Shopify": {"regex": r"Shopify", "category": "ecommerce"},
                "Wix": {"regex": r"Wix.com", "category": "cms"},
                "Ghost": {"regex": r"Ghost ?(?:([0-9.]+))?", "category": "cms"}
            }
        }
    }
    
    # Vulnerability checks (simplified for demonstration)
    VULNERABILITY_CHECKS = {
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "severity": VulnerabilitySeverity.HIGH,
            "cwe_id": "CWE-79",
            "description": "Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject client-side scripts into web pages viewed by other users.",
            "remediation": "Implement proper input validation and output encoding.",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting"
            ]
        },
        "sqli": {
            "name": "SQL Injection",
            "severity": VulnerabilitySeverity.CRITICAL,
            "cwe_id": "CWE-89",
            "description": "SQL Injection vulnerabilities allow attackers to inject malicious SQL code into database queries.",
            "remediation": "Use parameterized queries or prepared statements.",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection"
            ]
        },
        "open_redirect": {
            "name": "Open Redirect",
            "severity": VulnerabilitySeverity.MEDIUM,
            "cwe_id": "CWE-601",
            "description": "Open Redirect vulnerabilities allow attackers to redirect users to malicious websites.",
            "remediation": "Implement a whitelist of allowed redirect URLs or use relative URLs.",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"
            ]
        },
        "information_disclosure": {
            "name": "Information Disclosure",
            "severity": VulnerabilitySeverity.MEDIUM,
            "cwe_id": "CWE-200",
            "description": "Information Disclosure vulnerabilities expose sensitive information to unauthorized users.",
            "remediation": "Ensure sensitive information is properly protected and not exposed in responses.",
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://portswigger.net/kb/issues/00600300_information-disclosure"
            ]
        }
    }
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the web scanner.
        
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
        self.timeout = 10
        self.max_threads = 10
        self.max_depth = 3
        self.max_pages = 100
        self.user_agent = "Mozilla/5.0 APT-Toolkit WebScanner"
        self.follow_redirects = True
        self.scan_forms = True
        self.test_xss = True
        self.test_sqli = True
        self.test_open_redirect = True
        self.respect_robots = True
        self.cookies = {}
        
        if config:
            self.timeout = config.get("modules.web_scanner.timeout", 10)
            self.max_threads = config.get("modules.web_scanner.max_threads", 10)
            self.max_depth = config.get("modules.web_scanner.max_depth", 3)
            self.max_pages = config.get("modules.web_scanner.max_pages", 100)
            self.user_agent = config.get("modules.web_scanner.user_agent", self.user_agent)
            self.follow_redirects = config.get("modules.web_scanner.follow_redirects", True)
            self.scan_forms = config.get("modules.web_scanner.scan_forms", True)
            self.test_xss = config.get("modules.web_scanner.test_xss", True)
            self.test_sqli = config.get("modules.web_scanner.test_sqli", True)
            self.test_open_redirect = config.get("modules.web_scanner.test_open_redirect", True)
            self.respect_robots = config.get("modules.web_scanner.respect_robots", True)
            
            # Load cookies if specified
            cookies_str = config.get("modules.web_scanner.cookies", "")
            if cookies_str:
                try:
                    self.cookies = json.loads(cookies_str)
                except Exception as e:
                    logger.error(f"Failed to parse cookies from config: {e}")
    
    def scan(self, target_url: str, **kwargs) -> WebScanResult:
        """
        Scan a web application for content, technologies, and vulnerabilities.
        
        Args:
            target_url: URL of the web application to scan
            **kwargs: Optional scan parameters:
                - timeout: Request timeout in seconds
                - max_threads: Maximum number of concurrent threads
                - max_depth: Maximum crawl depth
                - max_pages: Maximum number of pages to scan
                - user_agent: User agent string to use
                - follow_redirects: Whether to follow redirects
                - scan_forms: Whether to scan forms
                - test_xss: Whether to test for XSS vulnerabilities
                - test_sqli: Whether to test for SQL injection vulnerabilities
                - test_open_redirect: Whether to test for open redirect vulnerabilities
                - respect_robots: Whether to respect robots.txt
                - cookies: Dictionary of cookies to include in requests
                
        Returns:
            WebScanResult: Web scanning results
        """
        start_time = time.time()
        
        # Parse scan parameters
        timeout = kwargs.get("timeout", self.timeout)
        max_threads = kwargs.get("max_threads", self.max_threads)
        max_depth = kwargs.get("max_depth", self.max_depth)
        max_pages = kwargs.get("max_pages", self.max_pages)
        user_agent = kwargs.get("user_agent", self.user_agent)
        follow_redirects = kwargs.get("follow_redirects", self.follow_redirects)
        scan_forms = kwargs.get("scan_forms", self.scan_forms)
        test_xss = kwargs.get("test_xss", self.test_xss)
        test_sqli = kwargs.get("test_sqli", self.test_sqli)
        test_open_redirect = kwargs.get("test_open_redirect", self.test_open_redirect)
        respect_robots = kwargs.get("respect_robots", self.respect_robots)
        cookies = kwargs.get("cookies", self.cookies)
        
        # Normalize target URL
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        
        # Remove trailing slash if present
        if target_url.endswith("/"):
            target_url = target_url[:-1]
        
        # Initialize result object
        result = WebScanResult(target_url=target_url)
        
        # Set up request headers
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache"
        }
        
        logger.info(f"Starting web scan of {target_url}")
        
        try:
            # Phase 1: Initial scan of the target URL
            logger.info(f"Performing initial scan of {target_url}")
            initial_page = self._scan_page(target_url, headers, cookies, timeout, follow_redirects)
            
            if not initial_page:
                error_msg = f"Failed to access {target_url}"
                logger.error(error_msg)
                result.errors.append(error_msg)
                result.notes.append("Initial scan failed, unable to access target URL")
                return result
            
            result.pages.append(initial_page)
            
            # Extract base URL for relative link resolution
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Phase 2: Check robots.txt if enabled
            disallowed_paths = []
            if respect_robots:
                robots_url = f"{base_url}/robots.txt"
                logger.info(f"Checking robots.txt at {robots_url}")
                disallowed_paths = self._parse_robots_txt(robots_url, headers, cookies, timeout)
                
                if disallowed_paths:
                    result.notes.append(f"Found {len(disallowed_paths)} disallowed paths in robots.txt")
            
            # Phase 3: Check common paths
            logger.info(f"Checking common paths on {base_url}")
            discovered_endpoints = self._check_common_paths(
                base_url, 
                headers, 
                cookies, 
                timeout, 
                follow_redirects,
                disallowed_paths if respect_robots else []
            )
            
            result.endpoints.extend(discovered_endpoints)
            result.notes.append(f"Discovered {len(discovered_endpoints)} endpoints from common paths")
            
            # Phase 4: Crawl the website
            logger.info(f"Crawling {target_url} (max depth: {max_depth}, max pages: {max_pages})")
            
            # Initialize crawl state
            crawled_urls = {target_url}
            pages_to_crawl = [(target_url, 0)]  # (url, depth)
            all_pages = [initial_page]
            
            # Process pages up to max_depth and max_pages
            while pages_to_crawl and len(all_pages) < max_pages:
                current_url, current_depth = pages_to_crawl.pop(0)
                
                # Skip if we've reached max depth
                if current_depth >= max_depth:
                    continue
                
                # Get the page (or use the one we already have)
                current_page = next((p for p in all_pages if p.url == current_url), None)
                if not current_page:
                    current_page = self._scan_page(current_url, headers, cookies, timeout, follow_redirects)
                    if current_page:
                        all_pages.append(current_page)
                
                if not current_page:
                    continue
                
                # Extract links from the page
                for link in current_page.links:
                    # Normalize and filter links
                    absolute_url = urljoin(current_url, link)
                    
                    # Skip external links, non-HTTP links, and already crawled URLs
                    if not absolute_url.startswith(base_url) or absolute_url in crawled_urls:
                        continue
                    
                    # Skip disallowed paths if respecting robots.txt
                    if respect_robots and any(absolute_url.endswith(path) for path in disallowed_paths):
                        continue
                    
                    # Add to crawl queue
                    crawled_urls.add(absolute_url)
                    pages_to_crawl.append((absolute_url, current_depth + 1))
                    
                    # Stop if we've reached max_pages
                    if len(crawled_urls) >= max_pages:
                        break
            
            # Use multithreading to scan discovered pages
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit page scanning tasks
                future_to_url = {}
                for url in crawled_urls:
                    if url != target_url:  # Skip the initial URL as we've already scanned it
                        future = executor.submit(
                            self._scan_page, 
                            url, 
                            headers, 
                            cookies, 
                            timeout, 
                            follow_redirects
                        )
                        future_to_url[future] = url
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        page = future.result()
                        if page:
                            result.pages.append(page)
                    except Exception as e:
                        logger.error(f"Error scanning {url}: {e}")
                        result.errors.append(f"Failed to scan {url}: {str(e)}")
            
            # Phase 5: Identify technologies
            logger.info("Identifying web technologies")
            technologies = self._identify_technologies(result.pages)
            result.technologies = technologies
            result.notes.append(f"Identified {len(technologies)} web technologies")
            
            # Phase 6: Test for vulnerabilities
            if test_xss or test_sqli or test_open_redirect:
                logger.info("Testing for vulnerabilities")
                vulnerabilities = self._test_vulnerabilities(
                    result.pages, 
                    result.endpoints,
                    headers,
                    cookies,
                    timeout,
                    test_xss,
                    test_sqli,
                    test_open_redirect
                )
                result.vulnerabilities = vulnerabilities
                result.notes.append(f"Discovered {len(vulnerabilities)} potential vulnerabilities")
            
            # Calculate scan duration
            scan_duration = time.time() - start_time
            result.notes.append(f"Web scan completed in {scan_duration:.2f} seconds")
            logger.info(f"Web scan of {target_url} completed in {scan_duration:.2f} seconds")
            
        except Exception as e:
            error_msg = f"Error during web scan: {str(e)}"
            logger.error(error_msg)
            result.errors.append(error_msg)
        
        return result
    
    def _scan_page(self, url: str, headers: Dict[str, str], cookies: Dict[str, str], 
                  timeout: float, follow_redirects: bool) -> Optional[WebPage]:
        """
        Scan a single web page.
        
        Args:
            url: URL to scan
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            follow_redirects: Whether to follow redirects
            
        Returns:
            WebPage: Web page information or None if scan failed
        """
        try:
            logger.debug(f"Scanning page: {url}")
            
            start_time = time.time()
            status, response_headers, body = self.network.get_http_request(
                url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                verify_ssl=False,
                allow_redirects=follow_redirects
            )
            response_time = time.time() - start_time
            
            if status <= 0:
                logger.debug(f"Failed to access {url}: No response")
                return None
            
            # Initialize page object
            page = WebPage(
                url=url,
                status_code=status,
                headers={k.lower(): v for k, v in response_headers.items()},
                content_type=response_headers.get("Content-Type", "").split(";")[0].strip(),
                size=len(body),
                response_time=response_time
            )
            
            # Extract page title
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if title_match:
                page.title = title_match.group(1).strip()
            
            # Extract links
            page.links = self._extract_links(url, body)
            
            # Extract forms
            if self.scan_forms:
                page.forms = self._extract_forms(url, body)
            
            # Extract scripts
            script_tags = re.findall(r"<script[^>]*src=['\"]([^'\"]+)['\"][^>]*>", body, re.IGNORECASE)
            page.scripts = [urljoin(url, src) for src in script_tags]
            
            # Extract HTML comments
            comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
            page.comments = [comment.strip() for comment in comments]
            
            return page
            
        except Exception as e:
            logger.debug(f"Error scanning {url}: {e}")
            return None
    
    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """
        Extract links from HTML content.
        
        Args:
            base_url: Base URL for resolving relative links
            html: HTML content
            
        Returns:
            List[str]: List of links
        """
        links = []
        
        # Extract href attributes from a tags
        a_tags = re.findall(r"<a[^>]*href=['\"]([^'\"]+)['\"][^>]*>", html, re.IGNORECASE)
        for href in a_tags:
            # Skip javascript: and mailto: links
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
                
            # Resolve relative URLs
            absolute_url = urljoin(base_url, href)
            links.append(absolute_url)
        
        return links
    
    def _extract_forms(self, base_url: str, html: str) -> List[Dict[str, Any]]:
        """
        Extract forms from HTML content.
        
        Args:
            base_url: Base URL for resolving relative links
            html: HTML content
            
        Returns:
            List[Dict]: List of forms with their attributes and inputs
        """
        forms = []
        
        # Find all form tags
        form_tags = re.finditer(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
        
        for form_match in form_tags:
            form_html = form_match.group(0)
            form_content = form_match.group(1)
            
            # Extract form attributes
            action_match = re.search(r"action=['\"]([^'\"]+)['\"]", form_html, re.IGNORECASE)
            method_match = re.search(r"method=['\"]([^'\"]+)['\"]", form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Resolve action URL
            action_url = urljoin(base_url, action) if action else base_url
            
            # Extract input fields
            inputs = []
            input_tags = re.finditer(r"<input[^>]*>", form_content, re.IGNORECASE)
            
            for input_match in input_tags:
                input_html = input_match.group(0)
                
                name_match = re.search(r"name=['\"]([^'\"]+)['\"]", input_html, re.IGNORECASE)
                type_match = re.search(r"type=['\"]([^'\"]+)['\"]", input_html, re.IGNORECASE)
                value_match = re.search(r"value=['\"]([^'\"]*)['\"]", input_html, re.IGNORECASE)
                
                name = name_match.group(1) if name_match else ""
                input_type = type_match.group(1).lower() if type_match else "text"
                value = value_match.group(1) if value_match else ""
                
                if name:
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": value
                    })
            
            # Extract select fields
            select_tags = re.finditer(r"<select[^>]*name=['\"]([^'\"]+)['\"][^>]*>(.*?)</select>", 
                                     form_content, re.IGNORECASE | re.DOTALL)
            
            for select_match in select_tags:
                name = select_match.group(1)
                select_content = select_match.group(2)
                
                # Extract options
                options = []
                option_tags = re.finditer(r"<option[^>]*value=['\"]([^'\"]*)['\"][^>]*>(.*?)</option>", 
                                         select_content, re.IGNORECASE | re.DOTALL)
                
                for option_match in option_tags:
                    value = option_match.group(1)
                    text = option_match.group(2).strip()
                    options.append({"value": value, "text": text})
                
                inputs.append({
                    "name": name,
                    "type": "select",
                    "options": options
                })
            
            # Extract textarea fields
            textarea_tags = re.finditer(r"<textarea[^>]*name=['\"]([^'\"]+)['\"][^>]*>(.*?)</textarea>", 
                                       form_content, re.IGNORECASE | re.DOTALL)
            
            for textarea_match in textarea_tags:
                name = textarea_match.group(1)
                value = textarea_match.group(2).strip()
                
                inputs.append({
                    "name": name,
                    "type": "textarea",
                    "value": value
                })
            
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs
            })
        
        return forms
    
    def _parse_robots_txt(self, robots_url: str, headers: Dict[str, str], 
                         cookies: Dict[str, str], timeout: float) -> List[str]:
        """
        Parse robots.txt to extract disallowed paths.
        
        Args:
            robots_url: URL of robots.txt
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            
        Returns:
            List[str]: List of disallowed paths
        """
        disallowed_paths = []
        
        try:
            status, _, body = self.network.get_http_request(
                robots_url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                verify_ssl=False
            )
            
            if status == 200:
                # Parse robots.txt content
                for line in body.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line[line.find(":") + 1:].strip()
                        if path and path != "/":
                            disallowed_paths.append(path)
            
        except Exception as e:
            logger.debug(f"Error parsing robots.txt at {robots_url}: {e}")
        
        return disallowed_paths
    
    def _check_common_paths(self, base_url: str, headers: Dict[str, str], 
                           cookies: Dict[str, str], timeout: float, 
                           follow_redirects: bool, disallowed_paths: List[str]) -> List[WebEndpoint]:
        """
        Check common paths on the target website.
        
        Args:
            base_url: Base URL of the website
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            follow_redirects: Whether to follow redirects
            disallowed_paths: List of disallowed paths from robots.txt
            
        Returns:
            List[WebEndpoint]: List of discovered endpoints
        """
        endpoints = []
        
        # Filter out disallowed paths
        paths_to_check = [p for p in self.COMMON_PATHS if p not in disallowed_paths]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {}
            
            for path in paths_to_check:
                url = f"{base_url}{path}"
                future = executor.submit(
                    self._check_endpoint, 
                    url, 
                    "GET", 
                    headers, 
                    cookies, 
                    timeout, 
                    follow_redirects
                )
                future_to_path[future] = path
            
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    endpoint = future.result()
                    if endpoint:
                        endpoints.append(endpoint)
                except Exception as e:
                    logger.debug(f"Error checking path {path}: {e}")
        
        return endpoints
    
    def _check_endpoint(self, url: str, method: str, headers: Dict[str, str], 
                       cookies: Dict[str, str], timeout: float, 
                       follow_redirects: bool) -> Optional[WebEndpoint]:
        """
        Check a specific endpoint.
        
        Args:
            url: URL to check
            method: HTTP method to use
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            follow_redirects: Whether to follow redirects
            
        Returns:
            WebEndpoint: Endpoint information or None if check failed
        """
        try:
            start_time = time.time()
            
            if method == "GET":
                status, response_headers, body = self.network.get_http_request(
                    url,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify_ssl=False,
                    allow_redirects=follow_redirects
                )
            else:
                # For demonstration, only handling GET requests
                return None
            
            response_time = time.time() - start_time
            
            if status <= 0:
                return None
            
            # Create endpoint object
            endpoint = WebEndpoint(
                url=url,
                method=method,
                status_code=status,
                content_type=response_headers.get("Content-Type", "").split(";")[0].strip(),
                size=len(body),
                response_time=response_time,
                headers={k.lower(): v for k, v in response_headers.items()}
            )
            
            # Extract URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)
                endpoint.parameters = list(params.keys())
            
            # Determine if the endpoint is dynamic
            endpoint.is_dynamic = self._is_dynamic_content(body, url)
            
            return endpoint
            
        except Exception as e:
            logger.debug(f"Error checking endpoint {url}: {e}")
            return None
    
    def _is_dynamic_content(self, content: str, url: str) -> bool:
        """
        Determine if content appears to be dynamically generated.
        
        Args:
            content: Page content
            url: URL of the page
            
        Returns:
            bool: True if content appears to be dynamic
        """
        # Check for common indicators of dynamic content
        dynamic_indicators = [
            # Server-side includes
            "<!--#include",
            # PHP
            "<?php", "<?=",
            # ASP/JSP tags
            "<%", "%>",
            # Common dynamic content markers
            "id=", "user=", "page=", "article=", "post=", "product=",
            # Session indicators
            "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
            # Database error messages
            "SQL syntax", "mysql_fetch", "pg_query", "sqlite3_query",
            "ORA-", "Microsoft SQL Server"
        ]
        
        # Check URL for query parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            return True
        
        # Check content for dynamic indicators
        for indicator in dynamic_indicators:
            if indicator in content:
                return True
        
        return False
    
    def _identify_technologies(self, pages: List[WebPage]) -> List[WebTechnology]:
        """
        Identify web technologies used by the website.
        
        Args:
            pages: List of web pages
            
        Returns:
            List[WebTechnology]: List of identified technologies
        """
        technologies = {}
        
        for page in pages:
            # Check headers
            if "headers" in self.TECHNOLOGY_FINGERPRINTS:
                for header_name, header_techs in self.TECHNOLOGY_FINGERPRINTS["headers"].items():
                    header_value = page.headers.get(header_name.lower(), "")
                    if header_value:
                        for tech_name, tech_info in header_techs.items():
                            if tech_name not in technologies:
                                match = re.search(tech_info["regex"], header_value, re.IGNORECASE)
                                if match:
                                    version = match.group(1) if match.groups() else ""
                                    technologies[tech_name] = WebTechnology(
                                        name=tech_name,
                                        version=version,
                                        confidence=0.9,
                                        category=tech_info["category"],
                                        detection_method="headers"
                                    )
            
            # Check HTML content
            if "html" in self.TECHNOLOGY_FINGERPRINTS:
                for tech_name, tech_info in self.TECHNOLOGY_FINGERPRINTS["html"].items():
                    if tech_name not in technologies:
                        # For simplicity, we're checking if the regex is in any of the page properties
                        # In a real implementation, you would parse the HTML properly
                        html_content = f"{page.title} {' '.join(page.scripts)} {' '.join(page.links)}"
                        match = re.search(tech_info["regex"], html_content, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.groups() else ""
                            technologies[tech_name] = WebTechnology(
                                name=tech_name,
                                version=version,
                                confidence=0.7,
                                category=tech_info["category"],
                                detection_method="html"
                            )
            
            # Check meta generator tag
            if "meta" in self.TECHNOLOGY_FINGERPRINTS and "generator" in self.TECHNOLOGY_FINGERPRINTS["meta"]:
                # For simplicity, using regex to find meta generator tag
                # In a real implementation, you would parse the HTML properly
                meta_match = re.search(r'<meta[^>]*name=[\'"]generator[\'"][^>]*content=[\'"]([^\'"]+)[\'"]', 
                                      str(page.title), re.IGNORECASE)
                if meta_match:
                    generator_content = meta_match.group(1)
                    for tech_name, tech_info in self.TECHNOLOGY_FINGERPRINTS["meta"]["generator"].items():
                        if tech_name not in technologies:
                            match = re.search(tech_info["regex"], generator_content, re.IGNORECASE)
                            if match:
                                version = match.group(1) if match.groups() else ""
                                technologies[tech_name] = WebTechnology(
                                    name=tech_name,
                                    version=version,
                                    confidence=0.8,
                                    category=tech_info["category"],
                                    detection_method="meta"
                                )
        
        return list(technologies.values())
    
    def _test_vulnerabilities(self, pages: List[WebPage], endpoints: List[WebEndpoint],
                             headers: Dict[str, str], cookies: Dict[str, str], 
                             timeout: float, test_xss: bool, test_sqli: bool, 
                             test_open_redirect: bool) -> List[WebVulnerability]:
        """
        Test for common web vulnerabilities.
        
        Args:
            pages: List of web pages
            endpoints: List of endpoints
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            test_xss: Whether to test for XSS vulnerabilities
            test_sqli: Whether to test for SQL injection vulnerabilities
            test_open_redirect: Whether to test for open redirect vulnerabilities
            
        Returns:
            List[WebVulnerability]: List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # For demonstration purposes, we'll implement simplified vulnerability checks
        # In a real implementation, you would use more sophisticated techniques
        
        # Test for reflected XSS
        if test_xss:
            xss_payloads = [
                "<script>alert(1)</script>",
                "';alert(1);//",
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ]
            
            for endpoint in endpoints:
                if endpoint.parameters:
                    for param in endpoint.parameters:
                        for payload in xss_payloads:
                            vuln = self._test_xss_vulnerability(
                                endpoint.url, 
                                param, 
                                payload, 
                                headers, 
                                cookies, 
                                timeout
                            )
                            if vuln:
                                vulnerabilities.append(vuln)
        
        # Test for SQL injection
        if test_sqli:
            sqli_payloads = [
                "' OR '1'='1",
                "' OR 1=1 --",
                "' OR 1=1#",
                "') OR ('1'='1",
                "1' ORDER BY 1--"
            ]
            
            for endpoint in endpoints:
                if endpoint.parameters:
                    for param in endpoint.parameters:
                        for payload in sqli_payloads:
                            vuln = self._test_sqli_vulnerability(
                                endpoint.url, 
                                param, 
                                payload, 
                                headers, 
                                cookies, 
                                timeout
                            )
                            if vuln:
                                vulnerabilities.append(vuln)
        
        # Test for open redirect
        if test_open_redirect:
            redirect_params = ["redirect", "url", "next", "return", "returnUrl", "returnTo", "goto", "continue"]
            redirect_payloads = [
                "https://example.com",
                "//example.com",
                "\\\\example.com",
                "javascript:alert(document.domain)"
            ]
            
            for endpoint in endpoints:
                if endpoint.parameters:
                    for param in endpoint.parameters:
                        if param.lower() in redirect_params:
                            for payload in redirect_payloads:
                                vuln = self._test_open_redirect_vulnerability(
                                    endpoint.url, 
                                    param, 
                                    payload, 
                                    headers, 
                                    cookies, 
                                    timeout
                                )
                                if vuln:
                                    vulnerabilities.append(vuln)
        
        # Test for information disclosure
        for page in pages:
            vuln = self._test_information_disclosure(page)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_xss_vulnerability(self, url: str, param: str, payload: str, 
                               headers: Dict[str, str], cookies: Dict[str, str], 
                               timeout: float) -> Optional[WebVulnerability]:
        """
        Test for XSS vulnerability.
        
        Args:
            url: URL to test
            param: Parameter to test
            payload: XSS payload
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            
        Returns:
            WebVulnerability: Vulnerability information or None if not vulnerable
        """
        # For demonstration purposes, this is a simplified check
        # In a real implementation, you would use more sophisticated techniques
        
        try:
            # Construct test URL
            parsed_url = urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Update the parameter with the payload
            query_params[param] = [payload]
            
            # Reconstruct the query string
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            
            # Construct the test URL
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Send the request
            status, _, body = self.network.get_http_request(
                test_url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                verify_ssl=False
            )
            
            if status > 0:
                # Check if the payload is reflected in the response
                if payload in body:
                    # Create vulnerability object
                    vuln_info = self.VULNERABILITY_CHECKS["xss"]
                    return WebVulnerability(
                        name=vuln_info["name"],
                        url=test_url,
                        severity=vuln_info["severity"],
                        description=vuln_info["description"],
                        details={
                            "parameter": param,
                            "payload": payload,
                            "reflected": True
                        },
                        evidence=f"Payload '{payload}' was reflected in the response",
                        cwe_id=vuln_info["cwe_id"],
                        remediation=vuln_info["remediation"],
                        references=vuln_info["references"],
                        confidence=0.7  # Medium confidence since this is a simple check
                    )
            
        except Exception as e:
            logger.debug(f"Error testing XSS vulnerability on {url}: {e}")
        
        return None
    
    def _test_sqli_vulnerability(self, url: str, param: str, payload: str, 
                                headers: Dict[str, str], cookies: Dict[str, str], 
                                timeout: float) -> Optional[WebVulnerability]:
        """
        Test for SQL injection vulnerability.
        
        Args:
            url: URL to test
            param: Parameter to test
            payload: SQL injection payload
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            
        Returns:
            WebVulnerability: Vulnerability information or None if not vulnerable
        """
        # For demonstration purposes, this is a simplified check
        # In a real implementation, you would use more sophisticated techniques
        
        try:
            # Construct test URL
            parsed_url = urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Update the parameter with the payload
            query_params[param] = [payload]
            
            # Reconstruct the query string
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            
            # Construct the test URL
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Send the request
            status, _, body = self.network.get_http_request(
                test_url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                verify_ssl=False
            )
            
            if status > 0:
                # Check for SQL error messages
                sql_errors = [
                    "SQL syntax", "mysql_fetch", "pg_query", "sqlite3_query",
                    "ORA-", "Microsoft SQL Server", "ODBC Driver",
                    "Warning: mysql_", "Warning: pg_", "Warning: sqlite3_",
                    "SQLSTATE", "Microsoft OLE DB Provider for SQL Server",
                    "Unclosed quotation mark", "Incorrect syntax near"
                ]
                
                for error in sql_errors:
                    if error in body:
                        # Create vulnerability object
                        vuln_info = self.VULNERABILITY_CHECKS["sqli"]
                        return WebVulnerability(
                            name=vuln_info["name"],
                            url=test_url,
                            severity=vuln_info["severity"],
                            description=vuln_info["description"],
                            details={
                                "parameter": param,
                                "payload": payload,
                                "error_message": error
                            },
                            evidence=f"SQL error message '{error}' was found in the response",
                            cwe_id=vuln_info["cwe_id"],
                            remediation=vuln_info["remediation"],
                            references=vuln_info["references"],
                            confidence=0.8  # High confidence due to error message
                        )
            
        except Exception as e:
            logger.debug(f"Error testing SQL injection vulnerability on {url}: {e}")
        
        return None
    
    def _test_open_redirect_vulnerability(self, url: str, param: str, payload: str, 
                                         headers: Dict[str, str], cookies: Dict[str, str], 
                                         timeout: float) -> Optional[WebVulnerability]:
        """
        Test for open redirect vulnerability.
        
        Args:
            url: URL to test
            param: Parameter to test
            payload: Redirect payload
            headers: Request headers
            cookies: Request cookies
            timeout: Request timeout
            
        Returns:
            WebVulnerability: Vulnerability information or None if not vulnerable
        """
        # For demonstration purposes, this is a simplified check
        # In a real implementation, you would use more sophisticated techniques
        
        try:
            # Construct test URL
            parsed_url = urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Update the parameter with the payload
            query_params[param] = [payload]
            
            # Reconstruct the query string
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            
            # Construct the test URL
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Send the request with redirect=False to check for redirect response
            status, response_headers, _ = self.network.get_http_request(
                test_url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                verify_ssl=False,
                allow_redirects=False
            )
            
            if status >= 300 and status < 400:
                # Check if the redirect location matches our payload
                location = response_headers.get("Location", "")
                if payload in location:
                    # Create vulnerability object
                    vuln_info = self.VULNERABILITY_CHECKS["open_redirect"]
                    return WebVulnerability(
                        name=vuln_info["name"],
                        url=test_url,
                        severity=vuln_info["severity"],
                        description=vuln_info["description"],
                        details={
                            "parameter": param,
                            "payload": payload,
                            "redirect_location": location,
                            "status_code": status
                        },
                        evidence=f"Redirect to '{location}' with status code {status}",
                        cwe_id=vuln_info["cwe_id"],
                        remediation=vuln_info["remediation"],
                        references=vuln_info["references"],
                        confidence=0.9  # High confidence due to direct redirect
                    )
            
        except Exception as e:
            logger.debug(f"Error testing open redirect vulnerability on {url}: {e}")
        
        return None
    
    def _test_information_disclosure(self, page: WebPage) -> Optional[WebVulnerability]:
        """
        Test for information disclosure vulnerabilities.
        
        Args:
            page: Web page to test
            
        Returns:
            WebVulnerability: Vulnerability information or None if not vulnerable
        """
        # For demonstration purposes, this is a simplified check
        # In a real implementation, you would use more sophisticated techniques
        
        # Check for sensitive information in comments
        sensitive_patterns = [
            r"password\s*=\s*['\"]([^'\"]+)['\"]",
            r"username\s*=\s*['\"]([^'\"]+)['\"]",
            r"api[_\-]?key\s*=\s*['\"]([^'\"]+)['\"]",
            r"secret\s*=\s*['\"]([^'\"]+)['\"]",
            r"database\s*=\s*['\"]([^'\"]+)['\"]",
            r"db_password\s*=\s*['\"]([^'\"]+)['\"]",
            r"(?:ip|host|server)_address\s*=\s*['\"]([^'\"]+)['\"]",
            r"(?:aws|azure|gcp)_(?:key|secret|token)\s*=\s*['\"]([^'\"]+)['\"]",
            r"TODO|FIXME|XXX|BUG|HACK"
        ]
        
        for comment in page.comments:
            for pattern in sensitive_patterns:
                match = re.search(pattern, comment, re.IGNORECASE)
                if match:
                    # Create vulnerability object
                    vuln_info = self.VULNERABILITY_CHECKS["information_disclosure"]
                    return WebVulnerability(
                        name=vuln_info["name"],
                        url=page.url,
                        severity=vuln_info["severity"],
                        description=vuln_info["description"],
                        details={
                            "comment": comment,
                            "pattern": pattern
                        },
                        evidence=f"Sensitive information found in HTML comment: '{comment}'",
                        cwe_id=vuln_info["cwe_id"],
                        remediation=vuln_info["remediation"],
                        references=vuln_info["references"],
                        confidence=0.7  # Medium confidence
                    )
        
        # Check for server information in headers
        sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
        for header in sensitive_headers:
            if header.lower() in page.headers:
                # Create vulnerability object
                vuln_info = self.VULNERABILITY_CHECKS["information_disclosure"]
                return WebVulnerability(
                    name=vuln_info["name"],
                    url=page.url,
                    severity=VulnerabilitySeverity.LOW,  # Lower severity for header disclosure
                    description="Server information disclosure in HTTP headers",
                    details={
                        "header": header,
                        "value": page.headers[header.lower()]
                    },
                    evidence=f"Server information disclosed in {header} header: '{page.headers[header.lower()]}'",
                    cwe_id=vuln_info["cwe_id"],
                    remediation="Configure the server to suppress version information in HTTP headers",
                    references=vuln_info["references"],
                    confidence=0.9  # High confidence
                )
        
        return None