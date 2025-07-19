# Cyinnove API Documentation

## Overview

This document provides comprehensive documentation for Cyinnove's security automation APIs, tools, and components. Our APIs are designed to help security engineers, developers, bug hunters, security researchers, and threat hunters build and manage vulnerability workflows efficiently.

## Table of Contents

- [Authentication](#authentication)
- [Core APIs](#core-apis)
  - [Vulnerability Management API](#vulnerability-management-api)
  - [Threat Detection API](#threat-detection-api)
  - [Attack Surface Management API](#attack-surface-management-api)
  - [Incident Management API](#incident-management-api)
- [Security Tools](#security-tools)
  - [Bug Hunter Tools](#bug-hunter-tools)
  - [Security Research Tools](#security-research-tools)
  - [Threat Hunter Tools](#threat-hunter-tools)
- [Components](#components)
- [SDKs](#sdks)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Changelog](#changelog)

## Authentication

All API endpoints require authentication using API keys or OAuth 2.0 tokens.

### API Key Authentication

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     https://api.cyinnove.org/v1/endpoint
```

### OAuth 2.0 Authentication

```python
import requests

headers = {
    'Authorization': 'Bearer YOUR_OAUTH_TOKEN',
    'Content-Type': 'application/json'
}

response = requests.get('https://api.cyinnove.org/v1/endpoint', headers=headers)
```

## Core APIs

### Vulnerability Management API

The Vulnerability Management API provides endpoints for discovering, tracking, and managing security vulnerabilities.

#### Endpoints

##### List Vulnerabilities

```http
GET /api/v1/vulnerabilities
```

**Description:** Retrieve a list of vulnerabilities with optional filtering.

**Parameters:**
- `severity` (string, optional): Filter by severity level (critical, high, medium, low)
- `status` (string, optional): Filter by status (open, in_progress, resolved, false_positive)
- `limit` (integer, optional): Number of results to return (default: 50, max: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

**Response:**
```json
{
  "data": [
    {
      "id": "vuln_123456",
      "title": "SQL Injection in User Authentication",
      "description": "A SQL injection vulnerability was found in the user authentication endpoint",
      "severity": "high",
      "status": "open",
      "cve_id": "CVE-2024-1234",
      "affected_assets": ["web-app-1", "api-gateway"],
      "discovered_date": "2024-01-15T10:30:00Z",
      "last_updated": "2024-01-16T14:45:00Z",
      "reporter": {
        "id": "user_789",
        "name": "Security Researcher",
        "email": "researcher@example.com"
      }
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

**Example Usage:**

```python
import requests

# Python example
def get_vulnerabilities(api_key, severity=None, status=None):
    """
    Retrieve vulnerabilities from the Cyinnove API
    
    Args:
        api_key (str): Your API key
        severity (str, optional): Filter by severity
        status (str, optional): Filter by status
    
    Returns:
        dict: API response containing vulnerability data
    """
    url = "https://api.cyinnove.org/v1/vulnerabilities"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    params = {}
    if severity:
        params['severity'] = severity
    if status:
        params['status'] = status
    
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()

# Usage
vulnerabilities = get_vulnerabilities("your_api_key", severity="high", status="open")
```

```javascript
// JavaScript example
async function getVulnerabilities(apiKey, options = {}) {
  /**
   * Retrieve vulnerabilities from the Cyinnove API
   * 
   * @param {string} apiKey - Your API key
   * @param {Object} options - Optional parameters
   * @param {string} options.severity - Filter by severity
   * @param {string} options.status - Filter by status
   * @returns {Promise<Object>} API response containing vulnerability data
   */
  const url = new URL('https://api.cyinnove.org/v1/vulnerabilities');
  
  if (options.severity) url.searchParams.append('severity', options.severity);
  if (options.status) url.searchParams.append('status', options.status);
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  return await response.json();
}

// Usage
const vulnerabilities = await getVulnerabilities('your_api_key', {
  severity: 'high',
  status: 'open'
});
```

##### Create Vulnerability Report

```http
POST /api/v1/vulnerabilities
```

**Description:** Submit a new vulnerability report.

**Request Body:**
```json
{
  "title": "Cross-Site Scripting in Comment System",
  "description": "Stored XSS vulnerability allows attackers to inject malicious scripts",
  "severity": "medium",
  "affected_assets": ["web-app-comments"],
  "proof_of_concept": "Detailed PoC steps...",
  "remediation_suggestion": "Implement proper input validation and output encoding"
}
```

**Response:**
```json
{
  "id": "vuln_789012",
  "status": "created",
  "message": "Vulnerability report submitted successfully"
}
```

### Threat Detection API

The Threat Detection API provides real-time threat intelligence and detection capabilities.

#### Endpoints

##### Analyze Threat Indicators

```http
POST /api/v1/threats/analyze
```

**Description:** Analyze threat indicators (IPs, domains, hashes) for malicious activity.

**Request Body:**
```json
{
  "indicators": [
    {
      "type": "ip",
      "value": "192.168.1.100"
    },
    {
      "type": "domain",
      "value": "malicious-site.com"
    },
    {
      "type": "hash",
      "value": "e3b0c44298fc1c149afbf4c8996fb924"
    }
  ]
}
```

**Response:**
```json
{
  "results": [
    {
      "indicator": "192.168.1.100",
      "type": "ip",
      "threat_score": 85,
      "classification": "malicious",
      "sources": ["threat_feed_1", "internal_analysis"],
      "first_seen": "2024-01-10T08:00:00Z",
      "last_seen": "2024-01-16T12:30:00Z"
    }
  ]
}
```

### Attack Surface Management API

The Attack Surface Management API helps organizations discover and monitor their external attack surface.

#### Endpoints

##### Discover Assets

```http
GET /api/v1/assets/discover
```

**Description:** Discover external assets associated with your organization.

**Parameters:**
- `domain` (string): Primary domain to scan
- `include_subdomains` (boolean): Include subdomain discovery
- `scan_ports` (boolean): Perform port scanning

**Example Usage:**

```python
def discover_assets(api_key, domain, include_subdomains=True, scan_ports=False):
    """
    Discover external assets for attack surface management
    
    Args:
        api_key (str): Your API key
        domain (str): Primary domain to scan
        include_subdomains (bool): Whether to include subdomain discovery
        scan_ports (bool): Whether to perform port scanning
    
    Returns:
        dict: Discovered assets and their security posture
    """
    url = "https://api.cyinnove.org/v1/assets/discover"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    params = {
        "domain": domain,
        "include_subdomains": include_subdomains,
        "scan_ports": scan_ports
    }
    
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()
```

### Incident Management API

The Incident Management API provides endpoints for creating, tracking, and managing security incidents.

#### Endpoints

##### Create Security Incident

```http
POST /api/v1/incidents
```

**Description:** Create a new security incident.

**Request Body:**
```json
{
  "title": "Potential Data Breach",
  "description": "Suspicious activity detected in user database",
  "severity": "high",
  "category": "data_breach",
  "affected_systems": ["database-1", "web-app-1"],
  "reporter_id": "user_123"
}
```

## Security Tools

### Bug Hunter Tools

#### Vulnerability Scanner Component

```python
class VulnerabilityScanner:
    """
    A comprehensive vulnerability scanner for web applications
    
    This component provides automated vulnerability detection capabilities
    specifically designed for bug hunters and security researchers.
    """
    
    def __init__(self, api_key, target_url):
        """
        Initialize the vulnerability scanner
        
        Args:
            api_key (str): Your Cyinnove API key
            target_url (str): The target URL to scan
        """
        self.api_key = api_key
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Cyinnove-Scanner/1.0'
        })
    
    def scan_sql_injection(self, parameters):
        """
        Scan for SQL injection vulnerabilities
        
        Args:
            parameters (list): List of parameters to test
            
        Returns:
            dict: Scan results with vulnerability details
        """
        results = {
            'vulnerabilities': [],
            'scan_time': None,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        for param in parameters:
            # SQL injection payloads
            payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--"
            ]
            
            for payload in payloads:
                test_data = {param: payload}
                response = self._send_request(test_data)
                
                if self._detect_sql_error(response):
                    results['vulnerabilities'].append({
                        'type': 'sql_injection',
                        'parameter': param,
                        'payload': payload,
                        'severity': 'high',
                        'description': f'SQL injection vulnerability found in parameter: {param}'
                    })
                
                results['total_tests'] += 1
        
        results['scan_time'] = time.time() - start_time
        return results
    
    def scan_xss(self, parameters):
        """
        Scan for Cross-Site Scripting (XSS) vulnerabilities
        
        Args:
            parameters (list): List of parameters to test
            
        Returns:
            dict: Scan results with XSS vulnerability details
        """
        results = {
            'vulnerabilities': [],
            'scan_time': None,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")'
        ]
        
        for param in parameters:
            for payload in xss_payloads:
                test_data = {param: payload}
                response = self._send_request(test_data)
                
                if payload in response.text:
                    results['vulnerabilities'].append({
                        'type': 'xss',
                        'parameter': param,
                        'payload': payload,
                        'severity': 'medium',
                        'description': f'XSS vulnerability found in parameter: {param}'
                    })
                
                results['total_tests'] += 1
        
        results['scan_time'] = time.time() - start_time
        return results
    
    def _send_request(self, data):
        """Send HTTP request with test data"""
        try:
            return self.session.post(self.target_url, data=data, timeout=10)
        except requests.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
    
    def _detect_sql_error(self, response):
        """Detect SQL error patterns in response"""
        error_patterns = [
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]
        
        return any(pattern.lower() in response.text.lower() for pattern in error_patterns)

# Usage Example
scanner = VulnerabilityScanner("your_api_key", "https://target-site.com/login")
sql_results = scanner.scan_sql_injection(['username', 'password'])
xss_results = scanner.scan_xss(['comment', 'message'])
```

### Security Research Tools

#### Threat Intelligence Analyzer

```python
class ThreatIntelligenceAnalyzer:
    """
    Advanced threat intelligence analysis tool for security researchers
    
    This component provides comprehensive threat analysis capabilities,
    including IOC analysis, threat attribution, and campaign tracking.
    """
    
    def __init__(self, api_key):
        """
        Initialize the threat intelligence analyzer
        
        Args:
            api_key (str): Your Cyinnove API key
        """
        self.api_key = api_key
        self.base_url = "https://api.cyinnove.org/v1"
        
    def analyze_ioc(self, indicator, indicator_type):
        """
        Analyze an Indicator of Compromise (IOC)
        
        Args:
            indicator (str): The IOC to analyze (IP, domain, hash, etc.)
            indicator_type (str): Type of indicator (ip, domain, hash, url)
            
        Returns:
            dict: Comprehensive analysis results
        """
        endpoint = f"{self.base_url}/threat-intel/analyze"
        
        payload = {
            "indicator": indicator,
            "type": indicator_type,
            "analysis_depth": "comprehensive"
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    def track_campaign(self, campaign_indicators):
        """
        Track and analyze a threat campaign based on multiple indicators
        
        Args:
            campaign_indicators (list): List of IOCs associated with the campaign
            
        Returns:
            dict: Campaign analysis with attribution and timeline
        """
        endpoint = f"{self.base_url}/threat-intel/campaign"
        
        payload = {
            "indicators": campaign_indicators,
            "analysis_type": "campaign_tracking"
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        
        return response.json()

# Usage Example
analyzer = ThreatIntelligenceAnalyzer("your_api_key")

# Analyze a suspicious IP
ip_analysis = analyzer.analyze_ioc("192.168.1.100", "ip")

# Track a campaign
campaign_iocs = [
    {"indicator": "malicious-domain.com", "type": "domain"},
    {"indicator": "192.168.1.100", "type": "ip"},
    {"indicator": "e3b0c44298fc1c149afbf4c8996fb924", "type": "hash"}
]
campaign_analysis = analyzer.track_campaign(campaign_iocs)
```

### Threat Hunter Tools

#### Behavioral Analysis Engine

```python
class BehavioralAnalysisEngine:
    """
    Advanced behavioral analysis engine for threat hunters
    
    This component analyzes system and network behavior to detect
    anomalies and potential threats using machine learning techniques.
    """
    
    def __init__(self, api_key):
        """
        Initialize the behavioral analysis engine
        
        Args:
            api_key (str): Your Cyinnove API key
        """
        self.api_key = api_key
        self.base_url = "https://api.cyinnove.org/v1"
    
    def analyze_network_behavior(self, network_logs, time_window="24h"):
        """
        Analyze network traffic patterns for anomalies
        
        Args:
            network_logs (list): Network log entries
            time_window (str): Analysis time window (1h, 24h, 7d)
            
        Returns:
            dict: Behavioral analysis results with anomaly scores
        """
        endpoint = f"{self.base_url}/behavior/network"
        
        payload = {
            "logs": network_logs,
            "time_window": time_window,
            "analysis_type": "anomaly_detection"
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    def detect_lateral_movement(self, host_logs):
        """
        Detect potential lateral movement activities
        
        Args:
            host_logs (list): Host-based log entries
            
        Returns:
            dict: Lateral movement detection results
        """
        endpoint = f"{self.base_url}/behavior/lateral-movement"
        
        payload = {
            "logs": host_logs,
            "detection_rules": [
                "unusual_authentication_patterns",
                "privilege_escalation",
                "remote_execution"
            ]
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        
        return response.json()

# Usage Example
engine = BehavioralAnalysisEngine("your_api_key")

# Analyze network behavior
network_logs = [
    {"timestamp": "2024-01-16T10:00:00Z", "src_ip": "10.0.1.100", "dst_ip": "8.8.8.8", "bytes": 1024},
    {"timestamp": "2024-01-16T10:01:00Z", "src_ip": "10.0.1.100", "dst_ip": "malicious-site.com", "bytes": 2048}
]
network_analysis = engine.analyze_network_behavior(network_logs)

# Detect lateral movement
host_logs = [
    {"timestamp": "2024-01-16T10:00:00Z", "event": "login", "user": "admin", "host": "server1"},
    {"timestamp": "2024-01-16T10:05:00Z", "event": "process_creation", "process": "psexec.exe", "host": "server2"}
]
lateral_movement = engine.detect_lateral_movement(host_logs)
```

## Components

### Security Dashboard Component

```javascript
/**
 * Security Dashboard Component
 * 
 * A React component for displaying security metrics and vulnerability status
 */
import React, { useState, useEffect } from 'react';
import { CyinnoveAPI } from './cyinnove-sdk';

const SecurityDashboard = ({ apiKey, organizationId }) => {
  const [dashboardData, setDashboardData] = useState({
    vulnerabilities: [],
    threats: [],
    incidents: [],
    metrics: {}
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const api = new CyinnoveAPI(apiKey);

  useEffect(() => {
    loadDashboardData();
  }, [organizationId]);

  /**
   * Load dashboard data from Cyinnove API
   */
  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      const [vulnerabilities, threats, incidents, metrics] = await Promise.all([
        api.getVulnerabilities({ status: 'open', limit: 10 }),
        api.getThreats({ severity: 'high', limit: 5 }),
        api.getIncidents({ status: 'active', limit: 5 }),
        api.getSecurityMetrics(organizationId)
      ]);

      setDashboardData({
        vulnerabilities: vulnerabilities.data,
        threats: threats.data,
        incidents: incidents.data,
        metrics: metrics.data
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Handle vulnerability status update
   */
  const updateVulnerabilityStatus = async (vulnId, newStatus) => {
    try {
      await api.updateVulnerability(vulnId, { status: newStatus });
      await loadDashboardData(); // Refresh data
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) return <div className="loading">Loading security dashboard...</div>;
  if (error) return <div className="error">Error: {error}</div>;

  return (
    <div className="security-dashboard">
      <h1>Security Dashboard</h1>
      
      {/* Security Metrics */}
      <div className="metrics-grid">
        <div className="metric-card">
          <h3>Open Vulnerabilities</h3>
          <span className="metric-value">{dashboardData.metrics.open_vulnerabilities}</span>
        </div>
        <div className="metric-card">
          <h3>Active Threats</h3>
          <span className="metric-value">{dashboardData.metrics.active_threats}</span>
        </div>
        <div className="metric-card">
          <h3>Security Score</h3>
          <span className="metric-value">{dashboardData.metrics.security_score}/100</span>
        </div>
      </div>

      {/* Recent Vulnerabilities */}
      <div className="vulnerabilities-section">
        <h2>Recent Vulnerabilities</h2>
        <div className="vulnerability-list">
          {dashboardData.vulnerabilities.map(vuln => (
            <div key={vuln.id} className={`vulnerability-item severity-${vuln.severity}`}>
              <h4>{vuln.title}</h4>
              <p>{vuln.description}</p>
              <div className="vulnerability-actions">
                <button onClick={() => updateVulnerabilityStatus(vuln.id, 'in_progress')}>
                  Mark In Progress
                </button>
                <button onClick={() => updateVulnerabilityStatus(vuln.id, 'resolved')}>
                  Mark Resolved
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
```

## SDKs

### Python SDK

```python
"""
Cyinnove Python SDK

A comprehensive Python SDK for interacting with Cyinnove's security APIs.
"""

import requests
import json
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Vulnerability:
    """Data class representing a vulnerability"""
    id: str
    title: str
    description: str
    severity: str
    status: str
    cve_id: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    discovered_date: Optional[datetime] = None
    last_updated: Optional[datetime] = None

class CyinnoveClient:
    """
    Main client class for interacting with Cyinnove APIs
    
    This client provides methods for all Cyinnove security APIs including
    vulnerability management, threat detection, and incident management.
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.cyinnove.org/v1"):
        """
        Initialize the Cyinnove client
        
        Args:
            api_key (str): Your Cyinnove API key
            base_url (str): Base URL for the API (default: https://api.cyinnove.org/v1)
        """
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'Cyinnove-Python-SDK/1.0'
        })
    
    def get_vulnerabilities(self, 
                          severity: Optional[str] = None,
                          status: Optional[str] = None,
                          limit: int = 50,
                          offset: int = 0) -> Dict:
        """
        Retrieve vulnerabilities
        
        Args:
            severity (str, optional): Filter by severity (critical, high, medium, low)
            status (str, optional): Filter by status (open, in_progress, resolved)
            limit (int): Number of results to return (default: 50)
            offset (int): Pagination offset (default: 0)
            
        Returns:
            Dict: API response containing vulnerability data
            
        Raises:
            requests.RequestException: If the API request fails
        """
        params = {'limit': limit, 'offset': offset}
        if severity:
            params['severity'] = severity
        if status:
            params['status'] = status
        
        response = self.session.get(f"{self.base_url}/vulnerabilities", params=params)
        response.raise_for_status()
        return response.json()
    
    def create_vulnerability(self, 
                           title: str,
                           description: str,
                           severity: str,
                           affected_assets: List[str],
                           proof_of_concept: Optional[str] = None,
                           remediation_suggestion: Optional[str] = None) -> Dict:
        """
        Create a new vulnerability report
        
        Args:
            title (str): Vulnerability title
            description (str): Detailed description
            severity (str): Severity level (critical, high, medium, low)
            affected_assets (List[str]): List of affected assets
            proof_of_concept (str, optional): Proof of concept details
            remediation_suggestion (str, optional): Suggested remediation
            
        Returns:
            Dict: API response with created vulnerability details
        """
        payload = {
            'title': title,
            'description': description,
            'severity': severity,
            'affected_assets': affected_assets
        }
        
        if proof_of_concept:
            payload['proof_of_concept'] = proof_of_concept
        if remediation_suggestion:
            payload['remediation_suggestion'] = remediation_suggestion
        
        response = self.session.post(f"{self.base_url}/vulnerabilities", json=payload)
        response.raise_for_status()
        return response.json()
    
    def analyze_threats(self, indicators: List[Dict[str, str]]) -> Dict:
        """
        Analyze threat indicators
        
        Args:
            indicators (List[Dict]): List of indicators with 'type' and 'value' keys
            
        Returns:
            Dict: Threat analysis results
        """
        payload = {'indicators': indicators}
        
        response = self.session.post(f"{self.base_url}/threats/analyze", json=payload)
        response.raise_for_status()
        return response.json()
    
    def discover_assets(self, 
                       domain: str,
                       include_subdomains: bool = True,
                       scan_ports: bool = False) -> Dict:
        """
        Discover external assets
        
        Args:
            domain (str): Primary domain to scan
            include_subdomains (bool): Include subdomain discovery
            scan_ports (bool): Perform port scanning
            
        Returns:
            Dict: Discovered assets and security posture
        """
        params = {
            'domain': domain,
            'include_subdomains': include_subdomains,
            'scan_ports': scan_ports
        }
        
        response = self.session.get(f"{self.base_url}/assets/discover", params=params)
        response.raise_for_status()
        return response.json()

# Usage Examples
if __name__ == "__main__":
    # Initialize client
    client = CyinnoveClient("your_api_key_here")
    
    # Get high severity vulnerabilities
    high_vulns = client.get_vulnerabilities(severity="high", status="open")
    print(f"Found {len(high_vulns['data'])} high severity vulnerabilities")
    
    # Create a new vulnerability report
    new_vuln = client.create_vulnerability(
        title="Cross-Site Scripting in Comment System",
        description="Stored XSS vulnerability in user comments",
        severity="medium",
        affected_assets=["web-app-1"],
        proof_of_concept="Steps to reproduce...",
        remediation_suggestion="Implement proper input validation"
    )
    print(f"Created vulnerability: {new_vuln['id']}")
    
    # Analyze threat indicators
    indicators = [
        {"type": "ip", "value": "192.168.1.100"},
        {"type": "domain", "value": "suspicious-site.com"}
    ]
    threat_analysis = client.analyze_threats(indicators)
    print(f"Threat analysis completed: {len(threat_analysis['results'])} indicators analyzed")
```

### JavaScript SDK

```javascript
/**
 * Cyinnove JavaScript SDK
 * 
 * A comprehensive JavaScript SDK for interacting with Cyinnove's security APIs.
 * Compatible with both Node.js and browser environments.
 */

class CyinnoveAPI {
  /**
   * Initialize the Cyinnove API client
   * 
   * @param {string} apiKey - Your Cyinnove API key
   * @param {string} baseUrl - Base URL for the API
   */
  constructor(apiKey, baseUrl = 'https://api.cyinnove.org/v1') {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
    this.defaultHeaders = {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': 'Cyinnove-JS-SDK/1.0'
    };
  }

  /**
   * Make HTTP request to the API
   * 
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Request options
   * @returns {Promise<Object>} API response
   * @private
   */
  async _request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const config = {
      headers: { ...this.defaultHeaders, ...options.headers },
      ...options
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`API Error: ${response.status} - ${errorData.message || response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Network error: Unable to connect to Cyinnove API');
      }
      throw error;
    }
  }

  /**
   * Get vulnerabilities with optional filtering
   * 
   * @param {Object} params - Query parameters
   * @param {string} params.severity - Filter by severity
   * @param {string} params.status - Filter by status
   * @param {number} params.limit - Number of results to return
   * @param {number} params.offset - Pagination offset
   * @returns {Promise<Object>} Vulnerabilities data
   */
  async getVulnerabilities(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/vulnerabilities${queryString ? `?${queryString}` : ''}`;
    
    return await this._request(endpoint, { method: 'GET' });
  }

  /**
   * Create a new vulnerability report
   * 
   * @param {Object} vulnerability - Vulnerability data
   * @param {string} vulnerability.title - Vulnerability title
   * @param {string} vulnerability.description - Description
   * @param {string} vulnerability.severity - Severity level
   * @param {Array<string>} vulnerability.affected_assets - Affected assets
   * @returns {Promise<Object>} Created vulnerability data
   */
  async createVulnerability(vulnerability) {
    return await this._request('/vulnerabilities', {
      method: 'POST',
      body: JSON.stringify(vulnerability)
    });
  }

  /**
   * Update vulnerability status
   * 
   * @param {string} vulnerabilityId - Vulnerability ID
   * @param {Object} updates - Updates to apply
   * @returns {Promise<Object>} Updated vulnerability data
   */
  async updateVulnerability(vulnerabilityId, updates) {
    return await this._request(`/vulnerabilities/${vulnerabilityId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates)
    });
  }

  /**
   * Analyze threat indicators
   * 
   * @param {Array<Object>} indicators - List of indicators to analyze
   * @returns {Promise<Object>} Threat analysis results
   */
  async analyzeThreats(indicators) {
    return await this._request('/threats/analyze', {
      method: 'POST',
      body: JSON.stringify({ indicators })
    });
  }

  /**
   * Discover assets for attack surface management
   * 
   * @param {Object} params - Discovery parameters
   * @param {string} params.domain - Primary domain to scan
   * @param {boolean} params.include_subdomains - Include subdomain discovery
   * @param {boolean} params.scan_ports - Perform port scanning
   * @returns {Promise<Object>} Discovered assets
   */
  async discoverAssets(params) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/assets/discover?${queryString}`;
    
    return await this._request(endpoint, { method: 'GET' });
  }

  /**
   * Get security incidents
   * 
   * @param {Object} params - Query parameters
   * @returns {Promise<Object>} Security incidents data
   */
  async getIncidents(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const endpoint = `/incidents${queryString ? `?${queryString}` : ''}`;
    
    return await this._request(endpoint, { method: 'GET' });
  }

  /**
   * Create a new security incident
   * 
   * @param {Object} incident - Incident data
   * @returns {Promise<Object>} Created incident data
   */
  async createIncident(incident) {
    return await this._request('/incidents', {
      method: 'POST',
      body: JSON.stringify(incident)
    });
  }

  /**
   * Get security metrics for organization
   * 
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Security metrics
   */
  async getSecurityMetrics(organizationId) {
    return await this._request(`/metrics/${organizationId}`, { method: 'GET' });
  }
}

// Usage Examples
async function exampleUsage() {
  const api = new CyinnoveAPI('your_api_key_here');

  try {
    // Get high severity vulnerabilities
    const vulnerabilities = await api.getVulnerabilities({
      severity: 'high',
      status: 'open',
      limit: 10
    });
    console.log(`Found ${vulnerabilities.data.length} high severity vulnerabilities`);

    // Create a new vulnerability
    const newVuln = await api.createVulnerability({
      title: 'SQL Injection in Login Form',
      description: 'SQL injection vulnerability found in user authentication',
      severity: 'high',
      affected_assets: ['web-app-1', 'database-1']
    });
    console.log(`Created vulnerability: ${newVuln.id}`);

    // Analyze threat indicators
    const threatAnalysis = await api.analyzeThreats([
      { type: 'ip', value: '192.168.1.100' },
      { type: 'domain', value: 'malicious-site.com' }
    ]);
    console.log('Threat analysis completed:', threatAnalysis.results);

  } catch (error) {
    console.error('API Error:', error.message);
  }
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
  // Node.js
  module.exports = CyinnoveAPI;
} else if (typeof window !== 'undefined') {
  // Browser
  window.CyinnoveAPI = CyinnoveAPI;
}
```

## Error Handling

All APIs return standardized error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request is invalid or malformed",
    "details": {
      "field": "severity",
      "issue": "Must be one of: critical, high, medium, low"
    }
  }
}
```

### Common Error Codes

- `AUTHENTICATION_FAILED`: Invalid API key or expired token
- `AUTHORIZATION_DENIED`: Insufficient permissions
- `INVALID_REQUEST`: Malformed request or invalid parameters
- `RESOURCE_NOT_FOUND`: Requested resource does not exist
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INTERNAL_ERROR`: Server error

### Error Handling Examples

```python
# Python error handling
try:
    vulnerabilities = client.get_vulnerabilities(severity="invalid")
except requests.HTTPError as e:
    if e.response.status_code == 400:
        error_data = e.response.json()
        print(f"Invalid request: {error_data['error']['message']}")
    elif e.response.status_code == 401:
        print("Authentication failed. Check your API key.")
    elif e.response.status_code == 429:
        print("Rate limit exceeded. Please wait before making more requests.")
```

```javascript
// JavaScript error handling
try {
  const vulnerabilities = await api.getVulnerabilities({ severity: 'invalid' });
} catch (error) {
  if (error.message.includes('400')) {
    console.error('Invalid request parameters');
  } else if (error.message.includes('401')) {
    console.error('Authentication failed. Check your API key.');
  } else if (error.message.includes('429')) {
    console.error('Rate limit exceeded. Please wait before making more requests.');
  } else {
    console.error('Unexpected error:', error.message);
  }
}
```

## Rate Limiting

The Cyinnove API implements rate limiting to ensure fair usage:

- **Standard Plan**: 1,000 requests per hour
- **Professional Plan**: 10,000 requests per hour
- **Enterprise Plan**: Custom limits

Rate limit headers are included in all responses:
- `X-RateLimit-Limit`: Maximum requests per hour
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when the rate limit resets

## Changelog

### Version 1.2.0 (2024-01-16)
- Added Behavioral Analysis Engine for threat hunters
- Enhanced threat intelligence capabilities
- Improved error handling and response times

### Version 1.1.0 (2024-01-10)
- Added Attack Surface Management API
- Introduced JavaScript SDK
- Enhanced vulnerability management features

### Version 1.0.0 (2024-01-01)
- Initial release of Cyinnove API
- Vulnerability Management API
- Threat Detection API
- Python SDK

---

For more information and support, contact us at zomasec@proton.me or visit our GitHub repository.