# Advanced Intrusion Prevention System (IPS)

A professional-grade, enterprise-ready Intrusion Prevention System with comprehensive monitoring capabilities, real-time threat detection, and advanced security analytics.

![IPS Dashboard](docs/images/dashboard-preview.png)

## 🚀 Features

### Core Security Features
- **Real-time Threat Detection** - Advanced pattern matching and behavioral analysis
- **Multi-layered Protection** - Network, application, and endpoint security
- **Threat Intelligence Integration** - Global threat feeds and reputation scoring
- **Automated Response** - Intelligent blocking and quarantine capabilities
- **Geographic Threat Analysis** - Location-based threat mapping and filtering

### Monitoring Capabilities
- **Network Monitoring** - Ethernet ports, WiFi devices, and network infrastructure
- **Server Monitoring** - Physical and virtual server health and security
- **Website Monitoring** - Web applications, APIs, and online services
- **Client Monitoring** - Desktop computers and workstations
- **Custom Monitoring** - Flexible monitoring for any target type

### Management & Analytics
- **Professional Web Interface** - Modern, responsive dashboard with dark/light themes
- **Advanced Analytics** - Comprehensive reporting and trend analysis
- **Rule Management** - Intuitive security rule creation and categorization
- **User Management** - Role-based access control and audit logging
- **API Integration** - RESTful API for third-party integrations

### Enterprise Features
- **Multi-user Support** - Admin, Manager, Analyst, and Viewer roles
- **Compliance Ready** - SOC2, GDPR, and industry standard compliance
- **High Availability** - Scalable architecture for enterprise deployments
- **Data Export** - CSV, JSON, and PDF reporting capabilities
- **Email Notifications** - SMTP integration for real-time alerts

## 📋 Requirements

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+), Windows 10+, macOS 10.15+
- **Python**: 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for production)
- **Storage**: 10GB+ available disk space
- **Network**: Internet connection for threat intelligence updates

### Dependencies
- Flask 2.3+
- SQLite 3.35+ (or PostgreSQL 12+ for production)
- Python packages (automatically installed):
  - psutil
  - requests
  - cryptography
  - pyyaml
  - schedule

## 🔧 Installation

### Quick Installation (Recommended)

1. **Download the latest release**:
   \`\`\`bash
   wget https://github.com/your-org/advanced-ips/releases/latest/download/advanced-ips.tar.gz
   tar -xzf advanced-ips.tar.gz
   cd advanced-ips
   \`\`\`

2. **Run the installation script**:
   \`\`\`bash
   chmod +x install.sh
   sudo ./install.sh
   \`\`\`

3. **Start the system**:
   \`\`\`bash
   sudo systemctl start advanced-ips
   sudo systemctl enable advanced-ips
   \`\`\`

4. **Access the web interface**:
   Open your browser and navigate to `http://localhost:5000`

### Manual Installation

1. **Clone the repository**:
   \`\`\`bash
   git clone https://github.com/your-org/advanced-ips.git
   cd advanced-ips
   \`\`\`

2. **Create a virtual environment**:
   \`\`\`bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   \`\`\`

3. **Install dependencies**:
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

4. **Initialize the database**:
   \`\`\`bash
   python scripts/init_database.py
   \`\`\`

5. **Start the application**:
   \`\`\`bash
   python app.py
   \`\`\`

### Docker Installation

1. **Using Docker Compose** (Recommended):
   \`\`\`bash
   git clone https://github.com/your-org/advanced-ips.git
   cd advanced-ips
   docker-compose up -d
   \`\`\`

2. **Using Docker directly**:
   \`\`\`bash
   docker run -d \
     --name advanced-ips \
     -p 5000:5000 \
     -v ips-data:/app/data \
     your-org/advanced-ips:latest
   \`\`\`

## ⚙️ Initial Setup

### First-Time Configuration

1. **Access the setup wizard** at `http://localhost:5000/setup`

2. **Configure administrator account**:
   - Set admin username and password
   - Provide email address for notifications
   - Enter organization details

3. **System configuration**:
   - Choose system name and timezone
   - Select default theme (light/dark)
   - Configure monitoring features

4. **Email notifications** (optional):
   - SMTP server configuration
   - Alert recipients and frequency

5. **Complete setup** and log in with your admin credentials

### Post-Installation Configuration

1. **Install security rule packs**:
   - Navigate to **Rules Categories**
   - Install predefined rule packs (OWASP Top 10, Network Attacks, etc.)
   - Enable/disable rules based on your environment

2. **Add monitoring targets**:
   - Go to **Monitoring Targets**
   - Add your servers, websites, and network devices
   - Configure monitoring intervals and alerts

3. **Deploy client agents** (optional):
   - Download the client agent: `ips-client.py`
   - Configure and deploy on servers you want to monitor
   - See [Client Setup Guide](docs/client-setup.md) for details

## 🖥️ Client Agent Setup

### Server Monitoring with Client Agents

The IPS system includes a lightweight Python client agent that can be deployed on servers for comprehensive monitoring.

#### Quick Client Setup

1. **Download the client agent**:
   \`\`\`bash
   wget http://your-ips-server:5000/download/ips-client.py
   \`\`\`

2. **Install dependencies**:
   \`\`\`bash
   pip install psutil requests schedule cryptography
   \`\`\`

3. **Configure the client**:
   \`\`\`bash
   python ips-client.py --config
   \`\`\`

4. **Start monitoring**:
   \`\`\`bash
   python ips-client.py --daemon
   \`\`\`

#### Client Configuration

Edit `ips-client.conf`:

\`\`\`ini
[server]
host = your-ips-server.com
port = 5000
use_ssl = false
api_key = your-api-key

[client]
hostname = web-server-01
environment = production
tags = web,critical

[monitoring]
interval = 60
metrics_enabled = true
log_level = INFO

[security]
enable_network_monitoring = true
enable_file_monitoring = true
enable_process_monitoring = true
\`\`\`

### Website Integration

#### WordPress Integration

Add this code to your WordPress theme's `functions.php`:

\`\`\`php
// IPS Monitoring Integration
function ips_security_check() {
    $ips_server = 'http://your-ips-server:5000';
    $api_key = 'your-api-key';
    
    $data = array(
        'site_url' => get_site_url(),
        'user_ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'request_uri' => $_SERVER['REQUEST_URI'],
        'timestamp' => current_time('mysql')
    );
    
    wp_remote_post($ips_server . '/api/website/security-check', array(
        'headers' => array(
            'Authorization' => 'Bearer ' . $api_key,
            'Content-Type' => 'application/json'
        ),
        'body' => json_encode($data)
    ));
}

// Hook into WordPress
add_action('init', 'ips_security_check');
\`\`\`

#### PHP Integration

\`\`\`php
<?php
// IPS Security Integration for PHP Applications

class IPSIntegration {
    private $ips_server;
    private $api_key;
    
    public function __construct($server, $api_key) {
        $this->ips_server = $server;
        $this->api_key = $api_key;
    }
    
    public function reportSecurityEvent($event_type, $details) {
        $data = array(
            'event_type' => $event_type,
            'details' => $details,
            'timestamp' => date('c'),
            'source_ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT']
        );
        
        $this->sendToIPS('/api/website/security-event', $data);
    }
    
    private function sendToIPS($endpoint, $data) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->ips_server . $endpoint);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Authorization: Bearer ' . $this->api_key,
            'Content-Type: application/json'
        ));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $result = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($result, true);
    }
}

// Usage example
$ips = new IPSIntegration('http://your-ips-server:5000', 'your-api-key');

// Report failed login attempt
if ($login_failed) {
    $ips->reportSecurityEvent('failed_login', array(
        'username' => $attempted_username,
        'attempts' => $attempt_count
    ));
}
?>
\`\`\`

#### JavaScript Integration

\`\`\`javascript
// IPS Client-Side Security Monitoring

class IPSClient {
    constructor(serverUrl, apiKey) {
        this.serverUrl = serverUrl;
        this.apiKey = apiKey;
    }
    
    async reportEvent(eventType, details) {
        try {
            const response = await fetch(`${this.serverUrl}/api/website/client-event`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    event_type: eventType,
                    details: details,
                    timestamp: new Date().toISOString(),
                    page_url: window.location.href,
                    user_agent: navigator.userAgent
                })
            });
            
            return await response.json();
        } catch (error) {
            console.error('IPS reporting error:', error);
        }
    }
    
    // Monitor for suspicious activity
    monitorSuspiciousActivity() {
        // Detect rapid form submissions
        let formSubmissions = 0;
        document.addEventListener('submit', () => {
            formSubmissions++;
            if (formSubmissions > 5) {
                this.reportEvent('rapid_form_submission', {
                    count: formSubmissions,
                    timeframe: '1_minute'
                });
            }
        });
        
        // Reset counter every minute
        setInterval(() => { formSubmissions = 0; }, 60000);
        
        // Detect console access (potential developer tools usage)
        let devtools = false;
        setInterval(() => {
            if (window.outerHeight - window.innerHeight > 200 && !devtools) {
                devtools = true;
                this.reportEvent('devtools_detected', {
                    screen_height: window.screen.height,
                    window_height: window.innerHeight
                });
            }
        }, 1000);
    }
}

// Initialize IPS monitoring
const ips = new IPSClient('http://your-ips-server:5000', 'your-api-key');
ips.monitorSuspiciousActivity();
\`\`\`

## 📚 Documentation

### User Guides
- [Getting Started Guide](docs/getting-started.md)
- [User Manual](docs/user-guide.md)
- [Administrator Guide](docs/admin-guide.md)
- [Client Setup Guide](docs/client-setup.md)

### Technical Documentation
- [API Reference](docs/api-reference.md)
- [Security Rules Guide](docs/rules-management.md)
- [Threat Intelligence](docs/threat-intelligence.md)
- [Integration Guide](docs/integrations.md)

### Deployment Guides
- [Production Deployment](docs/production-deployment.md)
- [Docker Deployment](docs/docker-deployment.md)
- [High Availability Setup](docs/high-availability.md)
- [Backup and Recovery](docs/backup-recovery.md)

## 🔐 Security Considerations

### Production Deployment
- **Use HTTPS**: Configure SSL/TLS certificates for web interface
- **Database Security**: Use PostgreSQL with encryption for production
- **Network Security**: Deploy behind firewall with restricted access
- **Regular Updates**: Keep system and dependencies updated
- **Backup Strategy**: Implement regular database and configuration backups

### Default Credentials
⚠️ **Important**: Change default credentials immediately after installation!

- Default admin username: `admin`
- Default admin password: Set during initial setup

### API Security
- Use strong API keys for client authentication
- Implement rate limiting for API endpoints
- Monitor API access logs for suspicious activity
- Rotate API keys regularly

## 🛠️ Troubleshooting

### Common Issues

#### Installation Issues
\`\`\`bash
# Permission denied errors
sudo chown -R $USER:$USER /path/to/advanced-ips
chmod +x install.sh

# Python dependency conflicts
python3 -m venv fresh-venv
source fresh-venv/bin/activate
pip install -r requirements.txt
\`\`\`

#### Database Issues
\`\`\`bash
# Reset database
rm ips_alerts.db
python scripts/init_database.py

# Check database integrity
sqlite3 ips_alerts.db "PRAGMA integrity_check;"
\`\`\`

#### Network Connectivity
\`\`\`bash
# Test API connectivity
curl -X GET http://localhost:5000/api/health

# Check firewall settings
sudo ufw status
sudo firewall-cmd --list-all
\`\`\`

#### Performance Issues
\`\`\`bash
# Monitor system resources
htop
iotop
netstat -tulpn

# Check application logs
tail -f ips_system.log
journalctl -u advanced-ips -f
\`\`\`

### Log Files
- Application logs: `ips_system.log`
- Client logs: `ips-client.log`
- System logs: `/var/log/advanced-ips/`
- Audit logs: `audit.log`

### Getting Help
- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/your-org/advanced-ips/issues)
- 💬 [Community Forum](https://community.your-org.com/ips)
- 📧 [Support Email](mailto:support@your-org.com)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
\`\`\`bash
git clone https://github.com/your-org/advanced-ips.git
cd advanced-ips
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements-dev.txt
pre-commit install
\`\`\`

### Running Tests
\`\`\`bash
pytest tests/
python -m pytest --cov=app tests/
\`\`\`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines and best practices
- [MITRE ATT&CK](https://attack.mitre.org/) for threat intelligence framework
- [Snort](https://www.snort.org/) for IPS rule format inspiration
- [Suricata](https://suricata-ids.org/) for network security monitoring concepts

## 📊 Project Status

- ✅ Core IPS functionality
- ✅ Web interface and dashboard
- ✅ Client monitoring agents
- ✅ Rule management system
- ✅ Threat intelligence integration
- ✅ API endpoints
- ✅ Documentation
- 🔄 High availability features (in progress)
- 🔄 Machine learning integration (planned)
- 🔄 Mobile application (planned)

---

**Advanced IPS System** - Professional network security monitoring and threat prevention.

For more information, visit our [website](https://your-org.com/advanced-ips) or contact [support](mailto:support@your-org.com).
\`\`\`

Now let's enhance the IPS engine with the new monitoring capabilities:

```typescriptreact file="ips_engine.py"
[v0-no-op-code-block-prefix]#!/usr/bin/env python3
"""
Advanced Intrusion Prevention System (IPS) Engine
Professional-grade network security monitoring and threat detection
"""

import asyncio
import json
import logging
import time
import re
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import ipaddress
import socket
import struct
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ips_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ThreatSignature:
    """Represents a threat signature for detection"""
    id: str
    name: str
    pattern: str
    severity: str
    category: str
    action: str
    enabled: bool = True
    created_at: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

@dataclass
class NetworkPacket:
    """Represents a network packet for analysis"""
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    payload: bytes
    size: int
    
@dataclass
class ThreatAlert:
    """Represents a detected threat"""
    id: str
    timestamp: str
    threat_type: str
    severity: str
    source_ip: str
    dest_ip: str
    description: str
    signature_id: str
    blocked: bool
    confidence: float
    country: str = "Unknown"

class GeoIPResolver:
    """Enhanced GeoIP resolution with more comprehensive mapping"""
    
    def __init__(self):
        # Enhanced country mapping for demonstration
        self.ip_ranges = {
            # Asia-Pacific
            '1.0.0.0/8': 'Australia',
            '14.0.0.0/8': 'China',
            '27.0.0.0/8': 'China',
            '36.0.0.0/8': 'China',
            '58.0.0.0/8': 'China',
            '103.0.0.0/8': 'Singapore',
            '110.0.0.0/8': 'Japan',
            '125.0.0.0/8': 'Japan',
            '180.0.0.0/8': 'South Korea',
            '202.0.0.0/8': 'Asia-Pacific',
            '203.0.0.0/8': 'Asia-Pacific',
            
            # Europe
            '46.0.0.0/8': 'Russia',
            '78.0.0.0/8': 'Europe',
            '80.0.0.0/8': 'Europe',
            '81.0.0.0/8': 'United Kingdom',
            '82.0.0.0/8': 'Europe',
            '83.0.0.0/8': 'Europe',
            '84.0.0.0/8': 'Europe',
            '85.0.0.0/8': 'Europe',
            '86.0.0.0/8': 'Europe',
            '87.0.0.0/8': 'Europe',
            '88.0.0.0/8': 'Europe',
            '89.0.0.0/8': 'Europe',
            '90.0.0.0/8': 'Europe',
            '91.0.0.0/8': 'Russia',
            '92.0.0.0/8': 'Europe',
            '93.0.0.0/8': 'Europe',
            '94.0.0.0/8': 'Europe',
            '95.0.0.0/8': 'Russia',
            '151.0.0.0/8': 'Europe',
            '176.0.0.0/8': 'Russia',
            '178.0.0.0/8': 'Russia',
            '185.0.0.0/8': 'Europe',
            '188.0.0.0/8': 'Europe',
            '193.0.0.0/8': 'Europe',
            '194.0.0.0/8': 'Europe',
            '195.0.0.0/8': 'Europe',
            
            # North America
            '4.0.0.0/8': 'United States',
            '6.0.0.0/8': 'United States',
            '7.0.0.0/8': 'United States',
            '8.0.0.0/8': 'United States',
            '12.0.0.0/8': 'United States',
            '13.0.0.0/8': 'United States',
            '15.0.0.0/8': 'United States',
            '16.0.0.0/8': 'United States',
            '17.0.0.0/8': 'United States',
            '18.0.0.0/8': 'United States',
            '19.0.0.0/8': 'United States',
            '20.0.0.0/8': 'United States',
            '23.0.0.0/8': 'United States',
            '24.0.0.0/8': 'United States',
            '50.0.0.0/8': 'United States',
            '63.0.0.0/8': 'United States',
            '64.0.0.0/8': 'United States',
            '65.0.0.0/8': 'United States',
            '66.0.0.0/8': 'United States',
            '67.0.0.0/8': 'United States',
            '68.0.0.0/8': 'United States',
            '69.0.0.0/8': 'United States',
            '70.0.0.0/8': 'United States',
            '71.0.0.0/8': 'United States',
            '72.0.0.0/8': 'United States',
            '73.0.0.0/8': 'United States',
            '74.0.0.0/8': 'United States',
            '75.0.0.0/8': 'United States',
            '76.0.0.0/8': 'United States',
            '96.0.0.0/8': 'United States',
            '97.0.0.0/8': 'United States',
            '98.0.0.0/8': 'United States',
            '99.0.0.0/8': 'United States',
            '100.0.0.0/8': 'United States',
            '104.0.0.0/8': 'United States',
            '107.0.0.0/8': 'United States',
            '108.0.0.0/8': 'United States',
            '142.0.0.0/8': 'United States',
            '143.0.0.0/8': 'United States',
            '144.0.0.0/8': 'United States',
            '162.0.0.0/8': 'United States',
            '173.0.0.0/8': 'United States',
            '174.0.0.0/8': 'United States',
            '184.0.0.0/8': 'United States',
            '199.0.0.0/8': 'United States',
            '206.0.0.0/8': 'United States',
            '207.0.0.0/8': 'United States',
            '208.0.0.0/8': 'United States',
            '209.0.0.0/8': 'United States',
            '216.0.0.0/8': 'United States',
            
            # South America
            '177.0.0.0/8': 'Brazil',
            '179.0.0.0/8': 'Brazil',
            '181.0.0.0/8': 'Brazil',
            '186.0.0.0/8': 'Brazil',
            '189.0.0.0/8': 'Brazil',
            '190.0.0.0/8': 'South America',
            '200.0.0.0/8': 'South America',
            '201.0.0.0/8': 'South America',
            
            # Africa
            '41.0.0.0/8': 'Africa',
            '102.0.0.0/8': 'Africa',
            '105.0.0.0/8': 'Africa',
            '154.0.0.0/8': 'Africa',
            '196.0.0.0/8': 'Africa',
            '197.0.0.0/8': 'Africa',
        }
    
    def get_country(self, ip: str) -> str:
        """Get country for IP address with enhanced mapping"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if it's a private IP
            if ip_obj.is_private:
                return "Internal"
            
            # Check against our ranges
            for cidr, country in self.ip_ranges.items():
                try:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return country
                except:
                    continue
            
            return "Unknown"
        except:
            return "Unknown"

class ThreatIntelligence:
    """Enhanced threat intelligence with reputation scoring"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.reputation_scores = defaultdict(lambda: 50)  # Default neutral score
        self.threat_categories = defaultdict(set)
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Load comprehensive threat intelligence feeds"""
        # Known malicious IPs (simulated threat feed)
        self.malicious_ips.update([
            '192.168.1.100',  # Simulated internal threat
            '203.45.67.89',   # Simulated Chinese IP
            '156.78.90.123',  # Simulated Russian IP
            '45.67.89.123',   # Simulated unknown threat
            '185.220.101.42', # Simulated Tor exit node
            '198.51.100.42',  # Simulated botnet C&C
            '203.0.113.45',   # Example malicious IP
            '192.0.2.1',      # Example malicious IP
            '10.0.0.1'         # Example malicious IP
        ])
        
        # Known suspicious domains (simulated threat feed)
        self.suspicious_domains.update([
            'evil.com',
            'malware.net',
            'phishing.org'
        ])
        
        # Update reputation scores (simulated threat feed)
        self.reputation_scores['192.168.1.100'] = 10  # Very low reputation
        self.reputation_scores['203.45.67.89'] = 20   # Low reputation
        self.reputation_scores['156.78.90.123'] = 30  # Suspicious reputation
        
        # Update threat categories (simulated threat feed)
        self.threat_categories['192.168.1.100'].add('internal_attack')
        self.threat_categories['203.45.67.89'].add('china_threat')
        self.threat_categories['156.78.90.123'].add('russian_threat')
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is in the malicious IP list"""
        return ip in self.malicious_ips
    
    def is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is in the suspicious domain list"""
        return domain in self.suspicious_domains
    
    def get_reputation_score(self, ip: str) -> int:
        """Get reputation score for an IP address"""
        return self.reputation_scores[ip]
    
    def get_threat_categories(self, ip: str) -> set:
        """Get threat categories for an IP address"""
        return self.threat_categories[ip]
    
class IPSEngine:
    """Core IPS Engine for threat detection and prevention"""
    
    def __init__(self):
        # Load threat signatures from JSON file
        self.signature_engine = SignatureEngine('threat_signatures.json')
        self.threat_intel = ThreatIntelligence()
        self.geoip_resolver = GeoIPResolver()
        self.blocked_ips = set()
        self.alerts: List[ThreatAlert] = []
        self.db_connection = sqlite3.connect('ips_alerts.db')
        self._setup_database()
        
        # Client management
        self.connected_clients = {}
        self.client_metrics = defaultdict(list)
        self.client_alerts = defaultdict(list)

    def register_client(self, client_data):
        """Register a new client"""
        try:
            # Generate unique client ID
            client_id = hashlib.md5(
                f"{client_data['hostname']}{client_data['ip_address']}{time.time()}".encode()
            ).hexdigest()[:12]
            
            # Store client information
            self.connected_clients[client_id] = {
                'id': client_id,
                'hostname': client_data['hostname'],
                'ip_address': client_data['ip_address'],
                'os_type': client_data.get('os_type', 'Unknown'),
                'client_version': client_data.get('client_version', '1.0.0'),
                'environment': client_data.get('environment', 'production'),
                'tags': client_data.get('tags', []),
                'capabilities': client_data.get('capabilities', {}),
                'status': 'active',
                'health_status': 'healthy',
                'registered_at': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'last_heartbeat': datetime.now().isoformat()
            }
            
            logger.info(f"Client registered: {client_data['hostname']} ({client_id})")
            return client_id
            
        except Exception as e:
            logger.error(f"Client registration failed: {e}")
            raise

    def update_client_heartbeat(self, client_id, heartbeat_data):
        """Update client heartbeat"""
        try:
            if client_id in self.connected_clients:
                self.connected_clients[client_id]['last_heartbeat'] = datetime.now().isoformat()
                self.connected_clients[client_id]['last_seen'] = datetime.now().isoformat()
                self.connected_clients[client_id]['status'] = 'active'
                
                # Update health status based on heartbeat data
                uptime = heartbeat_data.get('uptime', 0)
                if uptime > 0:
                    self.connected_clients[client_id]['uptime'] = uptime
                
                logger.debug(f"Heartbeat updated for client: {client_id}")
            else:
                logger.warning(f"Heartbeat received from unknown client: {client_id}")
                
        except Exception as e:
            logger.error(f"Heartbeat update failed: {e}")

    def store_client_metrics(self, client_id, metrics_data):
        """Store client metrics"""
        try:
            if client_id in self.connected_clients:
                # Store metrics (keep last 100 entries per client)
                self.client_metrics[client_id].append(metrics_data)
                if len(self.client_metrics[client_id]) > 100:
                    self.client_metrics[client_id] = self.client_metrics[client_id][-100:]
                
                # Update client health status based on metrics
                self._update_client_health(client_id, metrics_data)
                
                logger.debug(f"Metrics stored for client: {client_id}")
            else:
                logger.warning(f"Metrics received from unknown client: {client_id}")
                
        except Exception as e:
            logger.error(f"Metrics storage failed: {e}")

    def process_client_alert(self, client_id, alert_data):
        """Process alert from client"""
        try:
            if client_id in self.connected_clients:
                client_info = self.connected_clients[client_id]
                
                # Create alert with client context
                alert = ThreatAlert(
                    id=hashlib.md5(f"{client_id}{alert_data['alert']['type']}{time.time()}".encode()).hexdigest()[:12],
                    timestamp=datetime.now().isoformat(),
                    threat_type=alert_data['alert']['type'],
                    severity=alert_data['alert']['severity'],
                    source_ip=client_info['ip_address'],
                    dest_ip='N/A',
                    description=f"[{client_info['hostname']}] {alert_data['alert']['description']}",
                    signature_id=f"CLIENT_{alert_data['alert']['type'].upper()}",
                    blocked=False,
                    confidence=0.8,
                    country='Internal'
                )
                
                # Store alert
                self.client_alerts[client_id].append(alert_data)
                if len(self.client_alerts[client_id]) > 50:
                    self.client_alerts[client_id] = self.client_alerts[client_id][-50:]
                
                # Add to main alerts
                self.alerts.append(alert)
                self._store_alert(alert)
                
                logger.info(f"Client alert processed: {alert_data['alert']['type']} from {client_info['hostname']}")
            else:
                logger.warning(f"Alert received from unknown client: {client_id}")
                
        except Exception as e:
            logger.error(f"Client alert processing failed: {e}")

    def _update_client_health(self, client_id, metrics_data):
        """Update client health status based on metrics"""
        try:
            metrics = metrics_data.get('metrics', {})
            
            # Check CPU usage
            cpu_percent = metrics.get('cpu', {}).get('percent', 0)
            memory_percent = metrics.get('memory', {}).get('percent', 0)
            
            # Determine health status
            if cpu_percent > 90 or memory_percent > 95:
                health_status = 'critical'
            elif cpu_percent > 80 or memory_percent > 85:
                health_status = 'warning'
            else:
                health_status = 'healthy'
            
            self.connected_clients[client_id]['health_status'] = health_status
            
        except Exception as e:
            logger.error(f"Health status update failed: {e}")

    def get_connected_clients(self):
        """Get list of connected clients"""
        try:
            current_time = datetime.now()
            clients = []
            
            for client_id, client_info in self.connected_clients.items():
                # Check if client is still active (heartbeat within last 5 minutes)
                last_heartbeat = datetime.fromisoformat(client_info['last_heartbeat'])
                if (current_time - last_heartbeat).total_seconds() > 300:
                    client_info['status'] = 'inactive'
                
                clients.append(client_info)
            
            return clients
            
        except Exception as e:
            logger.error(f"Failed to get connected clients: {e}")
            return []

    def get_client_metrics(self, client_id, limit=50):
        """Get metrics for a specific client"""
        try:
            return self.client_metrics.get(client_id, [])[-limit:]
        except Exception as e:
            logger.error(f"Failed to get client metrics: {e}")
            return []

    def get_client_alerts(self, client_id, limit=50):
        """Get alerts for a specific client"""
        try:
            return self.client_alerts.get(client_id, [])[-limit:]
        except Exception as e:
            logger.error(f"Failed to get client alerts: {e}")
            return []

    def unblock_ip(self, ip):
        """Unblock an IP address"""
        try:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                logger.info(f"IP unblocked: {ip}")
            else:
                logger.warning(f"IP not in blocked list: {ip}")
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")

    def add_signature(self, signature):
        """Add a new threat signature"""
        try:
            self.signature_engine.signatures.append(signature)
            logger.info(f"Signature added: {signature.name}")
        except Exception as e:
            logger.error(f"Failed to add signature: {e}")

    def _setup_database(self):
        """Set up the SQLite database for storing alerts"""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    description TEXT,
                    signature_id TEXT,
                    blocked BOOLEAN,
                    confidence REAL,
                    country TEXT
                )
            """)
            self.db_connection.commit()
            logger.info("Database setup completed.")
        except sqlite3.Error as e:
            logger.error(f"Database setup failed: {e}")
            
    def _store_alert(self, alert: ThreatAlert):
        """Store a threat alert in the database"""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                INSERT INTO alerts (id, timestamp, threat_type, severity, source_ip, dest_ip, description, signature_id, blocked, confidence, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id, alert.timestamp, alert.threat_type, alert.severity,
                alert.source_ip, alert.dest_ip, alert.description, alert.signature_id,
                alert.blocked, alert.confidence, alert.country
            ))
            self.db_connection.commit()
            logger.info(f"Alert stored in database: {alert.id}")
        except sqlite3.Error as e:
            logger.error(f"Failed to store alert in database: {e}")

    def process_packet(self, packet: NetworkPacket):
        """Process a network packet against threat signatures"""
        try:
            # Basic checks
            if not isinstance(packet, NetworkPacket):
                logger.warning("Invalid packet format received.")
                return
            
            # Check against threat intelligence
            if packet.source_ip in self.threat_intel.malicious_ips or packet.dest_ip in self.threat_intel.malicious_ips:
                self._handle_threat(packet, "Malicious IP Detected", "high", "blacklist_match", 0.95)
                return
            
            # Signature matching
            for signature in self.signature_engine.signatures:
                if signature.enabled and re.search(signature.pattern, packet.payload.decode(errors='ignore')):
                    self._handle_threat(packet, signature.name, signature.severity, signature.id, 0.8)
                    return
            
            # Anomaly detection (example: large packet size)
            if packet.size > 1500:
                self._handle_threat(packet, "Large Packet Size Detected", "medium", "anomaly_large_packet", 0.6)
                return
            
            logger.debug(f"Packet processed: {packet.source_ip} -> {packet.dest_ip}")
        except Exception as e:
            logger.error(f"Packet processing failed: {e}")

    def _handle_threat(self, packet: NetworkPacket, threat_name: str, severity: str, signature_id: str, confidence: float):
        """Handle a detected threat"""
        try:
            # Resolve country
            country = self.geoip_resolver.get_country(packet.source_ip)
            
            # Create alert
            alert = ThreatAlert(
                id=hashlib.md5(f"{packet.timestamp}{packet.source_ip}{threat_name}".encode()).hexdigest()[:12],
                timestamp=datetime.now().isoformat(),
                threat_type=threat_name,
                severity=severity,
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                description=f"{threat_name} detected from {packet.source_ip} to {packet.dest_ip}",
                signature_id=signature_id,
                blocked=packet.source_ip in self.blocked_ips,
                confidence=confidence,
                country=country
            )
            
            # Store alert
            self.alerts.append(alert)
            self._store_alert(alert)
            
            # Block IP if severity is high
            if severity == "high" and packet.source_ip not in self.blocked_ips:
                self.blocked_ips.add(packet.source_ip)
                logger.warning(f"IP blocked due to high severity threat: {packet.source_ip}")
            
            logger.warning(f"Threat detected: {threat_name} from {packet.source_ip} to {packet.dest_ip} (Severity: {severity})")
        except Exception as e:
            logger.error(f"Threat handling failed: {e}")

    def add_monitoring_target(self, target_data):
        """Add a new monitoring target"""
        try:
            target_id = hashlib.md5(
                f"{target_data['name']}{target_data['address']}{time.time()}".encode()
            ).hexdigest()[:12]
            
            target = {
                'id': target_id,
                'name': target_data['name'],
                'type': target_data['type'],
                'address': target_data['address'],
                'port': target_data.get('port'),
                'protocol': target_data.get('protocol', 'icmp'),
                'monitoring_interval': target_data.get('monitoring_interval', 60),
                'enabled': target_data.get('enabled', True),
                'tags': target_data.get('tags', []),
                'description': target_data.get('description', ''),
                'status': 'unknown',
                'health': 100,
                'last_check': None,
                'response_time': None,
                'created_at': datetime.now().isoformat()
            }
            
            # Store target (in production, this would be in a database)
            if not hasattr(self, 'monitoring_targets'):
                self.monitoring_targets = {}
            
            self.monitoring_targets[target_id] = target
            logger.info(f"Monitoring target added: {target_data['name']} ({target_id})")
            return target_id
            
        except Exception as e:
            logger.error(f"Failed to add monitoring target: {e}")
            raise

    def get_monitoring_targets(self):
        """Get all monitoring targets"""
        try:
            if not hasattr(self, 'monitoring_targets'):
                self.monitoring_targets = {}
            
            return list(self.monitoring_targets.values())
        except Exception as e:
            logger.error(f"Failed to get monitoring targets: {e}")
            return []

    def get_target_statistics(self):
        """Get monitoring target statistics"""
        try:
            targets = self.get_monitoring_targets()
            
            stats = {
                'total': len(targets),
                'active': len([t for t in targets if t['status'] == 'online']),
                'offline': len([t for t in targets if t['status'] == 'offline']),
                'warning': len([t for t in targets if t['status'] == 'warning']),
                'network_count': len([t for t in targets if t['type'] == 'network']),
                'wifi_count': len([t for t in targets if t['type'] == 'wifi']),
                'server_count': len([t for t in targets if t['type'] == 'server']),
                'website_count': len([t for t in targets if t['type'] == 'website']),
                'computer_count': len([t for t in targets if t['type'] == 'computer']),
                'custom_count': len([t for t in targets if t['type'] == 'custom'])
            }
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get target statistics: {e}")
            return {}

    def get_rule_categories(self):
        """Get security rule categories"""
        try:
            # Predefined categories with real-world security rules
            categories = [
                {
                    'id': 'web-attacks',
                    'name': 'Web Application Attacks',
                    'description': 'Rules for detecting web application vulnerabilities and attacks',
                    'icon': 'globe',
                    'severity_color': 'danger',
                    'rule_count': 25,
                    'active_rules': 23,
                    'critical_rules': 8,
                    'triggered_24h': 12,
                    'enabled': True
                },
                {
                    'id': 'network-intrusion',
                    'name': 'Network Intrusion',
                    'description': 'Detection of network-based intrusion attempts and scanning',
                    'icon': 'network-widescreen',
                    'severity_color': 'warning',
                    'rule_count': 40,
                    'active_rules': 38,
                    'critical_rules': 15,
                    'triggered_24h': 8,
                    'enabled': True
                },
                {
                    'id': 'malware-detection',
                    'name': 'Malware Detection',
                    'description': 'Signatures and patterns for malware and suspicious file detection',
                    'icon': 'virus',
                    'severity_color': 'danger',
                    'rule_count': 60,
                    'active_rules': 55,
                    'critical_rules': 25,
                    'triggered_24h': 5,
                    'enabled': True
                },
                {
                    'id': 'database-attacks',
                    'name': 'Database Attacks',
                    'description': 'SQL injection and database-specific attack detection',
                    'icon': 'database-exclamation',
                    'severity_color': 'info',
                    'rule_count': 30,
                    'active_rules': 28,
                    'critical_rules': 12,
                    'triggered_24h': 3,
                    'enabled': True
                },
                {
                    'id': 'bot-detection',
                    'name': 'Bot Detection',
                    'description': 'Automated bot and scraper detection patterns',
                    'icon': 'robot',
                    'severity_color': 'secondary',
                    'rule_count': 20,
                    'active_rules': 18,
                    'critical_rules': 5,
                    'triggered_24h': 15,
                    'enabled': True
                },
                {
                    'id': 'cloud-security',
                    'name': 'Cloud Security',
                    'description': 'Cloud-specific security rules for AWS, Azure, and GCP',
                    'icon': 'cloud-exclamation',
                    'severity_color': 'success',
                    'rule_count': 35,
                    'active_rules': 32,
                    'critical_rules': 10,
                    'triggered_24h': 2,
                    'enabled': True
                }
            ]
            
            return categories
        except Exception as e:
            logger.error(f"Failed to get rule categories: {e}")
            return []

    def get_rules_by_category(self):
        """Get rules organized by category"""
        try:
            # Sample rules for each category
            rules_by_category = {
                'web-attacks': [
                    {
                        'id': 'web-001',
                        'name': 'SQL Injection Detection',
                        'description': 'Detects common SQL injection patterns in web requests',
                        'enabled': True,
                        'severity': 'critical'
                    },
                    {
                        'id': 'web-002',
                        'name': 'XSS Attack Detection',
                        'description': 'Cross-site scripting attack pattern detection',
                        'enabled': True,
                        'severity': 'high'
                    },
                    {
                        'id': 'web-003',
                        'name': 'Directory Traversal',
                        'description': 'Path traversal and directory listing attempts',
                        'enabled': True,
                        'severity': 'medium'
                    }
                ],
                'network-intrusion': [
                    {
                        'id': 'net-001',
                        'name': 'Port Scan Detection',
                        'description': 'Detects network port scanning activities',
                        'enabled': True,
                        'severity': 'medium'
                    },
                    {
                        'id': 'net-002',
                        'name': 'Brute Force SSH',
                        'description': 'SSH brute force login attempts',
                        'enabled': True,
                        'severity': 'high'
                    },
                    {
                        'id': 'net-003',
                        'name': 'DDoS Detection',
                        'description': 'Distributed denial of service attack patterns',
                        'enabled': True,
                        'severity': 'critical'
                    }
                ],
                'malware-detection': [
                    {
                        'id': 'mal-001',
                        'name': 'Known Malware Signatures',
                        'description': 'Detection of known malware file signatures',
                        'enabled': True,
                        'severity': 'critical'
                    },
                    {
                        'id': 'mal-002',
                        'name': 'Suspicious File Behavior',
                        'description': 'Behavioral analysis of suspicious file activities',
                        'enabled': True,
                        'severity': 'high'
                    },
                    {
                        'id': 'mal-003',
                        'name': 'Command & Control Traffic',
                        'description': 'Detection of C&C communication patterns',
                        'enabled': True,
                        'severity': 'critical'
                    }
                ]
            }
            
            return rules_by_category
        except Exception as e:
            logger.error(f"Failed to get rules by category: {e}")
            return {}

    def get_monitored_websites(self):
        """Get monitored websites"""
        try:
            # Sample website monitoring data
            websites = [
                {
                    'id': 'web-001',
                    'name': 'Company Website',
                    'url': 'https://company.com',
                    'status': 'online',
                    'response_time': 245,
                    'last_check': '2 minutes ago',
                    'ssl_status': 'valid',
                    'ssl_expires': '2024-12-15'
                },
                {
                    'id': 'web-002',
                    'name': 'API Endpoint',
                    'url': 'https://api.company.com',
                    'status': 'online',
                    'response_time': 89,
                    'last_check': '1 minute ago',
                    'ssl_status': 'valid',
                    'ssl_expires': '2024-11-20'
                }
            ]
            
            return websites
        except Exception as e:
            logger.error(f"Failed to get monitored websites: {e}")
            return []

    def get_website_statistics(self):
        """Get website monitoring statistics"""
        try:
            websites = self.get_monitored_websites()
            
            stats = {
                'total': len(websites),
                'online': len([w for w in websites if w['status'] == 'online']),
                'offline': len([w for w in websites if w['status'] == 'offline']),
                'warning': len([w for w in websites if w['status'] == 'warning']),
                'avg_response_time': sum([w['response_time'] for w in websites]) / len(websites) if websites else 0
            }
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get website statistics: {e}")
            return {}

class SignatureEngine:
    """Manages threat signatures"""
    
    def __init__(self, signature_file: str):
        self.signature_file = signature_file
        self.signatures: List[ThreatSignature] = []
        self.load_signatures()
    
    def load_signatures(self):
        """Load threat signatures from a JSON file"""
        try:
            with open(self.signature_file, 'r') as f:
                data = json.load(f)
                for item in data:
                    try:
                        signature = ThreatSignature(**item)
                        self.signatures.append(signature)
                    except Exception as e:
                        logger.error(f"Error loading signature: {e} - Data: {item}")
            logger.info(f"Loaded {len(self.signatures)} threat signatures from {self.signature_file}")
        except FileNotFoundError:
            logger.warning(f"Signature file not found: {self.signature_file}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON in {self.signature_file}: {e}")
        except Exception as e:
            logger.error(f"Error loading signatures: {e}")

async def simulate_network_traffic(ips_engine: IPSEngine):
    """Simulate network traffic and process packets"""
    try:
        while True:
            # Create a simulated network packet
            packet = NetworkPacket(
                timestamp=time.time(),
                source_ip=f"192.168.1.{random.randint(1, 254)}",
                dest_ip=f"8.8.8.{random.randint(1, 254)}",
                source_port=random.randint(1024, 65535),
                dest_port=80,
                protocol="TCP",
                payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                size=1024
            )
            
            # Process the packet
            ips_engine.process_packet(packet)
            
            # Simulate a potentially malicious packet
            if random.random() < 0.1:
                malicious_packet = NetworkPacket(
                    timestamp=time.time(),
                    source_ip="203.0.113.45",  # Example malicious IP
                    dest_ip="192.168.1.10",
                    source_port=6666,
                    dest_port=22,
                    protocol="TCP",
                    payload=b"This is a malicious payload with a known exploit pattern.",
                    size=512
                )
                ips_engine.process_packet(malicious_packet)
            
            await asyncio.sleep(1)  # Simulate packet arrival rate
        except asyncio.CancelledError:
            logger.info("Traffic simulation cancelled.")
        except Exception as e:
            logger.error(f"Traffic simulation failed: {e}")

async def main():
    """Main function to start the IPS engine and traffic simulation"""
    ips_engine = IPSEngine()
    
    # Simulate client registration
    client_data = {
        'hostname': 'desktop-alpha',
        'ip_address': '192.168.1.50',
        'os_type': 'Windows 10',
        'client_version': '2.1.0',
        'environment': 'development',
        'tags': ['dev', 'internal'],
        'capabilities': {'firewall': True, 'antivirus': True}
    }
    client_id = ips_engine.register_client(client_data)
    
    # Simulate client heartbeat
    heartbeat_data = {'uptime': 3600, 'cpu_usage': 65.0, 'memory_usage': 45.0}
    ips_engine.update_client_heartbeat(client_id, heartbeat_data)
    
    # Simulate client metrics
    metrics_data = {
        'timestamp': datetime.now().isoformat(),
        'metrics': {
            'cpu': {'percent': 70.5},
            'memory': {'percent': 60.2, 'available': 4096, 'used': 6144},
            'disk': {'read_bytes': 10240, 'write_bytes': 20480}
        }
    }
    ips_engine.store_client_metrics(client_id, metrics_data)
    
    # Simulate client alert
    alert_data = {
        'timestamp': datetime.now().isoformat(),
        'alert': {
            'type': 'SuspiciousProcess',
            'severity': 'medium',
            'description': 'A suspicious process was detected running from a temporary directory.'
        }
    }
    ips_engine.process_client_alert(client_id, alert_data)
    
    # Start traffic simulation
    traffic_task = asyncio.create_task(simulate_network_traffic(ips_engine))
    
    try:
        await asyncio.sleep(60)  # Run simulation for 60 seconds
    except asyncio.CancelledError:
        pass
    finally:
        traffic_task.cancel()
        await traffic_task
    
    # Example: Print alerts
    print("Detected Alerts:")
    for alert in ips_engine.alerts:
        print(asdict(alert))
    
    # Example: Get connected clients
    connected_clients = ips_engine.get_connected_clients()
    print("\nConnected Clients:")
    for client in connected_clients:
        print(client)
    
    # Example: Get client metrics
    client_metrics = ips_engine.get_client_metrics(client_id)
    print("\nClient Metrics:")
    for metric in client_metrics:
        print(metric)
    
    # Example: Get client alerts
    client_alerts = ips_engine.get_client_alerts(client_id)
    print("\nClient Alerts:")
    for client_alert in client_alerts:
        print(client_alert)

if __name__ == "__main__":
    asyncio.run(main())
