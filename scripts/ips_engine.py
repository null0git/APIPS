#!/usr/bin/env python3
"""
Advanced Intrusion Prevention System (IPS) Engine
Real-time network traffic analysis and threat detection
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
    """Simple GeoIP resolution (in production, use MaxMind or similar)"""
    
    def __init__(self):
        # Simplified country mapping for demonstration
        self.ip_ranges = {
            '1.0.0.0/8': 'Australia',
            '14.0.0.0/8': 'China',
            '27.0.0.0/8': 'China',
            '46.0.0.0/8': 'Russia',
            '78.0.0.0/8': 'Europe',
            '91.0.0.0/8': 'Russia',
            '103.0.0.0/8': 'Asia',
            '156.0.0.0/8': 'Russia',
            '185.0.0.0/8': 'Europe',
            '203.0.0.0/8': 'Asia'
        }
    
    def get_country(self, ip: str) -> str:
        """Get country for IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr, country in self.ip_ranges.items():
                if ip_obj in ipaddress.ip_network(cidr):
                    return country
            return "Unknown"
        except:
            return "Unknown"

class ThreatIntelligence:
    """Threat intelligence and reputation system"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.reputation_scores = defaultdict(int)
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Load threat intelligence feeds"""
        # Simulated malicious IPs
        self.malicious_ips.update([
            '192.168.1.100',
            '203.45.67.89',
            '156.78.90.123',
            '45.67.89.123'
        ])
        
        # Simulated suspicious domains
        self.suspicious_domains.update([
            'malware-site.com',
            'phishing-example.net',
            'suspicious-domain.org'
        ])
        
        logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs and {len(self.suspicious_domains)} suspicious domains")
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known to be malicious"""
        return ip in self.malicious_ips
    
    def get_reputation_score(self, ip: str) -> int:
        """Get reputation score for IP (0-100, lower is worse)"""
        if self.is_malicious_ip(ip):
            return 0
        return self.reputation_scores.get(ip, 50)  # Default neutral score
    
    def update_reputation(self, ip: str, delta: int):
        """Update reputation score for IP"""
        current = self.reputation_scores[ip]
        self.reputation_scores[ip] = max(0, min(100, current + delta))

class AnomalyDetector:
    """Machine learning-based anomaly detection"""
    
    def __init__(self):
        self.baseline_metrics = {}
        self.connection_patterns = defaultdict(list)
        self.request_rates = defaultdict(list)
        self.learning_period = 3600  # 1 hour learning period
        
    def update_baseline(self, packet: NetworkPacket):
        """Update baseline metrics for normal behavior"""
        current_time = time.time()
        
        # Track connection patterns
        key = f"{packet.source_ip}:{packet.dest_ip}"
        self.connection_patterns[key].append(current_time)
        
        # Track request rates
        self.request_rates[packet.source_ip].append(current_time)
        
        # Clean old data (keep only last hour)
        cutoff = current_time - self.learning_period
        for ip in list(self.request_rates.keys()):
            self.request_rates[ip] = [t for t in self.request_rates[ip] if t > cutoff]
            if not self.request_rates[ip]:
                del self.request_rates[ip]
    
    def detect_anomaly(self, packet: NetworkPacket) -> Tuple[bool, float, str]:
        """Detect if packet represents anomalous behavior"""
        current_time = time.time()
        
        # Check for high request rate (potential DDoS)
        recent_requests = [t for t in self.request_rates[packet.source_ip] 
                          if t > current_time - 60]  # Last minute
        
        if len(recent_requests) > 100:  # More than 100 requests per minute
            return True, 0.9, "High request rate detected"
        
        # Check for port scanning
        unique_ports = set()
        for timestamp in self.connection_patterns:
            if packet.source_ip in timestamp:
                parts = timestamp.split(':')
                if len(parts) >= 2 and parts[0] == packet.source_ip:
                    unique_ports.add(packet.dest_port)
        
        if len(unique_ports) > 20:  # Accessing many different ports
            return True, 0.8, "Port scanning behavior detected"
        
        # Check for unusual payload size
        if packet.size > 65000:  # Unusually large packet
            return True, 0.7, "Unusually large packet detected"
        
        return False, 0.0, ""

class SignatureEngine:
    """Pattern-based threat detection engine"""
    
    def __init__(self):
        self.signatures = []
        self.load_signatures()
    
    def load_signatures(self):
        """Load threat detection signatures"""
        # SQL Injection signatures
        self.signatures.extend([
            ThreatSignature(
                id="SQL_001",
                name="SQL Injection - Union Attack",
                pattern=r"(?i)(union\s+select|union\s+all\s+select)",
                severity="critical",
                category="sql_injection",
                action="block"
            ),
            ThreatSignature(
                id="SQL_002", 
                name="SQL Injection - Comment Bypass",
                pattern=r"(?i)(--|\#|/\*|\*/)",
                severity="high",
                category="sql_injection",
                action="alert"
            ),
            ThreatSignature(
                id="XSS_001",
                name="Cross-Site Scripting",
                pattern=r"(?i)(<script|javascript:|onload=|onerror=)",
                severity="high",
                category="xss",
                action="block"
            ),
            ThreatSignature(
                id="CMD_001",
                name="Command Injection",
                pattern=r"(?i)(;|\||&|`|\$\(|\${)",
                severity="critical",
                category="command_injection", 
                action="block"
            ),
            ThreatSignature(
                id="SCAN_001",
                name="Port Scan Detection",
                pattern=r"nmap|masscan|zmap",
                severity="medium",
                category="reconnaissance",
                action="monitor"
            )
        ])
        
        logger.info(f"Loaded {len(self.signatures)} threat signatures")
    
    def scan_payload(self, payload: bytes) -> List[Tuple[ThreatSignature, float]]:
        """Scan payload against all signatures"""
        matches = []
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except:
            payload_str = str(payload)
        
        for signature in self.signatures:
            if not signature.enabled:
                continue
                
            if re.search(signature.pattern, payload_str):
                confidence = self._calculate_confidence(signature, payload_str)
                matches.append((signature, confidence))
        
        return matches
    
    def _calculate_confidence(self, signature: ThreatSignature, payload: str) -> float:
        """Calculate confidence score for signature match"""
        base_confidence = 0.7
        
        # Increase confidence based on signature severity
        severity_boost = {
            'critical': 0.3,
            'high': 0.2,
            'medium': 0.1,
            'low': 0.05
        }
        
        confidence = base_confidence + severity_boost.get(signature.severity, 0)
        
        # Increase confidence if multiple patterns match
        pattern_count = len(re.findall(signature.pattern, payload, re.IGNORECASE))
        if pattern_count > 1:
            confidence = min(1.0, confidence + (pattern_count - 1) * 0.1)
        
        return confidence

class IPSEngine:
    """Main IPS Engine coordinating all detection systems"""
    
    def __init__(self):
        self.signature_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        self.threat_intel = ThreatIntelligence()
        self.geo_resolver = GeoIPResolver()
        
        self.blocked_ips = set()
        self.alerts = []
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'false_positives': 0
        }
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing alerts and statistics"""
        self.conn = sqlite3.connect('ips_database.db', check_same_thread=False)
        cursor = self.conn.cursor()
        
        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                threat_type TEXT,
                severity TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                description TEXT,
                signature_id TEXT,
                blocked INTEGER,
                confidence REAL,
                country TEXT
            )
        ''')
        
        # Create statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                timestamp TEXT,
                packets_processed INTEGER,
                threats_detected INTEGER,
                threats_blocked INTEGER,
                false_positives INTEGER
            )
        ''')
        
        self.conn.commit()
        logger.info("Database initialized successfully")
    
    async def process_packet(self, packet: NetworkPacket) -> Optional[ThreatAlert]:
        """Process a single network packet for threats"""
        self.stats['packets_processed'] += 1
        
        # Update anomaly detection baseline
        self.anomaly_detector.update_baseline(packet)
        
        # Check threat intelligence
        if self.threat_intel.is_malicious_ip(packet.source_ip):
            alert = self._create_alert(
                threat_type="malicious_ip",
                severity="high",
                packet=packet,
                description=f"Traffic from known malicious IP: {packet.source_ip}",
                signature_id="INTEL_001",
                confidence=0.95
            )
            return await self._handle_alert(alert)
        
        # Check for anomalies
        is_anomaly, confidence, description = self.anomaly_detector.detect_anomaly(packet)
        if is_anomaly:
            alert = self._create_alert(
                threat_type="anomaly",
                severity="medium",
                packet=packet,
                description=description,
                signature_id="ANOMALY_001",
                confidence=confidence
            )
            return await self._handle_alert(alert)
        
        # Signature-based detection
        signature_matches = self.signature_engine.scan_payload(packet.payload)
        if signature_matches:
            # Use the highest confidence match
            best_match = max(signature_matches, key=lambda x: x[1])
            signature, confidence = best_match
            
            alert = self._create_alert(
                threat_type=signature.category,
                severity=signature.severity,
                packet=packet,
                description=f"{signature.name} detected",
                signature_id=signature.id,
                confidence=confidence
            )
            return await self._handle_alert(alert)
        
        return None
    
    def _create_alert(self, threat_type: str, severity: str, packet: NetworkPacket,
                     description: str, signature_id: str, confidence: float) -> ThreatAlert:
        """Create a threat alert"""
        alert_id = hashlib.md5(
            f"{packet.timestamp}{packet.source_ip}{packet.dest_ip}{threat_type}".encode()
        ).hexdigest()[:12]
        
        return ThreatAlert(
            id=alert_id,
            timestamp=datetime.fromtimestamp(packet.timestamp).isoformat(),
            threat_type=threat_type,
            severity=severity,
            source_ip=packet.source_ip,
            dest_ip=packet.dest_ip,
            description=description,
            signature_id=signature_id,
            blocked=False,
            confidence=confidence,
            country=self.geo_resolver.get_country(packet.source_ip)
        )
    
    async def _handle_alert(self, alert: ThreatAlert) -> ThreatAlert:
        """Handle a threat alert based on configured actions"""
        self.stats['threats_detected'] += 1
        
        # Determine if we should block based on severity and confidence
        should_block = (
            alert.severity in ['critical', 'high'] and 
            alert.confidence > 0.7
        ) or alert.confidence > 0.9
        
        if should_block:
            alert.blocked = True
            self.blocked_ips.add(alert.source_ip)
            self.stats['threats_blocked'] += 1
            logger.warning(f"BLOCKED: {alert.description} from {alert.source_ip}")
        else:
            logger.info(f"ALERT: {alert.description} from {alert.source_ip}")
        
        # Store alert in database
        self._store_alert(alert)
        self.alerts.append(alert)
        
        # Keep only recent alerts in memory (last 1000)
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
        
        # Update threat intelligence reputation
        reputation_delta = -20 if alert.blocked else -5
        self.threat_intel.update_reputation(alert.source_ip, reputation_delta)
        
        return alert
    
    def _store_alert(self, alert: ThreatAlert):
        """Store alert in database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.id, alert.timestamp, alert.threat_type, alert.severity,
            alert.source_ip, alert.dest_ip, alert.description, alert.signature_id,
            int(alert.blocked), alert.confidence, alert.country
        ))
        self.conn.commit()
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts from database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        columns = [desc[0] for desc in cursor.description]
        alerts = []
        for row in cursor.fetchall():
            alert_dict = dict(zip(columns, row))
            alert_dict['blocked'] = bool(alert_dict['blocked'])
            alerts.append(alert_dict)
        
        return alerts
    
    def get_statistics(self) -> Dict:
        """Get current system statistics"""
        return {
            **self.stats,
            'blocked_ips_count': len(self.blocked_ips),
            'active_signatures': len([s for s in self.signature_engine.signatures if s.enabled]),
            'reputation_entries': len(self.threat_intel.reputation_scores)
        }
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        return ip in self.blocked_ips
    
    def unblock_ip(self, ip: str):
        """Remove IP from blocked list"""
        self.blocked_ips.discard(ip)
        logger.info(f"Unblocked IP: {ip}")
    
    def add_signature(self, signature: ThreatSignature):
        """Add new threat signature"""
        self.signature_engine.signatures.append(signature)
        logger.info(f"Added new signature: {signature.name}")
    
    def update_signature(self, signature_id: str, **kwargs):
        """Update existing signature"""
        for signature in self.signature_engine.signatures:
            if signature.id == signature_id:
                for key, value in kwargs.items():
                    if hasattr(signature, key):
                        setattr(signature, key, value)
                logger.info(f"Updated signature: {signature_id}")
                break

# Simulate network packet generation for testing
class PacketSimulator:
    """Simulate network packets for testing the IPS"""
    
    def __init__(self):
        self.attack_patterns = [
            b"SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin",
            b"<script>alert('XSS')</script>",
            b"; rm -rf /; --",
            b"../../../../etc/passwd",
            b"nmap -sS -O target.com"
        ]
        
        self.normal_patterns = [
            b"GET /index.html HTTP/1.1",
            b"POST /api/login HTTP/1.1",
            b"User-Agent: Mozilla/5.0",
            b"Content-Type: application/json"
        ]
    
    def generate_packet(self, malicious: bool = False) -> NetworkPacket:
        """Generate a simulated network packet"""
        import random
        
        timestamp = time.time()
        
        if malicious:
            source_ip = random.choice(['192.168.1.100', '203.45.67.89', '156.78.90.123'])
            payload = random.choice(self.attack_patterns)
        else:
            source_ip = f"10.0.0.{random.randint(1, 254)}"
            payload = random.choice(self.normal_patterns)
        
        return NetworkPacket(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip="10.0.0.1",
            source_port=random.randint(1024, 65535),
            dest_port=random.choice([80, 443, 22, 21]),
            protocol="TCP",
            payload=payload,
            size=len(payload)
        )

async def main():
    """Main function to demonstrate IPS functionality"""
    print("Starting Advanced IPS Engine...")
    
    # Initialize IPS
    ips = IPSEngine()
    simulator = PacketSimulator()
    
    print("IPS Engine initialized successfully")
    print(f"Loaded {len(ips.signature_engine.signatures)} signatures")
    print(f"Threat intelligence: {len(ips.threat_intel.malicious_ips)} known malicious IPs")
    
    # Simulate packet processing
    print("\nSimulating network traffic...")
    
    for i in range(100):
        # Generate mix of normal and malicious packets
        is_malicious = random.random() < 0.1  # 10% malicious traffic
        packet = simulator.generate_packet(malicious=is_malicious)
        
        alert = await ips.process_packet(packet)
        if alert:
            print(f"🚨 THREAT DETECTED: {alert.description} from {alert.source_ip} ({'BLOCKED' if alert.blocked else 'MONITORED'})")
        
        # Small delay to simulate real-time processing
        await asyncio.sleep(0.01)
    
    # Print statistics
    stats = ips.get_statistics()
    print(f"\n📊 IPS Statistics:")
    print(f"   Packets Processed: {stats['packets_processed']}")
    print(f"   Threats Detected: {stats['threats_detected']}")
    print(f"   Threats Blocked: {stats['threats_blocked']}")
    print(f"   Blocked IPs: {stats['blocked_ips_count']}")
    print(f"   Active Signatures: {stats['active_signatures']}")
    
    # Show recent alerts
    recent_alerts = ips.get_recent_alerts(10)
    print(f"\n🔍 Recent Alerts ({len(recent_alerts)}):")
    for alert in recent_alerts[:5]:
        status = "🛡️ BLOCKED" if alert['blocked'] else "👁️ MONITORED"
        print(f"   {status} {alert['description']} from {alert['source_ip']} ({alert['severity']})")

if __name__ == "__main__":
    import random
    asyncio.run(main())
