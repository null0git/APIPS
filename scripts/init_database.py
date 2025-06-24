#!/usr/bin/env python3
"""
Database initialization script for the IPS system
Creates and populates the database with initial data
"""

import sqlite3
import json
from datetime import datetime, timedelta
import random

def init_database():
    """Initialize the IPS database with tables and sample data"""
    
    print("Initializing IPS Database...")
    
    # Connect to database
    conn = sqlite3.connect('ips_database.db')
    cursor = conn.cursor()
    
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            packets_processed INTEGER,
            threats_detected INTEGER,
            threats_blocked INTEGER,
            false_positives INTEGER,
            cpu_usage REAL,
            memory_usage REAL,
            active_connections INTEGER
        )
    ''')
    
    # Create rules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            pattern TEXT,
            severity TEXT,
            category TEXT,
            action TEXT,
            enabled INTEGER,
            created_at TEXT,
            updated_at TEXT,
            triggered_count INTEGER DEFAULT 0
        )
    ''')
    
    # Create blocked_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at TEXT,
            reason TEXT,
            country TEXT,
            reputation_score INTEGER,
            auto_unblock_at TEXT
        )
    ''')
    
    # Create threat_intelligence table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            ip TEXT PRIMARY KEY,
            reputation_score INTEGER,
            last_seen TEXT,
            threat_types TEXT,
            is_malicious INTEGER,
            source TEXT
        )
    ''')
    
    # Create system_config table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        )
    ''')
    
    print("✓ Database tables created successfully")
    
    # Insert sample alerts
    sample_alerts = [
        ('alert_001', '2024-01-15T14:32:15', 'sql_injection', 'critical', '192.168.1.100', '10.0.0.5', 
         'SQL injection attempt detected', 'SQL_001', 1, 0.95, 'Unknown'),
        ('alert_002', '2024-01-15T14:28:42', 'reconnaissance', 'high', '203.45.67.89', '10.0.0.12',
         'Port scanning activity detected', 'SCAN_001', 1, 0.85, 'China'),
        ('alert_003', '2024-01-15T14:25:18', 'malware', 'critical', '156.78.90.123', '10.0.0.8',
         'Malware signature detected in file upload', 'MAL_001', 1, 0.92, 'Russia'),
        ('alert_004', '2024-01-15T14:20:33', 'brute_force', 'high', '45.67.89.123', '10.0.0.15',
         'Multiple failed login attempts', 'BF_001', 1, 0.88, 'Unknown'),
        ('alert_005', '2024-01-15T14:15:07', 'anomaly', 'medium', '10.0.0.25', '8.8.8.8',
         'Unusual outbound traffic pattern', 'ANOM_001', 0, 0.65, 'Internal')
    ]
    
    cursor.executemany('''
        INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_alerts)
    
    print("✓ Sample alerts inserted")
    
    # Insert default security rules
    default_rules = [
        ('SQL_001', 'SQL Injection - Union Attack', 'Detects SQL injection using UNION statements',
         r'(?i)(union\s+select|union\s+all\s+select)', 'critical', 'sql_injection', 'block', 1),
        ('SQL_002', 'SQL Injection - Comment Bypass', 'Detects SQL comment-based injection',
         r'(?i)(--|\#|/\*|\*/)', 'high', 'sql_injection', 'alert', 1),
        ('XSS_001', 'Cross-Site Scripting', 'Detects XSS attack patterns',
         r'(?i)(<script|javascript:|onload=|onerror=)', 'high', 'xss', 'block', 1),
        ('CMD_001', 'Command Injection', 'Detects command injection attempts',
         r'(?i)(;|\||&|`|\$\(|\${)', 'critical', 'command_injection', 'block', 1),
        ('SCAN_001', 'Port Scan Detection', 'Detects port scanning tools',
         r'nmap|masscan|zmap', 'medium', 'reconnaissance', 'monitor', 1),
        ('BF_001', 'Brute Force Attack', 'Detects brute force login attempts',
         r'(login|password|auth).*(fail|error|invalid)', 'high', 'brute_force', 'block', 1),
        ('MAL_001', 'Malware Signature', 'Detects known malware signatures',
         r'(malware|virus|trojan|backdoor)', 'critical', 'malware', 'quarantine', 1),
        ('DDOS_001', 'DDoS Attack Pattern', 'Detects distributed denial of service attacks',
         r'(floo
