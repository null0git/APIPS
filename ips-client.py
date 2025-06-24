#!/usr/bin/env python3
"""
IPS Client Agent - Server Monitoring Client
Monitors server health and security, reports to central IPS system
"""

import os
import sys
import time
import json
import logging
import requests
import psutil
import socket
import hashlib
import threading
import schedule
from datetime import datetime, timedelta
from configparser import ConfigParser
from cryptography.fernet import Fernet
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ips-client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IPSClient:
    """IPS Client Agent for server monitoring"""
    
    def __init__(self, config_file='ips-client.conf'):
        self.config = ConfigParser()
        self.config_file = config_file
        self.client_id = None
        self.session = requests.Session()
        self.running = False
        self.last_heartbeat = None
        
        # Load configuration
        self.load_config()
        
        # Initialize client
        self.initialize_client()
        
    def load_config(self):
        """Load configuration from file"""
        try:
            if not os.path.exists(self.config_file):
                self.create_default_config()
            
            self.config.read(self.config_file)
            
            # Server configuration
            self.server_host = self.config.get('server', 'host', fallback='localhost')
            self.server_port = self.config.getint('server', 'port', fallback=5000)
            self.use_ssl = self.config.getboolean('server', 'use_ssl', fallback=False)
            self.api_key = self.config.get('server', 'api_key', fallback='')
            
            # Client configuration
            self.hostname = self.config.get('client', 'hostname', fallback=socket.gethostname())
            self.environment = self.config.get('client', 'environment', fallback='production')
            self.tags = self.config.get('client', 'tags', fallback='').split(',')
            
            # Monitoring configuration
            self.monitor_interval = self.config.getint('monitoring', 'interval', fallback=60)
            self.metrics_enabled = self.config.getboolean('monitoring', 'metrics_enabled', fallback=True)
            self.log_level = self.config.get('monitoring', 'log_level', fallback='INFO')
            
            # Security configuration
            self.network_monitoring = self.config.getboolean('security', 'enable_network_monitoring', fallback=True)
            self.file_monitoring = self.config.getboolean('security', 'enable_file_monitoring', fallback=True)
            self.process_monitoring = self.config.getboolean('security', 'enable_process_monitoring', fallback=True)
            
            # Build base URL
            protocol = 'https' if self.use_ssl else 'http'
            self.base_url = f"{protocol}://{self.server_host}:{self.server_port}"
            
            logger.info(f"Configuration loaded from {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def create_default_config(self):
        """Create default configuration file"""
        config_content = """[server]
host = localhost
port = 5000
use_ssl = false
api_key = your-api-key-here

[client]
hostname = {hostname}
environment = production
tags = server,monitoring

[monitoring]
interval = 60
metrics_enabled = true
log_level = INFO
max_log_size = 100MB

[security]
enable_network_monitoring = true
enable_file_monitoring = true
enable_process_monitoring = true
alert_threshold = medium
""".format(hostname=socket.gethostname())
        
        with open(self.config_file, 'w') as f:
            f.write(config_content)
        
        logger.info(f"Default configuration created: {self.config_file}")
        logger.warning("Please update the configuration file with your server details")
    
    def initialize_client(self):
        """Initialize client with IPS server"""
        try:
            # Prepare registration data
            registration_data = {
                'hostname': self.hostname,
                'ip_address': self.get_local_ip(),
                'os_type': self.get_os_info(),
                'client_version': '2.0.0',
                'environment': self.environment,
                'tags': self.tags,
                'capabilities': {
                    'network_monitoring': self.network_monitoring,
                    'file_monitoring': self.file_monitoring,
                    'process_monitoring': self.process_monitoring,
                    'metrics_collection': self.metrics_enabled
                }
            }
            
            # Register with server
            response = self.make_api_request('POST', '/api/client/register', registration_data)
            
            if response and response.get('status') == 'success':
                self.client_id = response.get('client_id')
                logger.info(f"Successfully registered with IPS server. Client ID: {self.client_id}")
            else:
                logger.error("Failed to register with IPS server")
                sys.exit(1)
                
        except Exception as e:
            logger.error(f"Client initialization failed: {e}")
            sys.exit(1)
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def get_os_info(self):
        """Get operating system information"""
        try:
            import platform
            return {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            }
        except:
            return {'system': 'Unknown'}
    
    def make_api_request(self, method, endpoint, data=None):
        """Make API request to IPS server"""
        try:
            url = f"{self.base_url}{endpoint}"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': f'IPS-Client/2.0.0 ({self.hostname})'
            }
            
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            if method == 'POST':
                response = self.session.post(url, json=data, headers=headers, timeout=30)
            elif method == 'GET':
                response = self.session.get(url, headers=headers, timeout=30)
            else:
                return None
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"API request failed: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {e}")
            return None
    
    def collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': (usage.used / usage.total) * 100
                    }
                except:
                    continue
            
            # Network metrics
            network = psutil.net_io_counters()
            network_connections = len(psutil.net_connections())
            
            # Process metrics
            process_count = len(psutil.pids())
            
            # Load average (Unix-like systems)
            try:
                load_avg = os.getloadavg()
            except:
                load_avg = [0, 0, 0]
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'frequency': cpu_freq._asdict() if cpu_freq else None
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                },
                'disk': disk_usage,
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv,
                    'connections': network_connections
                },
                'system': {
                    'processes': process_count,
                    'load_avg': load_avg,
                    'uptime': time.time() - psutil.boot_time()
                }
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
            return None
    
    def detect_security_events(self):
        """Detect potential security events"""
        events = []
        
        try:
            # Check for suspicious processes
            if self.process_monitoring:
                suspicious_processes = self.check_suspicious_processes()
                events.extend(suspicious_processes)
            
            # Check network connections
            if self.network_monitoring:
                suspicious_connections = self.check_network_connections()
                events.extend(suspicious_connections)
            
            # Check file system changes
            if self.file_monitoring:
                file_changes = self.check_file_changes()
                events.extend(file_changes)
            
        except Exception as e:
            logger.error(f"Security event detection failed: {e}")
        
        return events
    
    def check_suspicious_processes(self):
        """Check for suspicious processes"""
        events = []
        suspicious_names = [
            'nc', 'netcat', 'ncat', 'socat',  # Network tools
            'nmap', 'masscan', 'zmap',        # Scanning tools
            'metasploit', 'msfconsole',       # Exploitation frameworks
            'sqlmap', 'nikto', 'dirb',        # Web security tools
            'john', 'hashcat', 'hydra'        # Password cracking
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    if any(sus_name in proc_name for sus_name in suspicious_names):
                        events.append({
                            'type': 'suspicious_process',
                            'severity': 'high',
                            'description': f'Suspicious process detected: {proc_name}',
                            'details': {
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'cmdline': proc_info['cmdline'],
                                'create_time': proc_info['create_time']
                            }
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")
        
        return events
    
    def check_network_connections(self):
        """Check for suspicious network connections"""
        events = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            # Check for connections to suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]  # Common backdoor ports
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_port = conn.raddr.port
                    
                    if remote_port in suspicious_ports:
                        events.append({
                            'type': 'suspicious_connection',
                            'severity': 'medium',
                            'description': f'Connection to suspicious port: {remote_port}',
                            'details': {
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'pid': conn.pid
                            }
                        })
                        
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
        
        return events
    
    def check_file_changes(self):
        """Check for critical file changes"""
        events = []
        
        # Monitor critical system files
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/hosts', '/etc/crontab', '/root/.ssh/authorized_keys'
        ]
        
        try:
            for file_path in critical_files:
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    
                    # Check if file was modified recently (last 5 minutes)
                    if time.time() - stat.st_mtime < 300:
                        events.append({
                            'type': 'file_modification',
                            'severity': 'high',
                            'description': f'Critical file modified: {file_path}',
                            'details': {
                                'file_path': file_path,
                                'modified_time': stat.st_mtime,
                                'size': stat.st_size,
                                'permissions': oct(stat.st_mode)
                            }
                        })
                        
        except Exception as e:
            logger.error(f"File monitoring error: {e}")
        
        return events
    
    def send_heartbeat(self):
        """Send heartbeat to IPS server"""
        try:
            heartbeat_data = {
                'client_id': self.client_id,
                'timestamp': datetime.now().isoformat(),
                'status': 'active',
                'uptime': time.time() - psutil.boot_time(),
                'version': '2.0.0'
            }
            
            response = self.make_api_request('POST', '/api/client/heartbeat', heartbeat_data)
            
            if response and response.get('status') == 'success':
                self.last_heartbeat = datetime.now()
                logger.debug("Heartbeat sent successfully")
            else:
                logger.warning("Heartbeat failed")
                
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
    
    def send_metrics(self):
        """Send system metrics to IPS server"""
        if not self.metrics_enabled:
            return
        
        try:
            metrics = self.collect_system_metrics()
            if metrics:
                metrics_data = {
                    'client_id': self.client_id,
                    'metrics': metrics
                }
                
                response = self.make_api_request('POST', '/api/client/metrics', metrics_data)
                
                if response and response.get('status') == 'success':
                    logger.debug("Metrics sent successfully")
                else:
                    logger.warning("Failed to send metrics")
                    
        except Exception as e:
            logger.error(f"Metrics submission error: {e}")
    
    def send_security_events(self):
        """Send security events to IPS server"""
        try:
            events = self.detect_security_events()
            
            if events:
                for event in events:
                    alert_data = {
                        'client_id': self.client_id,
                        'alert': event
                    }
                    
                    response = self.make_api_request('POST', '/api/client/alerts', alert_data)
                    
                    if response and response.get('status') == 'success':
                        logger.info(f"Security event reported: {event['type']}")
                    else:
                        logger.warning(f"Failed to report security event: {event['type']}")
                        
        except Exception as e:
            logger.error(f"Security event reporting error: {e}")
    
    def run_monitoring_cycle(self):
        """Run a complete monitoring cycle"""
        logger.debug("Running monitoring cycle")
        
        # Send heartbeat
        self.send_heartbeat()
        
        # Send metrics
        self.send_metrics()
        
        # Check and send security events
        self.send_security_events()
    
    def start(self):
        """Start the IPS client agent"""
        logger.info(f"Starting IPS Client Agent for {self.hostname}")
        logger.info(f"Server: {self.base_url}")
        logger.info(f"Client ID: {self.client_id}")
        
        self.running = True
        
        # Schedule monitoring tasks
        schedule.every(self.monitor_interval).seconds.do(self.run_monitoring_cycle)
        
        # Run initial monitoring cycle
        self.run_monitoring_cycle()
        
        # Main loop
        try:
            while self.running:
                schedule.run_pending()
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
            self.stop()
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self.stop()
    
    def stop(self):
        """Stop the IPS client agent"""
        logger.info("Stopping IPS Client Agent")
        self.running = False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='IPS Client Agent')
    parser.add_argument('--config', default='ips-client.conf', help='Configuration file path')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('--test', action='store_true', help='Test configuration and exit')
    
    args = parser.parse_args()
    
    try:
        # Initialize client
        client = IPSClient(args.config)
        
        if args.test:
            print("Configuration test successful")
            print(f"Server: {client.base_url}")
            print(f"Client ID: {client.client_id}")
            return
        
        if args.daemon:
            # Daemonize process (simplified)
            import daemon
            with daemon.DaemonContext():
                client.start()
        else:
            client.start()
            
    except Exception as e:
        logger.error(f"Failed to start IPS client: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
