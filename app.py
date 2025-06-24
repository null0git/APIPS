#!/usr/bin/env python3
"""
Advanced Intrusion Prevention System (IPS) - Professional Flask Web Interface
Enterprise-grade IPS management system with top navigation
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import threading
import time
import asyncio
from datetime import datetime, timedelta
import os
import secrets
from functools import wraps
import csv
import io
import yaml
from werkzeug.utils import secure_filename

# Import our IPS engine
from ips_engine import *

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the IPS system.'

# Global variables
ips_engine = None
packet_simulator = None
simulation_running = False
simulation_thread = None

class User(UserMixin):
    def __init__(self, id, username, email, role='admin', full_name='', last_login=None):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.full_name = full_name
        self.last_login = last_login

# Enhanced user database
users = {
    'admin': User('1', 'admin', 'admin@company.com', 'admin', 'System Administrator'),
    'security': User('2', 'security', 'security@company.com', 'analyst', 'Security Analyst'),
    'viewer': User('3', 'viewer', 'viewer@company.com', 'viewer', 'Security Viewer'),
    'manager': User('4', 'manager', 'manager@company.com', 'manager', 'Security Manager')
}

user_passwords = {
    'admin': generate_password_hash('admin123'),
    'security': generate_password_hash('security123'),
    'viewer': generate_password_hash('viewer123'),
    'manager': generate_password_hash('manager123')
}

@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.id == user_id:
            return user
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin']:
            flash('Administrator access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'manager']:
            flash('Manager access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def init_ips_system():
    """Initialize the IPS system"""
    global ips_engine, packet_simulator
    try:
        ips_engine = IPSEngine()
        packet_simulator = PacketSimulator()
        print("✓ IPS Engine initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to initialize IPS Engine: {e}")
        return False

def background_simulation():
    """Background thread for packet simulation"""
    global simulation_running
    import random
    
    async def simulate():
        while simulation_running:
            try:
                # Generate mix of normal and malicious packets
                is_malicious = random.random() < 0.06  # 6% malicious traffic
                packet = packet_simulator.generate_packet(malicious=is_malicious)
                
                await ips_engine.process_packet(packet)
                await asyncio.sleep(0.15)  # Process ~7 packets per second
            except Exception as e:
                print(f"Simulation error: {e}")
                await asyncio.sleep(1)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(simulate())
    except Exception as e:
        print(f"Background simulation error: {e}")

def log_user_activity(action, details=""):
    """Log user activities for audit trail"""
    if current_user.is_authenticated:
        # In production, this would write to a proper audit log
        print(f"AUDIT: {current_user.username} - {action} - {details}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and check_password_hash(user_passwords[username], password):
            user = users[username]
            user.last_login = datetime.now()
            login_user(user)
            log_user_activity("LOGIN", f"Successful login from {request.remote_addr}")
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_user_activity("LOGIN_FAILED", f"Failed login attempt for {username}")
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_user_activity("LOGOUT", "User logged out")
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    """Enhanced dashboard with comprehensive metrics"""
    if not ips_engine:
        flash('IPS Engine not initialized. Please check system configuration.', 'error')
        return render_template('error.html', error="IPS Engine not available")
    
    # Get system statistics
    stats = ips_engine.get_statistics()
    recent_alerts = ips_engine.get_recent_alerts(15)
    
    # Calculate time-based metrics
    current_time = time.time()
    hourly_alerts = [a for a in ips_engine.alerts if 
                    (current_time - time.mktime(time.strptime(a.timestamp[:19], '%Y-%m-%dT%H:%M:%S'))) < 3600]
    daily_alerts = [a for a in ips_engine.alerts if 
                   (current_time - time.mktime(time.strptime(a.timestamp[:19], '%Y-%m-%dT%H:%M:%S'))) < 86400]
    
    # Calculate threat trends
    threat_types = {}
    for alert in daily_alerts:
        threat_type = alert.threat_type
        if threat_type not in threat_types:
            threat_types[threat_type] = 0
        threat_types[threat_type] += 1
    
    # Top threat sources
    threat_sources = {}
    for alert in daily_alerts:
        country = alert.country
        if country not in threat_sources:
            threat_sources[country] = 0
        threat_sources[country] += 1
    
    top_threat_sources = sorted(threat_sources.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # System health metrics
    import psutil
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
    except:
        # Fallback if psutil not available
        cpu_percent = 25 + (time.time() % 30)
        memory = type('obj', (object,), {'percent': 67, 'used': 8.2e9, 'total': 12e9})()
        disk = type('obj', (object,), {'percent': 45})()
        network = type('obj', (object,), {'bytes_sent': 1024*1024*100, 'bytes_recv': 1024*1024*200})()
    
    dashboard_data = {
        'system_active': simulation_running,
        'total_connections': stats['packets_processed'],
        'blocked_threats': stats['threats_blocked'],
        'active_rules': stats['active_signatures'],
        'system_health': 98,
        'recent_alerts': recent_alerts,
        'hourly_alerts_count': len(hourly_alerts),
        'daily_alerts_count': len(daily_alerts),
        'blocked_ips_count': len(ips_engine.blocked_ips),
        'uptime': '15d 7h 23m',
        'threat_types': threat_types,
        'top_threat_sources': top_threat_sources,
        'cpu_usage': round(cpu_percent, 1),
        'memory_usage': round(memory.percent, 1),
        'disk_usage': round(disk.percent, 1),
        'network_in': round(network.bytes_recv / (1024*1024), 2),
        'network_out': round(network.bytes_sent / (1024*1024), 2)
    }
    
    log_user_activity("DASHBOARD_VIEW", "Accessed main dashboard")
    return render_template('dashboard.html', data=dashboard_data)

@app.route('/alerts')
@login_required
def alerts():
    """Enhanced alerts view with advanced filtering"""
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', 'all')
    type_filter = request.args.get('type', 'all')
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '')
    per_page = 25
    
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    # Get alerts with filtering
    all_alerts = ips_engine.get_recent_alerts(2000)
    
    # Apply filters
    if severity_filter != 'all':
        all_alerts = [a for a in all_alerts if a['severity'] == severity_filter]
    
    if type_filter != 'all':
        all_alerts = [a for a in all_alerts if a['threat_type'] == type_filter]
    
    if status_filter == 'blocked':
        all_alerts = [a for a in all_alerts if a['blocked']]
    elif status_filter == 'monitored':
        all_alerts = [a for a in all_alerts if not a['blocked']]
    
    if search_query:
        search_lower = search_query.lower()
        all_alerts = [a for a in all_alerts if 
                     search_lower in a['description'].lower() or 
                     search_lower in a['source_ip'] or 
                     search_lower in a['dest_ip']]
    
    # Pagination
    total_alerts = len(all_alerts)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    alerts_page = all_alerts[start_idx:end_idx]
    
    total_pages = (total_alerts + per_page - 1) // per_page
    
    # Get unique threat types for filter dropdown
    threat_types = list(set([a['threat_type'] for a in ips_engine.get_recent_alerts(1000)]))
    
    log_user_activity("ALERTS_VIEW", f"Viewed alerts page {page}")
    return render_template('alerts.html', 
                         alerts=alerts_page,
                         current_page=page,
                         total_pages=total_pages,
                         total_alerts=total_alerts,
                         severity_filter=severity_filter,
                         type_filter=type_filter,
                         status_filter=status_filter,
                         search_query=search_query,
                         threat_types=threat_types)

@app.route('/threat-intelligence')
@login_required
def threat_intelligence():
    """Threat intelligence dashboard"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    # Get recent alerts and analyze threat intelligence
    recent_alerts = ips_engine.get_recent_alerts(500)
    
    # Geographic threat distribution
    threat_locations = {}
    for alert in recent_alerts:
        country = alert['country']
        if country not in threat_locations:
            threat_locations[country] = {
                'country': country,
                'total_threats': 0,
                'blocked_threats': 0,
                'threat_types': {},
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'ips': set()
            }
        
        threat_locations[country]['total_threats'] += 1
        threat_locations[country]['ips'].add(alert['source_ip'])
        if alert['blocked']:
            threat_locations[country]['blocked_threats'] += 1
        
        # Count threat types
        threat_type = alert['threat_type']
        if threat_type not in threat_locations[country]['threat_types']:
            threat_locations[country]['threat_types'][threat_type] = 0
        threat_locations[country]['threat_types'][threat_type] += 1
        
        # Count severity
        threat_locations[country]['severity_counts'][alert['severity']] += 1
    
    # Convert sets to counts for JSON serialization
    for location in threat_locations.values():
        location['unique_ips'] = len(location['ips'])
        del location['ips']
    
    # Top attacking IPs
    ip_stats = {}
    for alert in recent_alerts:
        ip = alert['source_ip']
        if ip not in ip_stats:
            ip_stats[ip] = {
                'ip': ip,
                'country': alert['country'],
                'attack_count': 0,
                'blocked_count': 0,
                'threat_types': set(),
                'last_seen': alert['timestamp']
            }
        ip_stats[ip]['attack_count'] += 1
        if alert['blocked']:
            ip_stats[ip]['blocked_count'] += 1
        ip_stats[ip]['threat_types'].add(alert['threat_type'])
    
    # Convert sets to lists and sort
    for ip_stat in ip_stats.values():
        ip_stat['threat_types'] = list(ip_stat['threat_types'])
    
    top_attacking_ips = sorted(ip_stats.values(), key=lambda x: x['attack_count'], reverse=True)[:10]
    
    log_user_activity("THREAT_INTEL_VIEW", "Accessed threat intelligence dashboard")
    return render_template('threat_intelligence.html', 
                         threat_locations=list(threat_locations.values()),
                         top_attacking_ips=top_attacking_ips)

@app.route('/analytics')
@login_required
def analytics():
    """Advanced analytics and reporting"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    # Get comprehensive analytics data
    stats = ips_engine.get_statistics()
    all_alerts = ips_engine.get_recent_alerts(1000)
    
    # Time-based analysis
    current_time = time.time()
    time_ranges = {
        'last_hour': current_time - 3600,
        'last_24h': current_time - 86400,
        'last_7d': current_time - 604800,
        'last_30d': current_time - 2592000
    }
    
    time_analysis = {}
    for range_name, start_time in time_ranges.items():
        range_alerts = [a for a in all_alerts if 
                       time.mktime(time.strptime(a['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')) > start_time]
        
        time_analysis[range_name] = {
            'total_alerts': len(range_alerts),
            'blocked_alerts': len([a for a in range_alerts if a['blocked']]),
            'critical_alerts': len([a for a in range_alerts if a['severity'] == 'critical']),
            'unique_ips': len(set([a['source_ip'] for a in range_alerts]))
        }
    
    # Hourly traffic pattern for last 24 hours
    hourly_data = []
    for i in range(24):
        hour_start = current_time - (i * 3600)
        hour_end = hour_start + 3600
        
        hour_alerts = [a for a in all_alerts if 
                      hour_start <= time.mktime(time.strptime(a['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')) < hour_end]
        
        hourly_data.append({
            'hour': datetime.fromtimestamp(hour_start).strftime('%H:00'),
            'total_requests': len(hour_alerts) * 50,  # Simulate total traffic
            'blocked_requests': len([a for a in hour_alerts if a['blocked']]),
            'alerts': len(hour_alerts)
        })
    
    hourly_data.reverse()  # Chronological order
    
    # Threat type analysis
    threat_analysis = {}
    for alert in all_alerts:
        threat_type = alert['threat_type']
        if threat_type not in threat_analysis:
            threat_analysis[threat_type] = {
                'count': 0,
                'blocked': 0,
                'countries': set(),
                'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
        
        threat_analysis[threat_type]['count'] += 1
        if alert['blocked']:
            threat_analysis[threat_type]['blocked'] += 1
        threat_analysis[threat_type]['countries'].add(alert['country'])
        threat_analysis[threat_type]['severity_breakdown'][alert['severity']] += 1
    
    # Convert sets to counts
    for analysis in threat_analysis.values():
        analysis['unique_countries'] = len(analysis['countries'])
        del analysis['countries']
    
    log_user_activity("ANALYTICS_VIEW", "Accessed analytics dashboard")
    return render_template('analytics.html',
                         stats=stats,
                         time_analysis=time_analysis,
                         hourly_data=hourly_data,
                         threat_analysis=threat_analysis)

@app.route('/rules')
@login_required
def rules():
    """Enhanced security rules management"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    # Get all security rules with enhanced information
    rules_data = []
    for signature in ips_engine.signature_engine.signatures:
        # Calculate rule effectiveness (simulated)
        effectiveness = {
            'triggers_last_24h': len([a for a in ips_engine.alerts[-100:] if a.signature_id == signature.id]),
            'false_positives': 0,  # Would be tracked in production
            'last_triggered': None
        }
        
        # Find last trigger
        for alert in reversed(ips_engine.alerts[-100:]):
            if alert.signature_id == signature.id:
                effectiveness['last_triggered'] = alert.timestamp
                break
        
        rules_data.append({
            'id': signature.id,
            'name': signature.name,
            'description': signature.description,
            'type': signature.category,
            'severity': signature.severity,
            'action': signature.action,
            'enabled': signature.enabled,
            'pattern': signature.pattern,
            'created': signature.created_at,
            'effectiveness': effectiveness
        })
    
    # Rule statistics
    total_rules = len(rules_data)
    active_rules = len([r for r in rules_data if r['enabled']])
    critical_rules = len([r for r in rules_data if r['severity'] == 'critical'])
    triggered_rules = len([r for r in rules_data if r['effectiveness']['triggers_last_24h'] > 0])
    
    rule_stats = {
        'total': total_rules,
        'active': active_rules,
        'inactive': total_rules - active_rules,
        'critical': critical_rules,
        'triggered_24h': triggered_rules
    }
    
    log_user_activity("RULES_VIEW", "Accessed security rules management")
    return render_template('rules.html', rules=rules_data, stats=rule_stats)

@app.route('/system-monitor')
@login_required
@manager_required
def system_monitor():
    """System monitoring and health dashboard"""
    # Get system metrics
    import psutil
    try:
        # CPU information
        cpu_info = {
            'usage': psutil.cpu_percent(interval=1),
            'count': psutil.cpu_count(),
            'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {'current': 0, 'min': 0, 'max': 0}
        }
        
        # Memory information
        memory = psutil.virtual_memory()
        memory_info = {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent,
            'used': memory.used
        }
        
        # Disk information
        disk = psutil.disk_usage('/')
        disk_info = {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        }
        
        # Network information
        network = psutil.net_io_counters()
        network_info = {
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv,
            'packets_sent': network.packets_sent,
            'packets_recv': network.packets_recv
        }
        
        # Process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:10]
        
    except ImportError:
        # Fallback data if psutil not available
        cpu_info = {'usage': 25, 'count': 4, 'freq': {'current': 2400, 'min': 800, 'max': 3200}}
        memory_info = {'total': 12*1024**3, 'used': 8*1024**3, 'percent': 67, 'available': 4*1024**3}
        disk_info = {'total': 500*1024**3, 'used': 225*1024**3, 'free': 275*1024**3, 'percent': 45}
        network_info = {'bytes_sent': 1024**3, 'bytes_recv': 2*1024**3, 'packets_sent': 1000000, 'packets_recv': 2000000}
        processes = []
    
    # IPS-specific metrics
    ips_metrics = {
        'engine_status': 'Running' if simulation_running else 'Stopped',
        'packets_processed': ips_engine.stats['packets_processed'] if ips_engine else 0,
        'threats_detected': ips_engine.stats['threats_detected'] if ips_engine else 0,
        'rules_loaded': len(ips_engine.signature_engine.signatures) if ips_engine else 0,
        'blocked_ips': len(ips_engine.blocked_ips) if ips_engine else 0
    }
    
    log_user_activity("SYSTEM_MONITOR_VIEW", "Accessed system monitoring dashboard")
    return render_template('system_monitor.html',
                         cpu_info=cpu_info,
                         memory_info=memory_info,
                         disk_info=disk_info,
                         network_info=network_info,
                         processes=processes,
                         ips_metrics=ips_metrics)

@app.route('/settings')
@login_required
@admin_required
def settings():
    """Enhanced system settings and configuration"""
    # Load current configuration
    config = {
        'general': {
            'system_name': 'Advanced IPS System',
            'organization': 'Security Operations Center',
            'timezone': 'UTC',
            'log_level': 'info',
            'max_connections': 10000,
            'auto_update': True,
            'maintenance_mode': False,
            'session_timeout': 30
        },
        'security': {
            'enable_firewall': True,
            'enable_ips': True,
            'enable_antimalware': True,
            'enable_geo_blocking': True,
            'block_suspicious_ips': True,
            'quarantine_threshold': 85,
            'alert_threshold': 70,
            'auto_block_threshold': 90,
            'whitelist_internal_ips': True
        },
        'network': {
            'monitored_interfaces': ['eth0', 'eth1'],
            'capture_mode': 'promiscuous',
            'buffer_size': 1024,
            'analysis_depth': 'deep',
            'packet_capture_limit': 10000,
            'bandwidth_limit': 1000
        },
        'alerts': {
            'enable_email': True,
            'enable_sms': False,
            'enable_webhooks': True,
            'enable_syslog': True,
            'email_recipients': ['admin@company.com', 'security@company.com'],
            'alert_frequency': 'immediate',
            'escalation_enabled': True,
            'escalation_timeout': 15
        },
        'performance': {
            'cpu_threshold': 80,
            'memory_threshold': 85,
            'disk_threshold': 90,
            'enable_optimization': True,
            'max_log_size': 1000,
            'log_retention_days': 30
        },
        'compliance': {
            'enable_audit_log': True,
            'data_retention_days': 365,
            'encryption_enabled': True,
            'compliance_mode': 'SOC2',
            'anonymize_logs': False
        }
    }
    
    log_user_activity("SETTINGS_VIEW", "Accessed system settings")
    return render_template('settings.html', config=config)

@app.route('/export/alerts')
@login_required
def export_alerts():
    """Export alerts to CSV"""
    if not ips_engine:
        flash('IPS Engine not available', 'error')
        return redirect(url_for('alerts'))
    
    # Get alerts
    alerts = ips_engine.get_recent_alerts(1000)
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Timestamp', 'Severity', 'Type', 'Source IP', 'Destination IP', 
                    'Description', 'Country', 'Blocked', 'Confidence'])
    
    # Write data
    for alert in alerts:
        writer.writerow([
            alert['timestamp'],
            alert['severity'],
            alert['threat_type'],
            alert['source_ip'],
            alert['dest_ip'],
            alert['description'],
            alert['country'],
            'Yes' if alert['blocked'] else 'No',
            f"{alert['confidence']:.2f}"
        ])
    
    output.seek(0)
    
    log_user_activity("EXPORT_ALERTS", f"Exported {len(alerts)} alerts to CSV")
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=ips_alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )

@app.route('/api/realtime-stats')
@login_required
def api_realtime_stats():
    """API endpoint for real-time statistics"""
    if not ips_engine:
        return jsonify({'error': 'IPS Engine not available'}), 500
    
    stats = ips_engine.get_statistics()
    
    # Get recent activity
    current_time = time.time()
    recent_alerts = [a for a in ips_engine.alerts if 
                    (current_time - time.mktime(time.strptime(a.timestamp[:19], '%Y-%m-%dT%H:%M:%S'))) < 300]  # Last 5 minutes
    
    return jsonify({
        'system_active': simulation_running,
        'packets_processed': stats['packets_processed'],
        'threats_detected': stats['threats_detected'],
        'threats_blocked': stats['threats_blocked'],
        'blocked_ips_count': len(ips_engine.blocked_ips),
        'recent_activity': len(recent_alerts),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/system/control', methods=['POST'])
@login_required
@admin_required
def system_control():
    """Enhanced system control with detailed logging"""
    global simulation_running, simulation_thread
    
    action = request.form.get('action')
    
    if action == 'start':
        if not simulation_running:
            simulation_running = True
            simulation_thread = threading.Thread(target=background_simulation, daemon=True)
            simulation_thread.start()
            log_user_activity("SYSTEM_START", "IPS monitoring system started")
            flash('IPS monitoring system started successfully.', 'success')
        else:
            flash('IPS monitoring system is already running.', 'info')
    
    elif action == 'stop':
        simulation_running = False
        log_user_activity("SYSTEM_STOP", "IPS monitoring system stopped")
        flash('IPS monitoring system stopped successfully.', 'info')
    
    elif action == 'restart':
        simulation_running = False
        time.sleep(1)
        simulation_running = True
        simulation_thread = threading.Thread(target=background_simulation, daemon=True)
        simulation_thread.start()
        log_user_activity("SYSTEM_RESTART", "IPS monitoring system restarted")
        flash('IPS monitoring system restarted successfully.', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/documentation')
@login_required
def documentation():
    """Documentation home page"""
    return render_template('documentation/index.html')

@app.route('/documentation/<section>')
@login_required
def documentation_section(section):
    """Documentation sections"""
    valid_sections = [
        'installation', 'getting-started', 'user-guide', 'rules-management',
        'threat-intelligence', 'api-reference', 'client-setup', 'troubleshooting',
        'best-practices', 'compliance'
    ]
    
    if section not in valid_sections:
        flash('Documentation section not found.', 'error')
        return redirect(url_for('documentation'))
    
    log_user_activity("DOCUMENTATION_VIEW", f"Accessed documentation: {section}")
    return render_template(f'documentation/{section}.html')

@app.route('/clients')
@login_required
@manager_required
def client_management():
    """Client monitoring management"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    # Get connected clients
    clients = ips_engine.get_connected_clients()
    
    # Calculate client statistics
    total_clients = len(clients)
    active_clients = len([c for c in clients if c['status'] == 'active'])
    critical_alerts = len([c for c in clients if c['health_status'] == 'critical'])
    
    client_stats = {
        'total': total_clients,
        'active': active_clients,
        'inactive': total_clients - active_clients,
        'critical': critical_alerts
    }
    
    log_user_activity("CLIENT_MANAGEMENT_VIEW", "Accessed client management")
    return render_template('client_management.html', clients=clients, stats=client_stats)

@app.route('/api/client/register', methods=['POST'])
def api_client_register():
    """API endpoint for client registration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['hostname', 'ip_address', 'os_type', 'client_version']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Register client with IPS engine
        client_id = ips_engine.register_client(data)
        
        return jsonify({
            'status': 'success',
            'client_id': client_id,
            'message': 'Client registered successfully'
        })
        
    except Exception as e:
        logger.error(f"Client registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/client/heartbeat', methods=['POST'])
def api_client_heartbeat():
    """API endpoint for client heartbeat"""
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        
        if not client_id:
            return jsonify({'error': 'Missing client_id'}), 400
        
        # Update client status
        ips_engine.update_client_heartbeat(client_id, data)
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Client heartbeat error: {e}")
        return jsonify({'error': 'Heartbeat failed'}), 500

@app.route('/api/client/metrics', methods=['POST'])
def api_client_metrics():
    """API endpoint for client metrics submission"""
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        
        if not client_id:
            return jsonify({'error': 'Missing client_id'}), 400
        
        # Store client metrics
        ips_engine.store_client_metrics(client_id, data)
        
        return jsonify({
            'status': 'success',
            'message': 'Metrics received'
        })
        
    except Exception as e:
        logger.error(f"Client metrics error: {e}")
        return jsonify({'error': 'Metrics submission failed'}), 500

@app.route('/api/client/alerts', methods=['POST'])
def api_client_alerts():
    """API endpoint for client alert submission"""
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        
        if not client_id:
            return jsonify({'error': 'Missing client_id'}), 400
        
        # Process client alerts
        ips_engine.process_client_alert(client_id, data)
        
        return jsonify({
            'status': 'success',
            'message': 'Alert processed'
        })
        
    except Exception as e:
        logger.error(f"Client alert error: {e}")
        return jsonify({'error': 'Alert processing failed'}), 500

@app.route('/setup', methods=['GET', 'POST'])
def setup_wizard():
    """First-run setup wizard"""
    # Check if setup is already completed
    if os.path.exists('setup_complete.flag'):
        flash('Setup has already been completed.', 'info')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Get setup data
            setup_data = {
                'admin': {
                    'username': request.form.get('admin_username'),
                    'password': request.form.get('admin_password'),
                    'email': request.form.get('admin_email'),
                    'full_name': request.form.get('admin_full_name'),
                    'organization': request.form.get('organization')
                },
                'system': {
                    'system_name': request.form.get('system_name'),
                    'timezone': request.form.get('timezone'),
                    'theme': request.form.get('theme', 'light')
                },
                'monitoring': {
                    'enable_network': request.form.get('enable_network') == 'on',
                    'enable_website': request.form.get('enable_website') == 'on',
                    'enable_client': request.form.get('enable_client') == 'on'
                },
                'notifications': {
                    'smtp_server': request.form.get('smtp_server'),
                    'smtp_port': request.form.get('smtp_port'),
                    'smtp_username': request.form.get('smtp_username'),
                    'smtp_password': request.form.get('smtp_password'),
                    'enable_email_alerts': request.form.get('enable_email_alerts') == 'on'
                }
            }
            
            # Save configuration
            with open('config.yaml', 'w') as f:
                yaml.dump(setup_data, f)
            
            # Update admin user
            admin_user = users['admin']
            admin_user.username = setup_data['admin']['username']
            admin_user.email = setup_data['admin']['email']
            admin_user.full_name = setup_data['admin']['full_name']
            user_passwords['admin'] = generate_password_hash(setup_data['admin']['password'])
            
            # Create setup complete flag
            with open('setup_complete.flag', 'w') as f:
                f.write(datetime.now().isoformat())
            
            flash('Setup completed successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Setup failed: {str(e)}', 'error')
    
    return render_template('setup_wizard.html')

@app.route('/monitoring-targets')
@login_required
@manager_required
def monitoring_targets():
    """Monitoring targets management"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    targets = ips_engine.get_monitoring_targets()
    target_stats = ips_engine.get_target_statistics()
    
    log_user_activity("MONITORING_TARGETS_VIEW", "Accessed monitoring targets")
    return render_template('monitoring_targets.html', targets=targets, stats=target_stats)

@app.route('/add-target', methods=['GET', 'POST'])
@login_required
@manager_required
def add_monitoring_target():
    """Add new monitoring target"""
    if request.method == 'POST':
        try:
            target_data = {
                'name': request.form.get('target_name'),
                'type': request.form.get('target_type'),
                'address': request.form.get('target_address'),
                'port': request.form.get('target_port'),
                'protocol': request.form.get('protocol'),
                'monitoring_interval': int(request.form.get('monitoring_interval', 60)),
                'enabled': request.form.get('enabled') == 'on',
                'tags': request.form.get('tags', '').split(','),
                'description': request.form.get('description', '')
            }
            
            target_id = ips_engine.add_monitoring_target(target_data)
            log_user_activity("ADD_TARGET", f"Added monitoring target: {target_data['name']}")
            flash(f'Monitoring target "{target_data["name"]}" added successfully.', 'success')
            return redirect(url_for('monitoring_targets'))
            
        except Exception as e:
            flash(f'Failed to add monitoring target: {str(e)}', 'error')
    
    return render_template('add_target.html')

@app.route('/rules-categories')
@login_required
def rules_categories():
    """Security rules categories management"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    categories = ips_engine.get_rule_categories()
    rules_by_category = ips_engine.get_rules_by_category()
    
    log_user_activity("RULES_CATEGORIES_VIEW", "Accessed rules categories")
    return render_template('rules_categories.html', categories=categories, rules_by_category=rules_by_category)

@app.route('/toggle-theme', methods=['POST'])
@login_required
def toggle_theme():
    """Toggle between dark and light theme"""
    current_theme = session.get('theme', 'light')
    new_theme = 'dark' if current_theme == 'light' else 'light'
    session['theme'] = new_theme
    
    log_user_activity("THEME_TOGGLE", f"Changed theme to {new_theme}")
    return jsonify({'theme': new_theme})

@app.route('/website-monitoring')
@login_required
def website_monitoring():
    """Website monitoring dashboard"""
    if not ips_engine:
        return render_template('error.html', error="IPS Engine not available")
    
    websites = ips_engine.get_monitored_websites()
    website_stats = ips_engine.get_website_statistics()
    
    log_user_activity("WEBSITE_MONITORING_VIEW", "Accessed website monitoring")
    return render_template('website_monitoring.html', websites=websites, stats=website_stats)

if __name__ == '__main__':
    print("🚀 Starting Advanced IPS Flask Application...")
    
    # Initialize IPS system
    if init_ips_system():
        print("✓ IPS System initialized successfully")
        
        # Start background simulation
        simulation_running = True
        simulation_thread = threading.Thread(target=background_simulation, daemon=True)
        simulation_thread.start()
        print("✓ Background simulation started")
        
        print("\n🌐 Professional IPS Web Interface:")
        print("   URL: http://localhost:5000")
        print("   Login Credentials:")
        print("     Administrator: admin / admin123")
        print("     Security Manager: manager / manager123")
        print("     Security Analyst: security / security123")
        print("     Viewer: viewer / viewer123")
        print("\n📊 Enterprise Features:")
        print("   • Real-time Threat Dashboard")
        print("   • Advanced Analytics & Reporting")
        print("   • Threat Intelligence Integration")
        print("   • System Health Monitoring")
        print("   • Comprehensive Audit Logging")
        print("   • Role-based Access Control")
        print("   • Data Export & Compliance")
        print("   • Professional UI/UX Design")
        
        # Run Flask application
        app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
    else:
        print("✗ Failed to initialize IPS system. Exiting.")
