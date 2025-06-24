#!/usr/bin/env python3
"""
IPS API Server - RESTful API for the web interface
Provides endpoints for managing the IPS system
"""

from flask import Flask, jsonify, request, cors
from flask_cors import CORS
import asyncio
import threading
import time
import json
from datetime import datetime, timedelta
from ips_engine import IPSEngine, PacketSimulator, ThreatSignature

app = Flask(__name__)
CORS(app)

# Global IPS instance
ips_engine = None
packet_simulator = None
simulation_running = False

def init_ips():
    """Initialize the IPS engine"""
    global ips_engine, packet_simulator
    ips_engine = IPSEngine()
    packet_simulator = PacketSimulator()
    print("IPS Engine initialized for API server")

def background_simulation():
    """Run packet simulation in background"""
    global simulation_running
    import random
    
    async def simulate():
        while simulation_running:
            # Generate mix of normal and malicious packets
            is_malicious = random.random() < 0.05  # 5% malicious traffic
            packet = packet_simulator.generate_packet(malicious=is_malicious)
            
            await ips_engine.process_packet(packet)
            await asyncio.sleep(0.1)  # Process 10 packets per second
    
    # Run the async simulation
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(simulate())

@app.route('/api/status', methods=['GET'])
def get_system_status():
    """Get current system status and statistics"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    stats = ips_engine.get_statistics()
    
    # Calculate additional metrics
    current_time = time.time()
    recent_alerts = [a for a in ips_engine.alerts if 
                    (current_time - time.mktime(time.strptime(a.timestamp[:19], '%Y-%m-%dT%H:%M:%S'))) < 3600]
    
    return jsonify({
        'system_active': simulation_running,
        'uptime': '15d 7h 23m',  # Simulated uptime
        'total_connections': stats['packets_processed'],
        'blocked_threats': stats['threats_blocked'],
        'active_rules': stats['active_signatures'],
        'system_health': 98,
        'cpu_usage': 23 + (time.time() % 30),  # Simulated CPU usage
        'memory_usage': 67 + (time.time() % 20),  # Simulated memory usage
        'network_throughput': '2.4 Gbps',
        'recent_alerts_count': len(recent_alerts),
        'blocked_ips_count': len(ips_engine.blocked_ips)
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent security alerts"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    limit = request.args.get('limit', 50, type=int)
    severity_filter = request.args.get('severity', None)
    
    alerts = ips_engine.get_recent_alerts(limit)
    
    # Apply severity filter if specified
    if severity_filter and severity_filter != 'all':
        alerts = [a for a in alerts if a['severity'] == severity_filter]
    
    return jsonify({
        'alerts': alerts,
        'total_count': len(alerts)
    })

@app.route('/api/threats/map', methods=['GET'])
def get_threat_map():
    """Get threat data for geographic visualization"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    # Get recent alerts and group by country
    recent_alerts = ips_engine.get_recent_alerts(100)
    threat_map = {}
    
    for alert in recent_alerts:
        country = alert['country']
        if country not in threat_map:
            threat_map[country] = {
                'country': country,
                'total_threats': 0,
                'blocked_threats': 0,
                'threat_types': {},
                'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
        
        threat_map[country]['total_threats'] += 1
        if alert['blocked']:
            threat_map[country]['blocked_threats'] += 1
        
        # Count threat types
        threat_type = alert['threat_type']
        if threat_type not in threat_map[country]['threat_types']:
            threat_map[country]['threat_types'][threat_type] = 0
        threat_map[country]['threat_types'][threat_type] += 1
        
        # Count severity
        threat_map[country]['severity_breakdown'][alert['severity']] += 1
    
    return jsonify({
        'threat_locations': list(threat_map.values())
    })

@app.route('/api/analytics/traffic', methods=['GET'])
def get_traffic_analytics():
    """Get traffic analytics data"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    # Generate simulated traffic data for the last 24 hours
    current_time = time.time()
    traffic_data = []
    
    for i in range(24):
        hour_start = current_time - (i * 3600)
        timestamp = datetime.fromtimestamp(hour_start).strftime('%H:%M')
        
        # Simulate traffic patterns (higher during business hours)
        base_traffic = 1000
        if 8 <= datetime.fromtimestamp(hour_start).hour <= 18:
            base_traffic *= 2.5
        
        import random
        total_requests = int(base_traffic + random.randint(-200, 500))
        blocked_requests = int(total_requests * (0.02 + random.random() * 0.08))
        
        traffic_data.append({
            'timestamp': timestamp,
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'allowed_requests': total_requests - blocked_requests,
            'bandwidth': round(total_requests * 0.001, 1),  # Simulated bandwidth
            'unique_ips': int(total_requests * 0.3)
        })
    
    traffic_data.reverse()  # Show chronological order
    
    # Protocol statistics
    protocol_stats = [
        {'protocol': 'HTTP', 'requests': 12450, 'blocked': 234, 'percentage': 65.2},
        {'protocol': 'HTTPS', 'requests': 8930, 'blocked': 123, 'percentage': 46.8},
        {'protocol': 'FTP', 'requests': 567, 'blocked': 45, 'percentage': 7.9},
        {'protocol': 'SSH', 'requests': 234, 'blocked': 12, 'percentage': 5.1},
        {'protocol': 'SMTP', 'requests': 189, 'blocked': 8, 'percentage': 4.2}
    ]
    
    return jsonify({
        'traffic_data': traffic_data,
        'protocol_stats': protocol_stats
    })

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Get all security rules"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    rules = []
    for signature in ips_engine.signature_engine.signatures:
        rules.append({
            'id': signature.id,
            'name': signature.name,
            'description': signature.description,
            'type': signature.category,
            'severity': signature.severity,
            'action': signature.action,
            'enabled': signature.enabled,
            'conditions': [signature.pattern],  # Simplified for display
            'created': signature.created_at,
            'lastModified': signature.created_at,
            'triggeredCount': 0  # Would track in production
        })
    
    return jsonify({
        'rules': rules,
        'total_count': len(rules)
    })

@app.route('/api/rules', methods=['POST'])
def create_rule():
    """Create a new security rule"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'description', 'type', 'severity', 'action', 'pattern']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Create new signature
    signature = ThreatSignature(
        id=f"CUSTOM_{int(time.time())}",
        name=data['name'],
        pattern=data['pattern'],
        severity=data['severity'],
        category=data['type'],
        action=data['action']
    )
    
    ips_engine.add_signature(signature)
    
    return jsonify({
        'message': 'Rule created successfully',
        'rule_id': signature.id
    }), 201

@app.route('/api/rules/<rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Update an existing security rule"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    data = request.get_json()
    
    # Find and update the signature
    for signature in ips_engine.signature_engine.signatures:
        if signature.id == rule_id:
            if 'enabled' in data:
                signature.enabled = data['enabled']
            if 'severity' in data:
                signature.severity = data['severity']
            if 'action' in data:
                signature.action = data['action']
            
            return jsonify({'message': 'Rule updated successfully'})
    
    return jsonify({'error': 'Rule not found'}), 404

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IP addresses"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    blocked_ips = []
    for ip in ips_engine.blocked_ips:
        # Get additional info about the IP
        country = ips_engine.geo_resolver.get_country(ip)
        reputation = ips_engine.threat_intel.get_reputation_score(ip)
        
        blocked_ips.append({
            'ip': ip,
            'country': country,
            'reputation_score': reputation,
            'blocked_at': datetime.now().isoformat(),  # Simplified
            'reason': 'Malicious activity detected'
        })
    
    return jsonify({
        'blocked_ips': blocked_ips,
        'total_count': len(blocked_ips)
    })

@app.route('/api/blocked-ips/<ip>', methods=['DELETE'])
def unblock_ip(ip):
    """Unblock an IP address"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    ips_engine.unblock_ip(ip)
    
    return jsonify({'message': f'IP {ip} has been unblocked'})

@app.route('/api/system/start', methods=['POST'])
def start_system():
    """Start the IPS monitoring system"""
    global simulation_running
    
    if not simulation_running:
        simulation_running = True
        # Start background simulation thread
        thread = threading.Thread(target=background_simulation, daemon=True)
        thread.start()
        
        return jsonify({'message': 'IPS system started successfully'})
    else:
        return jsonify({'message': 'IPS system is already running'})

@app.route('/api/system/stop', methods=['POST'])
def stop_system():
    """Stop the IPS monitoring system"""
    global simulation_running
    
    simulation_running = False
    return jsonify({'message': 'IPS system stopped successfully'})

@app.route('/api/export/report', methods=['GET'])
def export_report():
    """Export system report"""
    if not ips_engine:
        return jsonify({'error': 'IPS engine not initialized'}), 500
    
    # Generate comprehensive report
    stats = ips_engine.get_statistics()
    recent_alerts = ips_engine.get_recent_alerts(100)
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'system_statistics': stats,
        'recent_alerts': recent_alerts,
        'blocked_ips': list(ips_engine.blocked_ips),
        'active_signatures': len([s for s in ips_engine.signature_engine.signatures if s.enabled]),
        'summary': {
            'total_threats_detected': stats['threats_detected'],
            'total_threats_blocked': stats['threats_blocked'],
            'block_rate': (stats['threats_blocked'] / max(stats['threats_detected'], 1)) * 100,
            'top_threat_types': {}  # Would calculate in production
        }
    }
    
    return jsonify(report)

if __name__ == '__main__':
    print("Initializing IPS API Server...")
    init_ips()
    
    # Start the simulation automatically
    simulation_running = True
    thread = threading.Thread(target=background_simulation, daemon=True)
    thread.start()
    
    print("IPS API Server starting on http://localhost:5000")
    print("Available endpoints:")
    print("  GET  /api/status - System status")
    print("  GET  /api/alerts - Security alerts")
    print("  GET  /api/threats/map - Threat map data")
    print("  GET  /api/analytics/traffic - Traffic analytics")
    print("  GET  /api/rules - Security rules")
    print("  POST /api/rules - Create new rule")
    print("  GET  /api/blocked-ips - Blocked IP addresses")
    print("  POST /api/system/start - Start monitoring")
    print("  POST /api/system/stop - Stop monitoring")
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
