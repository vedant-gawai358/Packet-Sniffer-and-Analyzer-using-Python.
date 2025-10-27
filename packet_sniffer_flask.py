#!/usr/bin/env python3
"""
Flask Web Server for Packet Sniffer & Analyzer
Connects backend with HTML UI
"""

from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, get_if_list
from scapy.layers.http import HTTPRequest
import threading
import json
import csv
from datetime import datetime
import os
import tempfile

app = Flask(__name__, template_folder='.')
CORS(app)

# Global sniffer state
class SnifferState:
    def __init__(self):
        self.packets = []
        self.is_capturing = False
        self.packet_count = 0
        self.protocol_stats = {
            'tcp': 0, 'udp': 0, 'http': 0, 'dns': 0, 'icmp': 0
        }
        self.start_time = None
        self.capture_thread = None
        self.interface = None

state = SnifferState()

def packet_callback(packet):
    """Process captured packet"""
    try:
        if IP in packet:
            state.packet_count += 1
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "OTHER"
            port = 0
            size = len(packet)
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Determine protocol
            if TCP in packet:
                protocol = "TCP"
                port = packet[TCP].dport
                state.protocol_stats['tcp'] += 1
                
                if packet.haslayer(HTTPRequest):
                    protocol = "HTTP"
                    state.protocol_stats['http'] += 1
                    
            elif UDP in packet:
                protocol = "UDP"
                port = packet[UDP].dport
                state.protocol_stats['udp'] += 1
                
                if packet.haslayer(DNS):
                    protocol = "DNS"
                    state.protocol_stats['dns'] += 1
                    
            elif ICMP in packet:
                protocol = "ICMP"
                state.protocol_stats['icmp'] += 1
            
            packet_info = {
                'id': state.packet_count,
                'time': timestamp,
                'srcIP': src_ip,
                'dstIP': dst_ip,
                'protocol': protocol,
                'port': port,
                'size': size
            }
            
            state.packets.append(packet_info)
            
            # Keep only last 1000 packets in memory
            if len(state.packets) > 1000:
                state.packets.pop(0)
                
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_capture_thread(interface=None, filter_str=None):
    """Start packet capture in background thread"""
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: not state.is_capturing,
            filter=filter_str
        )
    except Exception as e:
        print(f"Capture error: {e}")
        state.is_capturing = False

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('packet_sniffer_ui.html')

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = get_if_list()
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    if state.is_capturing:
        return jsonify({'error': 'Already capturing'}), 400
    
    try:
        data = request.json or {}
        interface = data.get('interface')
        
        state.is_capturing = True
        state.start_time = datetime.now()
        state.packets = []
        state.packet_count = 0
        state.protocol_stats = {key: 0 for key in state.protocol_stats}
        state.interface = interface
        
        # Start capture thread
        state.capture_thread = threading.Thread(
            target=start_capture_thread,
            args=(interface, None),
            daemon=True
        )
        state.capture_thread.start()
        
        return jsonify({'status': 'started'})
    except Exception as e:
        state.is_capturing = False
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    if not state.is_capturing:
        return jsonify({'error': 'Not capturing'}), 400
    
    state.is_capturing = False
    return jsonify({'status': 'stopped'})

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Get captured packets"""
    filter_protocol = request.args.get('filter', 'all')
    limit = int(request.args.get('limit', 50))
    
    packets = state.packets
    
    if filter_protocol and filter_protocol.lower() != 'all':
        packets = [p for p in packets if p['protocol'].lower() == filter_protocol.lower()]
    
    return jsonify({
        'packets': packets[-limit:],
        'total': len(packets)
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get capture statistics"""
    total_size = sum(p['size'] for p in state.packets)
    
    elapsed_time = 0
    if state.start_time:
        elapsed_time = (datetime.now() - state.start_time).total_seconds()
    
    packets_per_sec = 0
    if elapsed_time > 0:
        packets_per_sec = round(state.packet_count / elapsed_time, 1)
    
    return jsonify({
        'totalPackets': state.packet_count,
        'totalSize': round(total_size / 1024, 2),
        'protocolStats': state.protocol_stats,
        'isCapturing': state.is_capturing,
        'elapsedTime': int(elapsed_time),
        'packetsPerSec': packets_per_sec
    })

@app.route('/api/clear', methods=['POST'])
def clear_packets():
    """Clear captured packets"""
    state.packets = []
    state.packet_count = 0
    state.protocol_stats = {key: 0 for key in state.protocol_stats}
    state.start_time = None
    
    return jsonify({'status': 'cleared'})

@app.route('/api/export', methods=['GET'])
def export_packets():
    """Export packets to CSV"""
    if not state.packets:
        return jsonify({'error': 'No packets to export'}), 400
    
    try:
        # Create temporary CSV file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='')
        
        fieldnames = ['id', 'time', 'srcIP', 'dstIP', 'protocol', 'port', 'size']
        writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
        
        writer.writeheader()
        for packet in state.packets:
            writer.writerow(packet)
        
        temp_file.close()
        
        filename = f"packet_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return send_file(
            temp_file.name,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     PACKET SNIFFER & ANALYZER - WEB INTERFACE            ║
    ╚═══════════════════════════════════════════════════════════╝
    
    [INFO] Starting web server...
    [INFO] Access the application at: http://localhost:5000
    
    [WARNING] This application requires administrator/root privileges!
    [WARNING] Run with: sudo python3 app.py (Linux/Mac)
                       or run as Administrator (Windows)
    """)
    
    # Check privileges
    if os.name != 'nt' and os.geteuid() != 0:
        print("\n[ERROR] Root privileges required!")
        print("Please run: sudo python3 app.py\n")
        exit(1)
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
