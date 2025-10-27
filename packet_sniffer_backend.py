#!/usr/bin/env python3
"""
Packet Sniffer & Analyzer - Backend
Final Year Project
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.http import HTTPRequest
import json
import csv
from datetime import datetime
import threading
import os
import sys

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.is_capturing = False
        self.packet_count = 0
        self.protocol_stats = {
            'tcp': 0,
            'udp': 0,
            'http': 0,
            'dns': 0,
            'icmp': 0,
            'other': 0
        }
        self.capture_thread = None
        self.interface = None
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            if IP in packet:
                self.packet_count += 1
                
                # Extract basic info
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
                    self.protocol_stats['tcp'] += 1
                    
                    # Check for HTTP
                    if packet.haslayer(HTTPRequest):
                        protocol = "HTTP"
                        self.protocol_stats['http'] += 1
                    
                elif UDP in packet:
                    protocol = "UDP"
                    port = packet[UDP].dport
                    self.protocol_stats['udp'] += 1
                    
                    # Check for DNS
                    if packet.haslayer(DNS):
                        protocol = "DNS"
                        self.protocol_stats['dns'] += 1
                        
                elif ICMP in packet:
                    protocol = "ICMP"
                    self.protocol_stats['icmp'] += 1
                else:
                    self.protocol_stats['other'] += 1
                
                # Create packet info dictionary
                packet_info = {
                    'id': self.packet_count,
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'port': port,
                    'size': size,
                    'raw_packet': packet.summary()
                }
                
                self.packets.append(packet_info)
                
                # Print to console (optional)
                print(f"[{self.packet_count}] {timestamp} | {src_ip}:{port} -> {dst_ip} | {protocol} | {size}B")
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_capture(self, interface=None, packet_count=0, filter_protocol=None):
        """Start capturing packets"""
        if self.is_capturing:
            print("Already capturing packets!")
            return
        
        self.is_capturing = True
        self.interface = interface
        self.packets = []
        self.packet_count = 0
        self.protocol_stats = {key: 0 for key in self.protocol_stats}
        
        print(f"\n{'='*60}")
        print(f"Starting packet capture on interface: {interface or 'default'}")
        print(f"{'='*60}\n")
        
        # Build filter string
        bpf_filter = None
        if filter_protocol:
            filters = {
                'tcp': 'tcp',
                'udp': 'udp',
                'icmp': 'icmp',
                'http': 'tcp port 80',
                'dns': 'udp port 53'
            }
            bpf_filter = filters.get(filter_protocol.lower())
        
        def capture():
            try:
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=False,
                    count=packet_count,
                    filter=bpf_filter,
                    stop_filter=lambda x: not self.is_capturing
                )
            except PermissionError:
                print("\n[ERROR] Permission denied! Run with sudo/administrator privileges.")
                self.is_capturing = False
            except Exception as e:
                print(f"\n[ERROR] Capture error: {e}")
                self.is_capturing = False
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop capturing packets"""
        if not self.is_capturing:
            print("Not currently capturing!")
            return
        
        self.is_capturing = False
        print(f"\n{'='*60}")
        print(f"Capture stopped. Total packets captured: {self.packet_count}")
        print(f"{'='*60}\n")
    
    def get_packets(self, filter_protocol=None, limit=50):
        """Get captured packets with optional filtering"""
        packets = self.packets
        
        if filter_protocol and filter_protocol.lower() != 'all':
            packets = [p for p in packets if p['protocol'].lower() == filter_protocol.lower()]
        
        return packets[-limit:] if limit else packets
    
    def get_statistics(self):
        """Get capture statistics"""
        total_size = sum(p['size'] for p in self.packets)
        return {
            'total_packets': self.packet_count,
            'total_size_kb': round(total_size / 1024, 2),
            'protocol_stats': self.protocol_stats,
            'is_capturing': self.is_capturing
        }
    
    def save_to_csv(self, filename=None):
        """Save captured packets to CSV file"""
        if not self.packets:
            print("No packets to save!")
            return
        
        if not filename:
            filename = f"packet_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['id', 'timestamp', 'src_ip', 'dst_ip', 'protocol', 'port', 'size']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for packet in self.packets:
                    writer.writerow({k: packet[k] for k in fieldnames})
            
            print(f"\n[SUCCESS] Packets saved to: {filename}")
            return filename
        except Exception as e:
            print(f"\n[ERROR] Failed to save CSV: {e}")
            return None
    
    def save_to_json(self, filename=None):
        """Save captured packets to JSON file"""
        if not self.packets:
            print("No packets to save!")
            return
        
        if not filename:
            filename = f"packet_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as jsonfile:
                json.dump({
                    'capture_info': {
                        'total_packets': self.packet_count,
                        'statistics': self.get_statistics()
                    },
                    'packets': self.packets
                }, jsonfile, indent=2)
            
            print(f"\n[SUCCESS] Packets saved to: {filename}")
            return filename
        except Exception as e:
            print(f"\n[ERROR] Failed to save JSON: {e}")
            return None
    
    def display_summary(self):
        """Display capture summary"""
        stats = self.get_statistics()
        
        print(f"\n{'='*60}")
        print("CAPTURE SUMMARY")
        print(f"{'='*60}")
        print(f"Total Packets: {stats['total_packets']}")
        print(f"Total Size: {stats['total_size_kb']} KB")
        print(f"\nProtocol Distribution:")
        for protocol, count in stats['protocol_stats'].items():
            percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
            print(f"  {protocol.upper()}: {count} ({percentage:.1f}%)")
        print(f"{'='*60}\n")


def interactive_mode():
    """Interactive command-line interface"""
    sniffer = PacketSniffer()
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        PACKET SNIFFER & ANALYZER - INTERACTIVE MODE      ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    while True:
        print("\nAvailable Commands:")
        print("  1. start     - Start packet capture")
        print("  2. stop      - Stop packet capture")
        print("  3. show      - Show captured packets")
        print("  4. stats     - Show statistics")
        print("  5. save      - Save to CSV/JSON")
        print("  6. clear     - Clear captured packets")
        print("  7. exit      - Exit program")
        
        try:
            choice = input("\nEnter command: ").strip().lower()
            
            if choice in ['1', 'start']:
                if sniffer.is_capturing:
                    print("Already capturing!")
                    continue
                
                interface = input("Enter interface (press Enter for default): ").strip() or None
                filter_input = input("Filter protocol (tcp/udp/http/dns/icmp or Enter for all): ").strip()
                filter_protocol = filter_input if filter_input else None
                
                print("\n[INFO] Starting capture... Press Ctrl+C to stop manually or use 'stop' command")
                sniffer.start_capture(interface=interface, filter_protocol=filter_protocol)
                
            elif choice in ['2', 'stop']:
                sniffer.stop_capture()
                
            elif choice in ['3', 'show']:
                limit = input("Number of packets to show (default 20): ").strip()
                limit = int(limit) if limit.isdigit() else 20
                
                packets = sniffer.get_packets(limit=limit)
                if not packets:
                    print("\nNo packets captured yet!")
                else:
                    print(f"\n{'ID':<6} {'Time':<10} {'Source IP':<16} {'Dest IP':<16} {'Protocol':<8} {'Port':<8} {'Size':<8}")
                    print("-" * 80)
                    for p in packets[-20:]:
                        print(f"{p['id']:<6} {p['timestamp']:<10} {p['src_ip']:<16} {p['dst_ip']:<16} {p['protocol']:<8} {p['port']:<8} {p['size']:<8}")
                
            elif choice in ['4', 'stats']:
                sniffer.display_summary()
                
            elif choice in ['5', 'save']:
                print("\n1. CSV")
                print("2. JSON")
                format_choice = input("Choose format: ").strip()
                
                if format_choice == '1':
                    sniffer.save_to_csv()
                elif format_choice == '2':
                    sniffer.save_to_json()
                else:
                    print("Invalid choice!")
                    
            elif choice in ['6', 'clear']:
                sniffer.packets = []
                sniffer.packet_count = 0
                sniffer.protocol_stats = {key: 0 for key in sniffer.protocol_stats}
                print("\n[INFO] Packets cleared!")
                
            elif choice in ['7', 'exit', 'quit']:
                if sniffer.is_capturing:
                    sniffer.stop_capture()
                print("\nExiting... Goodbye!")
                break
                
            else:
                print("Invalid command!")
                
        except KeyboardInterrupt:
            print("\n\n[INFO] Interrupted by user")
            if sniffer.is_capturing:
                sniffer.stop_capture()
        except Exception as e:
            print(f"\n[ERROR] {e}")


if __name__ == "__main__":
    # Check for admin privileges
    if os.name == 'nt':  # Windows
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[WARNING] This script requires administrator privileges!")
            print("Please run as administrator.")
            sys.exit(1)
    else:  # Linux/Mac
        if os.geteuid() != 0:
            print("[WARNING] This script requires root privileges!")
            print("Please run with sudo: sudo python3 packet_sniffer.py")
            sys.exit(1)
    
    # Start interactive mode
    interactive_mode()
