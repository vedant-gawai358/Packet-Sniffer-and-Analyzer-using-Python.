**Packet Sniffer & Analyzer - Final Year Project**
A powerful, real-time network packet capturing and analysis tool built with Python and web technologies.

📋 Table of Contents
Overview
Features
Tech Stack
Installation
Usage
Project Structure
Screenshots
Troubleshooting
Future Enhancements

🎯 Overview
This Packet Sniffer & Analyzer captures and analyzes network packets in real-time, providing detailed insights into network
traffic. It's designed as a lightweight alternative to professional tools like Wireshark, with an intuitive web interface.
Key Capabilities
Real-time packet capture from network interfaces
Protocol identification (TCP, UDP, HTTP, DNS, ICMP)
Live statistics and visualization
Packet filtering and searching
Export functionality (CSV format)

✨ Features
Core Features
1. Live Packet Capture
Capture packets from any network interface (Ethernet, WiFi, Loopback)
Real-time display of packet information
Support for multiple protocols
2. Detailed Packet Information
Source and Destination IP addresses
Protocol type (TCP, UDP, HTTP, DNS, ICMP)
Port numbers
Packet size
Timestamp
3. Advanced Filtering
Filter by protocol type
Search by IP address
Search by port number
Real-time filtering without stopping capture
4. Statistics DashboardTotal packets captured
Data transferred (KB)
Capture duration
Packets per second rate
Protocol distribution with visual bars
5. Data Export
Export captured packets to CSV format
Timestamped filenames
All packet details included
6. User-Friendly Interface
Modern, responsive web UI
Real-time updates
Color-coded protocols
Smooth animations and transitions
🛠 Tech Stack
Backend
Python 3.7+
Scapy - Packet manipulation and capture
Flask - Web framewor
Flask - Web framework
Flask-CORS - Cross-origin resource sharing
Frontend
HTML5 - Structure
CSS3 - Styling with modern gradients and animations
JavaScript (Vanilla) - Dynamic functionality and API integration

📦 Installation
Prerequisites
Python 3.7 or higher
Administrator/Root privileges (required for packet capture)
pip (Python package manager)
