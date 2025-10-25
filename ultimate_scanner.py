#!/usr/bin/env python3
"""
ULTIMATE PORT SCANNER - Professional Edition
Cybersecurity Portfolio Project
Author: [Your Name]

Features:
- Multi-threaded TCP/UDP port scanning
- Network host discovery (ping sweep)
- Service banner grabbing
- Risk assessment & security recommendations
- Professional reporting (JSON/TXT)
- Zero dependencies - pure Python
"""

import socket
import threading
import time
import argparse
from datetime import datetime
import sys
import json
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

class UltimatePortScanner:
    def __init__(self):
        self.open_ports = []
        self.udp_ports = []
        self.services = {}
        self.live_hosts = []
        self.lock = threading.Lock()
        
        # Enhanced service database with risk assessment
        self.service_db = {
            21: {"name": "FTP", "risk": "Medium", "description": "File Transfer Protocol"},
            22: {"name": "SSH", "risk": "Low", "description": "Secure Shell"},
            23: {"name": "Telnet", "risk": "High", "description": "Unencrypted remote login"},
            25: {"name": "SMTP", "risk": "Medium", "description": "Simple Mail Transfer Protocol"},
            53: {"name": "DNS", "risk": "Medium", "description": "Domain Name System"},
            80: {"name": "HTTP", "risk": "Low", "description": "Hypertext Transfer Protocol"},
            110: {"name": "POP3", "risk": "Medium", "description": "Post Office Protocol v3"},
            143: {"name": "IMAP", "risk": "Medium", "description": "Internet Message Access Protocol"},
            443: {"name": "HTTPS", "risk": "Low", "description": "HTTP Secure"},
            993: {"name": "IMAPS", "risk": "Low", "description": "IMAP over SSL"},
            995: {"name": "POP3S", "risk": "Low", "description": "POP3 over SSL"},
            3389: {"name": "RDP", "risk": "High", "description": "Remote Desktop Protocol"},
            5432: {"name": "PostgreSQL", "risk": "Medium", "description": "PostgreSQL Database"},
            27017: {"name": "MongoDB", "risk": "Medium", "description": "MongoDB Database"},
            3306: {"name": "MySQL", "risk": "Medium", "description": "MySQL Database"},
            161: {"name": "SNMP", "risk": "High", "description": "Simple Network Management Protocol"},
        }
    
    def display_banner(self):
        """Display professional banner"""
        print(r"""
╔══════════════════════════════════════════════════════════════╗
║                   ULTIMATE PORT SCANNER                     ║
║                Professional Edition v3.0                    ║
║                                                              ║
║  Features: TCP/UDP Scanning • Host Discovery • Banner Grab  ║
║            Multi-threading • JSON Export • Professional Reports ║
║                                                              ║
║        ⚠️  FOR EDUCATIONAL AND AUTHORIZED USE ONLY ⚠️         ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def ping_sweep(self, network_prefix, start_range=1, end_range=255, timeout=1):
        """
        Discover live hosts on the network using ping sweeps
        """
        print(f"[*] Starting ping sweep: {network_prefix}.{start_range}-{end_range}")
        live_hosts = []
        
        def ping_host(ip):
            try:
                # Windows ping command
                if os.name == 'nt':  # Windows
                    command = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
                else:  # Linux/Mac
                    command = ["ping", "-c", "1", "-W", str(timeout), ip]
                
                result = subprocess.run(command, capture_output=True, text=True)
                
                if "Reply from" in result.stdout or "bytes from" in result.stdout:
                    with self.lock:
                        live_hosts.append(ip)
                    print(f"[+] Host alive: {ip}")
                    return ip
            except Exception as e:
                pass
            return None
        
        # Multi-threaded ping scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for i in range(start_range, end_range + 1):
                ip = f"{network_prefix}.{i}"
                futures.append(executor.submit(ping_host, ip))
            
            for future in as_completed(futures):
                future.result()
        
        self.live_hosts = live_hosts
        print(f"\n[*] Found {len(live_hosts)} live hosts")
        return live_hosts
    
    def grab_banner(self, target, port, timeout=2):
        """
        Grab service banners from open ports
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((target, port))
                
                # Protocol-specific banner grabbing
                if port in [80, 443, 8080, 8443]:  # HTTP/HTTPS
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: UltimateScanner/3.0\r\n\r\n" % target.encode())
                elif port == 21:  # FTP
                    sock.send(b"\r\n")
                elif port == 22:  # SSH
                    sock.send(b"SSH-2.0-UltimateScanner\r\n")
                elif port == 25:  # SMTP
                    sock.send(b"EHLO example.com\r\n")
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else "No banner received"
                
        except Exception as e:
            return f"Banner grab failed: {str(e)}"
    
    def scan_tcp_port(self, target, port, timeout=1, grab_banners=False):
        """
        TCP Connect port scanning
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service_info = self.service_db.get(port, {"name": "unknown", "risk": "Unknown", "description": ""})
                    banner = ""
                    
                    if grab_banners:
                        banner = self.grab_banner(target, port)
                    
                    with self.lock:
                        self.open_ports.append((port, service_info['name']))
                        self.services[port] = {
                            'service': service_info['name'],
                            'banner': banner,
                            'protocol': 'TCP',
                            'risk': service_info['risk']
                        }
                    
                    # Display with color coding
                    risk_emoji = {
                        "High": "🔴",
                        "Medium": "🟡", 
                        "Low": "🟢",
                        "Unknown": "⚪"
                    }
                    
                    print(f"{risk_emoji[service_info['risk']]} Port {port}/TCP open - {service_info['name']}")
                    
                    if grab_banners and banner:
                        print(f"      Banner: {banner[:80]}{'...' if len(banner) > 80 else ''}")
                
        except Exception:
            pass
    
    def scan_udp_port(self, target, port, timeout=3):
        """
        UDP port scanning - connectionless protocol
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                
                # Send empty packet to trigger response
                sock.sendto(b'', (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    # If we get a response, port might be open
                    service_info = self.service_db.get(port, {"name": "unknown", "risk": "Unknown"})
                    
                    with self.lock:
                        self.udp_ports.append((port, service_info['name']))
                        self.services[port] = {
                            'service': service_info['name'],
                            'protocol': 'UDP',
                            'risk': service_info['risk']
                        }
                    
                    print(f"🟣 Port {port}/UDP responsive - {service_info['name']}")
                    
                except socket.timeout:
                    # No response - might be open or filtered
                    pass
                    
        except Exception as e:
            pass

    def scan_ports(self, target, ports, scan_type='tcp', max_threads=100, timeout=1, grab_banners=False):
        """
        Multi-threaded port scanning for TCP/UDP
        """
        print(f"\n[*] Starting {scan_type.upper()} scan on {target}")
        print(f"[*] Scanning {len(ports)} ports with {max_threads} threads")
        print(f"[*] Timeout: {timeout}s | Banner grabbing: {'Yes' if grab_banners else 'No'}")
        print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            
            for port in ports:
                if scan_type.lower() == 'tcp':
                    future = executor.submit(
                        self.scan_tcp_port, target, port, timeout, grab_banners
                    )
                else:  # UDP
                    future = executor.submit(
                        self.scan_udp_port, target, port, timeout
                    )
                futures.append(future)
            
            # Wait for all scans to complete
            for future in as_completed(futures):
                future.result()
        
        scan_time = time.time() - start_time
        return scan_time

    def parse_ports(self, ports_arg):
        """
        Parse different port formats with enhanced options
        """
        port_presets = {
            'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389],
            'web': [80, 443, 8080, 8443, 8000, 3000],
            'database': [1433, 1521, 3306, 5432, 27017],
            'windows': [135, 139, 445, 3389, 5985, 5986],
            'top100': list(range(1, 101)),
            'top1000': list(range(1, 1001)),
            'all': list(range(1, 1001))  # Limited for demo
        }
        
        if ports_arg in port_presets:
            return port_presets[ports_arg]
        
        ports = []
        
        if ',' in ports_arg:
            for port in ports_arg.split(','):
                if '-' in port:
                    start, end = map(int, port.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(port))
        elif '-' in ports_arg:
            start, end = map(int, ports_arg.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(ports_arg)]
        
        return list(set(ports))  # Remove duplicates

    def generate_report(self, target, scan_time, scan_type='tcp'):
        """
        Generate comprehensive security report
        """
        print("\n" + "=" * 70)
        print("COMPREHENSIVE SECURITY SCAN REPORT")
        print("=" * 70)
        
        print(f"Target: {target}")
        print(f"Scan Type: {scan_type.upper()}")
        print(f"Scan Duration: {scan_time:.2f} seconds")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Risk Assessment
        high_risk = sum(1 for port, service in self.open_ports if self.service_db.get(port, {}).get('risk') == 'High')
        medium_risk = sum(1 for port, service in self.open_ports if self.service_db.get(port, {}).get('risk') == 'Medium')
        
        overall_risk = "HIGH" if high_risk > 0 else "MEDIUM" if medium_risk > 0 else "LOW"
        
        print(f"\nRISK ASSESSMENT: {overall_risk}")
        print(f"  🔴 High Risk Services: {high_risk}")
        print(f"  🟡 Medium Risk Services: {medium_risk}")
        print(f"  🟢 Low Risk Services: {len(self.open_ports) - high_risk - medium_risk}")
        
        # TCP Results
        if scan_type == 'tcp' and self.open_ports:
            print(f"\nOPEN TCP PORTS ({len(self.open_ports)} found):")
            print("-" * 60)
            for port, service in sorted(self.open_ports):
                risk = self.service_db.get(port, {}).get('risk', 'Unknown')
                risk_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢", "Unknown": "⚪"}
                print(f"  {risk_emoji[risk]} {port:5}/TCP - {service:20} [{risk:6}]")
        
        # UDP Results
        if scan_type == 'udp' and self.udp_ports:
            print(f"\nRESPONSIVE UDP PORTS ({len(self.udp_ports)} found):")
            print("-" * 60)
            for port, service in sorted(self.udp_ports):
                print(f"  🟣 {port:5}/UDP - {service}")
        
        # Security Recommendations
        print(f"\nSECURITY RECOMMENDATIONS:")
        print("-" * 60)
        
        services_found = [service for port, service in self.open_ports]
        
        if 'Telnet' in services_found:
            print("🔴 CRITICAL: Replace Telnet with SSH immediately (unencrypted)")
        if 'FTP' in services_found:
            print("🟡 IMPORTANT: Use SFTP/FTPS instead of plain FTP")
        if 'RDP' in services_found:
            print("🟡 IMPORTANT: Secure RDP with Network Level Authentication")
        if 'SNMP' in services_found:
            print("🟡 IMPORTANT: Change default SNMP community strings")
        
        if high_risk > 0:
            print("🔴 URGENT: Address high-risk services immediately")
        elif medium_risk > 0:
            print("🟡 REVIEW: Review medium-risk services for security")
        else:
            print("🟢 SECURE: No critical issues detected")
        
        print(f"\nReport completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def save_report(self, target, filename=None, format='json'):
        """
        Save comprehensive report in multiple formats
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_scan_{target}_{timestamp}.{format}"
        
        report_data = {
            'scan_metadata': {
                'scanner': 'Ultimate Port Scanner v3.0',
                'target': target,
                'scan_date': datetime.now().isoformat(),
                'scan_duration': None
            },
            'results': {
                'tcp_ports': [
                    {
                        'port': port,
                        'service': service,
                        'risk': self.service_db.get(port, {}).get('risk', 'Unknown'),
                        'description': self.service_db.get(port, {}).get('description', '')
                    } for port, service in sorted(self.open_ports)
                ],
                'udp_ports': [
                    {
                        'port': port,
                        'service': service
                    } for port, service in sorted(self.udp_ports)
                ]
            },
            'risk_assessment': {
                'high_risk_services': sum(1 for port, service in self.open_ports if self.service_db.get(port, {}).get('risk') == 'High'),
                'medium_risk_services': sum(1 for port, service in self.open_ports if self.service_db.get(port, {}).get('risk') == 'Medium'),
                'overall_risk': "HIGH" if any(self.service_db.get(port, {}).get('risk') == 'High' for port, service in self.open_ports) else "MEDIUM" if any(self.service_db.get(port, {}).get('risk') == 'Medium' for port, service in self.open_ports) else "LOW"
            }
        }
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
        elif format == 'txt':
            with open(filename, 'w') as f:
                f.write("ULTIMATE PORT SCANNER - SECURITY REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scan Date: {datetime.now()}\n")
                f.write(f"Open TCP Ports: {len(self.open_ports)}\n")
                f.write(f"Responsive UDP Ports: {len(self.udp_ports)}\n\n")
                
                f.write("OPEN PORTS:\n")
                for port, service in sorted(self.open_ports):
                    risk = self.service_db.get(port, {}).get('risk', 'Unknown')
                    f.write(f"Port {port}/TCP - {service} [{risk} Risk]\n")
        
        print(f"[+] Professional report saved to: {filename}")
        return filename

def main():
    """Main function"""
    scanner = UltimatePortScanner()
    scanner.display_banner()
    
    parser = argparse.ArgumentParser(
        description='ULTIMATE PORT SCANNER - Professional Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
EXAMPLES:
  python ultimate_scanner.py 192.168.1.1 -p common -b
  python ultimate_scanner.py 10.0.0.0/24 --ping-sweep
  python ultimate_scanner.py scanme.nmap.org -p 1-1000 --scan-type both
  python ultimate_scanner.py 127.0.0.1 -p web --output report.json
        '''
    )
    
    parser.add_argument('target', nargs='?', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Ports: 80, 1-100, common, web, database, top100 (default: common)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('-T', '--timeout', type=float, default=1,
                       help='Timeout in seconds (default: 1)')
    parser.add_argument('-b', '--banners', action='store_true',
                       help='Grab service banners')
    parser.add_argument('--udp', action='store_true',
                       help='Perform UDP scanning')
    parser.add_argument('--ping-sweep', action='store_true',
                       help='Perform ping sweep to find live hosts')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-f', '--format', choices=['txt', 'json'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--scan-type', choices=['tcp', 'udp', 'both'], default='tcp',
                       help='Scan type (default: tcp)')
    
    args = parser.parse_args()
    
    # If no target provided, show help
    if not args.target:
        parser.print_help()
        return
    
    try:
        # PING SWEEP MODE
        if args.ping_sweep and '/' in args.target:
            network_parts = args.target.split('/')
            network_prefix = network_parts[0]
            scanner.ping_sweep(network_prefix)
            
            if scanner.live_hosts:
                scan_hosts = input("\nScan discovered hosts? (y/n): ").lower()
                if scan_hosts == 'y':
                    for host in scanner.live_hosts:
                        print(f"\n{'='*50}")
                        print(f"SCANNING HOST: {host}")
                        print(f"{'='*50}")
                        
                        ports = scanner.parse_ports(args.ports)
                        scan_time = scanner.scan_ports(
                            target=host,
                            ports=ports,
                            scan_type=args.scan_type,
                            max_threads=args.threads,
                            timeout=args.timeout,
                            grab_banners=args.banners
                        )
                        
                        scanner.generate_report(host, scan_time, args.scan_type)
                        
                        if args.output:
                            scanner.save_report(host, f"{args.output}_{host}", args.format)
            return
        
        # SINGLE TARGET SCANNING
        ports = scanner.parse_ports(args.ports)
        
        print(f"[*] SCAN CONFIGURATION:")
        print(f"    Target: {args.target}")
        print(f"    Ports: {args.ports} ({len(ports)} ports)")
        print(f"    Scan Type: {args.scan_type.upper()}")
        print(f"    Threads: {args.threads}")
        print(f"    Timeout: {args.timeout}s")
        print(f"    Banner Grabbing: {'Yes' if args.banners else 'No'}")
        
        # Performance warning for large scans
        if len(ports) > 1000:
            print(f"    ⚠️  Large scan: {len(ports)} ports - this may take a while")
        
        # Scan execution
        if args.scan_type in ['tcp', 'both']:
            tcp_time = scanner.scan_ports(
                target=args.target,
                ports=ports,
                scan_type='tcp',
                max_threads=args.threads,
                timeout=args.timeout,
                grab_banners=args.banners
            )
            scanner.generate_report(args.target, tcp_time, 'tcp')
        
        if args.scan_type in ['udp', 'both']:
            print(f"\n[*] Starting UDP scan (this is slower...)")
            udp_time = scanner.scan_ports(
                target=args.target,
                ports=ports[:100] if len(ports) > 100 else ports,  # Limit UDP ports
                scan_type='udp',
                max_threads=50,  # Fewer threads for UDP
                timeout=3,  # Longer timeout for UDP
                grab_banners=False
            )
            scanner.generate_report(args.target, udp_time, 'udp')
        
        # Save results
        if args.output:
            scanner.save_report(args.target, args.output, args.format)
        else:
            save = input("\nSave comprehensive report? (y/n): ").lower()
            if save == 'y':
                format_choice = input("Format (txt/json) [json]: ").lower() or 'json'
                scanner.save_report(args.target, format=format_choice)
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan cancelled by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()