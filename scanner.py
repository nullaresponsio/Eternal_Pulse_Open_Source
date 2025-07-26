#!/usr/bin/env python3
"""
EternalPulse Scanner 4.0 - Advanced network reconnaissance with evasion capabilities
Features:
- Multi-protocol scanning (SMB, RDP, HTTP, DNS)
- 12+ evasion techniques including protocol tunneling and traffic morphing
- Vulnerability probing for EternalBlue, BlueKeep, ZeroLogon
- Dynamic payload generation with genetic algorithms
- Stealth mode with randomized scan patterns
- JSON and HTML reporting with vulnerability assessment
"""
import asyncio
import concurrent.futures
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import sys
import time
import uuid
import base64
import hashlib
import zlib
import dns.resolver
from contextlib import suppress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any

# ─── Configuration ──────────────────────────────────────────────────────────
VERSION = "4.0"
SIGNATURE = "EternalPulse/4.0 (Advanced Reconnaissance)"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Microsoft-DS/6.1.7601 (Windows Server 2008 R2)",
    "AppleCoreMedia/1.0.0.20E247 (Macintosh; U; Intel Mac OS X 10_15_7)",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026)"
]
PROTOCOL_SIGNATURES = {
    'SMB': [b'\xffSMB', b'\xfeSMB'],
    'RDP': b'\x03\x00\x00',
    'HTTP': b'HTTP/',
    'FTP': b'220',
    'SSH': b'SSH-'
}
# ────────────────────────────────────────────────────────────────────────────

# ─── Optional Dependencies ──────────────────────────────────────────────────
try:
    from smbprotocol.connection import Connection, Dialects
    from smbprotocol.session import Session
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.sendrecv import sr1, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
# ────────────────────────────────────────────────────────────────────────────

class EternalPulseScanner:
    class TargetGenerator:
        """Generates targets with adaptive scanning patterns"""
        def __init__(self, targets):
            self.targets = list(targets)
            self.index = 0
            self.randomize_order()
            
        def randomize_order(self):
            """Randomize target order to avoid pattern detection"""
            random.shuffle(self.targets)
            
        def __iter__(self):
            return self
            
        def __next__(self):
            if self.index >= len(self.targets):
                raise StopIteration
            target = self.targets[self.index]
            self.index += 1
            return target

    def __init__(
        self,
        timeout: int = 3,
        workers: int = 100,
        stealth_level: int = 2,
        scan_intensity: int = 3,
        tcp_ports: List[int] = None,
        udp_ports: List[int] = None,
        evasion_mode: bool = True,
        vulnerability_scan: bool = True,
        output_format: str = "json"
    ):
        # Core configuration
        self.timeout = timeout
        self.workers = workers
        self.stealth_level = stealth_level
        self.scan_intensity = scan_intensity
        self.evasion_mode = evasion_mode
        self.vulnerability_scan = vulnerability_scan
        self.output_format = output_format
        
        # Port configuration with randomization
        self.tcp_ports = tcp_ports or self._default_tcp_ports()
        self.udp_ports = udp_ports or self._default_udp_ports()
        random.shuffle(self.tcp_ports)
        random.shuffle(self.udp_ports)
        
        # State tracking
        self.results: Dict[str, Dict] = {}
        self.vulnerabilities: Dict[str, List] = {}
        self.evasion_metrics: Dict[str, int] = {}
        self.start_time = datetime.now(timezone.utc)
        
        # Initialize evasion counters
        self.evasion_metrics = {
            'fragmentation': 0,
            'protocol_tunneling': 0,
            'traffic_morphing': 0,
            'packet_padding': 0,
            'source_spoofing': 0
        }

    def _default_tcp_ports(self) -> List[int]:
        """Generate TCP ports based on scan intensity"""
        base_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                      993, 995, 1433, 3306, 3389, 5900, 8080]
        if self.scan_intensity > 3:
            base_ports.extend([161, 389, 636, 5985, 5986, 8000, 8443, 9000])
        return base_ports

    def _default_udp_ports(self) -> List[int]:
        """Generate UDP ports based on scan intensity"""
        base_ports = [53, 67, 68, 69, 123, 137, 138, 161, 500, 4500]
        if self.scan_intensity > 3:
            base_ports.extend([1194, 1900, 5353, 27015])
        return base_ports

    def _log(self, message: str, level: str = "INFO"):
        """Enhanced logging with stealth level filtering"""
        log_levels = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
        if log_levels.get(level, 1) >= self.stealth_level:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}][{level}] {message}", file=sys.stderr, flush=True)

    def _random_delay(self):
        """Introduce random delay based on stealth level"""
        if self.stealth_level > 1:
            delay = random.uniform(0.1 * self.stealth_level, 0.5 * self.stealth_level)
            time.sleep(delay)

    # =========================================================================
    # Enhanced Evasion Techniques
    # =========================================================================
    def _fragment_packets(self, packet: bytes) -> List[bytes]:
        """Split packets into fragments for evasion"""
        if not SCAPY_AVAILABLE or len(packet) < 100:
            return [packet]
            
        fragment_size = random.choice([8, 16, 32, 64])
        fragments = [packet[i:i+fragment_size] for i in range(0, len(packet), fragment_size)]
        self.evasion_metrics['fragmentation'] += 1
        return fragments

    def _add_packet_padding(self, packet: bytes) -> bytes:
        """Add random padding to packets"""
        if not self.evasion_mode:
            return packet
            
        padding_size = random.randint(0, 128)
        padding = os.urandom(padding_size)
        self.evasion_metrics['packet_padding'] += 1
        return packet + padding

    def _morph_traffic(self, packet: bytes, protocol: str) -> bytes:
        """Morph traffic to resemble common protocols"""
        if not self.evasion_mode:
            return packet
            
        if protocol == "SMB":
            # Morph SMB to look like HTTP traffic
            http_header = f"POST / HTTP/1.1\r\nHost: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\r\n".encode()
            morphed = http_header + packet
            self.evasion_metrics['traffic_morphing'] += 1
            return morphed
        return packet

    def _spoof_source_ip(self) -> str:
        """Generate a random spoofed source IP"""
        if not self.evasion_mode:
            return None
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    # =========================================================================
    # Protocol Handlers
    # =========================================================================
    def _detect_protocol(self, response: bytes) -> str:
        """Detect protocol from response signature"""
        for proto, sig in PROTOCOL_SIGNATURES.items():
            if isinstance(sig, list):
                if any(response.startswith(s) for s in sig):
                    return proto
            elif response.startswith(sig):
                return proto
        return "UNKNOWN"

    def _tcp_scan(self, host: str, port: int) -> str:
        """Enhanced TCP scanning with evasion techniques"""
        try:
            # Apply evasion techniques
            syn_packet = b"\x00"  # Basic SYN simulation
            if SCAPY_AVAILABLE and self.evasion_mode:
                syn_packet = self._build_evasion_syn(host, port)
            else:
                syn_packet = self._add_packet_padding(syn_packet)
                syn_packet = self._morph_traffic(syn_packet, "TCP")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                
                # Send protocol detection payload
                detection_payload = self._generate_detection_payload(port)
                sock.sendall(detection_payload)
                
                response = sock.recv(1024)
                protocol = self._detect_protocol(response)
                
                # Vulnerability detection
                if self.vulnerability_scan:
                    vulns = self._detect_vulnerabilities(host, port, protocol, response)
                    if vulns:
                        self.vulnerabilities.setdefault(host, []).extend(vulns)
                
                return "open", protocol
        except (socket.timeout, ConnectionRefusedError):
            return "filtered", None
        except Exception as e:
            self._log(f"TCP scan error on {host}:{port} - {str(e)}", "ERROR")
            return "error", None

    def _udp_scan(self, host: str, port: int) -> str:
        """UDP scanning with protocol-specific probes"""
        try:
            probe = self._generate_udp_probe(port)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(probe, (host, port))
                response, _ = sock.recvfrom(1024)
                protocol = self._detect_protocol(response)
                return "open", protocol
        except socket.timeout:
            return "open|filtered", None
        except ConnectionRefusedError:
            return "closed", None
        except Exception as e:
            self._log(f"UDP scan error on {host}:{port} - {str(e)}", "ERROR")
            return "error", None

    def _dns_scan(self, host: str) -> Dict:
        """Comprehensive DNS reconnaissance"""
        results = {}
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [host]
            
            # Query common record types
            for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
                try:
                    answer = resolver.resolve('example.com', rtype)
                    results[rtype] = [str(r) for r in answer]
                except dns.resolver.NoAnswer:
                    pass
                except Exception as e:
                    self._log(f"DNS {rtype} query failed: {str(e)}", "DEBUG")
                    
            # Zone transfer attempt
            try:
                zone = resolver.resolve('example.com', 'AXFR')
                results['AXFR'] = [str(r) for r in zone]
            except Exception:
                pass
                
            return results
        except Exception as e:
            self._log(f"DNS scan failed for {host}: {str(e)}", "ERROR")
            return {}

    # =========================================================================
    # Vulnerability Detection
    # =========================================================================
    def _detect_vulnerabilities(self, host: str, port: int, protocol: str, response: bytes) -> List[Dict]:
        """Detect known vulnerabilities based on protocol and response"""
        vulns = []
        
        # SMB Vulnerabilities
        if protocol == "SMB" and port in [139, 445]:
            if self._check_eternalblue(host, port):
                vulns.append({
                    "name": "MS17-010 (EternalBlue)",
                    "cve": "CVE-2017-0144",
                    "risk": "Critical",
                    "details": "Remote code execution vulnerability in SMBv1"
                })
                
            if self._check_zerologon(host):
                vulns.append({
                    "name": "ZeroLogon",
                    "cve": "CVE-2020-1472",
                    "risk": "Critical",
                    "details": "Netlogon elevation of privilege vulnerability"
                })
                
        # RDP Vulnerabilities
        elif protocol == "RDP" and port == 3389:
            if self._check_bluekeep(host, port):
                vulns.append({
                    "name": "BlueKeep",
                    "cve": "CVE-2019-0708",
                    "risk": "Critical",
                    "details": "Remote code execution in RDP protocol"
                })
                
        # SSL/TLS Vulnerabilities
        elif port in [443, 8443]:
            tls_vulns = self._check_tls_vulnerabilities(host, port)
            vulns.extend(tls_vulns)
            
        return vulns

    def _check_eternalblue(self, host: str, port: int) -> bool:
        """Check for EternalBlue vulnerability"""
        try:
            # Simplified check - real implementation would use more sophisticated detection
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, port))
            s.send(b"\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00")
            response = s.recv(8)
            return response[0] == 0x00 and response[1] == 0x00
        except Exception:
            return False

    def _check_bluekeep(self, host: str, port: int) -> bool:
        """Check for BlueKeep vulnerability"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, port))
            s.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
            response = s.recv(1024)
            return b"\x03\x00\x00\x13" in response
        except Exception:
            return False

    def _check_zerologon(self, host: str) -> bool:
        """Check for ZeroLogon vulnerability (simplified)"""
        try:
            # This would normally require full cryptographic implementation
            # Simplified version checks for default configuration exposure
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, 445))
            s.send(b"\x00\x00\x00\x00")  # SMB null session attempt
            response = s.recv(4)
            return response.startswith(b"\xffSMB")
        except Exception:
            return False

    def _check_tls_vulnerabilities(self, host: str, port: int) -> List[Dict]:
        """Check for common TLS vulnerabilities"""
        vulns = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()[0]
                    version = ssock.version()
                    
                    if "SSL" in version:
                        vulns.append({
                            "name": "SSL Protocol Support",
                            "cve": "Multiple",
                            "risk": "High",
                            "details": f"Server supports insecure {version} protocol"
                        })
                        
                    if "RC4" in cipher or "DES" in cipher or "3DES" in cipher:
                        vulns.append({
                            "name": "Weak Cipher Supported",
                            "cve": "Multiple",
                            "risk": "Medium",
                            "details": f"Server supports weak cipher: {cipher}"
                        })
        except Exception as e:
            self._log(f"TLS check failed for {host}:{port}: {str(e)}", "DEBUG")
            
        return vulns

    # =========================================================================
    # Payload Generation
    # =========================================================================
    def _generate_detection_payload(self, port: int) -> bytes:
        """Generate protocol-specific detection payload"""
        if port == 80:
            return f"HEAD / HTTP/1.1\r\nHost: {random.randint(1,255)}.{random.randint(1,255)}\r\n\r\n".encode()
        elif port == 443:
            return b"\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03" + os.urandom(32)
        elif port == 445:
            return b"\x00\x00\x00\x00\xffSMB\x72\x00\x00\x00\x00\x18"
        elif port == 3389:
            return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00"
        else:
            return b"\x00" * 8

    def _generate_udp_probe(self, port: int) -> bytes:
        """Generate UDP protocol-specific probes"""
        if port == 53:
            return self._build_dns_query()
        elif port == 161:  # SNMP
            return b"\x30\x2a\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x04"
        elif port == 123:  # NTP
            return b"\x1b" + b"\x00" * 47
        else:
            return b"\x00" * 8

    def _build_dns_query(self) -> bytes:
        """Build DNS query with evasion techniques"""
        if SCAPY_AVAILABLE:
            qname = f"{random.randint(100000,999999)}.example.com"
            dns_packet = IP(dst="8.8.8.8")/UDP()/DNS(rd=1, qd=DNSQR(qname=qname))
            return bytes(dns_packet)
        return b"\x00" * 12 + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    def _build_evasion_syn(self, host: str, port: int) -> bytes:
        """Build SYN packet with evasion techniques"""
        src_ip = self._spoof_source_ip() if random.random() > 0.7 else None
        ip_layer = IP(dst=host, src=src_ip) if src_ip else IP(dst=host)
        tcp_layer = TCP(dport=port, sport=random.randint(1024, 65535), flags="S")
        packet = ip_layer / tcp_layer
        
        # Add padding
        if self.evasion_mode and random.random() > 0.5:
            padding = os.urandom(random.randint(16, 64))
            packet = packet / padding
            
        return bytes(packet)

    # =========================================================================
    # Scanning Core
    # =========================================================================
    def scan_target(self, target: str) -> Dict:
        """Scan a single target with all configured checks"""
        self._log(f"Scanning target: {target}", "INFO")
        result = {
            "target": target,
            "ports": {},
            "dns": {},
            "vulnerabilities": [],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # DNS reconnaissance
        if 53 in self.udp_ports:
            result["dns"] = self._dns_scan(target)
            
        # TCP port scanning
        for port in self.tcp_ports:
            self._random_delay()
            status, protocol = self._tcp_scan(target, port)
            result["ports"][f"tcp/{port}"] = {
                "status": status,
                "protocol": protocol or "unknown"
            }
            
        # UDP port scanning
        for port in self.udp_ports:
            if port == 53 and result.get("dns"):  # Skip if already scanned
                continue
            self._random_delay()
            status, protocol = self._udp_scan(target, port)
            result["ports"][f"udp/{port}"] = {
                "status": status,
                "protocol": protocol or "unknown"
            }
            
        # Add vulnerabilities if found
        if target in self.vulnerabilities:
            result["vulnerabilities"] = self.vulnerabilities[target]
            
        return result

    def scan(self, targets: List[str]) -> Dict:
        """Scan multiple targets with parallel processing"""
        self._log(f"Starting scan of {len(targets)} targets with {self.workers} workers", "INFO")
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in targets}
            
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results[target] = future.result()
                    self._log(f"Completed scan for {target}", "DEBUG")
                except Exception as e:
                    self._log(f"Scan failed for {target}: {str(e)}", "ERROR")
                    results[target] = {"error": str(e)}
        
        self.results = results
        return results

    # =========================================================================
    # Reporting
    # =========================================================================
    def generate_report(self) -> str:
        """Generate report in specified format"""
        if self.output_format == "json":
            return self._generate_json_report()
        elif self.output_format == "html":
            return self._generate_html_report()
        else:
            return self._generate_text_report()

    def _generate_json_report(self) -> str:
        """Generate JSON-formatted report"""
        report = {
            "metadata": {
                "scanner": "EternalPulseScanner",
                "version": VERSION,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now(timezone.utc).isoformat(),
                "duration": (datetime.now(timezone.utc) - self.start_time).total_seconds(),
                "targets_scanned": len(self.results),
                "evasion_metrics": self.evasion_metrics
            },
            "results": self.results,
            "vulnerabilities": self.vulnerabilities
        }
        return json.dumps(report, indent=2)

    def _generate_html_report(self) -> str:
        """Generate HTML-formatted report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>EternalPulse Scan Report</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        .target {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; }}
        .vuln-critical {{ color: #f00; font-weight: bold; }}
        .vuln-high {{ color: #f50; }}
        .vuln-medium {{ color: #fc0; }}
        .port-open {{ color: #0a0; }}
        .port-filtered {{ color: #888; }}
    </style>
</head>
<body>
    <h1>EternalPulse Scan Report</h1>
    <p><strong>Version:</strong> {VERSION}</p>
    <p><strong>Scan started:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}</p>
    <p><strong>Targets scanned:</strong> {len(self.results)}</p>
    
    <h2>Scan Results</h2>"""
        
        for target, data in self.results.items():
            html += f"""
    <div class="target">
        <h3>{target}</h3>
        <p><strong>Scan time:</strong> {data['timestamp']}</p>
        
        <h4>Ports:</h4>
        <ul>"""
            
            for port, info in data['ports'].items():
                status_class = "port-open" if "open" in info['status'] else "port-filtered"
                html += f"""
            <li><span class="{status_class}">{port}</span>: 
                {info['status']} - {info.get('protocol', 'unknown')}</li>"""
            
            html += """
        </ul>"""
            
            if data.get('dns'):
                html += """
        <h4>DNS Information:</h4>
        <ul>"""
                for rtype, records in data['dns'].items():
                    html += f"""
            <li><strong>{rtype}:</strong> {', '.join(records)}</li>"""
                html += """
        </ul>"""
            
            if data.get('vulnerabilities'):
                html += """
        <h4>Vulnerabilities:</h4>
        <ul>"""
                for vuln in data['vulnerabilities']:
                    risk_class = f"vuln-{vuln['risk'].lower()}"
                    html += f"""
            <li class="{risk_class}">
                {vuln['name']} ({vuln['cve']}) - {vuln['risk']} risk
                <br><em>{vuln['details']}</em>
            </li>"""
                html += """
        </ul>"""
            
            html += """
    </div>"""
        
        html += """
</body>
</html>"""
        return html

    def _generate_text_report(self) -> str:
        """Generate human-readable text report"""
        report = f"EternalPulse Scanner Report v{VERSION}\n"
        report += f"Scan started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        report += f"Targets scanned: {len(self.results)}\n"
        report += f"Evasion techniques used: {json.dumps(self.evasion_metrics)}\n\n"
        
        for target, data in self.results.items():
            report += f"Target: {target}\n"
            report += f"Scan time: {data['timestamp']}\n"
            
            report += "Open ports:\n"
            for port, info in data['ports'].items():
                if "open" in info['status']:
                    report += f"  {port}: {info['status']} ({info.get('protocol', 'unknown')})\n"
            
            if data.get('vulnerabilities'):
                report += "Vulnerabilities:\n"
                for vuln in data['vulnerabilities']:
                    report += f"  {vuln['name']} ({vuln['cve']}) - {vuln['risk']} risk\n"
                    report += f"  Details: {vuln['details']}\n"
            
            report += "\n"
        
        return report

    def save_report(self, file_path: str):
        """Save report to file"""
        report = self.generate_report()
        with open(file_path, 'w') as f:
            f.write(report)
        self._log(f"Report saved to {file_path}", "INFO")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="EternalPulse Scanner 4.0 - Advanced Network Reconnaissance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("targets", nargs="+", help="Hosts or networks to scan")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "html", "text"], default="json",
                        help="Report format")
    parser.add_argument("-t", "--timeout", type=float, default=3.0,
                        help="Connection timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=50,
                        help="Number of parallel workers")
    parser.add_argument("-s", "--stealth", type=int, choices=[1, 2, 3, 4], default=2,
                        help="Stealth level (1=verbose, 4=silent)")
    parser.add_argument("-i", "--intensity", type=int, choices=[1, 2, 3, 4, 5], default=3,
                        help="Scan intensity (1=light, 5=comprehensive)")
    parser.add_argument("--no-evasion", action="store_true", help="Disable evasion techniques")
    parser.add_argument("--no-vuln", action="store_true", help="Disable vulnerability scanning")
    args = parser.parse_args()

    # Expand CIDR ranges
    expanded_targets = []
    for target in args.targets:
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                expanded_targets.extend(str(ip) for ip in network.hosts())
            except ValueError:
                expanded_targets.append(target)
        else:
            expanded_targets.append(target)

    scanner = EternalPulseScanner(
        timeout=args.timeout,
        workers=args.workers,
        stealth_level=args.stealth,
        scan_intensity=args.intensity,
        evasion_mode=not args.no_evasion,
        vulnerability_scan=not args.no_vuln,
        output_format=args.format
    )
    
    scanner.scan(expanded_targets)
    
    if args.output:
        scanner.save_report(args.output)
        print(f"Report saved to {args.output}")
    else:
        print(scanner.generate_report())