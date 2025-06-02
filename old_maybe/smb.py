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
import select
import threading
from datetime import datetime, timezone

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.file import CreateDisposition, FileAttributes, CreateOptions, FilePipePrinterAccessMask
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

DEFAULT_ALLOWLIST = {
    "ips": [],
    "cidrs": []
}

class SMBScanner:
    class RoundRobin:
        def __init__(self, t): self._t = list(t)
        def __iter__(self): return iter(self._t)

    def __init__(self, allowlist=None, timeout=2, workers=100, generalize=True, verbose=True, retries=1):
        self._nets, self._ips = self._load_allowlist(allowlist)
        self._timeout, self._workers, self._retries = timeout, workers, retries
        self._tcp_ports = [445, 139]
        self._udp_ports = [137, 138]
        self._results, self._generalize, self._verbose, self._skipped = {}, generalize, verbose, []

    def _log(self, *m):
        if self._verbose: print(*m, file=sys.stderr, flush=True)

    @staticmethod
    def _load_allowlist(src):
        if src is None:
            d = DEFAULT_ALLOWLIST
        elif isinstance(src, dict):
            d = src
        else:
            with open(src) as f:
                d = json.load(f)
        nets, ips = [], set()
        for t in d.get("cidrs", []):
            try: nets.append(ipaddress.ip_network(t, strict=False))
            except ValueError: pass
        for t in d.get("ips", []):
            try: ips.add(ipaddress.ip_address(t))
            except ValueError: pass
        return nets, ips

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets) or not nets and not ips

    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def _tcp_connect(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((h, p)); return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH): return "unreachable"
            return "error"
        finally:
            s.close()

    def _udp_state(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (h, p))
            ready = select.select([s], [], [], self._timeout)
            if ready[0]: return "open"
            return "open|filtered"
        except socket.timeout:
            return "open|filtered"
        except OSError as e:
            if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH): return "closed"
            return "error"
        finally:
            s.close()

    def _probe_port(self, h, p, proto):
        for _ in range(self._retries):
            st = self._tcp_connect(h, p) if proto == "tcp" else self._udp_state(h, p)
            if st != "error": return st
        return "error"

    def _probe_host(self, h):
        res = {"host": h, "ports": {}}
        for p in self._tcp_ports:
            res["ports"][p] = {"protocol": "tcp", "state": self._probe_port(h, p, "tcp")}
        for p in self._udp_ports:
            res["ports"][p] = {"protocol": "udp", "state": self._probe_port(h, p, "udp")}
        return res

    @staticmethod
    def _iter_targets(hosts, cidrs):
        for h in hosts: yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False): yield str(ip)

    def _filter_targets(self, t):
        a, seen = [], set()
        for x in t:
            if x in seen: continue
            seen.add(x)
            if self._allowed(x, self._nets, self._ips): a.append(x)
            else: self._skipped.append(x)
        return a

    def _is_success(self, r):
        for p in (445, 139):
            if r["ports"].get(p, {}).get("state") == "open": return True
        return False

    async def _async_scan(self, order):
        loop = asyncio.get_running_loop()
        futs = [loop.run_in_executor(None, self._probe_host, h) for h in order]
        for h, r in zip(order, await asyncio.gather(*futs)):
            self._results[h] = r
        return self._results

    def scan(self, hosts=None, cidrs=None, async_mode=False):
        t = self._filter_targets(list(self._iter_targets(hosts or [], cidrs or [])))
        if not t: return {}
        order = list(self.RoundRobin(t))
        if async_mode:
            asyncio.run(self._async_scan(order))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
                fs = {ex.submit(self._probe_host, h): h for h in order}
                for f in concurrent.futures.as_completed(fs):
                    h = fs[f]
                    try: self._results[h] = f.result()
                    except Exception as e: self._results[h] = {"error": str(e)}
        return self._results

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                hf = ("0.0.0.0/0" if ipaddress.ip_address(h).version == 4 else "::/0") if self._generalize else h
                s.append({"id": f"{hf}:445", "host": hf, "port": 445, "details": r, "ts": ts})
        return s

    def save_routes(self, path):
        if not path: return
        d = self.successful_routes()
        if not d: return
        e = self.load_routes(path) or []
        m = {r["id"]: r for r in e}
        for r in d: m[r["id"]] = r
        with open(path, "w") as f: json.dump(list(m.values()), f, indent=2)

    @staticmethod
    def load_routes(path):
        if path and os.path.isfile(path):
            with open(path) as f: return json.load(f)
        return None

def install_tunnel(host: str, username: str, password: str, domain: str, share: str, local_port: int, remote_pipe: str):
    if not SMB_AVAILABLE:
        print(f"[!] smbprotocol not installed; cannot tunnel to {host}", file=sys.stderr)
        return False

    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception as e:
        print(f"[!] Could not connect to {host}:445: {e}", file=sys.stderr)
        return False

    try:
        session = Session(conn, username=username, password=password, require_encryption=True, domain=domain or None)
        session.connect(timeout=5)
    except Exception as e:
        print(f"[!] Authentication to {host} failed: {e}", file=sys.stderr)
        conn.disconnect()
        return False

    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception as e:
        print(f"[!] TreeConnect to {share} on {host} failed: {e}", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", local_port))
    listener.listen(1)
    print(f"[+] Tunnel listening on localhost:{local_port} -> {host}\\{share}\\PIPE\\{remote_pipe}")

    def handle_client(client_sock):
        try:
            pipe = Open(tree, fr"PIPE\{remote_pipe}", access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OPEN_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
            pipe.create(timeout=5)
        except Exception as e:
            print(f"[!] Could not open pipe {remote_pipe} on {host}: {e}", file=sys.stderr)
            client_sock.close()
            return

        def forward_pipe_to_sock():
            while True:
                try:
                    data = pipe.read(4096, 0)
                    if not data: break
                    client_sock.sendall(data)
                except:
                    break
            try: client_sock.shutdown(socket.SHUT_RDWR); client_sock.close()
            except: pass

        def forward_sock_to_pipe():
            while True:
                try:
                    data = client_sock.recv(4096)
                    if not data: break
                    pipe.write(data, 0)
                except:
                    break
            try: pipe.close()
            except: pass

        threading.Thread(target=forward_pipe_to_sock, daemon=True).start()
        threading.Thread(target=forward_sock_to_pipe, daemon=True).start()

    while True:
        try:
            client_sock, _ = listener.accept()
            threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()
        except KeyboardInterrupt:
            break
        except:
            continue

    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def parse_args():
    p = argparse.ArgumentParser(description="SMB2/3 Tunnel Installer")
    p.add_argument("--host", action="append", default=[], help="Host(s) to tunnel to")
    p.add_argument("--cidr", action="append", default=[], help="CIDR range(s) to scan for hosts")
    p.add_argument("--input", help="File with hosts, one per line")
    p.add_argument("--timeout", type=int, default=2, help="Timeout seconds for scanning")
    p.add_argument("--workers", type=int, default=100, help="Parallel threads for scanning")
    p.add_argument("--allowlist", help="Allowlist JSON file")
    p.add_argument("--save", help="Save successful routes JSON")
    p.add_argument("--reload", help="Reload routes JSON")
    p.add_argument("--asyncio", action="store_true", help="Async scanning")
    p.add_argument("--no-generalize", action="store_false", dest="generalize", help="Exact IPs instead of 0.0.0.0/0")
    p.add_argument("--quiet", action="store_true", help="Suppress logs")
    p.add_argument("--username", required=True, help="SMB username")
    p.add_argument("--password", required=True, help="SMB password")
    p.add_argument("--domain", default="", help="SMB domain (optional)")
    p.add_argument("--share", default="IPC$", help="Samba share for pipe (default IPC$)")
    p.add_argument("--local-port", type=int, required=True, help="Local port to listen on")
    p.add_argument("--remote-pipe", required=True, help="Remote named pipe to open")
    p.set_defaults(generalize=True)
    return p.parse_args()

def main():
    a = parse_args()
    s = SMBScanner(allowlist=a.allowlist, timeout=a.timeout, workers=a.workers, generalize=a.generalize, verbose=not a.quiet)
    hosts = a.host[:]
    if a.input:
        with open(a.input) as f:
            hosts.extend(l.strip() for l in f if l.strip())
    cidrs = a.cidr or []
    if a.reload:
        d = s.load_routes(a.reload)
        if d:
            for r in d:
                x = r.get("details", {}).get("host") or r.get("host")
                if x and x not in hosts:
                    hosts.append(x)
    if not hosts and not cidrs:
        hosts = [str(x) for x in s._ips]
        cidrs = [str(n) for n in s._nets]
    s.scan(hosts, cidrs, async_mode=a.asyncio)
    if a.save or a.reload:
        s.save_routes(a.save or a.reload)
    ok = s.successful_routes()
    for r in ok:
        print(f"{r['host']}:{r['port']} open")
    for route in ok:
        host = route["host"]
        print(f"[*] Setting up tunnel to {host}")
        install_tunnel(host=host, username=a.username, password=a.password, domain=a.domain, share=a.share, local_port=a.local_port, remote_pipe=a.remote_pipe)

if __name__ == "__main__":
    main()
