#!/usr/bin/env python3
import argparse, socket, json, concurrent.futures, ipaddress, sys, os, errno, random, asyncio, select
from datetime import datetime, timezone

DEFAULT_ALLOWLIST = {
    "ips": [],
    "cidrs": []
}

class SMBScanner:
    class RoundRobin:
        def __init__(self, t): self._t = list(t)
        def __iter__(self): return iter(self._t)

    def __init__(self, allowlist=None, timeout=2, workers=100,
                 generalize=True, verbose=True, retries=1):
        self._nets, self._ips = self._load_allowlist(allowlist)
        self._timeout, self._workers, self._retries = timeout, workers, retries
        self._tcp_ports, self._udp_ports = [445, 139], [137, 138]
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

def parse_args():
    p = argparse.ArgumentParser(description="SMB port scanner")
    p.add_argument("--host", action="append", default=[], help="Host(s) to scan")
    p.add_argument("--cidr", action="append", default=[], help="CIDR range(s) to scan")
    p.add_argument("--input", help="File with hosts")
    p.add_argument("--timeout", type=int, default=2, help="Timeout seconds")
    p.add_argument("--workers", type=int, default=100, help="Parallel threads")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--allowlist", help="Allowlist JSON")
    p.add_argument("--save", help="Save successful routes JSON")
    p.add_argument("--reload", help="Reload routes JSON")
    p.add_argument("--asyncio", action="store_true", help="Async scanning")
    p.add_argument("--no-generalize", action="store_false", dest="generalize", help="Exact IPs in output")
    p.add_argument("--quiet", action="store_true", help="Suppress logs")
    p.set_defaults(generalize=True)
    return p.parse_args()

def main():
    a = parse_args()
    s = SMBScanner(allowlist=a.allowlist, timeout=a.timeout, workers=a.workers,
                   generalize=a.generalize, verbose=not a.quiet)
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
                if x and x not in hosts: hosts.append(x)
    if not hosts and not cidrs:
        hosts = [str(x) for x in s._ips]
        cidrs = [str(n) for n in s._nets]
    s.scan(hosts, cidrs, async_mode=a.asyncio)
    if a.save or a.reload:
        s.save_routes(a.save or a.reload)
    ok = s.successful_routes()
    if a.json:
        print(json.dumps(ok, indent=2))
    else:
        for r in ok:
            print(f"{r['host']}:{r['port']} open")

if __name__ == "__main__":
    main()
